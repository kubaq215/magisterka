#!/usr/bin/env python3
"""
gtp-endpoint.py

- Data Plane: GTP-U <-> TAP (Layer 2, for OVS)
- Control Plane: TCP with JSON + HMAC-SHA256 authentication
"""

import os
import fcntl
import struct
import subprocess
import socket
import hmac
import hashlib
import json
import binascii
import argparse
import signal
import sys
import select

from scapy.contrib.gtp import GTPHeader
from scapy.all import IP, IPv6, Raw

# --- Configuration Constants ---
TUNSETIFF = 0x400454ca
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000
MAX_PKT   = 65535
ETH_P_IP  = b'\x08\x00'
ETH_P_IPV6 = b'\x86\xdd'
ETH_DST   = b'\x02\x00\x00\x00\x00\x01'
ETH_SRC   = b'\x02\x00\x00\x00\x00\x02'

CTRL_RECV_BUF = 65535

# Global State
tun_fd_global = None
tun_name_global = None
shared_secret = b""
ue_mapping = {}  # { "UE_IP_STR": (TEID_INT, "REMOTE_IP_STR") }
ctrl_clients = []  # list of connected TCP client sockets
ctrl_buffers = {}  # sock -> bytes (partial read buffer)


# -----------------------
# Network Helpers
# -----------------------

def create_tap(name):
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TAP | IFF_NO_PI)
    ifs = fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    return tun_fd, ifs[:16].split(b"\x00", 1)[0].decode()

def setup_interface(name, mtu=1500):
    subprocess.check_call(["ip", "link", "set", "dev", name, "up"])
    # subprocess.check_call(["ip", "addr", "add", "10.45.0.1/16", "dev", name])
    subprocess.check_call(["ip", "link", "set", "dev", name, "mtu", str(mtu)])

def cleanup_and_exit(signum, frame):
    print(f"\n[!] Signal {signum} received. Cleaning up...")
    if tun_fd_global:
        try: os.close(tun_fd_global)
        except: pass
    if tun_name_global:
        subprocess.call(["ip", "link", "del", tun_name_global])
    sys.exit(0)

def try_parse_inner_headers(packet_bytes):
    """
    Lightweight parsing to extract Src/Dst IP without full Scapy overhead
    for every packet unless necessary. Returns (proto_str, info_dict).
    """
    if not packet_bytes:
        return "empty", {}

    ver = packet_bytes[0] >> 4
    if ver == 4 and len(packet_bytes) >= 20:
        # IPv4
        try:
            src = socket.inet_ntoa(packet_bytes[12:16])
            dst = socket.inet_ntoa(packet_bytes[16:20])
            return "IPv4", {"src": src, "dst": dst}
        except:
            pass
    elif ver == 6 and len(packet_bytes) >= 40:
        # IPv6
        try:
            src = socket.inet_ntop(socket.AF_INET6, packet_bytes[8:24])
            dst = socket.inet_ntop(socket.AF_INET6, packet_bytes[24:40])
            return "IPv6", {"src": src, "dst": dst}
        except:
            pass
            
    return "raw", {}

def hexdump(b, length=64):
    if not b: return ""
    s = binascii.hexlify(b).decode()
    return " ".join(s[i:i+2] for i in range(0, min(len(s), length*2), 2))

# -----------------------
# HMAC helpers
# -----------------------

def compute_sig(msg_body: dict, secret: bytes) -> str:
    payload = json.dumps(msg_body, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()

def verify_sig(msg: dict, secret: bytes) -> bool:
    sig = msg.get("sig", "")
    body = {k: v for k, v in msg.items() if k != "sig"}
    expected = compute_sig(body, secret)
    return hmac.compare_digest(sig, expected)

def sign_response(body: dict, secret: bytes) -> dict:
    body["sig"] = compute_sig(body, secret)
    return body

# -----------------------
# TCP Control Helpers
# -----------------------

def send_json_line(sock, obj):
    line = json.dumps(obj, separators=(",", ":")) + "\n"
    try:
        sock.sendall(line.encode())
    except (BrokenPipeError, ConnectionResetError, OSError):
        remove_ctrl_client(sock)

def remove_ctrl_client(sock):
    if sock in ctrl_clients:
        ctrl_clients.remove(sock)
    ctrl_buffers.pop(sock, None)
    try:
        sock.close()
    except OSError:
        pass
    print("[CTRL] Client disconnected")

# -----------------------
# Protocol Handlers
# -----------------------

def handle_ctrl_accept(listen_sock):
    conn, addr = listen_sock.accept()
    conn.setblocking(False)
    ctrl_clients.append(conn)
    ctrl_buffers[conn] = b""
    print(f"[CTRL] Client connected from {addr[0]}:{addr[1]}")

def handle_ctrl_data(sock):
    try:
        data = sock.recv(CTRL_RECV_BUF)
    except (ConnectionResetError, OSError):
        data = b""

    if not data:
        remove_ctrl_client(sock)
        return

    ctrl_buffers[sock] = ctrl_buffers.get(sock, b"") + data

    while b"\n" in ctrl_buffers[sock]:
        line, ctrl_buffers[sock] = ctrl_buffers[sock].split(b"\n", 1)
        process_ctrl_line(sock, line)

def process_ctrl_line(sock, line_bytes):
    try:
        msg = json.loads(line_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        send_json_line(sock, {"status": "error", "message": "invalid JSON"})
        return

    if shared_secret and not verify_sig(msg, shared_secret):
        send_json_line(sock, {"status": "error", "message": "bad signature"})
        return

    cmd = msg.get("cmd", "").upper()
    resp = {"status": "ok"}

    try:
        if cmd == "ADD":
            ue_ip = msg["ue_ip"]
            teid = int(msg["teid"])
            remote_ip = msg["remote_ip"]
            ue_mapping[ue_ip] = (teid, remote_ip)
            resp["ue_ip"] = ue_ip
            print(f"[CTRL] Added mapping: {ue_ip} -> TEID {teid} @ {remote_ip}")

        elif cmd == "DEL":
            ue_ip = msg["ue_ip"]
            if ue_ip in ue_mapping:
                del ue_mapping[ue_ip]
                resp["ue_ip"] = ue_ip
                print(f"[CTRL] Removed mapping for {ue_ip}")
            else:
                resp = {"status": "error", "message": "IP not found"}

        elif cmd == "SYNC":
            mappings = []
            for ip, (teid, remote) in ue_mapping.items():
                mappings.append({"ue_ip": ip, "teid": teid, "remote_ip": remote})
            resp["mappings"] = mappings

        else:
            resp = {"status": "error", "message": f"unknown command: {cmd}"}

    except (KeyError, ValueError) as e:
        resp = {"status": "error", "message": str(e)}

    if shared_secret:
        resp = sign_response(resp, shared_secret)
    send_json_line(sock, resp)


def handle_rx_gtp(sock, tun_fd, args):
    """Receive GTP-U -> Write Inner IP to TUN"""
    try:
        data, addr = sock.recvfrom(MAX_PKT)
    except Exception:
        return

    try:
        gtp = GTPHeader(data)
    except:
        return

    # Check incoming TEID filter if set
    if args.teid and getattr(gtp, "teid", 0) != args.teid:
        return

    # Extract payload
    if hasattr(gtp, "payload"):
        p = bytes(gtp.payload)
        # Handle Extension Header
        if getattr(gtp, "E", 0) == 1 and len(p) > 2:
            skip = p[0] * 4
            p = p[skip:] if len(p) >= skip else b""
        
        # Write to TAP (prepend Ethernet header)
        if p and (p[0] >> 4) in (4, 6):
            ethertype = ETH_P_IP if (p[0] >> 4) == 4 else ETH_P_IPV6
            eth_hdr = ETH_DST + ETH_SRC + ethertype
            os.write(tun_fd, eth_hdr + p)
            if args.verbose:
                print(f"[RX] GTP (TEID={gtp.teid}) -> TAP")


def handle_tx_tun(tun_fd, sock, default_gw, default_teid):
    """Read TAP -> Strip Ethernet header -> Lookup TEID -> Encapsulate GTP"""
    try:
        raw = os.read(tun_fd, MAX_PKT)
    except OSError:
        return

    # Strip 14-byte Ethernet header
    if len(raw) <= 14:
        return
    packet = raw[14:]

    # Parse headers to find destination IP (The UE IP)
    kind, info = try_parse_inner_headers(packet)
    dst_ip = info.get("dst")

    if not dst_ip:
        return # Not IP or parse error

    # 1. Check dynamic mapping
    if dst_ip in ue_mapping:
        teid, remote_ip = ue_mapping[dst_ip]
    # 2. Check defaults
    elif default_gw and default_teid:
        teid, remote_ip = default_teid, default_gw
    else:
        # No mapping found and no default -> Drop
        # print(f"[DROP] No TEID mapping for UE {dst_ip}")
        return

    # Encapsulate
    gtp_hdr = GTPHeader(teid=teid, gtp_type=255)
    final_pkt = bytes(gtp_hdr / packet)

    sock.sendto(final_pkt, (remote_ip, 2152))
    print(f"[TX] TUN -> GTP: UE={dst_ip} mapped to TEID={teid} @ {remote_ip}")


# -----------------------
# Main
# -----------------------

def main():
    global tun_fd_global, tun_name_global

    parser = argparse.ArgumentParser()
    parser.add_argument("--bind-ip", default="0.0.0.0", help="GTP-U Listen IP")
    parser.add_argument("--control-ip", default="0.0.0.0", help="Control TCP listen IP")
    parser.add_argument("--control-port", type=int, default=5555, help="Control TCP listen port")
    parser.add_argument("--secret", default="", help="Shared HMAC-SHA256 secret (empty = no auth)")
    parser.add_argument("--tun-name", default="gtp0")
    parser.add_argument("--default-remote-ip", help="Default Remote GTP Peer")
    parser.add_argument("--default-teid", type=int, help="Default TX TEID")
    parser.add_argument("--teid", type=int, help="RX Filter TEID (incoming)")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    global shared_secret

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    if args.secret:
        shared_secret = args.secret.encode()
        print("[+] HMAC-SHA256 authentication enabled")

    # 1. Setup TAP
    tun_fd, tun_name = create_tap(args.tun_name)
    tun_fd_global, tun_name_global = tun_fd, tun_name

    setup_interface(tun_name)
    print(f"[+] TAP {tun_name} active.")

    # 2. Setup GTP Data Socket
    data_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data_sock.bind((args.bind_ip, 2152))

    # 3. Setup TCP Control Socket
    ctrl_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl_listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ctrl_listen.setblocking(False)
    ctrl_listen.bind((args.control_ip, args.control_port))
    ctrl_listen.listen(4)
    print(f"[+] Control TCP listening on {args.control_ip}:{args.control_port}")

    # 4. Event Loop
    try:
        while True:
            inputs = [data_sock, ctrl_listen, tun_fd] + ctrl_clients
            readable, _, _ = select.select(inputs, [], [], 1.0)

            for r in readable:
                if r is ctrl_listen:
                    handle_ctrl_accept(ctrl_listen)
                elif r in ctrl_clients:
                    handle_ctrl_data(r)
                elif r is data_sock:
                    handle_rx_gtp(data_sock, tun_fd, args)
                elif r is tun_fd:
                    handle_tx_tun(tun_fd, data_sock, args.default_remote_ip, args.default_teid)

    except KeyboardInterrupt:
        pass
    finally:
        for c in list(ctrl_clients):
            remove_ctrl_client(c)
        ctrl_listen.close()
        cleanup_and_exit(None, None)

if __name__ == "__main__":
    main()