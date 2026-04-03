#!/usr/bin/env python3
"""
gtp-endpoint.py

- Data Plane: GTP-U <-> TAP (Layer 2, for OVS)
- Control Plane: TCP with JSON + HMAC-SHA256 authentication

Performance notes:
- Manual GTP-U header parsing via struct (no Scapy)
- epoll-based event loop (selectors)
- Pre-allocated receive buffer with recvfrom_into
- Zero-copy TAP writes via os.writev + memoryview
- Raw 4-byte IP keys for fast-path UE lookup
- Non-blocking drain loops for batched I/O
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
import errno
import selectors

# --- Configuration Constants ---
TUNSETIFF = 0x400454ca
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000
MAX_PKT   = 65535
ETH_P_IP  = b'\x08\x00'
ETH_P_IPV6 = b'\x86\xdd'
ETH_DST   = b'\x02\x00\x00\x00\x00\x01'
ETH_SRC   = b'\x02\x00\x00\x00\x00\x02'

# Pre-computed 14-byte Ethernet headers
ETH_HDR_IPV4 = ETH_DST + ETH_SRC + ETH_P_IP
ETH_HDR_IPV6 = ETH_DST + ETH_SRC + ETH_P_IPV6

# GTP-U v1 header: flags(1B) type(1B) length(2B) teid(4B) = 8 bytes
GTP_HDR = struct.Struct('!BBHI')
GTP_HDR_SIZE = GTP_HDR.size

CTRL_RECV_BUF = 65535

# Global State
tun_fd_global = None
tun_name_global = None
shared_secret = b""
ue_mapping = {}       # { "UE_IP_STR": (TEID_INT, "REMOTE_IP_STR") }
ue_mapping_fast = {}  # { 4-byte-raw-ip: (TEID_INT, "REMOTE_IP_STR") }
ctrl_clients = []     # list of connected TCP client sockets
ctrl_buffers = {}     # sock -> bytes (partial read buffer)
sel = None            # global selector


# -----------------------
# Network Helpers
# -----------------------

def create_tap(name):
    tun_fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    ifr = struct.pack("16sH", name.encode(), IFF_TAP | IFF_NO_PI)
    ifs = fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    return tun_fd, ifs[:16].split(b"\x00", 1)[0].decode()

def setup_interface(name, mtu=1500):
    subprocess.check_call(["ip", "link", "set", "dev", name, "up"])
    subprocess.check_call(["ip", "link", "set", "dev", name, "mtu", str(mtu)])

def cleanup_and_exit(signum, frame):
    print(f"\n[!] Signal {signum} received. Cleaning up...")
    if tun_fd_global:
        try: os.close(tun_fd_global)
        except: pass
    if tun_name_global:
        subprocess.call(["ip", "link", "del", tun_name_global])
    sys.exit(0)

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
    if sel:
        try:
            sel.unregister(sock)
        except (KeyError, ValueError):
            pass
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
    sel.register(conn, selectors.EVENT_READ, "ctrl_client")
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
            ue_mapping_fast[socket.inet_aton(ue_ip)] = (teid, remote_ip)
            resp["ue_ip"] = ue_ip
            print(f"[CTRL] Added mapping: {ue_ip} -> TEID {teid} @ {remote_ip}")

        elif cmd == "DEL":
            ue_ip = msg["ue_ip"]
            if ue_ip in ue_mapping:
                del ue_mapping[ue_ip]
                ue_mapping_fast.pop(socket.inet_aton(ue_ip), None)
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


def handle_rx_gtp(data_sock, tun_fd, recv_buf, recv_mv, args):
    """Drain GTP-U socket -> parse headers manually -> write inner IP to TAP."""
    while True:
        try:
            nbytes, addr = data_sock.recvfrom_into(recv_buf)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                break
            return

        if nbytes < GTP_HDR_SIZE:
            continue

        flags, msg_type, length, teid = GTP_HDR.unpack_from(recv_buf, 0)

        if args.teid and teid != args.teid:
            continue

        # Compute inner packet offset, skipping optional + extension headers
        hdr_len = GTP_HDR_SIZE
        if flags & 0x07:  # any of E, S, PN flags set
            hdr_len = 12
            if flags & 0x04 and nbytes > 11:  # E flag -> extension chain
                next_ext = recv_buf[11]
                while next_ext != 0 and hdr_len < nbytes:
                    ext_len = recv_buf[hdr_len] * 4
                    if ext_len < 4:
                        break
                    hdr_len += ext_len
                    if hdr_len <= nbytes:
                        next_ext = recv_buf[hdr_len - 1]
                    else:
                        break

        if hdr_len >= nbytes:
            continue

        ver = recv_buf[hdr_len] >> 4
        if ver == 4:
            eth_hdr = ETH_HDR_IPV4
        elif ver == 6:
            eth_hdr = ETH_HDR_IPV6
        else:
            continue

        os.writev(tun_fd, [eth_hdr, recv_mv[hdr_len:nbytes]])

        if args.verbose:
            print(f"[RX] GTP (TEID={teid}) -> TAP ({nbytes - hdr_len}B)")


def handle_tx_tun(tun_fd, data_sock, default_gw, default_teid, verbose):
    """Drain TAP (non-blocking) -> lookup TEID -> encapsulate GTP-U."""
    while True:
        try:
            raw = os.read(tun_fd, MAX_PKT)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                break
            raise

        if len(raw) <= 14:
            continue
        packet = raw[14:]

        ver = packet[0] >> 4
        if ver == 4 and len(packet) >= 20:
            dst_raw = bytes(packet[16:20])
            if dst_raw in ue_mapping_fast:
                teid, remote_ip = ue_mapping_fast[dst_raw]
            elif default_gw and default_teid:
                teid, remote_ip = default_teid, default_gw
            else:
                continue
        elif ver == 6 and len(packet) >= 40:
            try:
                dst_str = socket.inet_ntop(socket.AF_INET6, packet[24:40])
            except Exception:
                continue
            if dst_str in ue_mapping:
                teid, remote_ip = ue_mapping[dst_str]
            elif default_gw and default_teid:
                teid, remote_ip = default_teid, default_gw
            else:
                continue
        else:
            continue

        gtp_hdr = GTP_HDR.pack(0x30, 0xFF, len(packet), teid)
        data_sock.sendto(gtp_hdr + bytes(packet), (remote_ip, 2152))

        if verbose:
            if ver == 4:
                dst_str = socket.inet_ntoa(dst_raw)
            print(f"[TX] TUN -> GTP: UE={dst_str} TEID={teid} @ {remote_ip}")


# -----------------------
# Main
# -----------------------

def main():
    global tun_fd_global, tun_name_global, shared_secret, sel

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

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    if args.secret:
        shared_secret = args.secret.encode()
        print("[+] HMAC-SHA256 authentication enabled")

    # 1. Setup TAP (O_NONBLOCK for batch drain)
    tun_fd, tun_name = create_tap(args.tun_name)
    tun_fd_global, tun_name_global = tun_fd, tun_name

    setup_interface(tun_name)
    print(f"[+] TAP {tun_name} active.")

    # 2. Setup GTP Data Socket (non-blocking for batch drain)
    data_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data_sock.bind((args.bind_ip, 2152))
    data_sock.setblocking(False)

    # Pre-allocated receive buffer + memoryview for zero-copy slicing
    recv_buf = bytearray(MAX_PKT)
    recv_mv = memoryview(recv_buf)

    # 3. Setup TCP Control Socket
    ctrl_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl_listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ctrl_listen.setblocking(False)
    ctrl_listen.bind((args.control_ip, args.control_port))
    ctrl_listen.listen(4)
    print(f"[+] Control TCP listening on {args.control_ip}:{args.control_port}")

    # 4. Event Loop (epoll on Linux via selectors)
    sel = selectors.DefaultSelector()
    sel.register(data_sock, selectors.EVENT_READ, "gtp_data")
    sel.register(tun_fd, selectors.EVENT_READ, "tap")
    sel.register(ctrl_listen, selectors.EVENT_READ, "ctrl_listen")

    try:
        while True:
            events = sel.select(timeout=1.0)
            for key, mask in events:
                tag = key.data
                if tag == "gtp_data":
                    handle_rx_gtp(data_sock, tun_fd, recv_buf, recv_mv, args)
                elif tag == "tap":
                    handle_tx_tun(tun_fd, data_sock,
                                  args.default_remote_ip, args.default_teid,
                                  args.verbose)
                elif tag == "ctrl_listen":
                    handle_ctrl_accept(ctrl_listen)
                elif tag == "ctrl_client":
                    handle_ctrl_data(key.fileobj)

    except KeyboardInterrupt:
        pass
    finally:
        for c in list(ctrl_clients):
            remove_ctrl_client(c)
        ctrl_listen.close()
        sel.close()
        cleanup_and_exit(None, None)

if __name__ == "__main__":
    main()
