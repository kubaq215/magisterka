#!/usr/bin/env python3
"""
gtp_tun_injector_dynamic.py

- Data Plane: GTP-U <-> TUN
- Control Plane: UDP/5555 (commands to map UE IPs to TEIDs)
"""

import os
import fcntl
import struct
import subprocess
import socket
import time
import binascii
import argparse
import signal
import sys
import select

from scapy.contrib.gtp import GTPHeader
from scapy.all import IP, IPv6, Raw

# --- Configuration Constants ---
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
MAX_PKT   = 65535

# Global State
tun_fd_global = None
tun_name_global = None
ue_mapping = {}  # Format: { "UE_IP_STR": (TEID_INT, "REMOTE_IP_STR") }


# -----------------------
# Network Helpers
# -----------------------

def create_tun(name):
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    ifs = fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    return tun_fd, ifs[:16].split(b"\x00", 1)[0].decode()

def setup_interface(name, mtu=1500):
    subprocess.check_call(["ip", "link", "set", "dev", name, "up"])
    subprocess.check_call(["ip", "addr", "add", "10.45.0.1/16", "dev", name])
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
# Protocol Handlers
# -----------------------

def handle_control_msg(sock):
    """
    Reads commands from the control socket.
    Format: ADD <UE_IP> <TEID> <REMOTE_IP>
            DEL <UE_IP>
            LIST
    """
    try:
        data, addr = sock.recvfrom(4096)
        msg = data.decode('utf-8').strip()
    except Exception:
        return

    parts = msg.split()
    if not parts:
        return

    cmd = parts[0].upper()
    response = "OK\n"

    try:
        if cmd == "ADD":
            # ADD 10.45.0.2 200 192.168.1.50
            if len(parts) < 4:
                response = "ERROR: Usage: ADD <UE_IP> <TEID> <REMOTE_IP>\n"
            else:
                ue_ip, teid, remote_ip = parts[1], int(parts[2]), parts[3]
                ue_mapping[ue_ip] = (teid, remote_ip)
                print(f"[CTRL] Added mapping: {ue_ip} -> TEID {teid} @ {remote_ip}")

        elif cmd == "DEL":
            if len(parts) < 2:
                response = "ERROR: Usage: DEL <UE_IP>\n"
            else:
                ue_ip = parts[1]
                if ue_ip in ue_mapping:
                    del ue_mapping[ue_ip]
                    print(f"[CTRL] Removed mapping for {ue_ip}")
                else:
                    response = "ERROR: IP not found\n"

        elif cmd == "LIST":
            response = "--- Active Mappings ---\n"
            for ip, (teid, remote) in ue_mapping.items():
                response += f"{ip} -> TEID: {teid}, GW: {remote}\n"
            response += "-----------------------\n"
        
        else:
            response = "ERROR: Unknown command\n"
    
    except ValueError:
        response = "ERROR: Invalid format (TEID must be int)\n"

    sock.sendto(response.encode(), addr)


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
        
        # Write to TUN
        if p and (p[0] >> 4) in (4, 6):
            os.write(tun_fd, p)
            if args.verbose:
                print(f"[RX] GTP (TEID={gtp.teid}) -> TUN")


def handle_tx_tun(tun_fd, sock, default_gw, default_teid):
    """Read TUN -> Lookup TEID based on Dest IP -> Encapsulate GTP"""
    try:
        packet = os.read(tun_fd, MAX_PKT)
    except OSError:
        return

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
    parser.add_argument("--control-ip", default="127.0.0.1", help="Control Socket IP")
    parser.add_argument("--control-port", type=int, default=5555, help="Control Socket Port")
    parser.add_argument("--tun-name", default="gtp0")
    
    # Optional defaults if mapping is missed
    parser.add_argument("--default-remote-ip", help="Default Remote GTP Peer")
    parser.add_argument("--default-teid", type=int, help="Default TX TEID")
    parser.add_argument("--teid", type=int, help="RX Filter TEID (incoming)")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    # Signals
    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    # 1. Setup TUN
    tun_fd, tun_name = create_tun(args.tun_name)
    tun_fd_global, tun_name_global = tun_fd, tun_name

    setup_interface(tun_name)
    print(f"[+] TUN {tun_name} active.")

    # 2. Setup GTP Data Socket
    data_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data_sock.bind((args.bind_ip, 2152))

    # 3. Setup Control Socket
    ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ctrl_sock.bind((args.control_ip, args.control_port))
    print(f"[+] Control Socket listening on {args.control_ip}:{args.control_port}")
    print(f"    Use: echo 'ADD <UE_IP> <TEID> <GW_IP>' | nc -u {args.control_ip} {args.control_port}")

    # 4. Event Loop
    inputs = [data_sock, ctrl_sock, tun_fd]

    try:
        while True:
            readable, _, _ = select.select(inputs, [], [])

            for r in readable:
                if r is ctrl_sock:
                    handle_control_msg(ctrl_sock)
                elif r is data_sock:
                    handle_rx_gtp(data_sock, tun_fd, args)
                elif r is tun_fd:
                    handle_tx_tun(tun_fd, data_sock, args.default_remote_ip, args.default_teid)

    except KeyboardInterrupt:
        pass
    finally:
        cleanup_and_exit(None, None)

if __name__ == "__main__":
    main()