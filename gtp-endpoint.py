#!/usr/bin/env python3
"""
gtp_tun_injector.py

- Listens on UDP/2152 for GTP-U packets (binds to LISTEN_ADDR:LISTEN_PORT).
- Decapsulates GTPv1 using scapy.contrib.gtp.GTPHeader.
- Injects inner IP packets into a TUN device so kernel routing applies.
- Deletes TUN interface cleanly on SIGINT/SIGTERM/SIGHUP.
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

from scapy.contrib.gtp import GTPHeader
from scapy.all import IP, IPv6, Raw

# /dev/net/tun ioctl flags
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 2152
TUN_NAME = "gtp0"
MAX_PKT = 65535
HEX_PREVIEW_LEN = 128

tun_fd_global = None
tun_name_global = None


# -----------------------
# Helpers
# -----------------------

def cleanup_and_exit(signum, frame):
    """Delete the TUN interface on exit."""
    global tun_fd_global, tun_name_global
    print(f"\n[!] Caught signal {signum}, cleaning up…")

    if tun_fd_global is not None:
        try:
            os.close(tun_fd_global)
        except Exception:
            pass

    if tun_name_global:
        print(f"[+] Deleting TUN interface: {tun_name_global}")
        subprocess.call(["ip", "link", "del", tun_name_global])

    print("[+] Cleanup done. Exiting.")
    sys.exit(0)


def hexdump(b, length=128):
    s = binascii.hexlify(b).decode()
    groups = [s[i:i+32] for i in range(0, min(len(s), length*2), 32)]
    return "\n".join(
        " ".join(groups[i][j:j+2] for j in range(0, len(groups[i]), 2))
        for i in range(len(groups))
    )


def create_tun(name=TUN_NAME):
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    ifs = fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    real_name = ifs[:16].split(b"\x00", 1)[0].decode()
    return tun_fd, real_name


def setup_interface(name, mtu=None):
    subprocess.check_call(["ip", "link", "set", "dev", name, "up"])
    subprocess.check_call(["ip", "addr", "add", "10.45.0.1/16", "dev", name])
    if mtu:
        subprocess.check_call(["ip", "link", "set", "dev", name, "mtu", str(mtu)])


def try_parse_inner(inner):
    if inner is None:
        return "empty", None, b""

    if isinstance(inner, IP):
        info = {"src": inner.src, "dst": inner.dst, "proto": inner.proto, "total_len": inner.len}
        return "IPv4", info, bytes(inner)

    if isinstance(inner, IPv6):
        info = {"src": inner.src, "dst": inner.dst, "next_hdr": inner.nh}
        return "IPv6", info, bytes(inner)

    if isinstance(inner, Raw):
        return "raw", None, bytes(inner.load)

    raw = bytes(inner) if not isinstance(inner, bytes) else inner

    # minimal sniffing fallback
    if raw:
        n = raw[0] >> 4
        if n == 4 and len(raw) >= 20:
            src = socket.inet_ntoa(raw[12:16])
            dst = socket.inet_ntoa(raw[16:20])
            proto = raw[9]
            total_len = struct.unpack("!H", raw[2:4])[0]
            info = {"src": src, "dst": dst, "proto": proto, "total_len": total_len}
            return "IPv4", info, raw
        if n == 6 and len(raw) >= 40:
            src = socket.inet_ntop(socket.AF_INET6, raw[8:24])
            dst = socket.inet_ntop(socket.AF_INET6, raw[24:40])
            info = {"src": src, "dst": dst, "next_hdr": raw[6]}
            return "IPv6", info, raw

    return "raw", None, raw


# -----------------------
# Main
# -----------------------

def main():
    global tun_fd_global, tun_name_global

    parser = argparse.ArgumentParser(description="GTP-U → TUN injector")
    parser.add_argument("--listen-addr", default=LISTEN_ADDR)
    parser.add_argument("--listen-port", type=int, default=LISTEN_PORT)
    parser.add_argument("--tun-name", default=TUN_NAME)
    parser.add_argument("--setup-iface", action="store_true")
    parser.add_argument("--mtu", type=int, default=None)
    parser.add_argument("--teid", type=int, default=None)
    parser.add_argument("--hex-preview", type=int, default=HEX_PREVIEW_LEN)
    args = parser.parse_args()

    # Handle signals
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, cleanup_and_exit)

    # Create TUN
    tun_fd, tun_name = create_tun(args.tun_name)
    tun_fd_global = tun_fd
    tun_name_global = tun_name

    print(f"[+] Created TUN interface: {tun_name} (fd={tun_fd})")

    if args.setup_iface:
        setup_interface(tun_name, mtu=args.mtu)
        print(f"[+] Brought {tun_name} up")

    # UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen_addr, args.listen_port))
    print(f"[+] Listening on {args.listen_addr}:{args.listen_port} (GTP-U). TEID filter={args.teid}")

    try:
        while True:
            data, addr = sock.recvfrom(MAX_PKT)
            ts = time.strftime("%Y-%m-%d %H:%M:%S")

            try:
                gtp = GTPHeader(data)
            except Exception:
                print(f"{ts} {addr[0]} parse error")
                continue

            teid = getattr(gtp, "teid", None)
            if args.teid is not None and teid != args.teid:
                continue

            # --- Fixed GTP inner extraction ---
            inner = None
            if hasattr(gtp, "payload"):
                p = bytes(gtp.payload)

                # Skip GTP-U extension headers if present
                if getattr(gtp, "E") == 1 and len(p) > 2:
                    skip = p[0] * 4             # length in 4-byte units
                    p = p[skip:] if len(p) >= skip else b""

                inner = p

            kind, info, inner_bytes = try_parse_inner(inner)
            if args.hex_preview:
                print("Full hexdump:")
                print(hexdump(data))
                print("Inner hexdump:")
                print(hexdump(inner_bytes))

            # --- Drop non-IP traffic ---
            if not inner_bytes or inner_bytes[0] >> 4 not in (4, 6):
                print(f"{ts} TEID={teid} non-IP inner payload -> drop")
                continue

            written = os.write(tun_fd, inner_bytes) if inner_bytes else 0

            print(f"{ts} FROM {addr[0]} TEID={teid} wrote={written}B ({kind})")

    except KeyboardInterrupt:
        pass

    cleanup_and_exit(None, None)


if __name__ == "__main__":
    main()