"""
OpenFlow 1.3 flow installer using python-openflow (pyof) + raw sockets.
No Ryu dependency required.

Usage:
  1. pip install python-openflow
  2. Set OVS to connect to this controller:
       ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
  3. Run: python3 openflow_pyof.py

The script listens on port 6653, performs the OF1.3 handshake,
then installs several example flows on the first switch that connects.
"""

import socket
import struct
import logging

from pyof.v0x04.common.header import Header, Type
from pyof.v0x04.common.flow_match import (
    Match, MatchType, OxmOfbMatchField, OxmTLV, OxmClass, VlanId,
)
from pyof.v0x04.common.action import (
    ActionOutput, ActionSetField,
)
from pyof.v0x04.common.flow_instructions import (
    InstructionApplyAction,
)
from pyof.v0x04.common.port import PortNo
from pyof.v0x04.controller2switch.flow_mod import FlowMod, FlowModCommand
from pyof.v0x04.symmetric.hello import Hello
from pyof.v0x04.controller2switch.features_request import FeaturesRequest

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger(__name__)

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 6653
OF_HEADER_SIZE = 8


# ---------------------------------------------------------------------------
# OXM field helpers – build TLVs for common match fields
# ---------------------------------------------------------------------------

def _oxm_tlv(field, value_bytes, has_mask=False):
    """Build an OxmTLV for an OpenFlow Basic match field."""
    tlv = OxmTLV()
    tlv.oxm_class = OxmClass.OFPXMC_OPENFLOW_BASIC
    tlv.oxm_field = field
    tlv.oxm_hasmask = has_mask
    tlv.oxm_value = value_bytes
    return tlv


def match_eth_type(eth_type: int):
    return _oxm_tlv(OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE,
                     struct.pack("!H", eth_type))


def match_ipv4_src(ip_str: str):
    return _oxm_tlv(OxmOfbMatchField.OFPXMT_OFB_IPV4_SRC,
                     socket.inet_aton(ip_str))


def match_ipv4_dst(ip_str: str):
    return _oxm_tlv(OxmOfbMatchField.OFPXMT_OFB_IPV4_DST,
                     socket.inet_aton(ip_str))


def match_ip_proto(proto: int):
    return _oxm_tlv(OxmOfbMatchField.OFPXMT_OFB_IP_PROTO,
                     struct.pack("!B", proto))


def match_tcp_dst(port: int):
    return _oxm_tlv(OxmOfbMatchField.OFPXMT_OFB_TCP_DST,
                     struct.pack("!H", port))


def match_in_port(port: int):
    return _oxm_tlv(OxmOfbMatchField.OFPXMT_OFB_IN_PORT,
                     struct.pack("!I", port))


def match_eth_dst(mac: str):
    return _oxm_tlv(OxmOfbMatchField.OFPXMT_OFB_ETH_DST,
                     bytes.fromhex(mac.replace(":", "")))


def match_eth_src(mac: str):
    return _oxm_tlv(OxmOfbMatchField.OFPXMT_OFB_ETH_SRC,
                     bytes.fromhex(mac.replace(":", "")))


# ---------------------------------------------------------------------------
# Flow construction helpers
# ---------------------------------------------------------------------------

def build_match(oxm_fields):
    """Build an OFP Match with the given list of OxmTLV objects."""
    match = Match()
    match.match_type = MatchType.OFPMT_OXM
    for field in oxm_fields:
        match.oxm_match_fields.append(field)
    return match


def build_flow_mod(match, actions, priority=0, table_id=0,
                   idle_timeout=0, hard_timeout=0, xid=None):
    """Construct a FlowMod message (OFPFC_ADD)."""
    flow_mod = FlowMod(xid=xid)
    flow_mod.command = FlowModCommand.OFPFC_ADD
    flow_mod.table_id = table_id
    flow_mod.priority = priority
    flow_mod.idle_timeout = idle_timeout
    flow_mod.hard_timeout = hard_timeout
    flow_mod.match = match

    if actions:
        instruction = InstructionApplyAction()
        instruction.actions = actions
        flow_mod.instructions = [instruction]

    return flow_mod


# ---------------------------------------------------------------------------
# Network I/O helpers
# ---------------------------------------------------------------------------

def send_msg(sock, msg):
    """Pack and send an OpenFlow message."""
    data = msg.pack()
    sock.sendall(data)


def recv_msg(sock):
    """Receive a full OpenFlow message (header + body)."""
    header_data = _recv_exact(sock, OF_HEADER_SIZE)
    if not header_data:
        return None, None
    version, msg_type, length, xid = struct.unpack("!BBHI", header_data)
    body = b""
    remaining = length - OF_HEADER_SIZE
    if remaining > 0:
        body = _recv_exact(sock, remaining)
    return header_data, body


def _recv_exact(sock, n):
    """Read exactly n bytes from socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# Flow definitions
# ---------------------------------------------------------------------------

def install_flows(sock):
    """Send several FlowMod messages to the connected switch."""

    xid = 100

    # Flow 1: Table-miss – send unmatched packets to controller (priority 0)
    log.info("Installing table-miss flow (send to controller)")
    match = build_match([])
    actions = [ActionOutput(port=PortNo.OFPP_CONTROLLER, max_length=128)]
    send_msg(sock, build_flow_mod(match, actions, priority=0, xid=xid))
    xid += 1

    # Flow 2: Flood all ARP traffic (eth_type 0x0806)
    log.info("Installing ARP flood flow")
    match = build_match([match_eth_type(0x0806)])
    actions = [ActionOutput(port=PortNo.OFPP_FLOOD)]
    send_msg(sock, build_flow_mod(match, actions, priority=10, xid=xid))
    xid += 1

    # Flow 3: Forward IP 10.0.0.1 -> 10.0.0.2 to port 2
    log.info("Installing flow: 10.0.0.1 -> 10.0.0.2 => port 2")
    match = build_match([
        match_eth_type(0x0800),
        match_ipv4_src("10.0.0.1"),
        match_ipv4_dst("10.0.0.2"),
    ])
    actions = [ActionOutput(port=2)]
    send_msg(sock, build_flow_mod(match, actions, priority=20, xid=xid))
    xid += 1

    # Flow 4: Forward IP 10.0.0.2 -> 10.0.0.1 to port 1
    log.info("Installing flow: 10.0.0.2 -> 10.0.0.1 => port 1")
    match = build_match([
        match_eth_type(0x0800),
        match_ipv4_src("10.0.0.2"),
        match_ipv4_dst("10.0.0.1"),
    ])
    actions = [ActionOutput(port=1)]
    send_msg(sock, build_flow_mod(match, actions, priority=20, xid=xid))
    xid += 1

    # Flow 5: Drop all traffic from 10.0.0.99 (empty action list = drop)
    log.info("Installing DROP flow for src 10.0.0.99")
    match = build_match([
        match_eth_type(0x0800),
        match_ipv4_src("10.0.0.99"),
    ])
    send_msg(sock, build_flow_mod(match, [], priority=30, xid=xid))
    xid += 1

    # Flow 6: Redirect TCP/80 traffic to port 2 with dst MAC rewrite
    log.info("Installing HTTP redirect flow (tcp/80 => port 2, rewrite MAC)")
    match = build_match([
        match_eth_type(0x0800),
        match_ip_proto(6),
        match_tcp_dst(80),
    ])
    set_field = ActionSetField(
        field=_oxm_tlv(OxmOfbMatchField.OFPXMT_OFB_ETH_DST,
                        bytes.fromhex("000000000002"))
    )
    actions = [set_field, ActionOutput(port=2)]
    send_msg(sock, build_flow_mod(match, actions, priority=25, xid=xid))
    xid += 1

    log.info("All flows installed successfully")


# ---------------------------------------------------------------------------
# Main: listen for switch connection and perform handshake
# ---------------------------------------------------------------------------

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(1)
    log.info("Listening on %s:%d – waiting for OVS to connect...", LISTEN_HOST, LISTEN_PORT)

    while True:
        conn, addr = server.accept()
        log.info("Switch connected from %s:%d", *addr)
        try:
            handle_switch(conn)
        except Exception as e:
            log.error("Error handling switch: %s", e, exc_info=True)
        finally:
            conn.close()
            log.info("Connection closed")


def handle_switch(sock):
    """Perform OF1.3 handshake then install flows."""

    # Step 1: Exchange Hello messages
    hello = Hello(xid=0)
    send_msg(sock, hello)
    log.info("Sent Hello")

    header_data, body = recv_msg(sock)
    if not header_data:
        log.error("Connection lost before Hello reply")
        return
    msg_type = header_data[1]
    log.info("Received message type=%d (expected Hello=%d)", msg_type, Type.OFPT_HELLO.value)

    # Step 2: Send Features Request
    features_req = FeaturesRequest(xid=1)
    send_msg(sock, features_req)
    log.info("Sent FeaturesRequest")

    header_data, body = recv_msg(sock)
    if not header_data:
        log.error("Connection lost before FeaturesReply")
        return
    msg_type = header_data[1]
    log.info("Received message type=%d (expected FeaturesReply=%d)", msg_type, Type.OFPT_FEATURES_REPLY.value)

    # Step 3: Install flows
    install_flows(sock)

    # Step 4: Keep connection alive – echo replies
    log.info("Entering echo loop (Ctrl+C to stop)...")
    while True:
        header_data, body = recv_msg(sock)
        if not header_data:
            log.info("Switch disconnected")
            break
        version, msg_type, length, xid = struct.unpack("!BBHI", header_data)

        if msg_type == Type.OFPT_ECHO_REQUEST.value:
            # Reply with echo response (same xid, same body)
            echo_reply = struct.pack("!BBHI", version, Type.OFPT_ECHO_REPLY.value,
                                     OF_HEADER_SIZE + len(body), xid)
            sock.sendall(echo_reply + body)
        elif msg_type == Type.OFPT_PACKET_IN.value:
            log.info("PacketIn received (xid=%d, %d bytes payload)", xid, length)
        elif msg_type == Type.OFPT_ERROR.value:
            if body and len(body) >= 4:
                err_type, err_code = struct.unpack("!HH", body[:4])
                log.warning("Error message: type=%d code=%d", err_type, err_code)
        else:
            log.debug("Received msg type=%d xid=%d len=%d", msg_type, xid, length)


if __name__ == "__main__":
    main()
