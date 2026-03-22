#!/usr/bin/env python3
"""
upf_controller.py  –  Ryu-based UPF Control Plane

1. Receives JSON Session info from Open5GS (C-Code) via REST (Ryu WSGI).
2. Programs OVS flows on br0 via OpenFlow 1.3 using FlowManager.
3. Sends simplified "ADD/DEL" commands to the Dataplane script via UDP.

Usage:
  ryu-manager upf_controller.py --wsapi-host 0.0.0.0 --wsapi-port 8080

  Then point OVS at this controller:
    ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
"""

import json
import logging
import socket
from dataclasses import dataclass
from typing import Optional, Dict, List

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

from openflow_flows import FlowManager

# ---------------------------------------------------------------------------
# Configuration – fill in these placeholders with your actual OVS port numbers
# ---------------------------------------------------------------------------
GTP_ENDPOINT_IP = "127.0.0.1"
GTP_ENDPOINT_PORT = 5555

# OVS br0 port numbers (find with: ovs-ofctl -O OpenFlow13 dump-ports-desc br0)
OVS_PORT_ACCESS = "veth-gtp-br"   # PLACEHOLDER: port number facing gNB (N3 side)
OVS_PORT_CORE   = "veth-ext-br"   # PLACEHOLDER: port number facing gtp0/internet (N6 side)

upf_app_name = "upf_controller_app"

# --- Class Definitions ---

@dataclass
class OuterHeaderCreation:
    teid: int
    dest_ip: str


@dataclass
class FAR:
    far_id: int
    apply_action: str          # "BUFF" | "FORW"
    destination_interface: str
    outer_header_creation: Optional[OuterHeaderCreation] = None


@dataclass
class PDR:
    pdr_id: int
    precedence: int
    source_interface: str
    ue_ip: str
    far_id: int
    outer_header_removal: bool


@dataclass
class Flow:
    pdr_id: int
    precedence: int
    source_interface: str
    destination_interface: str
    ue_ip: str
    apply_action: str


@dataclass
class Tunnel:
    ue_ip: str
    teid: int
    dest_ip: str


@dataclass
class Session:
    session_id: str
    pdrs: List[PDR]
    fars: Dict[int, FAR]

    def get_tunnel(self) -> Optional[Tunnel]:
        for pdr in self.pdrs:
            far = self.fars.get(pdr.far_id)
            if not far or not far.outer_header_creation or far.destination_interface == "CP_FUNCTION":
                continue
            ohc = far.outer_header_creation
            return Tunnel(ue_ip=pdr.ue_ip, teid=ohc.teid, dest_ip=ohc.dest_ip)
        return None

    def get_flows(self) -> List[Flow]:
        result = []
        for pdr in self.pdrs:
            far = self.fars.get(pdr.far_id)
            if not far or far.destination_interface == "CP_FUNCTION":
                continue
            result.append(Flow(
                pdr_id=pdr.pdr_id,
                precedence=pdr.precedence,
                source_interface=pdr.source_interface,
                destination_interface=far.destination_interface,
                ue_ip=pdr.ue_ip,
                apply_action=far.apply_action
            ))
        return result

class SessionStore:
    def __init__(self):
        self.sessions_by_id: dict[str, Session] = {}
        self.sessions_by_ue_ip: dict[str, set[str]] = {}

    def add_session(self, session: Session):
        self.sessions_by_id[session.session_id] = session

        for pdr in session.pdrs:
            self.sessions_by_ue_ip \
                .setdefault(pdr.ue_ip, set()) \
                .add(session.session_id)
    
    def remove_session(self, session_id: str):
        session = self.sessions_by_id.pop(session_id, None)
        if not session:
            return

        for pdr in session.pdrs:
            self.sessions_by_ue_ip.get(pdr.ue_ip, set()).discard(session_id)

    def get_sessions_by_ue_ip(self, ue_ip: str):
        ids = self.sessions_by_ue_ip.get(ue_ip, set())
        return [self.sessions_by_id[i] for i in ids]

# --- Helpers ---

def gtp_add_tunnel(
    ue_ip: str,
    teid: int,
    remote_ip: str,
    timeout: float = 1.0,
):
    msg = f"ADD {ue_ip} {teid} {remote_ip}\n"
    logging.debug(f"[GTP] -> endpoint send: {msg.strip()}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.sendto(msg.encode(), (GTP_ENDPOINT_IP, GTP_ENDPOINT_PORT))
        resp, _ = sock.recvfrom(4096)
        decoded = resp.decode().strip()
        logging.debug(f"[GTP] <- endpoint resp: {decoded}")
        return decoded
    finally:
        sock.close()

def gtp_del_tunnel(
    ue_ip: str,
    timeout: float = 1.0,
):
    msg = f"DEL {ue_ip}\n"
    logging.debug(f"[GTP] -> endpoint send: {msg.strip()}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.sendto(msg.encode(), (GTP_ENDPOINT_IP, GTP_ENDPOINT_PORT))
        resp, _ = sock.recvfrom(4096)
        decoded = resp.decode().strip()
        logging.debug(f"[GTP] <- endpoint resp: {decoded}")
        return decoded
    finally:
        sock.close()

# --- OVS Flow Management (OpenFlow via FlowManager) ---

def _flow_match_fields(flow: Flow) -> dict:
    """Translate a UPF Flow into OFPMatch keyword args.

    PLACEHOLDER: Adjust the match fields below to fit your OVS topology.
    Currently matches on eth_type=IPv4 + UE IP (src or dst depending on
    direction) + in_port.
    """
    fields = {"eth_type": 0x0800}

    if flow.source_interface == "ACCESS":
        # Uplink: traffic arriving from gNB side, destined for UE IP
        fields["ipv4_dst"] = flow.ue_ip
        if OVS_PORT_ACCESS is not None:
            fields["in_port"] = OVS_PORT_ACCESS
    elif flow.source_interface == "CORE":
        # Downlink: traffic arriving from core/internet side, from UE IP
        fields["ipv4_src"] = flow.ue_ip
        if OVS_PORT_CORE is not None:
            fields["in_port"] = OVS_PORT_CORE

    return fields


def _flow_actions(flow: Flow) -> list:
    """Translate a UPF Flow into a list of FlowManager action dicts.

    PLACEHOLDER: Adjust output ports and header rewrites to fit your topology.
    """
    if flow.apply_action in ("BUFF", "DROP"):
        # Buffering = drop for now (no output action)
        return []

    # FORW – forward to the other side
    if flow.destination_interface == "ACCESS":
        if OVS_PORT_ACCESS is not None:
            return [{"type": "output", "port": OVS_PORT_ACCESS}]
    elif flow.destination_interface == "CORE":
        if OVS_PORT_CORE is not None:
            return [{"type": "output", "port": OVS_PORT_CORE}]

    # Fallback: flood (safe default until ports are configured)
    return [{"type": "output", "port": 0xfffffffb}]  # OFPP_FLOOD


def add_ovs_flow(flow: Flow, flow_manager: Optional[FlowManager]):
    """Install an OVS flow for a UPF PDR via OpenFlow."""
    logging.info(
        "[OVS] Adding flow PDR %d: UE %s, prec=%d, %s->%s, action=%s",
        flow.pdr_id, flow.ue_ip, flow.precedence,
        flow.source_interface, flow.destination_interface, flow.apply_action,
    )
    if flow_manager is None:
        logging.warning("[OVS] No switch connected – flow not installed")
        return
    flow_manager.add_flow(
        priority=flow.precedence,
        match_fields=_flow_match_fields(flow),
        actions=_flow_actions(flow),
    )


def delete_ovs_flow(flow: Flow, flow_manager: Optional[FlowManager]):
    """Delete an OVS flow for a specific PDR via OpenFlow."""
    logging.info("[OVS] Deleting flow PDR %d for UE %s", flow.pdr_id, flow.ue_ip)
    if flow_manager is None:
        logging.warning("[OVS] No switch connected – flow not deleted")
        return
    flow_manager.delete_flow(
        match_fields=_flow_match_fields(flow),
        priority=flow.precedence,
    )


def modify_ovs_flow(flow: Flow, flow_manager: Optional[FlowManager]):
    """Modify an existing OVS flow (delete + re-add)."""
    logging.info("[OVS] Modifying flow PDR %d for UE %s", flow.pdr_id, flow.ue_ip)
    delete_ovs_flow(flow, flow_manager)
    add_ovs_flow(flow, flow_manager)

# ---------------------------------------------------------------------------
# Ryu App – OpenFlow switch management + WSGI REST API
# ---------------------------------------------------------------------------

class UPFControllerApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session_store = SessionStore()
        self.flow_manager: Optional[FlowManager] = None

        wsgi = kwargs["wsgi"]
        wsgi.register(UPFRestController, {upf_app_name: self})
        self.logger.info("[CTRL] Ryu UPF controller started – WSGI registered")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Called when OVS connects. Store datapath and install table-miss."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto

        self.flow_manager = FlowManager(datapath)
        self.logger.info("[OVS] Switch connected: dpid=%s", datapath.id)

        # Table-miss: send unmatched packets to controller
        self.flow_manager.add_flow(
            priority=0,
            actions=[{"type": "output", "port": ofproto.OFPP_CONTROLLER,
                       "max_length": ofproto.OFPCML_NO_BUFFER}],
        )
        self.logger.info("[OVS] Installed table-miss flow")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle packets sent to controller (table-miss). Flood by default."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        )
        datapath.send_msg(out)


# ---------------------------------------------------------------------------
# REST Controller – handles /session/* endpoints via Ryu WSGI
# ---------------------------------------------------------------------------

def _json_response(body: dict, status: int = 200) -> Response:
    return Response(
        content_type="application/json",
        charset="utf-8",
        body=json.dumps(body),
        status=status,
    )


def _parse_request_json(req) -> dict:
    return json.loads(req.body.decode("utf-8"))


def _parse_session(data: dict) -> Session:
    """Parse a session establish JSON payload into a Session object."""
    pdrs = []
    for p in data.get("pdrs", []):
        pdrs.append(PDR(
            pdr_id=p["pdr_id"],
            precedence=p["precedence"],
            source_interface=p["source_interface"],
            ue_ip=p["ue_ip"],
            far_id=p["far_id"],
            outer_header_removal=p.get("outer_header_removal", False),
        ))

    fars = {}
    for f in data.get("fars", []):
        ohc = None
        if f.get("outer_header_creation"):
            ohc = OuterHeaderCreation(
                teid=f["outer_header_creation"]["teid"],
                dest_ip=f["outer_header_creation"]["dest_ip"],
            )
        fars[f["far_id"]] = FAR(
            far_id=f["far_id"],
            apply_action=f["apply_action"],
            destination_interface=f["destination_interface"],
            outer_header_creation=ohc,
        )

    return Session(session_id=data.get("session_id"), pdrs=pdrs, fars=fars)


class UPFRestController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app: UPFControllerApp = data[upf_app_name]

    # --- POST /session/establish -------------------------------------------

    @route("upf", "/session/establish", methods=["POST"])
    def session_establish(self, req, **kwargs):
        """Session Establishment: save session, create tunnels and OVS flows."""
        try:
            data = _parse_request_json(req)
            logging.info("[API] Session establishment: %s", data)

            session = _parse_session(data)
            self.app.session_store.add_session(session)
            logging.debug("[STATE] session count=%d",
                          len(self.app.session_store.sessions_by_id))

            tunnel = session.get_tunnel()
            if tunnel:
                try:
                    gtp_resp = gtp_add_tunnel(
                        ue_ip=tunnel.ue_ip, teid=tunnel.teid,
                        remote_ip=tunnel.dest_ip,
                    )
                    logging.debug("[GTP] establish add tunnel result=%s", gtp_resp)
                except socket.timeout:
                    logging.warning("[GTP] Tunnel add timed out (gtp-endpoint not running?)")

            for flow in session.get_flows():
                add_ovs_flow(flow, self.app.flow_manager)

            return _json_response(
                {"status": "success", "session_id": session.session_id})
        except Exception as e:
            logging.exception("[API] Establishment failed: %s", e)
            return _json_response({"status": "error", "message": str(e)}, 500)

    # --- PUT /session/modify -----------------------------------------------

    @route("upf", "/session/modify", methods=["PUT"])
    def session_modify(self, req, **kwargs):
        """Session Modification: update PDR/FAR, modify tunnels/flows."""
        try:
            data = _parse_request_json(req)
            logging.info("[API] Session modification: %s", data)

            session_id = data.get("session_id")
            session = self.app.session_store.sessions_by_id.get(session_id)
            if not session:
                return _json_response(
                    {"status": "error", "message": "Session not found"}, 404)

            old_tunnel = session.get_tunnel()
            old_flows = {f.pdr_id: f for f in session.get_flows()}

            # Apply PDR updates
            for p in data.get("update_pdrs", []):
                pdr_id = p["pdr_id"]
                existing = next(
                    (pdr for pdr in session.pdrs if pdr.pdr_id == pdr_id), None)
                if existing:
                    existing.precedence = p.get("precedence", existing.precedence)
                    existing.source_interface = p.get(
                        "source_interface", existing.source_interface)
                    existing.ue_ip = p.get("ue_ip", existing.ue_ip)
                    existing.far_id = p.get("far_id", existing.far_id)
                    existing.outer_header_removal = p.get(
                        "outer_header_removal", existing.outer_header_removal)

            # Apply FAR updates
            for f in data.get("update_fars", []):
                far_id = f["far_id"]
                ohc = None
                if f.get("outer_header_creation"):
                    ohc = OuterHeaderCreation(
                        teid=f["outer_header_creation"]["teid"],
                        dest_ip=f["outer_header_creation"]["dest_ip"],
                    )
                if far_id in session.fars:
                    session.fars[far_id].apply_action = f.get(
                        "apply_action", session.fars[far_id].apply_action)
                    session.fars[far_id].destination_interface = f.get(
                        "destination_interface",
                        session.fars[far_id].destination_interface)
                    if ohc:
                        session.fars[far_id].outer_header_creation = ohc

            new_tunnel = session.get_tunnel()
            new_flows = {f.pdr_id: f for f in session.get_flows()}

            # Tunnel changes
            try:
                if old_tunnel and not new_tunnel:
                    gtp_resp = gtp_del_tunnel(ue_ip=old_tunnel.ue_ip)
                    logging.debug("[GTP] modify del tunnel result=%s", gtp_resp)
                elif not old_tunnel and new_tunnel:
                    gtp_resp = gtp_add_tunnel(
                        ue_ip=new_tunnel.ue_ip, teid=new_tunnel.teid,
                        remote_ip=new_tunnel.dest_ip)
                    logging.debug("[GTP] modify add tunnel result=%s", gtp_resp)
                elif old_tunnel and new_tunnel and old_tunnel != new_tunnel:
                    gtp_del_tunnel(ue_ip=old_tunnel.ue_ip)
                    gtp_add_tunnel(
                        ue_ip=new_tunnel.ue_ip, teid=new_tunnel.teid,
                        remote_ip=new_tunnel.dest_ip)
            except socket.timeout:
                logging.warning("[GTP] Tunnel modify timed out (gtp-endpoint not running?)")

            # Flow changes
            fm = self.app.flow_manager
            for pdr_id, flow in new_flows.items():
                if pdr_id not in old_flows:
                    add_ovs_flow(flow, fm)
                elif flow != old_flows[pdr_id]:
                    modify_ovs_flow(flow, fm)

            for pdr_id, flow in old_flows.items():
                if pdr_id not in new_flows:
                    delete_ovs_flow(flow, fm)

            return _json_response(
                {"status": "success", "session_id": session_id})
        except Exception as e:
            logging.exception("[API] Modification failed: %s", e)
            return _json_response({"status": "error", "message": str(e)}, 500)

    # --- DELETE /session/delete --------------------------------------------

    @route("upf", "/session/delete", methods=["DELETE"])
    def session_delete(self, req, **kwargs):
        """Session Deletion: delete flows, tunnels, and session data."""
        try:
            data = _parse_request_json(req)
            logging.info("[API] Session deletion: %s", data)

            session_id = data.get("session_id")
            session = self.app.session_store.sessions_by_id.get(session_id)
            if not session:
                return _json_response(
                    {"status": "error", "message": "Session not found"}, 404)

            tunnel = session.get_tunnel()
            if tunnel:
                try:
                    gtp_resp = gtp_del_tunnel(ue_ip=tunnel.ue_ip)
                    logging.debug("[GTP] delete tunnel result=%s", gtp_resp)
                except socket.timeout:
                    logging.warning("[GTP] Tunnel delete timed out (gtp-endpoint not running?)")

            fm = self.app.flow_manager
            for flow in session.get_flows():
                delete_ovs_flow(flow, fm)

            self.app.session_store.remove_session(session_id)
            logging.debug("[STATE] session count=%d",
                          len(self.app.session_store.sessions_by_id))

            return _json_response(
                {"status": "success", "session_id": session_id})
        except Exception as e:
            logging.exception("[API] Deletion failed: %s", e)
            return _json_response({"status": "error", "message": str(e)}, 500)