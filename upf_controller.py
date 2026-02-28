#!/usr/bin/env python3
"""
upf_controller.py
Role: Control Plane
1. Receives complex JSON Session info from Open5GS (C-Code) via REST.
2. Configures OVS to steer traffic into the TUN interface.
3. Sends simplified "ADD/DEL" commands to the Dataplane script via UDP.
"""

import logging
import socket
import subprocess
import argparse
from flask import Flask, request, jsonify
from dataclasses import dataclass
from typing import Optional, Dict, List

# Configuration
GTP_ENDPOINT_IP = "127.0.0.1"
GTP_ENDPOINT_PORT = 5555
TUN_INTERFACE = "gtp0"  # The interface OVS sends traffic to

# Logging
app = Flask(__name__)
DEBUG_MODE = False


def configure_logging(debug: bool):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - [CTRL] - %(levelname)s - %(message)s',
        force=True,
    )


configure_logging(False)

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
            if not far or not far.outer_header_creation:
                continue
            ohc = far.outer_header_creation
            return Tunnel(ue_ip=pdr.ue_ip, teid=ohc.teid, dest_ip=ohc.dest_ip)
        return None

    def get_flows(self) -> List[Flow]:
        result = []
        for pdr in self.pdrs:
            far = self.fars.get(pdr.far_id)
            if not far:
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

# --- OVS Flow Management ---

def add_ovs_flow(flow: Flow):
    """Add OVS flow to route traffic. Placeholder."""
    logging.info(f"[OVS] Adding flow PDR {flow.pdr_id}: UE {flow.ue_ip}, prec={flow.precedence}, {flow.source_interface}->{flow.destination_interface}, action={flow.apply_action}")
    # TODO: ovs-ofctl add-flow br0 "priority={flow.precedence},ip,nw_dst={flow.ue_ip},actions=..."
    pass

def delete_ovs_flow(flow: Flow):
    """Delete OVS flow for specific PDR. Placeholder."""
    logging.info(f"[OVS] Deleting flow PDR {flow.pdr_id} for UE {flow.ue_ip}")
    # TODO: ovs-ofctl del-flows br0 "ip,nw_dst={flow.ue_ip}"
    pass

def modify_ovs_flow(flow: Flow):
    """Modify existing OVS flow. Placeholder."""
    logging.info(f"[OVS] Modifying flow PDR {flow.pdr_id} for UE {flow.ue_ip}")
    delete_ovs_flow(flow)
    add_ovs_flow(flow)

# --- Logic ---

session_store = SessionStore()


@app.before_request
def debug_log_request():
    if not DEBUG_MODE:
        return

    payload = request.get_json(silent=True)
    logging.debug(
        f"[HTTP] {request.method} {request.path} from={request.remote_addr} payload={payload}"
    )


@app.after_request
def debug_log_response(response):
    if not DEBUG_MODE:
        return response

    body = response.get_data(as_text=True)
    if len(body) > 500:
        body = body[:500] + "..."
    logging.debug(f"[HTTP] {request.method} {request.path} -> {response.status_code} body={body}")
    return response

# --- REST Endpoints ---

@app.route('/session/establish', methods=['POST'])
def session_establish():
    """Session Establishment: save session, create tunnels and OVS flows."""
    try:
        data = request.get_json()
        logging.info(f"[API] Session establishment: {data}")
        
        session_id = data.get('session_id')
        
        # Parse PDRs
        pdrs = []
        for p in data.get('pdrs', []):
            pdrs.append(PDR(
                pdr_id=p['pdr_id'],
                precedence=p['precedence'],
                source_interface=p['source_interface'],
                ue_ip=p['ue_ip'],
                far_id=p['far_id'],
                outer_header_removal=p.get('outer_header_removal', False)
            ))
        
        # Parse FARs
        fars = {}
        for f in data.get('fars', []):
            ohc = None
            if f.get('outer_header_creation'):
                ohc = OuterHeaderCreation(
                    teid=f['outer_header_creation']['teid'],
                    dest_ip=f['outer_header_creation']['dest_ip']
                )
            fars[f['far_id']] = FAR(
                far_id=f['far_id'],
                apply_action=f['apply_action'],
                destination_interface=f['destination_interface'],
                outer_header_creation=ohc
            )
        
        session = Session(session_id=session_id, pdrs=pdrs, fars=fars)
        session_store.add_session(session)
        logging.debug(f"[STATE] session count={len(session_store.sessions_by_id)}")
        
        tunnel = session.get_tunnel()
        if tunnel:
            gtp_resp = gtp_add_tunnel(ue_ip=tunnel.ue_ip, teid=tunnel.teid, remote_ip=tunnel.dest_ip)
            logging.debug(f"[GTP] establish add tunnel result={gtp_resp}")
        
        flows = session.get_flows()
        for flow in flows:
            add_ovs_flow(flow)
        
        return jsonify({"status": "success", "session_id": session_id}), 200
    except Exception as e:
        logging.exception(f"[API] Establishment failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/session/modify', methods=['PUT'])
def session_modify():
    """Session Modification: update PDR/FAR, modify tunnels/flows as needed."""
    try:
        data = request.get_json()
        logging.info(f"[API] Session modification: {data}")
        
        session_id = data.get('session_id')
        session = session_store.sessions_by_id.get(session_id)
        if not session:
            return jsonify({"status": "error", "message": "Session not found"}), 404
        
        old_tunnel = session.get_tunnel()
        old_flows = {f.pdr_id: f for f in session.get_flows()}
        logging.debug(f"[STATE] old_tunnel={old_tunnel}, old_flows={len(old_flows)}")
        
        # Parse and apply PDR updates
        for p in data.get('update_pdrs', []):
            pdr_id = p['pdr_id']
            existing = next((pdr for pdr in session.pdrs if pdr.pdr_id == pdr_id), None)
            if existing:
                existing.precedence = p.get('precedence', existing.precedence)
                existing.source_interface = p.get('source_interface', existing.source_interface)
                existing.ue_ip = p.get('ue_ip', existing.ue_ip)
                existing.far_id = p.get('far_id', existing.far_id)
                existing.outer_header_removal = p.get('outer_header_removal', existing.outer_header_removal)
        
        # Parse and apply FAR updates
        for f in data.get('update_fars', []):
            far_id = f['far_id']
            ohc = None
            if f.get('outer_header_creation'):
                ohc = OuterHeaderCreation(
                    teid=f['outer_header_creation']['teid'],
                    dest_ip=f['outer_header_creation']['dest_ip']
                )
            if far_id in session.fars:
                session.fars[far_id].apply_action = f.get('apply_action', session.fars[far_id].apply_action)
                session.fars[far_id].destination_interface = f.get('destination_interface', session.fars[far_id].destination_interface)
                if ohc:
                    session.fars[far_id].outer_header_creation = ohc
        
        new_tunnel = session.get_tunnel()
        new_flows = {f.pdr_id: f for f in session.get_flows()}
        logging.debug(f"[STATE] new_tunnel={new_tunnel}, new_flows={len(new_flows)}")
        
        # Determine tunnel changes
        if old_tunnel and not new_tunnel:
            gtp_resp = gtp_del_tunnel(ue_ip=old_tunnel.ue_ip)
            logging.debug(f"[GTP] modify del tunnel result={gtp_resp}")
        elif not old_tunnel and new_tunnel:
            gtp_resp = gtp_add_tunnel(ue_ip=new_tunnel.ue_ip, teid=new_tunnel.teid, remote_ip=new_tunnel.dest_ip)
            logging.debug(f"[GTP] modify add tunnel result={gtp_resp}")
        elif old_tunnel and new_tunnel and old_tunnel != new_tunnel:
            gtp_resp = gtp_del_tunnel(ue_ip=old_tunnel.ue_ip)
            logging.debug(f"[GTP] modify swap del result={gtp_resp}")
            gtp_resp = gtp_add_tunnel(ue_ip=new_tunnel.ue_ip, teid=new_tunnel.teid, remote_ip=new_tunnel.dest_ip)
            logging.debug(f"[GTP] modify swap add result={gtp_resp}")
        
        # Determine flow changes
        for pdr_id, flow in new_flows.items():
            if pdr_id not in old_flows:
                add_ovs_flow(flow)
            elif flow != old_flows[pdr_id]:
                modify_ovs_flow(flow)
        
        for pdr_id, flow in old_flows.items():
            if pdr_id not in new_flows:
                delete_ovs_flow(flow)
        
        return jsonify({"status": "success", "session_id": session_id}), 200
    except Exception as e:
        logging.exception(f"[API] Modification failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/session/delete', methods=['DELETE'])
def session_delete():
    """Session Deletion: delete flows, tunnels, and session data."""
    try:
        data = request.get_json()
        logging.info(f"[API] Session deletion: {data}")
        
        session_id = data.get('session_id')
        session = session_store.sessions_by_id.get(session_id)
        if not session:
            return jsonify({"status": "error", "message": "Session not found"}), 404
        
        tunnel = session.get_tunnel()
        if tunnel:
            gtp_resp = gtp_del_tunnel(ue_ip=tunnel.ue_ip)
            logging.debug(f"[GTP] delete tunnel result={gtp_resp}")
        
        flows = session.get_flows()
        for flow in flows:
            delete_ovs_flow(flow)
        
        session_store.remove_session(session_id)
        logging.debug(f"[STATE] session count={len(session_store.sessions_by_id)}")
        
        return jsonify({"status": "success", "session_id": session_id}), 200
    except Exception as e:
        logging.exception(f"[API] Deletion failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="UPF controller API")
    parser.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='Bind port (default: 8080)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode with verbose logs')
    args = parser.parse_args()

    DEBUG_MODE = args.debug
    configure_logging(DEBUG_MODE)

    if DEBUG_MODE:
        logging.debug('[DEBUG] Debug mode enabled')

    # Listen on port 8080 for Open5GS
    app.run(host=args.host, port=args.port, debug=DEBUG_MODE)