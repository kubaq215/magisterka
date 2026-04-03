#!/usr/bin/env python3
"""
upf_controller.py  –  Ryu-based UPF Control Plane

1. Receives JSON Session info from Open5GS (C-Code) via REST (Ryu WSGI).
2. Programs OVS flows on br0 via OpenFlow 1.3 using FlowManager.
3. Manages GTP tunnel mappings on the dataplane via a persistent
   TCP connection with JSON + HMAC-SHA256 authentication.
4. Persists sessions to disk and periodically reconciles state with
   the GTP endpoint via the SYNC command.

Usage:
  ryu-manager upf_controller.py --wsapi-host 0.0.0.0 --wsapi-port 8080

  Then point OVS at this controller:
    ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
"""

import configparser
import hashlib
import hmac as hmac_mod
import json
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

from openflow_flows import FlowManager

# ---------------------------------------------------------------------------
# Configuration – loaded from upf_controller.ini (or path in UPF_CONFIG env var)
# ---------------------------------------------------------------------------
_CONFIG_FILE_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "upf_controller.ini")

def _load_config(path: str = None) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read_dict({
        "gtp": {
            "endpoint_ip":   "127.0.0.1",
            "endpoint_port": "5555",
            "secret":        "",
        },
        "controller": {
            "ip":   "127.0.0.1",
            "port": "6653",
        },
        "ovs": {
            "port_access": "1",
            "port_core":   "2",
        },
        "persistence": {
            "session_file": "",
            "reconcile_interval": "30",
        },
    })
    config_path = path or os.environ.get("UPF_CONFIG", _CONFIG_FILE_DEFAULT)
    if os.path.isfile(config_path):
        cfg.read(config_path)
    return cfg

_cfg = _load_config()

GTP_ENDPOINT_IP   = _cfg.get("gtp", "endpoint_ip")
GTP_ENDPOINT_PORT = _cfg.getint("gtp", "endpoint_port")
GTP_SECRET        = _cfg.get("gtp", "secret").encode() or b""
CONTROLLER_IP     = _cfg.get("controller", "ip")
CONTROLLER_PORT   = _cfg.getint("controller", "port")

OVS_PORT_ACCESS = _cfg.getint("ovs", "port_access")
OVS_PORT_CORE   = _cfg.getint("ovs", "port_core")

_SESSION_FILE_DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "sessions.json")
SESSION_FILE = _cfg.get("persistence", "session_file") or _SESSION_FILE_DEFAULT
RECONCILE_INTERVAL = _cfg.getint("persistence", "reconcile_interval")

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
            if pdr.source_interface == "CP_FUNCTION" or pdr.ue_ip == "0.0.0.0":
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

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "pdrs": [asdict(p) for p in self.pdrs],
            "fars": {str(k): asdict(v) for k, v in self.fars.items()},
        }

    @staticmethod
    def from_dict(d: dict) -> "Session":
        pdrs = [PDR(**p) for p in d["pdrs"]]
        fars = {}
        for k, v in d["fars"].items():
            ohc = None
            if v.get("outer_header_creation"):
                ohc = OuterHeaderCreation(**v["outer_header_creation"])
            fars[int(k)] = FAR(
                far_id=v["far_id"],
                apply_action=v["apply_action"],
                destination_interface=v["destination_interface"],
                outer_header_creation=ohc,
            )
        return Session(session_id=d["session_id"], pdrs=pdrs, fars=fars)


class SessionStore:
    def __init__(self, persist_path: str = ""):
        self.sessions_by_id: dict[str, Session] = {}
        self.sessions_by_ue_ip: dict[str, set[str]] = {}
        self._persist_path = persist_path
        self._lock = threading.Lock()

    def _rebuild_ue_ip_index(self):
        self.sessions_by_ue_ip.clear()
        for session in self.sessions_by_id.values():
            for pdr in session.pdrs:
                self.sessions_by_ue_ip \
                    .setdefault(pdr.ue_ip, set()) \
                    .add(session.session_id)

    def add_session(self, session: Session):
        with self._lock:
            self.sessions_by_id[session.session_id] = session
            for pdr in session.pdrs:
                self.sessions_by_ue_ip \
                    .setdefault(pdr.ue_ip, set()) \
                    .add(session.session_id)
            self._persist()

    def remove_session(self, session_id: str):
        with self._lock:
            session = self.sessions_by_id.pop(session_id, None)
            if not session:
                return
            for pdr in session.pdrs:
                self.sessions_by_ue_ip.get(pdr.ue_ip, set()).discard(session_id)
            self._persist()

    def update_session(self, session: Session):
        with self._lock:
            self.sessions_by_id[session.session_id] = session
            self._rebuild_ue_ip_index()
            self._persist()

    def get_all_expected_tunnels(self) -> Dict[str, Tunnel]:
        with self._lock:
            tunnels = {}
            for session in self.sessions_by_id.values():
                t = session.get_tunnel()
                if t:
                    tunnels[t.ue_ip] = t
            return tunnels

    def get_all_expected_flows(self) -> List[Flow]:
        with self._lock:
            flows = []
            for session in self.sessions_by_id.values():
                flows.extend(session.get_flows())
            return flows

    def _persist(self):
        if not self._persist_path:
            return
        try:
            data = {sid: s.to_dict() for sid, s in self.sessions_by_id.items()}
            tmp = self._persist_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f, separators=(",", ":"))
            os.replace(tmp, self._persist_path)
        except Exception as e:
            logging.warning("[PERSIST] Failed to save sessions: %s", e)

    def load_from_disk(self):
        if not self._persist_path or not os.path.isfile(self._persist_path):
            return 0
        try:
            with open(self._persist_path, "r") as f:
                data = json.load(f)
            with self._lock:
                for sid, d in data.items():
                    self.sessions_by_id[sid] = Session.from_dict(d)
                self._rebuild_ue_ip_index()
            logging.info("[PERSIST] Loaded %d sessions from %s",
                         len(data), self._persist_path)
            return len(data)
        except Exception as e:
            logging.warning("[PERSIST] Failed to load sessions: %s", e)
            return 0

# ---------------------------------------------------------------------------
# Persistent TCP client for GTP endpoint communication (JSON + HMAC)
# ---------------------------------------------------------------------------

class GtpEndpointClient:
    """Thread-safe persistent TCP connection to gtp-endpoint.py."""

    def __init__(self, host: str, port: int, secret: bytes,
                 timeout: float = 2.0):
        self._host = host
        self._port = port
        self._secret = secret
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._buf = b""

    def _compute_sig(self, body: dict) -> str:
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hmac_mod.new(
            self._secret, payload.encode(), hashlib.sha256
        ).hexdigest()

    def _verify_sig(self, msg: dict) -> bool:
        if not self._secret:
            return True
        sig = msg.get("sig", "")
        body = {k: v for k, v in msg.items() if k != "sig"}
        expected = self._compute_sig(body)
        return hmac_mod.compare_digest(sig, expected)

    def _connect(self):
        if self._sock is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        sock.connect((self._host, self._port))
        self._sock = sock
        self._buf = b""
        logging.info("[GTP] TCP connected to %s:%d", self._host, self._port)

    def _close(self):
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._buf = b""

    def _send_and_recv(self, msg: dict) -> dict:
        if self._secret:
            msg["sig"] = self._compute_sig(msg)

        line = json.dumps(msg, separators=(",", ":")) + "\n"
        self._sock.sendall(line.encode())

        while b"\n" not in self._buf:
            chunk = self._sock.recv(65535)
            if not chunk:
                raise ConnectionError("GTP endpoint closed connection")
            self._buf += chunk

        resp_line, self._buf = self._buf.split(b"\n", 1)
        resp = json.loads(resp_line.decode("utf-8"))

        if not self._verify_sig(resp):
            raise ValueError("GTP endpoint response has bad signature")

        return resp

    def _request(self, msg: dict) -> dict:
        with self._lock:
            for attempt in range(2):
                try:
                    self._connect()
                    return self._send_and_recv(msg)
                except (OSError, ConnectionError, ValueError) as e:
                    logging.warning("[GTP] Request failed (attempt %d): %s",
                                    attempt + 1, e)
                    self._close()
                    if attempt == 1:
                        raise

    def add_tunnel(self, ue_ip: str, teid: int, remote_ip: str) -> dict:
        msg = {"cmd": "ADD", "ue_ip": ue_ip,
               "teid": teid, "remote_ip": remote_ip}
        logging.debug("[GTP] -> ADD %s teid=%d remote=%s",
                      ue_ip, teid, remote_ip)
        resp = self._request(msg)
        logging.debug("[GTP] <- %s", resp)
        return resp

    def del_tunnel(self, ue_ip: str) -> dict:
        msg = {"cmd": "DEL", "ue_ip": ue_ip}
        logging.debug("[GTP] -> DEL %s", ue_ip)
        resp = self._request(msg)
        logging.debug("[GTP] <- %s", resp)
        return resp

    def sync(self) -> dict:
        msg = {"cmd": "SYNC"}
        logging.debug("[GTP] -> SYNC")
        resp = self._request(msg)
        logging.debug("[GTP] <- SYNC: %d mappings",
                      len(resp.get("mappings", [])))
        return resp


_gtp_client = GtpEndpointClient(
    GTP_ENDPOINT_IP, GTP_ENDPOINT_PORT, GTP_SECRET
)

# ---------------------------------------------------------------------------
# Reconciliation loop – periodic GTP endpoint state check
# ---------------------------------------------------------------------------

class ReconciliationLoop:
    """Background thread that periodically reconciles GTP tunnel state."""

    def __init__(self, session_store: SessionStore,
                 gtp_client: GtpEndpointClient,
                 interval: int = 30):
        self._store = session_store
        self._gtp = gtp_client
        self._interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._interval <= 0:
            logging.info("[RECONCILE] Disabled (interval=%d)", self._interval)
            return
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="reconcile")
        self._thread.start()
        logging.info("[RECONCILE] Started (interval=%ds)", self._interval)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def run_once(self):
        try:
            self._reconcile()
        except Exception as e:
            logging.warning("[RECONCILE] Failed: %s", e)

    def _run(self):
        while not self._stop.wait(self._interval):
            try:
                self._reconcile()
            except Exception as e:
                logging.warning("[RECONCILE] Cycle failed: %s", e)

    def _reconcile(self):
        expected = self._store.get_all_expected_tunnels()

        try:
            resp = self._gtp.sync()
        except (OSError, ConnectionError, ValueError) as e:
            logging.warning("[RECONCILE] GTP SYNC failed: %s", e)
            return

        actual = {}
        for m in resp.get("mappings", []):
            actual[m["ue_ip"]] = (m["teid"], m["remote_ip"])

        added = 0
        updated = 0
        removed = 0

        # Add/update tunnels that should exist
        for ue_ip, tunnel in expected.items():
            if ue_ip not in actual:
                try:
                    self._gtp.add_tunnel(ue_ip, tunnel.teid, tunnel.dest_ip)
                    added += 1
                except (OSError, ConnectionError, ValueError) as e:
                    logging.warning("[RECONCILE] Add %s failed: %s", ue_ip, e)
            else:
                a_teid, a_remote = actual[ue_ip]
                if a_teid != tunnel.teid or a_remote != tunnel.dest_ip:
                    try:
                        self._gtp.del_tunnel(ue_ip)
                        self._gtp.add_tunnel(ue_ip, tunnel.teid, tunnel.dest_ip)
                        updated += 1
                    except (OSError, ConnectionError, ValueError) as e:
                        logging.warning("[RECONCILE] Update %s failed: %s",
                                        ue_ip, e)

        # Remove stale tunnels
        for ue_ip in actual:
            if ue_ip not in expected:
                try:
                    self._gtp.del_tunnel(ue_ip)
                    removed += 1
                except (OSError, ConnectionError, ValueError) as e:
                    logging.warning("[RECONCILE] Del %s failed: %s", ue_ip, e)

        if added or updated or removed:
            logging.info("[RECONCILE] Tunnels: +%d ~%d -%d",
                         added, updated, removed)
        else:
            logging.debug("[RECONCILE] GTP state in sync")


# --- OVS Flow Management (OpenFlow via FlowManager) ---

def _flow_match_fields(flow: Flow) -> dict:
    fields = {"eth_type": 0x0800}

    if flow.source_interface == "ACCESS":
        fields["ipv4_src"] = flow.ue_ip
        if OVS_PORT_ACCESS is not None:
            fields["in_port"] = OVS_PORT_ACCESS
    elif flow.source_interface == "CORE":
        fields["ipv4_dst"] = flow.ue_ip
        if OVS_PORT_CORE is not None:
            fields["in_port"] = OVS_PORT_CORE

    return fields


def _flow_actions(flow: Flow) -> list:
    if flow.apply_action in ("BUFF", "DROP"):
        return []

    if flow.destination_interface == "ACCESS":
        if OVS_PORT_ACCESS is not None:
            return [{"type": "output", "port": OVS_PORT_ACCESS}]
    elif flow.destination_interface == "CORE":
        if OVS_PORT_CORE is not None:
            return [{"type": "output", "port": OVS_PORT_CORE}]

    return [{"type": "output", "port": 0xfffffffb}]  # OFPP_FLOOD


def add_ovs_flow(flow: Flow, flow_manager: Optional[FlowManager]):
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
    logging.info("[OVS] Deleting flow PDR %d for UE %s", flow.pdr_id, flow.ue_ip)
    if flow_manager is None:
        logging.warning("[OVS] No switch connected – flow not deleted")
        return
    flow_manager.delete_flow(
        match_fields=_flow_match_fields(flow),
        priority=flow.precedence,
    )


def modify_ovs_flow(flow: Flow, flow_manager: Optional[FlowManager]):
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
        self.session_store = SessionStore(persist_path=SESSION_FILE)
        self.flow_manager: Optional[FlowManager] = None
        self._reconciler = ReconciliationLoop(
            self.session_store, _gtp_client, RECONCILE_INTERVAL)

        # Load persisted sessions from previous run
        loaded = self.session_store.load_from_disk()
        if loaded:
            self.logger.info("[INIT] Restored %d sessions from disk", loaded)

        wsgi = kwargs["wsgi"]
        wsgi.register(UPFRestController, {upf_app_name: self})
        config_path = os.environ.get("UPF_CONFIG", _CONFIG_FILE_DEFAULT)
        self.logger.info("[CTRL] Ryu UPF controller started – WSGI registered")
        self.logger.info("[CFG]  Config file : %s%s", config_path,
                         " (loaded)" if os.path.isfile(config_path) else " (not found, using defaults)")
        self.logger.info("[CFG]  GTP endpoint: %s:%d", GTP_ENDPOINT_IP, GTP_ENDPOINT_PORT)
        self.logger.info("[CFG]  OF controller: %s:%d", CONTROLLER_IP, CONTROLLER_PORT)
        self.logger.info("[CFG]  Session file: %s", SESSION_FILE)
        self.logger.info("[CFG]  Reconcile interval: %ds", RECONCILE_INTERVAL)

        self._reconciler.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Called when OVS connects. Restore datapath, table-miss, and all flows."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto

        self.flow_manager = FlowManager(datapath)
        self.logger.info("[OVS] Switch connected: dpid=%s", datapath.id)

        self.flow_manager.add_flow(
            priority=0,
            actions=[{"type": "output", "port": ofproto.OFPP_CONTROLLER,
                       "max_length": ofproto.OFPCML_NO_BUFFER}],
        )
        self.logger.info("[OVS] Installed table-miss flow")

        # Re-push all flows from persisted sessions
        flows = self.session_store.get_all_expected_flows()
        if flows:
            self.logger.info("[OVS] Restoring %d flows from session store", len(flows))
            for flow in flows:
                add_ovs_flow(flow, self.flow_manager)

        # Trigger immediate reconciliation for GTP tunnels
        self._reconciler.run_once()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
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
        try:
            data = _parse_request_json(req)
            logging.info("[API] Session establishment: %s", data)

            session = _parse_session(data)
            self.app.session_store.add_session(session)

            errors = []

            tunnel = session.get_tunnel()
            if tunnel:
                try:
                    gtp_resp = _gtp_client.add_tunnel(
                        ue_ip=tunnel.ue_ip, teid=tunnel.teid,
                        remote_ip=tunnel.dest_ip,
                    )
                    if gtp_resp.get("status") != "ok":
                        errors.append("GTP tunnel add: %s" % gtp_resp)
                except (OSError, ConnectionError, ValueError) as e:
                    errors.append("GTP tunnel add: %s" % e)
                    logging.warning("[GTP] Tunnel add failed: %s", e)

            if self.app.flow_manager is None:
                errors.append("OVS not connected")

            for flow in session.get_flows():
                add_ovs_flow(flow, self.app.flow_manager)

            if errors:
                return _json_response(
                    {"status": "partial", "session_id": session.session_id,
                     "errors": errors}, 503)

            return _json_response(
                {"status": "success", "session_id": session.session_id})
        except Exception as e:
            logging.exception("[API] Establishment failed: %s", e)
            return _json_response({"status": "error", "message": str(e)}, 500)

    # --- PUT /session/modify -----------------------------------------------

    @route("upf", "/session/modify", methods=["PUT"])
    def session_modify(self, req, **kwargs):
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

            errors = []

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

            # Persist updated session
            self.app.session_store.update_session(session)

            new_tunnel = session.get_tunnel()
            new_flows = {f.pdr_id: f for f in session.get_flows()}

            try:
                if old_tunnel and not new_tunnel:
                    _gtp_client.del_tunnel(ue_ip=old_tunnel.ue_ip)
                elif not old_tunnel and new_tunnel:
                    _gtp_client.add_tunnel(
                        ue_ip=new_tunnel.ue_ip, teid=new_tunnel.teid,
                        remote_ip=new_tunnel.dest_ip)
                elif old_tunnel and new_tunnel and old_tunnel != new_tunnel:
                    _gtp_client.del_tunnel(ue_ip=old_tunnel.ue_ip)
                    _gtp_client.add_tunnel(
                        ue_ip=new_tunnel.ue_ip, teid=new_tunnel.teid,
                        remote_ip=new_tunnel.dest_ip)
            except (OSError, ConnectionError, ValueError) as e:
                errors.append("GTP tunnel modify: %s" % e)
                logging.warning("[GTP] Tunnel modify failed: %s", e)

            fm = self.app.flow_manager
            for pdr_id, flow in new_flows.items():
                if pdr_id not in old_flows:
                    add_ovs_flow(flow, fm)
                elif flow != old_flows[pdr_id]:
                    modify_ovs_flow(flow, fm)
            for pdr_id, flow in old_flows.items():
                if pdr_id not in new_flows:
                    delete_ovs_flow(flow, fm)

            if errors:
                return _json_response(
                    {"status": "partial", "session_id": session_id,
                     "errors": errors}, 503)

            return _json_response(
                {"status": "success", "session_id": session_id})
        except Exception as e:
            logging.exception("[API] Modification failed: %s", e)
            return _json_response({"status": "error", "message": str(e)}, 500)

    # --- DELETE /session/delete --------------------------------------------

    @route("upf", "/session/delete", methods=["DELETE"])
    def session_delete(self, req, **kwargs):
        try:
            data = _parse_request_json(req)
            logging.info("[API] Session deletion: %s", data)

            session_id = data.get("session_id")
            session = self.app.session_store.sessions_by_id.get(session_id)
            if not session:
                return _json_response(
                    {"status": "error", "message": "Session not found"}, 404)

            errors = []

            tunnel = session.get_tunnel()
            if tunnel:
                try:
                    _gtp_client.del_tunnel(ue_ip=tunnel.ue_ip)
                except (OSError, ConnectionError, ValueError) as e:
                    errors.append("GTP tunnel delete: %s" % e)
                    logging.warning("[GTP] Tunnel delete failed: %s", e)

            fm = self.app.flow_manager
            for flow in session.get_flows():
                delete_ovs_flow(flow, fm)

            self.app.session_store.remove_session(session_id)

            if errors:
                return _json_response(
                    {"status": "partial", "session_id": session_id,
                     "errors": errors}, 503)

            return _json_response(
                {"status": "success", "session_id": session_id})
        except Exception as e:
            logging.exception("[API] Deletion failed: %s", e)
            return _json_response({"status": "error", "message": str(e)}, 500)
