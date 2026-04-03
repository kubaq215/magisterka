"""
OpenFlow 1.3 flow manager using Ryu – importable module with add/delete API.

Can be used in two ways:

  1. As a standalone Ryu app:
       ryu-manager openflow_flows.py

  2. Imported from another Ryu app:
       from openflow_flows import FlowManager

       # In your RyuApp, after obtaining a datapath:
       fm = FlowManager(datapath)
       fm.add_flow(priority=20, match_fields={"eth_type": 0x0800, "ipv4_src": "10.0.0.1"},
                   actions=[{"type": "output", "port": 2}])
       fm.delete_flow(match_fields={"eth_type": 0x0800, "ipv4_src": "10.0.0.1"})
       fm.delete_all_flows()

Requires: pip install ryu
"""

import logging

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# FlowManager – importable helper, operates on a single datapath
# ---------------------------------------------------------------------------

class FlowManager:
    """High-level API for adding / deleting OpenFlow 1.3 flows on a datapath."""

    def __init__(self, datapath):
        self.datapath = datapath
        self.ofproto = datapath.ofproto
        self.parser = datapath.ofproto_parser

    # -- public API ---------------------------------------------------------

    def add_flow(self, priority, match_fields=None, actions=None,
                 table_id=0, idle_timeout=0, hard_timeout=0):
        """Add a flow entry.

        Args:
            priority:      Flow priority (higher = matched first).
            match_fields:  Dict of OFPMatch keyword args, e.g.
                           {"eth_type": 0x0800, "ipv4_src": "10.0.0.1"}.
            actions:       List of action dicts, each with a "type" key:
                           - {"type": "output",    "port": 2}
                           - {"type": "set_field", "field": "eth_dst",
                              "value": "00:00:00:00:00:02"}
                           - {"type": "drop"} or None/[] for drop
            table_id:      Flow table (default 0).
            idle_timeout:  Seconds idle before removal (0 = permanent).
            hard_timeout:  Seconds before forced removal (0 = permanent).
        """
        match = self.parser.OFPMatch(**(match_fields or {}))
        ofp_actions = self._build_actions(actions)
        inst = [self.parser.OFPInstructionActions(
            self.ofproto.OFPIT_APPLY_ACTIONS, ofp_actions)]

        mod = self.parser.OFPFlowMod(
            datapath=self.datapath,
            table_id=table_id,
            priority=priority,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match,
            instructions=inst,
        )
        self.datapath.send_msg(mod)
        log.info("ADD flow: priority=%d match=%s actions=%s",
                 priority, match_fields, actions)

    def delete_flow(self, match_fields=None, priority=None, table_id=0,
                    out_port=None, out_group=None):
        """Delete flow entries matching the given criteria.

        Args:
            match_fields:  Dict of OFPMatch keyword args to match against.
                           Use None/{} to match all entries in the table.
            priority:      If set, delete only the entry with this exact
                           priority (uses OFPFC_DELETE_STRICT).
            table_id:      Table to delete from (default 0).
            out_port:      Restrict to flows outputting to this port.
            out_group:     Restrict to flows referencing this group.
        """
        match = self.parser.OFPMatch(**(match_fields or {}))

        kwargs = dict(
            datapath=self.datapath,
            table_id=table_id,
            match=match,
            out_port=out_port or self.ofproto.OFPP_ANY,
            out_group=out_group or self.ofproto.OFPG_ANY,
        )

        if priority is not None:
            kwargs["command"] = self.ofproto.OFPFC_DELETE_STRICT
            kwargs["priority"] = priority
        else:
            kwargs["command"] = self.ofproto.OFPFC_DELETE

        mod = self.parser.OFPFlowMod(**kwargs)
        self.datapath.send_msg(mod)
        log.info("DELETE flow: match=%s priority=%s table=%d",
                 match_fields, priority, table_id)

    def delete_all_flows(self, table_id=None):
        """Delete every flow entry. If table_id is None, clear all tables."""
        tid = table_id if table_id is not None else self.ofproto.OFPTT_ALL
        match = self.parser.OFPMatch()
        mod = self.parser.OFPFlowMod(
            datapath=self.datapath,
            command=self.ofproto.OFPFC_DELETE,
            table_id=tid,
            match=match,
            out_port=self.ofproto.OFPP_ANY,
            out_group=self.ofproto.OFPG_ANY,
        )
        self.datapath.send_msg(mod)
        log.info("DELETE ALL flows (table=%s)", table_id)

    # -- internal -----------------------------------------------------------

    def _build_actions(self, action_list):
        """Convert a list of action dicts to Ryu OFPAction objects."""
        if not action_list:
            return []
        result = []
        for a in action_list:
            atype = a.get("type", "drop")
            if atype == "output":
                port = a["port"]
                max_len = a.get("max_length", 0)
                result.append(self.parser.OFPActionOutput(port, max_len))
            elif atype == "set_field":
                result.append(
                    self.parser.OFPActionSetField(**{a["field"]: a["value"]}))
            elif atype == "drop":
                pass  # empty action list = drop
            else:
                raise ValueError(f"Unknown action type: {atype!r}")
        return result


# ---------------------------------------------------------------------------
# FlowInstallerApp – standalone Ryu app with example flows
# ---------------------------------------------------------------------------

class FlowInstallerApp(app_manager.RyuApp):
    """Ryu app that installs example flows on switch connect.

    Run directly:  ryu-manager openflow_flows.py
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}   # dpid -> FlowManager

    def _get_fm(self, datapath):
        dpid = datapath.id
        if dpid not in self.datapaths:
            self.datapaths[dpid] = FlowManager(datapath)
        return self.datapaths[dpid]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install example flows when a switch connects."""
        datapath = ev.msg.datapath
        fm = self._get_fm(datapath)
        ofproto = datapath.ofproto

        self.logger.info("Switch connected: dpid=%s", datapath.id)

        # Table-miss: send to controller
        fm.add_flow(
            priority=0,
            actions=[{"type": "output", "port": ofproto.OFPP_CONTROLLER,
                       "max_length": ofproto.OFPCML_NO_BUFFER}],
        )

        # ARP flood
        fm.add_flow(
            priority=10,
            match_fields={"eth_type": 0x0806},
            actions=[{"type": "output", "port": ofproto.OFPP_FLOOD}],
        )

        # IP 10.0.0.1 -> 10.0.0.2 => port 2
        fm.add_flow(
            priority=20,
            match_fields={"eth_type": 0x0800,
                           "ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.2"},
            actions=[{"type": "output", "port": 2}],
        )

        # IP 10.0.0.2 -> 10.0.0.1 => port 1
        fm.add_flow(
            priority=20,
            match_fields={"eth_type": 0x0800,
                           "ipv4_src": "10.0.0.2", "ipv4_dst": "10.0.0.1"},
            actions=[{"type": "output", "port": 1}],
        )

        # Drop all from 10.0.0.99
        fm.add_flow(
            priority=30,
            match_fields={"eth_type": 0x0800, "ipv4_src": "10.0.0.99"},
            actions=[],
        )

        # TCP/80 => rewrite dst MAC + output port 2
        fm.add_flow(
            priority=25,
            match_fields={"eth_type": 0x0800, "ip_proto": 6, "tcp_dst": 80},
            actions=[
                {"type": "set_field", "field": "eth_dst",
                 "value": "00:00:00:00:00:02"},
                {"type": "output", "port": 2},
            ],
        )

        self.logger.info("All example flows installed")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Flood unknown packets."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        )
        datapath.send_msg(out)
