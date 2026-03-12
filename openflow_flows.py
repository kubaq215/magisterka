"""
Example script: Send OpenFlow 1.3 messages to create OVS flows using Ryu.

Usage:
  1. Start OVS bridge: ovs-vsctl add-br br0 -- set bridge br0 protocols=OpenFlow13
  2. Point OVS to this controller: ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
  3. Run this script: ryu-manager openflow_flows.py

Requires: pip install ryu
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp


class FlowInstaller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Called when a switch connects. Install default and custom flows."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Switch connected: dpid=%s", datapath.id)

        # --- Flow 1: Default table-miss rule (send to controller) ---
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("Installed table-miss flow (send to controller)")

        # --- Flow 2: Forward all ARP traffic to all ports (flood) ---
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self._add_flow(datapath, priority=10, match=match, actions=actions)
        self.logger.info("Installed ARP flood flow")

        # --- Flow 3: Forward IP traffic 10.0.0.1 -> 10.0.0.2 to port 2 ---
        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src="10.0.0.1",
            ipv4_dst="10.0.0.2",
        )
        actions = [parser.OFPActionOutput(2)]
        self._add_flow(datapath, priority=20, match=match, actions=actions)
        self.logger.info("Installed IP flow: 10.0.0.1 -> 10.0.0.2 => port 2")

        # --- Flow 4: Forward IP traffic 10.0.0.2 -> 10.0.0.1 to port 1 ---
        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src="10.0.0.2",
            ipv4_dst="10.0.0.1",
        )
        actions = [parser.OFPActionOutput(1)]
        self._add_flow(datapath, priority=20, match=match, actions=actions)
        self.logger.info("Installed IP flow: 10.0.0.2 -> 10.0.0.1 => port 1")

        # --- Flow 5: Drop all traffic from 10.0.0.99 (no actions = drop) ---
        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src="10.0.0.99",
        )
        self._add_flow(datapath, priority=30, match=match, actions=[])
        self.logger.info("Installed DROP flow for src 10.0.0.99")

        # --- Flow 6: Match on TCP dst port 80, set output + rewrite dst MAC ---
        match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,
            tcp_dst=80,
        )
        actions = [
            parser.OFPActionSetField(eth_dst="00:00:00:00:00:02"),
            parser.OFPActionOutput(2),
        ]
        self._add_flow(datapath, priority=25, match=match, actions=actions)
        self.logger.info("Installed HTTP redirect flow (tcp/80 => port 2, rewrite MAC)")

        # --- Flow 7: Meter + group example – rate-limit UDP to 1 Mbps ---
        self._install_meter(datapath, meter_id=1, rate_kbps=1000)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17)
        inst = [
            parser.OFPInstructionMeter(1),
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(ofproto.OFPP_NORMAL)],
            ),
        ]
        self._add_flow(datapath, priority=15, match=match, actions=None,
                        instructions=inst)
        self.logger.info("Installed metered UDP flow (1 Mbps)")

    def _add_flow(self, datapath, priority, match, actions, instructions=None,
                  table_id=0, idle_timeout=0, hard_timeout=0):
        """Helper: send an OFPFlowMod to install a flow entry."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if instructions is None:
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = instructions

        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=table_id,
            priority=priority,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)

    def _install_meter(self, datapath, meter_id, rate_kbps):
        """Install a meter band that drops traffic exceeding rate_kbps."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        bands = [parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=10)]
        req = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands,
        )
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle packets sent to the controller (table-miss)."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # If we know the destination port, install a flow and forward;
        # otherwise flood.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Learn path: install a flow so future packets don't hit controller
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(datapath, priority=1, match=match, actions=actions,
                           idle_timeout=300)
            self.logger.info("Learned: %s -> port %s (dpid %s)", dst, out_port, dpid)

        # Send the buffered packet out
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        )
        datapath.send_msg(out)
