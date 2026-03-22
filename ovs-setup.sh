#!/bin/bash
set -e

# ── 0. Prerequisites ──
sysctl -w net.ipv4.ip_forward=1

# ── 1. Create veth pairs ──
ip link add veth-gtp  type veth peer name veth-gtp-br
ip link add veth-ext  type veth peer name veth-ext-br

# ── 2. Create OVS bridge and attach the bridge-side ends ──
ovs-vsctl add-br br0
ovs-vsctl add-port br0 veth-gtp-br
ovs-vsctl add-port br0 veth-ext-br

# ── 3. Bring everything up ──
ip link set veth-gtp    up
ip link set veth-gtp-br up
ip link set veth-ext    up
ip link set veth-ext-br up

# ── 4. Assign IPs – same /24 bridged through OVS ──
ip addr add 10.200.0.1/24 dev veth-gtp
ip addr add 10.200.0.2/24 dev veth-ext

# ── 5. Narrow gtp0 address from /16 to /32 ──
#    (so we can control the 10.45.0.0/16 route separately)
ip addr del 10.45.0.1/16 dev gtp0 2>/dev/null || true
ip addr add 10.45.0.1/32 dev gtp0
# Keep a direct route for return traffic to reach gtp0 at the end
ip route add 10.45.0.0/16 dev gtp0

# ── 6. Disable reverse-path filtering on veth endpoints ──
#    (packets carry 10.45.0.x source, not 10.200.0.x)
sysctl -w net.ipv4.conf.veth-gtp.rp_filter=0
sysctl -w net.ipv4.conf.veth-ext.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

# ── 7. Policy routing: OUTBOUND  gtp0 → OVS → enp0s9 ──
iptables -t mangle -A PREROUTING -i gtp0 -j MARK --set-mark 0x64
ip rule  add fwmark 0x64 table 100
ip route add default via 10.200.0.2 table 100

# ── 8. Policy routing: INBOUND  enp0s9 → OVS → gtp0 ──
#    (conntrack de-masquerades dst back to 10.45.0.x before mangle runs)
iptables -t mangle -A PREROUTING -i enp0s9 -d 10.45.0.0/16 -j MARK --set-mark 0xC8
ip rule  add fwmark 0xC8 table 200
ip route add 10.45.0.0/16 via 10.200.0.1 dev veth-ext table 200

# ── 9. Clear fwmarks after OVS to prevent routing loops ──
iptables -t mangle -A PREROUTING -i veth-gtp -j MARK --set-mark 0
iptables -t mangle -A PREROUTING -i veth-ext -j MARK --set-mark 0

# ── 10. NAT ──
iptables -t nat -A POSTROUTING -s 10.45.0.0/16 -o enp0s9 -j MASQUERADE

# ── 11. Connect OVS to Ryu controller and set OpenFlow version ──
ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
ovs-vsctl set bridge br0 protocols=OpenFlow13

# ── Done ──
echo "--- OVS port map ---"
ovs-ofctl show br0
echo ""
echo "Use the port numbers above for OVS_PORT_ACCESS / OVS_PORT_CORE in upf_controller.py"