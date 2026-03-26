# Create OVS bridge
ovs-vsctl del-br br0
ovs-vsctl add-br br0

# Start gtp-endpoint.py (creates gtp0 as TAP now)
# Then add gtp0 to OVS
ovs-vsctl add-port br0 gtp0

# Create veth pair: veth-ovs goes into OVS, veth-ext stays in kernel
ip link add veth-ovs type veth peer name veth-ext

# Assign known MACs (locally-administered unicast) — must match gtp-endpoint.py
ip link set veth-ext address 02:00:00:00:00:01
ip link set gtp0   address 02:00:00:00:00:02

ip link set veth-ovs up
ip link set veth-ext up

# Add one end to OVS
ovs-vsctl add-port br0 veth-ovs

# Give veth-ext a transit /30 (NOT the UE /16 — that would make the
# kernel treat UE traffic as local instead of forwarding it)
ip addr add 10.99.0.1/30 dev veth-ext

# Route UE subnet via a fake next-hop inside the /30
# 10.99.0.2 is resolved by the static neighbor entry below
ip route add 10.45.0.0/16 via 10.99.0.2 dev veth-ext

# Static ARP so the kernel can send return traffic without real ARP resolution
# (nothing on the OVS side answers ARP requests)
ip neigh add 10.99.0.2 lladdr 02:00:00:00:00:02 nud permanent dev veth-ext

# Enable forwarding
sysctl -w net.ipv4.ip_forward=1

# NAT + FORWARD rules
iptables -t nat -D POSTROUTING -s 10.45.0.0/16 -o enp0s9 -j MASQUERADE 2>/dev/null
iptables -t nat -A POSTROUTING -s 10.45.0.0/16 -o enp0s9 -j MASQUERADE
