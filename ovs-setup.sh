# Create OVS bridge
ovs-vsctl del-br br0
ovs-vsctl add-br br0

# Start gtp-endpoint.py (creates gtp0 as TAP now)
# Then add gtp0 to OVS
ovs-vsctl add-port br0 gtp0

# Create an internal port for the kernel IP stack (routing + NAT)
ovs-vsctl add-port br0 uplink -- set interface uplink type=internal
ip addr add 10.45.0.1/16 dev uplink
ip link set uplink up

# Remove the old IP from gtp0 (OVS handles it now)
ip addr flush dev gtp0

# NAT via uplink
iptables -t nat -A POSTROUTING -s 10.45.0.0/16 -o enp0s9 -j MASQUERADE

# Enable forwarding
sysctl -w net.ipv4.ip_forward=1

# setup controller
ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
ovs-vsctl set bridge br0 protocols=OpenFlow13