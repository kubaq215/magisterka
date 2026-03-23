#!/bin/bash
iptables -t nat -D POSTROUTING -s 10.45.0.0/16 -o enp0s9 -j MASQUERADE 2>/dev/null

ovs-vsctl del-br br0 2>/dev/null
ip link del veth-ovs 2>/dev/null  # also removes veth-ext (peer)

# Restore gtp0's original address
ip addr add 10.45.0.1/16 dev gtp0 2>/dev/null