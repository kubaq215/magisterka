#!/bin/bash
iptables -t mangle -D PREROUTING -i gtp0 -j MARK --set-mark 0x64
iptables -t mangle -D PREROUTING -i enp0s9 -d 10.45.0.0/16 -j MARK --set-mark 0xC8
iptables -t mangle -D PREROUTING -i veth-gtp -j MARK --set-mark 0
iptables -t mangle -D PREROUTING -i veth-ext -j MARK --set-mark 0
iptables -t nat -D POSTROUTING -s 10.45.0.0/16 -o enp0s9 -j MASQUERADE

ip rule del fwmark 0x64 table 100
ip rule del fwmark 0xC8 table 200
ip route flush table 100
ip route flush table 200

ovs-vsctl del-br br0
ip link del veth-gtp 2>/dev/null
ip link del veth-ext 2>/dev/null

# Restore gtp0's original address
ip addr add 10.45.0.1/16 dev gtp0 2>/dev/null