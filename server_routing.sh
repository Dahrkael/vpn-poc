#!/bin/sh
if [ $# -eq 2 ]
then
    echo "executing server routing commands!"
    echo "sysctl net.ipv4.ip_forward=1"
    sysctl net.ipv4.ip_forward=1
    echo "iptables -t filter -I FORWARD -i $1 -o $2 -j ACCEPT"
    iptables -t filter -I FORWARD -i $1 -o $2 -j ACCEPT
    echo "iptables -t filter -I FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT"
    iptables -t filter -I FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    echo "iptables -t nat -I POSTROUTING -o $2 -j MASQUERADE"
    iptables -t nat -I POSTROUTING -o $2 -j MASQUERADE
else
    echo "usage: $0 <tun device> <default gateway interface>"
fi
