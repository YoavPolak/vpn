#!/bin/bash

sysctl -w net.ipv4.ip_forward=1
iptables -P FORWARD ACCEPT
iptables -t nat -A POSTROUTING -s 10.1.0.0/24 -j MASQUERADE