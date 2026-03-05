#!/bin/bash
# scripts/debug_nat.sh — Проверка NAT и Forwarding

echo "--- IP Forwarding ---"
cat /proc/sys/net/ipv4/ip_forward

echo -e "\n--- IPTables NAT ---"
sudo iptables -t nat -L POSTROUTING -n -v

echo -e "\n--- IPTables Forward ---"
sudo iptables -L FORWARD -n -v

echo -e "\n--- Routing Table ---"
ip route show

echo -e "\n--- TUN Device ---"
ip addr show dev tun0 2>/dev/null || echo "tun0 not found"
