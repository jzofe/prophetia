#!/bin/sh

sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X

sudo iptables -I INPUT -m ttl --ttl-lt 11 -j DROP 2>/dev/null
sudo ip6tables -A INPUT -m hl --hl-lt 11 -j DROP 2>/dev/null

sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

