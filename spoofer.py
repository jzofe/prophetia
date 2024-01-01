#!/usr/bin/python3

#ENDER PROJECT

import socket
import binascii
import struct
from scapy.all import *
import time
from ipaddress import ip_address
import daemon
import traceback

addresses = [
    "217.115.147.245", "8.44.101.6", "153.31.119.142", "198.81.129.20",
    "195.99.147.120", "195.208.24.107", "152.152.15.131", "199.209.154.0",
    "199.208.239.67", "41.134.107.17"
]

addresses6 = [
    "2001:4860:4860::8888", "2a03:2880:f11c:8083:face:b00c:0:25de", "2610:20:6005:13::49",
    "2607:5300:60:3fc9:0:de:face:ab1e", "2001:678:5::1", "2607:f330:8400:100::50", "2001:19e8:d::100",
    "2001:4d0:8300:401::189", "2607:f6d0:0:925a::ab43:d7c8", "2001:500:89::53"
]

SRC_MAC = "00:1a:79:a2:42:1a"
DST_MAC = "e0:19:54:2b:ca:88"

IFACE = "enp1s0"
LISTEN = ("127.0.0.1", 1406)

sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sender.bind((IFACE, 0))

receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
receiver.bind(LISTEN)

context = daemon.DaemonContext()
context.files_preserve = [sender, receiver]

with context:
    while True:
        data, addr = receiver.recvfrom(0xFFFF)
        if len(data) < 42:
            continue
        ip_version = 4 if data[12:14] == b'\x08\x00' else 6
        orig_ip_frame = data[14:]
        if ip_version == 4:
            ttl = orig_ip_frame[8]
            src_addr = str(ip_address(orig_ip_frame[12:16]))
            dst_addr = str(ip_address(orig_ip_frame[16:20]))
            spoof_addr = str(ip_address(addresses[(ttl - 1) % len(addresses)]))
            packet = Ether(dst=DST_MAC, src=SRC_MAC) / IP(src=spoof_addr, dst=src_addr) / ICMP(type=0xb, code=0) / orig_ip_frame
        else:
            ttl = orig_ip_frame[7]
            src_addr = str(ip_address(orig_ip_frame[8:24]))
            dst_addr = str(ip_address(orig_ip_frame[24:40]))
            spoof_addr = str(ip_address(addresses6[(ttl - 1) % len(addresses6)]))
            packet = Ether(dst=DST_MAC, src=SRC_MAC) / IPv6(src=spoof_addr, dst=src_addr) / ICMPv6TimeExceeded() / orig_ip_frame
        sender.send(bytes(packet))
