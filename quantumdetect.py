#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
import os
import sys
import subprocess
from scapy.all import *

size = 4096
g_ip_queue = collections.deque(size*[], size)

def handleArgs(args):
    interface = ""
    read_files = ""
    filter = ""

    i = 1
    while i < len(args):
        if (args[i] == "-i"):
            interface = args[i + 1]
            i += 1
        elif (args[i] == "-r"):
            read_files = args[i + 1]
            i += 1
        else:
            filter += args[i] + " "
        
        i += 1

    return interface, read_files, filter

def alertAttack(ip1, ip2, mac1, mac2):
    print("Attack found!")
    print("\t" + ip1 + " - " + mac1)
    print("\t" + ip2 + " - " + mac2)

def pkt_callback(pkt):
    # Record Packet Info
    ip = pkt.getlayer(IP).src
    mac = pkt.src

    # For all items in queue
    for g in g_ip_queue:
        # If we find the correct IP
        if (g[0] == ip):
            # If it has an unusual MAC address
            if (g[1] != mac):
                # Give an alert
                alertAttack(ip, g[0], mac, g[1])
                g[1] = mac

            # Return, since we found our packet.
            return

    # Otherwise, 
    g_ip_queue.appendleft([ip, mac])


def handlePCAP(pcap, filters):
    print("Reading PCAP file from " + pcap + ", looking for: " + filters)
    pkts = sniff(offline = pcap, prn = pkt_callback, filter = filters)
    print("PCAP checked. " + str(len(pkts)) + " packets checked.")

def sniffInterface(interface, filters):
    print("Sniffing from " + interface + ", looking for: " + filters)
    if (interface == "all"):
        sniff(prn = pkt_callback, filter = filters)
    else:
        sniff(prn = pkt_callback, filter = filters, iface = interface)

def quantumHelp():
    print("Usage: sudo python quantumdetect.py -i [interface] -r [file] [filters]\n\tEither -i or -r should be used.\n\t[interface] can be all, which lists all packets from all interfaces.\n\t[file] is a .pcap file containing multiple packets.")

def checkRootPrivileges():
    if (os.getuid() != 0):
        print "Sniffing interfaces will require root priviliges"
        subprocess.call(["sudo"] + sys.argv)
        exit(77)

# Because writing code globally is ridiculous
def main(argv):
    interface, read_files, filters = handleArgs(argv)

    if (read_files != ""):
        handlePCAP(read_files, filters)
    elif(interface != ""):
        checkRootPrivileges()
        sniffInterface(interface, filters)
    else:
        quantumHelp()

if __name__ == "__main__":
    main(sys.argv)