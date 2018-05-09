#!/usr/bin/env python

import sys
from scapy.all import *

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

def pkt_callback(pkt):
    pkt.show()

def handlePCAP(pcap):
    print("Reading from " + pcap)
    sniff(count = 10, offline = pcap, prn = pkt_callback) # , store=0)

def sniffInterface(interface, filters):
    print("Sniffing from " + interface)
    p = []
    if (interface == "all"):
        sniff(count = 10, prn = pkt_callback, filter = filters)
    else:
        sniff(count = 10, prn = pkt_callback, filter = filters, iface = interface)

def quantumHelp():
    print("Usage: sudo python quantumdetect.py -i [interface] -r [file] [filters]\n\tEither -i or -r should be used.\n\t[interface] can be all, which lists all packets from all interfaces.\n\t[file] is a .pcap file containing multiple packets.")

# Because writing code globally is ridiculous
def main(argv):
    interface, read_files, filters = handleArgs(argv)

    if (read_files != ""):
        handlePCAP(read_files)
    elif(interface != ""):
        sniffInterface(interface, filters)
    else:
        quantumHelp()

if __name__ == "__main__":
    main(sys.argv)