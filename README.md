# Quantum Inject/Detect
This is a man-on-the-side attack tool for TCP payloads, accompanied by a malicious packet detector.

This tool was written for a Secure Systems Engineering course.

# Dependencies
Python and PIP are needed: check any OS specifics for these.

```bash
pip install --user scapy flask
```

# Usage
## QuantumInject
Run `quantuminject.py` and `sampleserver.py` on the same ether.

QuantumInject's usage is as follows:
```
        (python2.7 |./)quantuminject.py [­-i interface] [­-r regexp] [­-d datafile] expression

        -i --interface Listen on network device (e.g., eth0). If not specified, quantuminject should select a default interface to listen on. The same interface should be used for packet injection.

        ­-r --regex Use regular expression to match the request packets for which a response will be spoofed.

        ­-d --data Read the python script that will generate the TCP payload of the spoofed response packet from <datafile>

        expression is a packet filter.
```

Defaults will be used for anything not provided.

(We opted for a Python script generating payloads instead of a raw payload for flexibility reasons.)

Also on the same ether, `curl` the sample server.

If everything goes right, instead of 'Authentic' you should see 'Spoofed'.

You can then stop the scripts by sending an interrupt using `Ctrl + C`.


## QuantumDetect
QuantumDetect's invocation is as follows:

```
sudo python quantumdetect.py -i [interface] -r [file] [filters]
        Either -i or -r should be used.
        [interface] can be all, which lists all packets from all interfaces.
        [file] is a .pcap file containing multiple packets.
```

You just provide the same interface as QuantumInject.

You can also use the following to capture packets for later, though, like the scripts, you will need to use `Ctrl + C` to stop the capture.
```
sudo tcpdump -w capture.pcap
```

## License
The Unlicense. Check 'UNLICENSE'.
