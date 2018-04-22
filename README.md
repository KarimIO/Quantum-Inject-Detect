# Quantum Inject and Detect

This is a Man on the Side tool, accompanied by a malicious packet detector.

Made for Dr. Sherif Kassas at the American University in Cairo

## Authors

* [Mohamed Gaber](http://github.com/donn)
* [Karim Abdel Hamid](https://github.com/KarimIO)

## Usage

```
sudo python quantumdetect.py -i [interface] -r [file] [filters]
        Either -i or -r should be used.
        [interface] can be all, which lists all packets from all interfaces.
        [file] is a .pcap file containing multiple packets.
```

## Dependencies

```bash
sudo apt install python
sudo apt install python-pip
pip install scap
```

## License

Unlicense. Do whatever you want.