# Pniffer
Network sniffer tool written by Python

## Feature
- Promiscuous mode

## Supported Protocol
- Ethernet
- IPv4
- TCP
- UDP

## Demo

```
sudo python3 demo.py

Ethernet ++++++++++++++++++++++++++++++++++++++++++++++++++
source mac address: 00:00:00:00:00:00
destination mac address: 00:00:00:00:00:00
ethertype: 0x800

IPv4 ++++++++++++++++++++++++++++++++++++++++++++++++++
version 4
header length: 20
protocol: TCP
source ip address: 127.0.0.1
destination ip address: 127.0.0.1

TCP ++++++++++++++++++++++++++++++++++++++++++++++++++
source port: 49526
destination port: 9999
control flag: [('ACK', '0x10')]
header length: 32
window size: 342
```
