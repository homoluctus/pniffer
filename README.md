# Pniffer
Network sniffer tool written by Python

## Feature
- Promiscuous mode
- Command line operation
- json dump
- Write captured packet to file
- Binary output

## Supported Protocol
- Ethernet
- IPv4
- TCP
- UDP

## Demo

```
sudo python3 -m pniffer -i lo -f json
{
  "Ethernet": {
    "destination": "00:00:00:00:00:00",
    "source": "00:00:00:00:00:00",
    "ethertype": "0x800"
  },
  "IPv4": {
    "version": 4,
    "hdl": 20,
    "tos": "0",
    "total": 52,
    "identification": 24913,
    "fragment": 0,
    "fragment_offset": "4000",
    "ttl": 64,
    "protocol": "TCP",
    "checksum": 56176,
    "destination": "127.0.0.1",
    "source": "127.0.0.1"
  },
  "TCP": {
    "source_port": 57728,
    "destination_port": 9999,
    "sequence_number": "99a61fb4",
    "acknowledgement_number": "b8cef850",
    "data_offset": 32,
    "control_flag": [
      [
        "ACK",
        "0x10"
      ]
    ],
    "window_size": 342,
    "checksum": 65064,
    "urgent_pointer": "0000"
  }
}
```
