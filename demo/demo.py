import json
import struct
import socket


try:
    from pniffer.ethernet import Ethernet
    from pniffer.ipv4 import IPv4
    from pniffer.tcp import TCP
    from pniffer.udp import UDP
    from promiscuous import promiscuous_mode
except (ModuleNotFoundError, ImportError):
    import sys
    from traceback import print_exc
    print_exc()
    sys.exit("\n[!] Please add pniffer path to PYTHONPATH")


def display_packet(packet, fmt=None):
    packets = {}

    ether = Ethernet(packet)
    packets['Ethernet'] = ether()

    if ether.ethertype() != '0x800':
        return
    
    ip = IPv4(ether.payload)
    packets['IPv4'] = ip()

    l4_protocol = ip.protocol().name

    if l4_protocol == 'TCP':
        tcp = TCP(ip.payload)
        packets['TCP'] = tcp()
    elif l4_protocol == 'UDP':
        udp = UDP(ip.payload)
        packets['UDP'] = udp()

    if fmt == 'json':
        print(json.dumps(packets, indent=2))
    else:
        print(packets)


if __name__ == '__main__':
    interface = 'lo'

    # For proto argument of socket object
    ETH_P_ALL = 3   # All protocol pakcet

    with socket.socket(socket.AF_PACKET,
                       socket.SOCK_RAW,
                       socket.htons(ETH_P_ALL)) as sock:
        sock.bind((interface, 0))
        promiscuous_mode(sock, interface)        

        try:
            while True:
                packet = sock.recv(1024)
                display_packet(packet, fmt='json')
        except KeyboardInterrupt:
            print("EXIT")
