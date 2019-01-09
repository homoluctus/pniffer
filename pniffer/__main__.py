import sys
import json
import struct
import socket
import pprint

try:
    from pniffer.ethernet import Ethernet
    from pniffer.ipv4 import IPv4
    from pniffer.tcp import TCP
    from pniffer.udp import UDP
    from pniffer.promiscuous import promiscuous_mode
    from pniffer.cmd import operate_args
except (ModuleNotFoundError, ImportError):
    import sys
    from traceback import print_exc
    print_exc()
    sys.exit("\n[!] Please add pniffer path to PYTHONPATH")


def dump_packet(packet, file, fmt=None):
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
        file.write(json.dumps(packets, indent=2))
    else:
        file.write(str(packets))

    if file.name == '<stdout>':
        file.flush()


def main():
    args = operate_args()

    # For proto argument of socket object
    ETH_P_ALL = 3   # All protocol pakcet

    with socket.socket(socket.AF_PACKET,
                       socket.SOCK_RAW,
                       socket.htons(ETH_P_ALL)) as sock:
        sock.bind((args.interface, 0))

        if args.promis:
            promiscuous_mode(sock, args.interface)

        try:
            while True:
                packet = sock.recv(1024)
                dump_packet(packet, args.file, fmt=args.fmt)
        except KeyboardInterrupt:
            print("EXIT")
        finally:
            args.file.close()


if __name__ == '__main__':
    sys.exit(main())
