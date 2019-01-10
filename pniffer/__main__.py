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


def get_formatted_packets(raw_packets, fmt=None):
    packets = {}

    ether = Ethernet(raw_packets)
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
        return json.dumps(packets, indent=2)
    else:
        return pprint.pformat(packets) + '\n'


def main():
    args = operate_args()

    if args.binary:
        filemode = 'ab'
    else:
        filemode = 'a'

    if getattr(args, 'filename') is not None:
        output_file = open(args.filename, filemode)
    else:
        if args.binary:
            output_file = sys.stdout.buffer
        else:
            output_file = sys.stdout

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
                packets = sock.recv(512)

                if args.binary:
                    output_file.write(packets)
                else:
                    output_file.write(
                        get_formatted_packets(packets, fmt=args.fmt))

        except KeyboardInterrupt:
            print("EXIT")
        finally:
            output_file.close()


if __name__ == '__main__':
    sys.exit(main())
