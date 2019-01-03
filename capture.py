import struct
import sys
import socket
import ipaddress

from ethernet import Ethernet
from ipv4 import IPv4
from tcp import TCP
from utils import bin2str, bin2int

def display_packet(packet):
    suffix = "+"*50

    ether = Ethernet(packet)
    print("\nEthernet", suffix)
    print("source mac address:", ether.src_mac())
    print("destination mac address:", ether.dst_mac())
    print("ethertype:", ether.ethertype())

    if ether.ethertype() != '0x800':
        return

    ip = IPv4(ether.payload)
    print("\nIPv4", suffix)
    print("version", ip.version())
    print("header length:", ip.header_length())
    print("protocol:", ip.protocol())
    print("source ip address:", ip.src_ip())
    print("destination ip address:", ip.dst_ip())

    if ip.protocol().value != 6:
        return

    tcp = TCP(ip.payload)
    print("\nTCP", suffix)
    print("source port:", tcp.src_port())
    print("destination port:", tcp.dst_port())
    print("control flag:", tcp.control_flag())
    print("header length:", tcp.data_offset())
    print("window size:", tcp.window_size())


if __name__ == '__main__':
    iface = 'lo'
    ETH_P_ALL = 3
    PACKET_MR_PROMISC = 1
    PACKET_ADD_MEMBERSHIP = 1
    SOL_PACKET = 263

    ifindex = socket.if_nametoindex(iface)
    action = PACKET_MR_PROMISC
    alen = 0
    address = b'\0'

    packet_mreq = struct.pack('iHH8s', ifindex, action, alen, address)

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)) as sock:
        sock.bind((iface, 0))
        sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, packet_mreq)
        try:
            while True:
                packet = sock.recv(1024)
                display_packet(packet)
        except KeyboardInterrupt:
            print("EXIT")
        except:
            from traceback import print_exc
            print_exc()