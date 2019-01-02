import struct
import sys
import socket
import ipaddress

from utils import bin2str, bin2int

class Ethernet:
    def __init__(self, packet):
        self.packet = packet
        self.__payload = packet[14:]

    @property
    def payload(self):
        return self.__payload

    def dst_mac(self):
        raw_data = bin2str(self.packet[0:6])
        return self.process_mac(raw_data)

    def src_mac(self):
        raw_data = bin2str(self.packet[6:12])
        return self.process_mac(raw_data)

    def ethertype(self):
        return bin2str(self.packet[12:14])

    def process_mac(self, raw_mac):
        return (':').join([raw_mac[i:i+2] for i in range(0, 12, 2)])


class IPv4:
    """
    Support only little endian.
    """

    def __init__(self, packet):
        self.packet = packet
        self.__payload = packet[self.header_length():]

    @property
    def payload(self):
        return self.__payload

    def version(self):
        return self.packet[0] >> 4

    def header_length(self):
        return (self.packet[0] & 0x0f) * 4

    def tos(self):
        return bin2str(self.packet[1])

    def total_length(self):
        return bin2int(self.packet[2:4])

    def identification(self):
        return bin2int(self.packet[4:6])

    def flags(self):
        return bin2str(self.packet[6] & 0x03)

    def fragment_offset(self):
        return bin2str(self.packet[6:8])

    def ttl(self):
        return bin2int(self.packet[8])

    def protocol(self):
        return bin2int(self.packet[9])

    def checksum(self):
        return bin2str(self.packet[10:12])

    def src_ip(self):
        return self.process_ip(bin2int(self.packet[12:16]))

    def dst_ip(self):
        return self.process_ip(bin2int(self.packet[16:20]))

    def process_ip(self, ip):
        return ipaddress.ip_address(ip)

class TCP:
    def __init__(self, packet):
        self.packet = packet
        #self.__payload = packet[self.data_offset():]

    def src_port(self):
        return bin2int(self.packet[0:2])

    def dst_port(self):
        return bin2int(self.packet[2:4])

    def sequence_number(self):
        return bin2str(self.packet[4:8])

    def acknowledgement_number(self):
        return bin2str(self.packet[8:12])

    def data_offset(self):
        return bin2int(self.packet[13]) & 0x0f * 4

    def control_flag(self):
        return self.packet[13]

    def window_size(self):
        return bin2int(self.packet[14:16])

    def checksum(self):
        return bin2str(self.packet[16:18])

    def urgent_pointer(self):
        return bin2str(self.packet[18:20])

def display_packet(packet):
    suffix = "+"*50

    ether = Ethernet(packet)
    print("\nEthernet", suffix)
    print("source mac address:", ether.src_mac())
    print("destination mac address:", ether.dst_mac())
    print("ethertype:", ether.ethertype())

    if ether.ethertype() != '0800':
        return

    ip = IPv4(ether.payload)
    print("\nIPv4", suffix)
    print("version", ip.version())
    print("header length:", ip.header_length())
    print("protocol:", ip.protocol())
    print("source ip address:", ip.src_ip())
    print("destination ip address:", ip.dst_ip())

    if ip.protocol() != 6:
        return

    tcp = TCP(ip.payload)
    print("\nTCP", suffix)
    print("source port", tcp.src_port())
    print("destination port", tcp.dst_port())
    print("control flag", tcp.control_flag())


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