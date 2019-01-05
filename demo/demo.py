import struct
import socket

try:
    from pniffer.ethernet import Ethernet
    from pniffer.ipv4 import IPv4
    from pniffer.tcp import TCP
    from pniffer.udp import UDP
except (ModuleNotFoundError, ImportError):
    import sys
    from traceback import print_exc
    print_exc()
    sys.exit("\n[!] Please add pniffer path to PYTHONPATH")
except:
    raise

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

    l4_protocol = ip.protocol().name

    if l4_protocol == 'TCP':
        tcp = TCP(ip.payload)
        print("\nTCP", suffix)
        print("source port:", tcp.src_port())
        print("destination port:", tcp.dst_port())
        print("control flag:", tcp.control_flag())
        print("header length:", tcp.data_offset())
        print("window size:", tcp.window_size())

    elif l4_protocol == 'UDP':
        udp = UDP(ip.payload)
        print("\nUDP", suffix)
        print("source port:", udp.src_port())
        print("destination port:", udp.dst_port())
        print("packet length: %d bytes" % udp.packet_length())
        print("checksum: %#x" % udp.checksum())

if __name__ == '__main__':
    interface = 'lo'

    # For proto argument of socket object
    ETH_P_ALL = 3   # All protocol pakcet

    # For socket.setsockopt()
    SOL_PACKET = 263    # Socket level
    PACKET_ADD_MEMBERSHIP = 1   # Socket option name

    # For mr_type (action) of packet_mreq structure 
    PACKET_MR_PROMISC = 1   # Promiscuous mode

    # For packet_mreq structure
    mr_ifindex = socket.if_nametoindex(interface)   # c_type is int
    mr_type = PACKET_MR_PROMISC                     # c_type is unsigned short
    mr_alen = 0                                     # c_type is unsigned short
    mr_address = b'\0'                              # c_type is unsigned char[8]

    packet_mreq = struct.pack('iHH8s',
                              mr_ifindex,
                              mr_type,
                              mr_alen,
                              mr_address)

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)) as sock:
        sock.bind((interface, 0))
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
