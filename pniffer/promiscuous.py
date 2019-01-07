import socket
import struct


def promiscuous_mode(sock, interface='lo'):
    # For socket.setsockopt()
    SOL_PACKET = 263    # Socket level
    PACKET_ADD_MEMBERSHIP = 1   # Socket option name

    # For mr_type (action) of packet_mreq structure
    PACKET_MR_PROMISC = 1   # Promiscuous mode

    # For packet_mreq structure
    mr_ifindex = socket.if_nametoindex(interface)   # c_type is int
    mr_type = PACKET_MR_PROMISC                     # c_type is unsigned short
    mr_alen = 0           # c_type is unsigned short
    mr_address = b'\0'    # c_type is unsigned char[8]

    packet_mreq = struct.pack('iHH8s',
                              mr_ifindex,
                              mr_type,
                              mr_alen,
                              mr_address)

    sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, packet_mreq)
