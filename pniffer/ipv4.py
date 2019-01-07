import ipaddress
from enum import Enum

from .utils import (
    bin2str, bin2int, generate_header_dict)


class IPv4:
    """
    Support only little endian.
    """

    def __init__(self, packet):
        self.packet = packet
        self.__payload = packet[self.header_length():]

    def __call__(self):
        field_name = ['version', 'hdl', 'tos', 'total', 'identification',
                      'fragment', 'fragment_offset', 'ttl', 'protocol',
                      'checksum', 'destination', 'source']

        values = (self.version(), self.header_length(), self.tos(),
                  self.total_length(), self.identification(),
                  self.fragment(), self.fragment_offset(), self.ttl(),
                  str(self.protocol()), self.checksum(), self.src_ip(),
                  self.dst_ip())

        return generate_header_dict(field_name, values)

    @property
    def payload(self):
        return self.__payload

    def version(self):
        return self.packet[0] >> 4

    def header_length(self):
        return (self.packet[0] & 0x0f) * 4

    def tos(self):
        return str(self.packet[1])

    def total_length(self):
        return bin2int(self.packet[2:4])

    def identification(self):
        return bin2int(self.packet[4:6])

    def fragment(self):
        return self.packet[6] & 0x03

    def fragment_offset(self):
        return bin2str(self.packet[6:8])

    def ttl(self):
        return self.packet[8]

    def protocol(self):
        """
        Return enum object
        """

        return Protocol(self.packet[9])

    def checksum(self):
        return bin2str(self.packet[10:12])

    def src_ip(self):
        return self._format_ip(bin2int(self.packet[12:16]))

    def dst_ip(self):
        return self._format_ip(bin2int(self.packet[16:20]))

    def _format_ip(self, ip):
        return str(ipaddress.ip_address(ip))


class Protocol(Enum):
    IP = 0
    ICMP = 1
    IGMP = 2
    TCP = 6
    UDP = 17
    IP6 = 41
    IP6_ROUTE = 43
    IP6_FLAG = 44
    GRE = 47
    ESP = 50
    AH = 51
    ICMP6 = 58

    def __str__(self):
        return self.name
