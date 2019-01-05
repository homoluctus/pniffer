from enum import Enum
from .utils import bin2str, bin2int

class TCP:
    def __init__(self, packet):
        self.packet = packet
        self.__payload = packet[self.data_offset():]

    def src_port(self):
        return bin2int(self.packet[0:2])

    def dst_port(self):
        return bin2int(self.packet[2:4])

    def sequence_number(self):
        return bin2str(self.packet[4:8])

    def acknowledgement_number(self):
        return bin2str(self.packet[8:12])

    def data_offset(self):
        return (self.packet[12] >> 4) * 4

    def control_flag(self):
        return FlagHandler(self.packet[13])

    def window_size(self):
        return bin2int(self.packet[14:16])

    def checksum(self):
        return bin2str(self.packet[16:18])

    def urgent_pointer(self):
        return bin2str(self.packet[18:20])

class FlagHandler:
    """
    Return a list includes 2-tuple (Flag.name, hex(Flag.value))
    """

    def __new__(cls, value):
        if not isinstance(value, int):
            raise TypeError("%r can't be interpreted as an integer" % value)

        return cls._get(value)

    @classmethod
    def _get(cls, value):
        return [(member.name, hex(member.value)) for key, member in Flag._value2member_map_.items() if (key & value) != 0x0]

class Flag(Enum):
    CWR = 0x80
    ECE = 0x40
    URG = 0x20
    ACK = 0x10
    PSH = 0x08
    RST = 0x04
    SYN = 0x02
    FIN = 0x01

    def __str__(self):
        return self.name
