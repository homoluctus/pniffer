from .utils import bin2str, bin2int


class UDP:
    def __init__(self, packet):
        self.packet = packet
        self.__payload = packet[8:]

    @property
    def payload(self):
        return self.__payload

    def src_port(self):
        return bin2int(self.packet[0:2])

    def dst_port(self):
        return bin2int(self.packet[2:4])

    def packet_length(self):
        return bin2int(self.packet[4:6])

    def checksum(self):
        return bin2int(self.packet[6:8])
