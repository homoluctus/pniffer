from utils import bin2str, bin2int

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
        return hex(self.packet[13])

    def window_size(self):
        return bin2int(self.packet[14:16])

    def checksum(self):
        return bin2str(self.packet[16:18])

    def urgent_pointer(self):
        return bin2str(self.packet[18:20])