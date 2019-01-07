from .utils import (
    bin2str, bin2int, generate_header_dict)


class UDP:
    def __init__(self, packet):
        self.packet = packet
        self.__payload = packet[8:]

    def __call__(self):
        field_name = ['source_port', 'destination_port',
                      'packet_length', 'checksum']

        values = (self.src_port(), self.dst_port(),
                  self.packet_length(), self.checksum())

        return generate_header_dict(field_name, values)

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
