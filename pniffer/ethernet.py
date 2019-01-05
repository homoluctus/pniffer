from .utils import bin2str, bin2int


class Ethernet:
    def __init__(self, packet):
        self.packet = packet
        self.__payload = packet[14:]

    @property
    def payload(self):
        return self.__payload

    def dst_mac(self):
        raw_data = bin2str(self.packet[0:6])
        return self._format_mac(raw_data)

    def src_mac(self):
        raw_data = bin2str(self.packet[6:12])
        return self._format_mac(raw_data)

    def ethertype(self):
        return hex(bin2int(self.packet[12:14]))

    def _format_mac(self, raw_mac):
        return (':').join([raw_mac[i:i+2] for i in range(0, 12, 2)])
