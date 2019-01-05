import socket
import binascii


def bin2str(data, encoding='utf-8'):
    """
    Convert binary data to utf-8 string.
    """

    return binascii.hexlify(data).decode(encoding)


def bin2int(raw_data, base=16):
    """
    Convert binary raw data based hex to integer.
    """

    if isinstance(raw_data, bytes):
        data = bin2str(raw_data)
    elif isinstance(raw_data, int):
        return raw_data
    else:
        data = raw_data

    return int(data, base)


def ip2domain(ip):
    """
    Resolve given address to domain name.
    Return address if not resolution.
    """
    if not isinstance(ip, str):
        try:
            ip = str(ip)
        except Exception:
            raise

    try:
        host = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        host = ip

    return host
