import sys
import argparse


def operate_args():
    parser = argparse.ArgumentParser(
        prog='Pniffer',
        description='This is traffic capture tool',)

    parser.add_argument('-i', '--interface',
                        required=True,
                        help='Bind interface')

    parser.add_argument('--promis', action='store_true',
                        help='Enable promiscuous mode')

    parser.add_argument('-f', '--format',
                        choices=['dict', 'json', 'yaml'],
                        default='dict',
                        dest='fmt',
                        help='Dump json or yaml (default: python dict)')

    parser.add_argument('-w', dest='file',
                        nargs='?',
                        default=sys.stdout,
                        type=argparse.FileType('w'),
                        help='Write captured packet to file')

    return parser.parse_args()
