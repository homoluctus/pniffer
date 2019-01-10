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

    parser.add_argument('-w', dest='filename',
                        metavar='FILE',
                        help='Write captured packet to file. \
                              Append if FILE exists')

    parser.add_argument('-b', '--binary',
                        action='store_true',
                        help='Output binary packets')

    return parser.parse_args()
