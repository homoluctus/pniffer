import argparse


def operate_args():
    parser = argparse.ArgumentParser(
        prog='Pniffer',
        description='This is traffic capture tool',)

    parser.add_argument('-i', '--interface',
                        required=True,
                        help='bind interface')

    parser.add_argument('--promis', action='store_true',
                        help='enable promiscuous mode')

    parser.add_argument('-f', '--format',
                        choices=['dict', 'json', 'yaml'],
                        default='dict',
                        dest='fmt',
                        help='dump json or yaml (default: python dict)')

    return parser.parse_args()
