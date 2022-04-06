import binascii
from dissononce.extras.dh.experimental.secp256k1.public \
        import PublicKey
from dissononce.extras.dh.experimental.secp256k1.private \
        import PrivateKey
from noisychain import ethutils
import binascii
import argparse
import sys
import asyncio
import logging
import noisychain

"""
noisychain-cli send --role initiator --to address --key /path/to/key --protocol k
noisychain-cli recv --role initiator [--from address] --key /path/to/key
noisychain-cli channel --key /path/to/key --from address
noisychain-cli address
noisychain-cli pubkey --key /path/to/key
"""

ADDRESS_EXAMPLES = ""
PUBKEY_EXAMPLES = ""
EXAMPLES = ()


def handle_address(args):
    if args.pubkey == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(args.pubkey, 'rb') as f:
            data = f.read()

    data = data.strip()
    if args.input_format == 'hex':
        data = binascii.unhexlify(data)

    address = ethutils.pubkey_to_address(PublicKey(data))
    print(address)

def read_data(source, fmt='raw'):
    if source == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(source, 'rb') as f:
            data = f.read()

    data = data.strip()

    if fmt == 'hex':
        data = binascii.unhexlify(data)
    elif fmt == 'ascii':
        data = data.decode()

    return data

def handle_pubkey(args):
    if args.key:
        keydata = read_data(args.key, args.input_format)
        public = ethutils.private_to_public(PrivateKey(keydata))
        print(binascii.hexlify(public.data).decode())
    elif args.address:
        address = read_data(args.address, 'ascii')
        pubkey = asyncio.run(ethutils.address_to_public(address))
        print(binascii.hexlify(pubkey.data).decode())

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Commands',
            epilog='\n'.join(EXAMPLES),
            formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-d', '--debug', action="store_true")
    subparsers = parser.add_subparsers(title='subjects',
            description='Available subjects:',
            help='additional help')

    address_parser = subparsers.add_parser('address',
            aliases=['a', 'addr'],
            epilog=ADDRESS_EXAMPLES,
            formatter_class=argparse.RawDescriptionHelpFormatter)
    address_parser.set_defaults(func=handle_address)
    address_parser.add_argument('-K', '--pubkey', action='store', metavar=('PATH'))
    address_parser.add_argument('-f', '--input-format', action='store', choices=('raw', 'hex'))

    #####################

    pubkey_parser = subparsers.add_parser('pubkey',
            aliases=['pub'],
            epilog=PUBKEY_EXAMPLES,
            formatter_class=argparse.RawDescriptionHelpFormatter)
    pubkey_parser.set_defaults(func=handle_pubkey)

    group = pubkey_parser.add_mutually_exclusive_group()
    group.add_argument('-k', '--key', action='store', metavar=('PATH'))
    group.add_argument('-a', '--address', action='store', metavar=('ADDRESS'))

    pubkey_parser.add_argument('-f', '--input-format', action='store', choices=('raw', 'hex'))

    args = parser.parse_args()

    if args.debug:
        noisychain.logger.setLevel(logging.DEBUG)
    if hasattr(args, 'func'):
        args.func(args)
