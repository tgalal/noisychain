import binascii
from dissononce.extras.dh.experimental.secp256k1.public \
        import PublicKey
from dissononce.extras.dh.experimental.secp256k1.private \
        import PrivateKey
from dissononce.extras.dh.experimental.secp256k1.keypair \
        import KeyPair
from dissononce.extras.dh.experimental.secp256k1.secp256k1 \
        import SECP256K1DH
from noisychain import ethutils
import binascii
import argparse
import sys
import asyncio
import logging
import noisychain
from noisychain.protocols import MAGIC
from noisychain.protocols import k
from noisychain.protocols.k.initiator import KInitiatorProtocol

"""
noisychain-cli send --role initiator --to-addr address --key /path/to/key --protocol k
noisychain-cli recv --role initiator [--from address] --key /path/to/key
noisychain-cli channel --key /path/to/key --from address
noisychain-cli address
noisychain-cli pubkey --key /path/to/key
"""

ADDRESS_EXAMPLES = ""
PUBKEY_EXAMPLES = ""
SEND_EXAMPLES = ""
CHANNEL_EXAMPLES = ""
RECV_EXAMPLES = ""
EXAMPLES = ()

PROTOCOLS = {
    "K" : (KInitiatorProtocol,)
};

def read_data(source, fmt='raw', accept_stdin=False):
    if source == "-" and accept_stdin:
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

def handle_channel(args):
    key = read_data(args.key, fmt=args.key_format)
    local_static = SECP256K1DH().generate_keypair(PrivateKey(key))
    if args.address:
        remote_public = asyncio.run(ethutils.address_to_public(args.address))
    elif args.pubkey:
        remote_public = PublicKey(binascii.unhexlify(args.pubkey))
    else:
        print("Specify either an address or public key of the sender")
        sys.exit(1)

    channel = channels.derive_channel(local_static, remote_public, 0)
    print(channel)


def handle_recv(args):
    initiator = args.role == "initiator"
    key = read_data(args.key, fmt=args.key_format)
    protocol_id = args.protocol
    local_static = SECP256K1DH().generate_keypair(PrivateKey(key))

    if args.address:
        remote_public = asyncio.run(ethutils.address_to_public(args.address))
    elif args.pubkey:
        remote_public = PublicKey(binascii.unhexlify(args.pubkey))
    else:
        print("Specify either an address or public key of the sender")
        sys.exit(1)

    if initiator:
        pass
    else:
        protocol = PROTOCOLS[protocol_id][1](local_static, remote_public)
        protocol.setup()

        channel = protocol.channel
        transactions = asyncio.run(
                ethutils.get_transactions(to_address=channel))

        transactions_data = map(
                lambda tx: binascii.unhexlify(tx.input[2:]),
                transactions)

        messages = filter(
                lambda data: data.startswith(MAGIC),
                transactions_data)
        i = 0
        for message in messages:
            plaintext = asyncio.run(protocol.recv(message))
            print(f"Message [{i}]: {plaintext.decode().strip()}")
            i += 1

def handle_send(args):
    initiator = args.role == "initiator"
    key = read_data(args.key, fmt=args.key_format)
    protocol_id = args.protocol
    local_static = SECP256K1DH().generate_keypair(PrivateKey(key))
    message = sys.stdin.buffer.read().strip()

    if args.address:
        remote_public = asyncio.run(ethutils.address_to_public(args.address))
    elif args.pubkey:
        remote_public = PublicKey(binascii.unhexlify(args.pubkey))
    else:
        print("Specify either an address or public key of the recipient")
        sys.exit(1)

    if initiator:
        protocol = PROTOCOLS[protocol_id][0](
                local_static, remote_public, message)
        protocol.setup()
        print("\nSending...")
        txhash = asyncio.run(protocol.send())
        print(f"Sent: {txhash}")

def handle_address(args):
    data = read_data(args.pubkey, args.pubkey_format, True)
    address = ethutils.pubkey_to_address(PublicKey(data))
    print(address)

def handle_pubkey(args):
    if args.key:
        keydata = read_data(args.key, args.key_format, True)
        public = ethutils.private_to_public(PrivateKey(keydata))
        print(binascii.hexlify(public.data).decode())
    elif args.address:
        if args.address == "-":
            address = sys.stdin.read()
        else:
            address = args.address
        pubkey = asyncio.run(ethutils.address_to_public(address))
        print(binascii.hexlify(pubkey.data).decode())

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Commands',
            epilog='\n'.join(EXAMPLES),
            formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(title='subjects',
            description='Available subjects:',
            help='additional help')

    address_parser = subparsers.add_parser('address',
            aliases=['a', 'addr'],
            epilog=ADDRESS_EXAMPLES,
            formatter_class=argparse.RawDescriptionHelpFormatter)
    address_parser.set_defaults(func=handle_address)
    address_parser.add_argument('-d', '--debug', action="store_true")
    address_parser.add_argument('-K', '--pubkey', action='store', metavar=('PATH'))
    address_parser.add_argument('--pubkey-format', action='store', choices=('raw', 'hex'))

    #####################

    pubkey_parser = subparsers.add_parser('pubkey',
            aliases=['pub'],
            epilog=PUBKEY_EXAMPLES,
            formatter_class=argparse.RawDescriptionHelpFormatter)
    pubkey_parser.set_defaults(func=handle_pubkey)
    pubkey_parser.add_argument('-d', '--debug', action="store_true")

    group = pubkey_parser.add_mutually_exclusive_group()
    group.add_argument('-k', '--key', action='store', metavar=('PATH'))
    group.add_argument('-a', '--address', action='store', metavar=('ADDRESS'))

    pubkey_parser.add_argument('--key-format', action='store', choices=('raw', 'hex'))

    #####################

    send_parser = subparsers.add_parser('send',
            aliases=['s'],
            epilog=SEND_EXAMPLES,
            formatter_class=argparse.RawDescriptionHelpFormatter)
    send_parser.set_defaults(func=handle_send)
    send_parser.add_argument('-d', '--debug', action="store_true")

    send_parser.add_argument('-k', '--key', action='store')
    send_parser.add_argument('-r', '--role', action='store',
            choices=('initiator', 'responder'), required=True)
    send_parser.add_argument('-p', '--protocol', action='store',
            choices=PROTOCOLS.keys(), required=True)

    group = send_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-K', '--pubkey', action='store')
    group.add_argument('-a', '--address', action='store')

    send_parser.add_argument('--key-format', action='store', choices=('raw', 'hex'))

    args = parser.parse_args()
    if args.debug:
        noisychain.logger.setLevel(logging.DEBUG)
    if hasattr(args, 'func'):
        args.func(args)
