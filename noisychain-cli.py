from dissononce.extras.dh.experimental.secp256k1.public \
        import PublicKey
from dissononce.extras.dh.experimental.secp256k1.private \
        import PrivateKey
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
from noisychain.protocols.k.initiator import KInitiatorProtocol
from noisychain.protocols.k.responder import KResponderProtocol
from noisychain.protocols.n.initiator import NInitiatorProtocol
from noisychain.protocols.n.responder import NResponderProtocol
from noisychain import channels
from noisychain.ethutils import funding

"""
noisychain-cli send --role initiator --to-addr address --key /path/to/key --protocol k
noisychain-cli recv --role initiator [--from address] --key /path/to/key
noisychain-cli channel --key /path/to/key --from address
noisychain-cli address
noisychain-cli pubkey --key /path/to/key
"""

ADDRESS_EXAMPLES = ""
PUBKEY_EXAMPLES = ""
SEND_EXAMPLES = """
Send Message Examples
=====================

> Send using K Protocol

python noisychain-cli.py send \\
        --protocol K \\
        --key data/alice.bin --key-format hex \\
        --pubkey 032c80af6ce6dbce65f0efd3f441dd2a8a5528a29d4d27483895a6bc17e1d5c240

> Send using N Protocol

python noisychain-cli.py send \\
        --protocol N \\
        --pubkey 032c80af6ce6dbce65f0efd3f441dd2a8a5528a29d4d27483895a6bc17e1d5c240

"""
RECV_EXAMPLES = """
Receive Message Examples
========================

> Receive using K Protocol

python noisychain-cli.py recv \\
        --protocol K \\
        --key data/bob.bin --key-format hex \\
        --pubkey 037c52cf41d23397d6312cbcf8deba4b1ad7b68635de4d9d967c86e0496e3f4d1c

> Receive using N Protocol

python noisychain-cli.py recv \\
        --protocol N \\
        --key data/bob.bin --key-format hex

"""
CHANNEL_EXAMPLES = ""
FUND_EXAMPLES = """
Fund Examples
=============

python noisychain-cli.py fund \\
        --key data/alice.bin --key-format hex \\
        --address 0x69A11f901e48D85AE1dEB516627F45DCC1190f3C \\
        --method external \\
        --value 2576000000000000
"""
EXAMPLES = ()

PROTOCOLS = {
    "K" : (KInitiatorProtocol, KResponderProtocol),
    "N" : (NInitiatorProtocol, NResponderProtocol),
};
ONEWAY_PROTOCOLS = ("K", "N")

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

def handle_fund(args):
    key = read_data(args.key, fmt=args.key_format)
    keypair = SECP256K1DH().generate_keypair(PrivateKey(key))

    if args.method == 'internal':
        funder = funding.InternalFunder(keypair.private)
    elif args.method == 'external':
        funder = funding.ExternalFunder()
    else:
        raise Exception(f"Unsupported funding method: {args.method}")

    asyncio.run(funder.fund(args.address, args.value))

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
    protocol_id = args.protocol

    if protocol_id in ONEWAY_PROTOCOLS:
        assert args.role in ("responder", None)
        initiator = False
    else:
        initiator = args.role == "initiator"
    key = read_data(args.key, fmt=args.key_format)
    local_static = SECP256K1DH().generate_keypair(PrivateKey(key))
    remote_public = None

    # The following protocols require a remote static key
    if protocol_id in ("K",):
        if args.address:
            remote_public = asyncio.run(ethutils.address_to_public(args.address))
        elif args.pubkey:
            remote_public = PublicKey(binascii.unhexlify(args.pubkey))
        else:
            print("Specify either an address or public key of the sender")
            sys.exit(1)

    Protocol = PROTOCOLS[protocol_id][0 if initiator else 1]

    if initiator:
        raise Exception("Not yet supported")
    else:
        address = ethutils.pubkey_to_address(local_static.public)
        if protocol_id == "K":
            assert remote_public, "Protocol requires specifing --pubkey"
            protocol = Protocol(local_static, remote_public)
            protocol.setup()
            address = protocol.channel
        elif protocol_id == "N":
            protocol = Protocol(local_static)
        else:
            raise Exception("Unsupported")

        transactions = asyncio.run(
                ethutils.get_transactions(to_address=address))

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
    protocol_id = args.protocol

    if protocol_id in ONEWAY_PROTOCOLS:
        assert args.role in ("initiator", None)
        initiator = True
    else:
        initiator = args.role == "initiator"

    if protocol_id in ("K",):
        assert args.key, "Specified protocol requires passing --key KEY"
        key = read_data(args.key, fmt=args.key_format)
        local_static = SECP256K1DH().generate_keypair(PrivateKey(key))
    else:
        local_static = None
    sys.stdout.write("Enter your message, followed by Ctrl+D > ")
    sys.stdout.flush()
    message = sys.stdin.buffer.read().strip()

    if args.address:
        remote_public = asyncio.run(ethutils.address_to_public(args.address))
    elif args.pubkey:
        remote_public = PublicKey(binascii.unhexlify(args.pubkey))
    else:
        print("Specify either an address or public key of the recipient")
        sys.exit(1)

    if initiator:
        Protocol = PROTOCOLS[protocol_id][0]
        if protocol_id == "K":
            protocol = Protocol(local_static, remote_public, message)
            protocol.setup()
        elif protocol_id == "N":
            protocol = Protocol(remote_public, message)
        else:
            raise Exception(f"Unsupported protocol: {protocol_id}")

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
            choices=('initiator', 'responder'))
    send_parser.add_argument('-p', '--protocol', action='store',
            choices=PROTOCOLS.keys(), required=True)

    group = send_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-K', '--pubkey', action='store')
    group.add_argument('-a', '--address', action='store')

    send_parser.add_argument('--key-format', action='store', choices=('raw', 'hex'))

    #####################

    channel_parser = subparsers.add_parser('channel',
            aliases=['c'],
            epilog=CHANNEL_EXAMPLES,
            formatter_class=argparse.RawDescriptionHelpFormatter)
    channel_parser.set_defaults(func=handle_channel)
    channel_parser.add_argument('-d', '--debug', action="store_true")

    channel_parser.add_argument('-k', '--key', action='store', required=True)
    group = channel_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-K', '--pubkey', action='store')
    group.add_argument('-a', '--address', action='store')

    channel_parser.add_argument('--key-format', action='store', choices=('raw', 'hex'))

    #####################

    recv_parser = subparsers.add_parser('recv',
            aliases=['r'],
            epilog=RECV_EXAMPLES,
            formatter_class=argparse.RawDescriptionHelpFormatter)
    recv_parser.set_defaults(func=handle_recv)
    recv_parser.add_argument('-d', '--debug', action="store_true")

    recv_parser.add_argument('-k', '--key', action='store', required=True)
    recv_parser.add_argument('-r', '--role', action='store',
            choices=('initiator', 'responder'), required=False)
    recv_parser.add_argument('-p', '--protocol', action='store',
            choices=PROTOCOLS.keys(), required=True)

    group = recv_parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-K', '--pubkey', action='store')
    group.add_argument('-a', '--address', action='store')

    recv_parser.add_argument('--key-format', action='store', choices=('raw', 'hex'))

    #####################

    fund_parser = subparsers.add_parser('fund',
            aliases=['f'],
            epilog=FUND_EXAMPLES,
            formatter_class=argparse.RawDescriptionHelpFormatter)
    fund_parser.set_defaults(func=handle_fund)
    fund_parser.add_argument('-d', '--debug', action="store_true")

    fund_parser.add_argument('-k', '--key', action='store', required=True)
    fund_parser.add_argument('-m', '--method', action='store',
            choices=('internal', 'tornado', 'external'), default='internal')
    fund_parser.add_argument('-a', '--address', action='store')
    fund_parser.add_argument('-v', '--value', action='store', type=int)

    fund_parser.add_argument('--key-format', action='store', choices=('raw', 'hex'))

    args = parser.parse_args()
    if args.debug:
        noisychain.logger.setLevel(logging.DEBUG)
    if hasattr(args, 'func'):
        args.func(args)
