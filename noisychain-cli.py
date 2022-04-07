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
########
from noisychain.protocols import k
from noisychain.protocols.k.initiator import KInitiatorProtocol
from noisychain.protocols.k.responder import KResponderProtocol
########
from noisychain.protocols import n
from noisychain.protocols.n.initiator import NInitiatorProtocol
from noisychain.protocols.n.responder import NResponderProtocol
########
from noisychain.protocols import x
from noisychain.protocols.x.initiator import XInitiatorProtocol
from noisychain.protocols.x.responder import XResponderProtocol
########
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
    "K" : (k.PROTOCOL_IDENTIFIER_BYTES, KInitiatorProtocol, KResponderProtocol),
    "N" : (n.PROTOCOL_IDENTIFIER_BYTES, NInitiatorProtocol, NResponderProtocol),
    "X" : (x.PROTOCOL_IDENTIFIER_BYTES, XInitiatorProtocol, XResponderProtocol),
};
ONEWAY_PROTOCOLS = ("K", "N", "X")

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
    assert args.protocol or args.role, "Specify either a protocol or role"
    assert not (args.protocol in ONEWAY_PROTOCOLS and args.role == "initiator")

    if args.protocol is None:
        protocol_ids = ("X", "N", "K")
    else:
        protocol_ids = (args.protocol,)

    multi_mode = len(protocol_ids) > 1

    if multi_mode:
        sys.stderr.write("Multi Protocol Mode\n")
        sys.stderr.write(f"Receiving messages for {protocol_ids} protocols\n")
    else:
        sys.stderr.write("Single Protocol Mode\n")
        sys.stderr.write(f"Receiving messages for {protocol_ids[0]} protocol\n")

    if args.key:
        key = read_data(args.key, fmt=args.key_format)
        local_static = SECP256K1DH().generate_keypair(PrivateKey(key))
    else:
        local_static = None
    remote_public = None

    # The following protocols require a remote static key
    if "K" in protocol_ids:
        if args.address:
            remote_public = asyncio.run(ethutils.address_to_public(args.address))
        elif args.pubkey:
            remote_public = PublicKey(binascii.unhexlify(args.pubkey))

    protocol_handlers = {};
    addresses = []
    for protocol_id in protocol_ids:
        try:
            if protocol_id == "K":
                assert local_static
                assert remote_public, "Remote public required"
                protocol = KResponderProtocol(local_static, remote_public)
                protocol.setup()
                protocol_handlers[k.PROTOCOL_IDENTIFIER_BYTES] = protocol
                addresses.append(protocol.channel)
            elif protocol_id == "N":
                assert local_static
                protocol_handlers[n.PROTOCOL_IDENTIFIER_BYTES] = \
                        NResponderProtocol(local_static)
                addresses.append(ethutils.pubkey_to_address(local_static.public))
            elif protocol_id == "X":
                assert local_static
                protocol_handlers[x.PROTOCOL_IDENTIFIER_BYTES] = \
                        XResponderProtocol(local_static)
                addresses.append(ethutils.pubkey_to_address(local_static.public))
            else:
                raise Exception("Not supported")
        except AssertionError as e:
            if not multi_mode:
                raise
            else:
                sys.stderr.write( f"Ignoring protocol {protocol_id}: "
                                  f"{e}\n")
    assert len(addresses)
    sys.stderr.write("\nMessages:\n\n")
    transactions = asyncio.run(
            ethutils.get_transactions(to_addresses=addresses))

    for tx in transactions:
        for identifier_bytes, protocol in protocol_handlers.items():
            if binascii.unhexlify(tx.input[2:]).startswith(
                    MAGIC + identifier_bytes
                    ):
                sender, plaintext = asyncio.run(protocol.recv(tx))
                sender = sender or "Unknown sender"
                print(f"[{sender}]: {plaintext.decode().strip()}")

def handle_send(args):
    protocol_id = args.protocol

    if protocol_id in ONEWAY_PROTOCOLS:
        assert args.role in ("initiator", None)
        initiator = True
    else:
        initiator = args.role == "initiator"

    if protocol_id in ("K", "X"):
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
        Protocol = PROTOCOLS[protocol_id][1]
        if protocol_id == "K":
            protocol = Protocol(local_static, remote_public, message)
            protocol.setup()
        elif protocol_id == "N":
            protocol = Protocol(remote_public, message)
        elif protocol_id == "X":
            protocol = Protocol(local_static, remote_public, message)
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
            choices=PROTOCOLS.keys())

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
