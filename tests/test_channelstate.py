from dissononce.processing.handshakepatterns.interactive.NK import NKHandshakePattern
from noisychain import ethutils
from dissononce.hash.sha256 import SHA256Hash
from noisychain.ethutils.funding.funder_internal import InternalFunder
from dissononce.processing.handshakepatterns.interactive.KK import KKHandshakePattern
from dissononce.extras.dh.experimental.secp256k1.private import PrivateKey
from dissononce.cipher.aesgcm import AESGCMCipher
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.extras.dh.experimental.secp256k1.secp256k1 import SECP256K1DH
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.handshakestate import HandshakeState
from noisychain.channels.channelstate import ChannelState, EthereumTransport
from noisychain.protocols import MAGIC
import asyncio
import binascii
import random

# Funding source, for simplicity it is used by both Alice and Bob.
funding_key = PrivateKey(
    binascii.unhexlify(
        # "653f725e1da9998bdc771e0fc467bc8f"
        # "787df9a0a858524b052de9d82b1b1392"
        "080c111d94edbf118a290efd3b9b2cf"
        "f1fb4e73af533b8b233d8fce794362ea6"
    )
)

# Load Alice's static key pair.
alice_keypair = SECP256K1DH().generate_keypair(
    PrivateKey(
        binascii.unhexlify(
            "700534a834d069a840afd2edc4826a7c"
            "e11709b707f87f4f65360b9c68d3361a"
        )
    )
)

# Load Bob's static key pair.
bob_keypair = SECP256K1DH().generate_keypair(
    PrivateKey(
        binascii.unhexlify(
            "609cbcf4550c13e124fe9e3a7575b8f1"
            "ed90853e05806f8043424d2e0f910ea9"
        )
    )
)

# Initialize the funder.
funder = InternalFunder(funding_key)

def test_kk_channelstate():
    # Create Alice's channel.
    # This encapsulates sendch and recvch of Alice, automatically updating them
    # as messages are sent and received.
    alice_channelstate = ChannelState(
        EthereumTransport(MAGIC + b'\x05', funder),
        HandshakeState(
            SymmetricState(
                CipherState(AESGCMCipher()),
                SHA256Hash()
            ),
            SECP256K1DH())
    )
    alice_channelstate.initialize(
            initiator=True,
            pattern=KKHandshakePattern(),
            s=alice_keypair,
            rs=bob_keypair.public
            )
    # Create Bob's channel state.
    # This encapsulates sendch and recvch of Bob, automatically updating them
    # as messages are sent and received.
    bob_channelstate = ChannelState(
        EthereumTransport(MAGIC + b'\x05', funder),
        HandshakeState(
            SymmetricState(
                CipherState(AESGCMCipher()),
                SHA256Hash()
            ),
            SECP256K1DH())
    )
    bob_channelstate.initialize(
            initiator=False,
            pattern=KKHandshakePattern(),
            s=bob_keypair,
            rs=alice_keypair.public
            )

    # Will keep track of already used addresses in those lists to ensure no
    # address is used more than once.
    alice_chouts = []
    bob_chouts = []
 
    ######################################## Round 1
    print("Round 1: Alice sends to Bob")
    message = b"Message 1"
    alice_chouts.append(alice_channelstate.chout)

    # Generate a random Wei amount to ensure Bob receives it.
    value = random.randint(1000000000000000000, 2000000000000000000)

    # Send the message with payment, ensure Bob receives it and that Bob's
    # balance now has at least the sent payment.
    alice_channelstate.send_message(message, value)
    received_message, chkey = bob_channelstate.receive_message()
    assert received_message == message
    assert value <= asyncio.run(
            ethutils.get_balance(ethutils.privkey_to_address(chkey)))

    ######################################## Round 2
    print("Round 2: Bob sends to Alice")
    message = b"Message 2"
    bob_chouts.append(bob_channelstate.chout)

    # Generate a random Wei amount to ensure Alice receives it.
    value = random.randint(1000000000000000000, 2000000000000000000)

    # Send the message with payment, ensure Alice receives it and that Alice's
    # balance now has at least the sent payment.
    bob_channelstate.send_message(message, value)
    received_message, chkey = alice_channelstate.receive_message()
    assert received_message == message
    assert value <= asyncio.run(
            ethutils.get_balance(ethutils.privkey_to_address(chkey)))

    ######################################## Round 3
    print("Round 3: Messages flowing in any direction.")
    print("Alice sends Bob 2 messages")
    for i in range(0, 2):
        print(f"Alice to Bob {i + 3}" )
        message = b"Message %d" % random.randint(1000, 10000)

        # Sends to different addresses every time
        assert alice_channelstate.chout not in alice_chouts
        alice_chouts.append(alice_channelstate.chout)

        # Send
        value = random.randint(10000000000000000, 20000000000000000)
        alice_channelstate.send_message(message, value)
        received_message, chkey = bob_channelstate.receive_message()
        assert received_message == message

        # Can spend funds
        assert value == asyncio.run(
                ethutils.get_balance(ethutils.privkey_to_address(chkey)))

    print("Bob sends Alice 2 messages")
    for i in range(0, 2):
        print(f"Bob to Alice {i + 3}" )
        message = b"Message %d" % random.randint(1000, 10000)

        # Sends to different addresses every time
        assert bob_channelstate.chout not in bob_chouts
        bob_chouts.append(bob_channelstate.chout)

        # Send
        value = random.randint(10000000000000000, 20000000000000000)
        bob_channelstate.send_message(message, value)
        received_message, chkey = alice_channelstate.receive_message()
        assert received_message == message

        # Can spend funds
        assert value == asyncio.run(
                ethutils.get_balance(ethutils.privkey_to_address(chkey)))
