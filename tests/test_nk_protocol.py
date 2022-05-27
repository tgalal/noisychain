from noisychain.state.state import StateManager
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from dissononce.extras.dh.experimental.secp256k1.secp256k1 \
        import SECP256K1DH
from dissononce.extras.dh.experimental.secp256k1.keypair import KeyPair
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from dissononce.extras.dh.experimental.secp256k1.private import PrivateKey
import binascii
import asyncio
import noisychain
from noisychain import ethutils
from noisychain.protocols.nk.protocol import NKProtocol
from noisychain.ethutils.funding import InternalFunder
from noisychain.session import ProtocolState, ProtocolSession, InMemorySessionStore
from noisychain import ethutils
import logging
import pytest
import asyncio

noisychain.logger.setLevel(logging.DEBUG)


def test_protocol_discrete_runs():
    funding_key = PrivateKey(
        binascii.unhexlify(
            "653f725e1da9998bdc771e0fc467bc8f"
            "787df9a0a858524b052de9d82b1b1392"
        )
    )

    alice_keypair = SECP256K1DH().generate_keypair(
        PrivateKey(
            binascii.unhexlify(
                "700534a834d069a840afd2edc4826a7c"
                "e11709b707f87f4f65360b9c68d3361a"
            )
        )
    )

    bob_keypair = SECP256K1DH().generate_keypair(
        PrivateKey(
            binascii.unhexlify(
                "609cbcf4550c13e124fe9e3a7575b8f1"
                "ed90853e05806f8043424d2e0f910ea9"
            )
        )
    )
    alice_session = ProtocolSession(NKProtocol.NOISE_PROTOCOL_NAME)
    bob_session = ProtocolSession(NKProtocol.NOISE_PROTOCOL_NAME)


    # Round 1: Alice sends to Bob.
    protocol_alice = NKProtocol(session=alice_session, funder=InternalFunder(funding_key))
    protocol_bob = NKProtocol(session=bob_session, funder=InternalFunder(funding_key))

    protocol_alice.setup_initiator(bob_keypair.public)
    protocol_bob.setup_responder(bob_keypair.private)

    txhash = asyncio.run(protocol_alice.send(b"Message 1"))
    assert txhash is not None

    tx = asyncio.run(ethutils.get_transaction(txhash))

    sender, message = asyncio.run(protocol_bob.recv(tx))
    assert sender is None
    assert message == b"Message 1"
    print("Sent Message 1")

    # Round 2: Bob sends to Alice.
    protocol_alice = NKProtocol(session=alice_session, funder=InternalFunder(funding_key))
    protocol_bob = NKProtocol(session=bob_session, funder=InternalFunder(funding_key))

    protocol_alice.setup_initiator(bob_keypair.public)
    protocol_bob.setup_responder(bob_keypair.private)

    txhash = asyncio.run(protocol_bob.send(b"Message 2"))
    assert txhash is not None

    tx = asyncio.run(ethutils.get_transaction(txhash))

    sender, message = asyncio.run(protocol_alice.recv(tx))
    assert sender is None # TODO: this should be Bob
    assert message == b"Message 2"
    print("Sent Message 2")
 
    # Round 3+: Messages flow in any direction

    protocol_alice = NKProtocol(session=alice_session, funder=InternalFunder(funding_key))
    protocol_bob = NKProtocol(session=bob_session, funder=InternalFunder(funding_key))

    protocol_alice.setup_initiator(bob_keypair.public)
    protocol_bob.setup_responder(bob_keypair.private)

    txhash = asyncio.run(protocol_bob.send(b"Message 3"))
    assert txhash is not None

    tx = asyncio.run(ethutils.get_transaction(txhash))

    sender, message = asyncio.run(protocol_alice.recv(tx))
    assert sender is None # TODO: this should be Bob
    assert message == b"Message 3"
    print("Sent Message 3")
 
    txhash = asyncio.run(protocol_bob.send(b"Message 4"))
    assert txhash is not None

    tx = asyncio.run(ethutils.get_transaction(txhash))

    sender, message = asyncio.run(protocol_alice.recv(tx))
    assert sender is None # TODO: this should be Bob
    assert message == b"Message 4"
    print("Sent Message 4")
