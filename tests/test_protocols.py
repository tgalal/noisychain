from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from noisychain.protocols.k.initiator import KInitiatorProtocol
from dissononce.extras.dh.experimental.secp256k1.secp256k1 \
        import SECP256K1DH
from dissononce.extras.dh.experimental.secp256k1.keypair import KeyPair
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from dissononce.extras.dh.experimental.secp256k1.private import PrivateKey
import binascii
import asyncio
import noisychain
from noisychain import ethutils
import logging

noisychain.logger.setLevel(logging.DEBUG)


def test_protocol_k():
    keypair = SECP256K1DH().generate_keypair(
        PrivateKey(
            binascii.unhexlify(
                "700534a834d069a840afd2edc4826a7c"
                "e11709b707f87f4f65360b9c68d3361a"
            )
        )
    )
    keypair2 = SECP256K1DH().generate_keypair(
        PrivateKey(
            binascii.unhexlify(
                "609cbcf4550c13e124fe9e3a7575b8f1"
                "ed90853e05806f8043424d2e0f910ea9"
            )
        )
    )
    remote_public = keypair2.public
    print(f"My address: {ethutils.pubkey_to_address(keypair.public)}")
    print(f"Their address: {ethutils.pubkey_to_address(remote_public)}")

    protocol = KInitiatorProtocol(keypair, remote_public, b"Hello")
    protocol.setup()
    asyncio.run(protocol.send())
