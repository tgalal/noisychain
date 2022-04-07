import binascii
from dissononce.extras.dh.experimental.secp256k1.keypair import KeyPair
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
from dissononce.processing.handshakepatterns.oneway.X import XHandshakePattern
from web3 import Web3
import logging

from ... import ethutils
from ...ethutils.funding import InternalFunder
from . import PROTOCOL_IDENTIFIER_BYTES
from .. import MAGIC

logger = logging.getLogger(__name__)


class XInitiatorProtocol:
    def __init__(self,
            local_static: KeyPair,
            remote_static: PublicKey,
            message: bytes):

        self._local_static = local_static
        self._remote_static = remote_static
        self._message = message
        self._protocol = NoiseProtocolFactory().get_noise_protocol(
                "Noise_X_secp256k1_AESGCM_SHA256")

    async def send(self) -> str | None:
        logger.debug("send()")
        ############## Noise init
        handshakestate = self._protocol.create_handshakestate()
        handshakestate.initialize(XHandshakePattern(), True, b'',
                s=self._local_static, rs=self._remote_static)
        logger.debug("Initialized Noise Protocol for Initiator")
        ######################

        payload_buffer = bytearray()
        handshakestate.write_message(self._message, payload_buffer)
        payload_buffer = MAGIC + PROTOCOL_IDENTIFIER_BYTES + payload_buffer

        local_ephemeral = handshakestate.e
        local_ephemeral_address = ethutils.pubkey_to_address(
                local_ephemeral.public)

        tx, signed = await ethutils.create_and_sign_transaction(
                key=local_ephemeral.private,
                to=self._remote_static,
                data=payload_buffer,
                value=0
            )

        estimated_cost = tx['gas'] * tx['gasPrice']
        logger.debug(f"Payload is {len(payload_buffer)} bytes")
        logger.debug(
            f"Estimated cost is {Web3.fromWei(estimated_cost, 'ether')} ether")

        await InternalFunder(self._local_static.private).fund(
                local_ephemeral_address, estimated_cost)
        await ethutils.send(signed)

        logger.info("Sent")
        return binascii.hexlify(signed.hash).decode()

