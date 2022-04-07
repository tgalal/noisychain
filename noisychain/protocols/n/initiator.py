import binascii
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
from dissononce.processing.handshakepatterns.oneway.N import NHandshakePattern
from web3 import Web3
import logging

from ... import ethutils
from ...ethutils.funding import ExternalFunder
from . import PROTOCOL_ID
from .. import MAGIC

logger = logging.getLogger(__name__)


class NInitiatorProtocol:
    def __init__(self,
            remote_static: PublicKey,
            message: bytes):
        self._remote_static = remote_static
        self._message = message
        self._noise = NoiseProtocolFactory().get_noise_protocol(
                "Noise_N_secp256k1_AESGCM_SHA256")

    async def send(self) -> str | None:
        logger.debug("send()")
        ############## Noise init
        handshakestate = self._noise.create_handshakestate()
        handshakestate.initialize(NHandshakePattern(), True, b'',
                rs=self._remote_static)
        ######################

        payload_buffer = bytearray()
        handshakestate.write_message(self._message, payload_buffer)
        payload_buffer = MAGIC + PROTOCOL_ID.to_bytes(1, 'big') + payload_buffer

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

        await ExternalFunder().fund(local_ephemeral_address, estimated_cost)
        await ethutils.send(signed)

        logger.info("Sent")
        return binascii.hexlify(signed.hash).decode()

