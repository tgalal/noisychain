import binascii
from dissononce.extras.dh.experimental.secp256k1.secp256k1 \
        import SECP256K1DH
from dissononce.extras.dh.experimental.secp256k1.keypair import KeyPair
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
from dissononce.processing.handshakepatterns.oneway.K import KHandshakePattern
from web3 import Web3
import logging

from ...channels import derive_channel
from ... import ethutils
from ...ethutils.funding import ExternalFunder, InternalFunder
from . import PROTOCOL_ID
from .. import MAGIC

logger = logging.getLogger(__name__)


class KInitiatorProtocol:
    def __init__(self,
            local_static: KeyPair,
            remote_static: PublicKey,
            message: bytes):
        self._local_static = local_static
        self._remote_static = remote_static
        self._message = message

        ############## Funder init
        self._funder = InternalFunder(self._local_static.private)

        logger.debug("Initialized K Protocol for Initiator")

    def setup(self):
        logger.debug("setup()")
        self._channel : str = derive_channel(self._local_static,
                self._remote_static, 0)
        logger.debug("Created channel %s" % self._channel)

    async def send(self) -> str | None:
        logger.debug("send()")
        ############## Noise init
        protocol = NoiseProtocolFactory().get_noise_protocol(
                "Noise_K_secp256k1_AESGCM_SHA256")
        handshakestate = protocol.create_handshakestate()
        handshakestate.initialize(KHandshakePattern(), True, b'',
                s=self._local_static, rs=self._remote_static)
        ######################

        payload_buffer = bytearray()
        handshakestate.write_message(self._message, payload_buffer)
        payload_buffer = MAGIC + PROTOCOL_ID.to_bytes(1, 'big') + payload_buffer

        local_ephemeral = handshakestate.e
        local_ephemeral_address = ethutils.pubkey_to_address(
                local_ephemeral.public)

        tx, signed = await ethutils.create_and_sign_transaction(
                key=local_ephemeral.private,
                to=self._channel,
                data=payload_buffer,
                value=0
            )

        estimated_cost = tx['gas'] * tx['gasPrice']
        logger.debug(f"Payload is {len(payload_buffer)} bytes")
        logger.debug(
            f"Estimated cost is {Web3.fromWei(estimated_cost, 'ether')} ether")

        await self._funder.fund(local_ephemeral_address, estimated_cost)
        await ethutils.send(signed)

        logger.info("Sent")
        return binascii.hexlify(signed.hash).decode()

