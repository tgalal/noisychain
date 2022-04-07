from dissononce.extras.dh.experimental.secp256k1.keypair import KeyPair
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
from dissononce.processing.handshakepatterns.oneway.K import KHandshakePattern
import logging
import binascii

from ...channels import derive_channel
from .. import MAGIC
from . import PROTOCOL_IDENTIFIER_BYTES
from ... import ethutils

logger = logging.getLogger(__name__)


class KResponderProtocol:
    def __init__(self,
            local_static: KeyPair,
            remote_static: PublicKey):

        self._local_static = local_static
        self._remote_static = remote_static

    @property
    def channel(self):
        return self._channel

    def setup(self):
        logger.debug("setup()")
        self._channel : str = derive_channel(self._local_static,
                self._remote_static, 0)
        logger.debug("Created channel %s" % self._channel)

    async def recv(self, transaction):
        payload = binascii.unhexlify(transaction.input[2:])
        logger.debug("recv()")
        assert payload.startswith(MAGIC + PROTOCOL_IDENTIFIER_BYTES)

        # Strip magic and paload id
        payload = payload[len(MAGIC + PROTOCOL_IDENTIFIER_BYTES):]

        ############## Noise init
        protocol = NoiseProtocolFactory().get_noise_protocol(
                "Noise_K_secp256k1_AESGCM_SHA256")
        handshakestate = protocol.create_handshakestate()
        handshakestate.initialize(KHandshakePattern(), False, b'',
                s=self._local_static, rs=self._remote_static)

        logger.debug("Initialized K Protocol for Responder")

        # Decrypt payload.
        message_buffer = bytearray()
        handshakestate.read_message(payload, message_buffer)

        return ethutils.pubkey_to_address(
                self._remote_static), bytes(message_buffer)

