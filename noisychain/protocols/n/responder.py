from dissononce.extras.dh.experimental.secp256k1.keypair import KeyPair
from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
from dissononce.processing.handshakepatterns.oneway.N import NHandshakePattern
import logging
import binascii

from .. import MAGIC
from . import PROTOCOL_IDENTIFIER_BYTES

logger = logging.getLogger(__name__)


class NResponderProtocol:
    def __init__(self,
            local_static: KeyPair):

        self._local_static = local_static
        self._noise = NoiseProtocolFactory().get_noise_protocol(
                "Noise_N_secp256k1_AESGCM_SHA256")

    async def recv(self, transaction):
        logger.debug("recv()")
        payload = binascii.unhexlify(transaction.input[2:])
        assert payload.startswith(MAGIC + PROTOCOL_IDENTIFIER_BYTES)

        # Strip magic and paload id
        payload = payload[len(MAGIC + PROTOCOL_IDENTIFIER_BYTES):]

        ############## Noise init
        handshakestate = self._noise.create_handshakestate()
        handshakestate.initialize(NHandshakePattern(), False, b'',
                s=self._local_static)
        logger.debug("Initialized Noise Protocol for Responder")

        # Decrypt payload.
        message_buffer = bytearray()
        handshakestate.read_message(payload, message_buffer)

        return None, bytes(message_buffer)
