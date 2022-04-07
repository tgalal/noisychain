from dissononce.extras.dh.experimental.secp256k1.keypair import KeyPair
from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
from dissononce.processing.handshakepatterns.oneway.N import NHandshakePattern
import logging

from .. import MAGIC
from . import PROTOCOL_ID

logger = logging.getLogger(__name__)


class NResponderProtocol:
    def __init__(self,
            local_static: KeyPair):

        self._local_static = local_static
        self._noise = NoiseProtocolFactory().get_noise_protocol(
                "Noise_N_secp256k1_AESGCM_SHA256")

    async def recv(self, payload: bytes):
        logger.debug("recv()")
        assert payload.startswith(MAGIC)
        assert payload[len(MAGIC)] == PROTOCOL_ID

        # Strip magic and paload id
        payload = payload[len(MAGIC) + 1:]

        ############## Noise init
        handshakestate = self._noise.create_handshakestate()
        handshakestate.initialize(NHandshakePattern(), False, b'',
                s=self._local_static)
        logger.debug("Initialized Noise Protocol for Responder")

        # Decrypt payload.
        message_buffer = bytearray()
        handshakestate.read_message(payload, message_buffer)

        return bytes(message_buffer)
