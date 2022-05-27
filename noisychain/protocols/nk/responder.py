from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from dissononce.extras.dh.experimental.secp256k1.keypair import KeyPair
from dissononce.extras.dh.experimental.secp256k1.secp256k1 import SECP256K1DH
from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
from dissononce.processing.handshakepatterns.oneway.N import NHandshakePattern
from dissononce.extras.dh.experimental.secp256k1.private import PrivateKey
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.cipher.aesgcm import AESGCMCipher
from dissononce.hash.sha256 import SHA256Hash
from dissononce.extras.dh.dangerous.dh_nogen import NoGenDH
from dissononce.processing.handshakepatterns.interactive.NK import \
        NKHandshakePattern
import logging
import binascii
from web3 import Web3
from ... import channels

from ... import ethutils
from ...ethutils.funding import InternalFunder
from .. import MAGIC
from . import PROTOCOL_IDENTIFIER_BYTES
from ...state.state import ConversationState, ProtocolState

logger = logging.getLogger(__name__)

class NKResponderProtocol:
    def __init__(self, local_static: KeyPair):
        self._local_static = local_static
        self._symmetricstate = SymmetricState(
                CipherState(AESGCMCipher()), SHA256Hash())

    @property
    def channel(self):
        return self._recv_ch

    @property
    def state(self):
        return self._state

    def setup(self, state: ConversationState | None):
        if state and len(state.protocol_states):
            dh = SECP256K1DH()
            if len(state.protocol_states) > 1:
                dh = NoGenDH(dh, PrivateKey(state.protocol_states[1].e))
            self._handshakestate = HandshakeState(self._symmetricstate, dh)
            self._state = state
        else:
            self._handshakestate = HandshakeState(
                    self._symmetricstate, SECP256K1DH())
            self._recv_ch = ethutils.pubkey_to_address(
                    self._local_static.public)
            self._state = ConversationState(
                    protocol_name="Noise_NK_secp256k1_AESGCM_SHA256")
            self._send_channel_key = None

        self._handshakestate.initialize(NKHandshakePattern(), False, b'',
                s=self._local_static)

        for i in range(0, len(self._state.protocol_states)):
            protocol_state = self._state.protocol_states[i]
            # self._recv_ch = protocol_state.recv_ch
            if protocol_state.my_ch_key:
                my_ch_keypair = SECP256K1DH().generate_keypair(
                        PrivateKey(protocol_state.my_ch_key))
            else:
                my_ch_keypair = self._local_static
            self._recv_ch = channels.derive_channel(
                my_ch_keypair,
                PublicKey(protocol_state.their_ch_key),
                0
            )
            if i % 2 == 0:
                self._handshakestate.read_message(
                        protocol_state.m, bytearray())
            else:
                self._handshakestate.write_message(
                        protocol_state.m, bytearray())

    async def send(self, message):
        logger.debug("send()")
        assert len(self._state.protocol_states) == 1,\
            "Protocol is in receiving state"
        payload_buffer = bytearray()
        self._handshakestate.write_message(message, payload_buffer)
        next_channel_keypair = SECP256K1DH().generate_keypair()

        payload_buffer = MAGIC + \
                PROTOCOL_IDENTIFIER_BYTES + \
                next_channel_keypair.public.data + \
                payload_buffer

        local_ephemeral = self._handshakestate.e
        local_ephemeral_address = ethutils.pubkey_to_address(
               local_ephemeral.public)

        if(self._state.last().my_ch_key):
            my_ch_keypair = SECP256K1DH().generate_keypair(
                    self._state.last().my_ch_key)
        else:
            my_ch_keypair = self._local_static

        send_ch = channels.derive_channel(my_ch_keypair,
            PublicKey(self._state.last().their_ch_key), 0
        )
        tx, signed = await ethutils.create_and_sign_transaction(
                key=local_ephemeral.private,
                # this was created from the last received message
                to=send_ch,
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

        # channel = channels.derive_channel(next_channel_keypair,
        #         self._remote_static, 0)

        self._state.protocol_states.append(
            ProtocolState(
                e=self._handshakestate.e.private.data,
                my_ch_key=next_channel_keypair.private.data,
                their_ch_key=self._state.last().their_ch_key,
                # send_ch=next_channel_keypair.private.data,
                # recv_ch=channel,
                m=message,
                h=self._handshakestate.symmetricstate.get_handshake_hash()
            )
        )
        logger.info("Sent")
        return binascii.hexlify(signed.hash).decode()

    async def recv(self, transaction):
        logger.debug("recv()")
        assert len(self._state.protocol_states) == 0, "Protocol is in sending state"
        payload = binascii.unhexlify(transaction.input[2:])
        assert payload.startswith(MAGIC + PROTOCOL_IDENTIFIER_BYTES)

        # Strip magic, protocol id and next channel public
        payload = payload[len(MAGIC + PROTOCOL_IDENTIFIER_BYTES):]
        their_ch_key, payload = payload[:33], payload[33:]

        # Decrypt payload.
        message_buffer = bytearray()
        self._handshakestate.read_message(payload, message_buffer)

        # send_channel_key = self._send_channel_key or self._local_static
        # next_send_channel = channels.derive_channel(send_channel_key,
        #         PublicKey(next_channel_remote_public), 0)

        self._state.protocol_states.append(
            ProtocolState(
                # send_ch=next_send_channel,
                my_ch_key=self._send_channel_key or None,
                their_ch_key=their_ch_key,
                m=payload,
                h=self._handshakestate.symmetricstate.get_handshake_hash()
            )
        )

        return None, bytes(message_buffer)
