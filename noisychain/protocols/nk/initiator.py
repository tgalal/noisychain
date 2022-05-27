import binascii
from dissononce.extras.dh.experimental.secp256k1.private import PrivateKey
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from dissononce.extras.dh.experimental.secp256k1.keypair import KeyPair
from dissononce.extras.dh.experimental.secp256k1.secp256k1 import SECP256K1DH
from dissononce.processing.handshakepatterns.interactive.NK import \
        NKHandshakePattern
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.cipher.aesgcm import AESGCMCipher
from dissononce.hash.sha256 import SHA256Hash
from dissononce.extras.dh.dangerous.dh_nogen import NoGenDH

from web3 import Web3
import logging
import base64
import json
import hashlib
import os

from ... import ethutils
from ...ethutils.funding import InternalFunder
from . import PROTOCOL_IDENTIFIER_BYTES
from .. import MAGIC
from ... import channels
from ...state.state import ConversationState, ProtocolState

logger = logging.getLogger(__name__)

class NKInitiatorProtocol:
    def __init__(self,
            local_static: KeyPair,
            remote_static: PublicKey,
            message: bytes = None
        ):
        self._local_static = local_static
        self._remote_static = remote_static
        self._message = message

        ############## Noise init
        self._symmetricstate = SymmetricState(
                CipherState(AESGCMCipher()), SHA256Hash())
    
    @property
    def channel(self):
        return self._channel

    @property
    def state(self):
        return self._state

    def setup(self, state: ConversationState | None):
        if state and len(state.protocol_states):
            self._handshakestate = HandshakeState(
                    self._symmetricstate, NoGenDH(SECP256K1DH(),
                        PrivateKey(state.protocol_states[0].e)))
            self._state = state
        else:
            self._handshakestate = HandshakeState(
                    self._symmetricstate, SECP256K1DH())
            self._channel = ethutils.pubkey_to_address(
                    self._remote_static)
            self._state = ConversationState(
                    protocol_name="Noise_NK_secp256k1_AESGCM_SHA256")

        self._handshakestate.initialize(NKHandshakePattern(), True, b'',
                rs=self._remote_static)

        for i in range(0, len(self._state.protocol_states)):
            protocol_state = self._state.protocol_states[i]
            # self._channel = protocol_state.recv_ch
            if protocol_state.my_ch_key:
                my_ch_keypair = SECP256K1DH().generate_keypair(
                        PrivateKey(protocol_state.my_ch_key))
            else:
                my_ch_keypair = self._local_static
            self._channel = channels.derive_channel(
                my_ch_keypair,
                PublicKey(protocol_state.their_ch_key),
                0
            )
            if i % 2 == 0:
                self._handshakestate.write_message(
                        protocol_state.m, bytearray())
            else:
                self._handshakestate.read_message(
                        protocol_state.m, bytearray())

    async def send(self) -> str | None:
        logger.debug("send()")
        assert len(self._state.protocol_states) != 1,\
            "Protocol is in receiving state"

        payload_buffer = bytearray()
        self._handshakestate.write_message(self._message, payload_buffer)
        next_channel_keypair = SECP256K1DH().generate_keypair()

        payload_buffer = MAGIC + \
                PROTOCOL_IDENTIFIER_BYTES + \
                next_channel_keypair.public.data + \
                payload_buffer

        local_ephemeral = self._handshakestate.e
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

        await InternalFunder(self._local_static.private).fund(
                local_ephemeral_address, estimated_cost)
        await ethutils.send(signed)

        # channel = channels.derive_channel(next_channel_keypair,
        #         self._remote_static, 0)

        self._state.protocol_states.append(
            ProtocolState(
                e=self._handshakestate.e.private.data,
                my_ch_key=next_channel_keypair.private.data,
                their_ch_key=self._remote_static.data,
                # recv_ch=channel,
                m=self._message,
                h=self._handshakestate.symmetricstate.get_handshake_hash()
            )
        )
        logger.info("Sent")
        return binascii.hexlify(signed.hash).decode()

    async def recv(self, transaction):
        logger.debug("recv()")
        # assert len(self._state.protocol_states) == 0, "Protocol is in sending state"
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
                my_ch_key=self._state.last().my_ch_key,
                their_ch_key=their_ch_key,
                m=payload,
                h=self._handshakestate.symmetricstate.get_handshake_hash()
            )
        )

        return None, bytes(message_buffer)
