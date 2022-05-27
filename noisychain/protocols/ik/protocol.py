from dissononce.processing.handshakepatterns.interactive.IK import IKHandshakePattern
from noisychain import channels, ethutils
from dissononce.extras.dh.experimental.secp256k1.private import PrivateKey
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from dissononce.extras.dh.dangerous.dh_nogen import NoGenDH
from dissononce.extras.dh.experimental.secp256k1.secp256k1 import SECP256K1DH
from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
from web3 import Web3
import logging
import binascii

from . import PROTOCOL_IDENTIFIER_BYTES
from .. import MAGIC

from ...session import ProtocolSession, ProtocolState

logger = logging.getLogger(__name__)


class IKProtocol:
    NOISE_PROTOCOL_NAME = "Noise_IK_secp256k1_AESGCM_SHA256"
    def __init__(self, session: ProtocolSession, funder):
        self._noise = NoiseProtocolFactory().get_noise_protocol(
                self.NOISE_PROTOCOL_NAME
        )
        self._handshakestate = None
        self._sending_cipherstate = None
        self._receiving_cipherstate = None
        self._session = session
        self._funder = funder
        self._recvch = None

    @property
    def channel(self):
        return self._recvch

    @property
    def session(self):
        return self._session

    def _setup_cipherstates(self):
        assert(self._session.last().their_public)
        self._their_public = self._session.last().their_public
        # Sending
        self._sending_cipher_state = self._noise.create_cipherstate()
        self._sending_cipher_state.initialize_key(
                self._session.last().cipher_sending_key[0])
        self._sending_cipher_state.set_nonce(
                self._session.last().cipher_sending_key[1])

        # Receiving
        self._receiving_cipher_state = self._noise.create_cipherstate()
        self._receiving_cipher_state.initialize_key(
                self._session.last().cipher_receiving_key[0])
        self._receiving_cipher_state.set_nonce(
                self._session.last().cipher_receiving_key[1])

        self._sendch = channels.derive_send_ch(
            self._session.last().my_ch_key,
            self._session.last().their_ch_key,
            self._their_public,
            0
        )
        _, self._recvch = channels.derive_recv_ch(
            self._session.last().my_ch_key,
            self._session.last().their_ch_key,
            self._my_private,
            0
        )

    def setup_initiator(self, my_private: PrivateKey, their_public: PublicKey):
        self._my_private = my_private
        self._their_public = their_public
        self._initiator = True
        self._sendch = ethutils.pubkey_to_address(their_public)
        self._recvch = channels.derive_recv_ch(
            self._my_private, self._their_public, self._my_private, 0
        )

        if len(self._session) == 0:
            self._handshakestate = self._noise.create_handshakestate()
        if len(self._session) == 1:
            self._handshakestate = self._noise.create_handshakestate(
                dh=NoGenDH(self._noise.dh, self._session[0].e))

        if self._handshakestate:
            self._handshakestate.initialize(IKHandshakePattern(), True, b'',
                    s=SECP256K1DH().generate_keypair(my_private), rs=their_public)
            self._sync_handshakestate()
        else:
            self._setup_cipherstates()

    def setup_responder(self, my_private: PrivateKey):
        self._my_private = my_private
        self._their_public = None
        self._initiator = False
        self._sendch = None
        self._recvch = ethutils.pubkey_to_address(
            ethutils.private_to_public(my_private)
        )

        if len(self._session) in (0, 1):
            self._handshakestate = self._noise.create_handshakestate()

        if self._handshakestate:
            self._handshakestate.initialize(IKHandshakePattern(), False, b'',
                    s=SECP256K1DH().generate_keypair(my_private))
            self._sync_handshakestate()
        else:
            self._setup_cipherstates()

    def _sync_handshakestate(self):
        for i in range(0, len(self._session)):
            protocol_state = self._session[i]

            self._their_public = protocol_state.their_public

            if i % 2 != int(self._initiator):
                self._handshakestate.write_message(
                        protocol_state.m, bytearray())
            else:
                self._handshakestate.read_message(
                        protocol_state.m, bytearray())

        protocol_state = self._session.last()
        if len(self._session) == 1 and self._initiator:
            self._sendch = channels.derive_send_ch(
                protocol_state.my_ch_key,
                protocol_state.their_public,
                protocol_state.their_public,
                0
            )
        if len(self._session) == 2 and self._initiator:
            _, self._recvch = channels.derive_recv_ch(
                protocol_state.my_ch_key,
                protocol_state.their_ch_key,
                self._my_private,
                0
            )

    async def send(self, message) -> str | None:
        logger.debug("send()")

        # 1. Generate new channel keys
        my_next_ch_keypair = SECP256K1DH().generate_keypair()

        # 2. Encrypt message
        payload_buffer = bytearray()
        if self._handshakestate:
            new_state = ProtocolState(m=message)
            new_state.their_public = self._their_public
            cipherstates = self._handshakestate.write_message(
                    message, payload_buffer)
            new_state.e = self._handshakestate.e.private
            new_state.h = \
                self._handshakestate.symmetricstate.get_handshake_hash()
            if cipherstates:
                new_state.cipher_sending_key = \
                        cipherstates[0 if self._initiator else 1]._key, 0
                new_state.cipher_receiving_key = \
                        cipherstates[1 if self._initiator else 0]._key, 0
            signing_keypair = self._handshakestate.e
        else:
            new_state = self._session[-1]
            signing_keypair = SECP256K1DH().generate_keypair() 
            payload_buffer = \
                    self._sending_cipher_state.encrypt_with_ad(b"", message)
            new_state.cipher_sending_key = (
                self._sending_cipher_state._key,
                self._sending_cipher_state._nonce )

        # 3. Construct payload for encrypted data and new channel public
        payload_buffer = MAGIC + \
                PROTOCOL_IDENTIFIER_BYTES + \
                my_next_ch_keypair.public.data + \
                payload_buffer

        # 4. Construct transaction to compute its cost
        tx, signed = await ethutils.create_and_sign_transaction(
                key=signing_keypair.private,
                to=self._sendch,
                data=payload_buffer,
                value=0
            )

        estimated_cost = tx['gas'] * tx['gasPrice']
        logger.debug(f"Payload is {len(payload_buffer)} bytes")
        logger.debug(f"Estimated cost is "
                f"{Web3.fromWei(estimated_cost, 'ether')} ether")

        # 5. Fund the account which is sending the transaction
        await self._funder.fund(
                ethutils.pubkey_to_address(signing_keypair.public),
                estimated_cost)

        # 6. Send the transaction from the funded account
        await ethutils.send(signed)

        # 7. Store the state
        if len(self._session):
            their_ch_key = self._session[-1].their_ch_key
        else:
            their_ch_key = self._their_public

        self._sendch = channels.derive_send_ch(
            my_next_ch_keypair.private, their_ch_key, self._their_public, 0
        )
        new_state.my_ch_key = my_next_ch_keypair.private
        new_state.their_ch_key = their_ch_key

        if self._handshakestate:
            self._session.append(new_state)

        logger.info("Sent")
        return binascii.hexlify(signed.hash).decode()

    async def recv(self, transaction):
        logger.debug("recv()")

        # 1. Check and strip identifiers.
        payload = binascii.unhexlify(transaction.input[2:])
        assert payload.startswith(MAGIC + PROTOCOL_IDENTIFIER_BYTES)
        payload = payload[len(MAGIC + PROTOCOL_IDENTIFIER_BYTES):]

        # 2. Parse payload.
        their_ch_key, payload = PublicKey(payload[:33]), payload[33:]

        # 3. Decrypt ciphertext.
        message_buffer = bytearray()
        if self._handshakestate:
            new_state = ProtocolState(m=payload)
            cipherstates = self._handshakestate.read_message(
                    payload, message_buffer)
            new_state.h = \
                self._handshakestate.symmetricstate.get_handshake_hash()
            new_state.their_public = self._handshakestate.rs
            if cipherstates:
                new_state.cipher_sending_key = \
                        cipherstates[0 if self._initiator else 1]._key, 0
                new_state.cipher_receiving_key = \
                        cipherstates[1 if self._initiator else 0]._key, 0
        else:
            new_state = self._session[-1]
            message_buffer = self._receiving_cipher_state.decrypt_with_ad(
                    b"", payload)
            new_state.cipher_receiving_key = (
                self._receiving_cipher_state._key,
                self._receiving_cipher_state._nonce)

        # 4. Store the state
        if len(self._session):
            my_ch_key = self._session[-1].my_ch_key
        else:
            my_ch_key = None

        their_public = self._their_public or new_state.their_public
        _, self._recvch = channels.derive_recv_ch(
            my_ch_key or self._my_private, their_ch_key, their_public, 0
        )

        new_state.my_ch_key = my_ch_key
        new_state.their_ch_key = their_ch_key

        if self._handshakestate:
            self._session.append(new_state)

        return their_public, bytes(message_buffer)
