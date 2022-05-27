from noisychain.ethutils.funding.funder import Funder
from noisychain import ethutils
from dissononce.extras.dh.experimental.secp256k1.private import PrivateKey
from dissononce.processing.handshakepatterns.handshakepattern import HandshakePattern
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.extras.dh.experimental.secp256k1.secp256k1 import SECP256K1DH
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.dh.keypair import KeyPair
from typing import Tuple
import binascii
import asyncio
import logging
from web3 import Web3
from . import derive_send_ch as out_channel, derive_payee_channel as in_channel


logger = logging.getLogger(__name__)

class EthereumTransport:
    def __init__(self, magic: bytes, funder: Funder):
        self._magic = magic
        self._funder = funder

    async def send_tx(self, sk: PrivateKey, address: str, data: bytes, value: int = 0):
        full_data = self._magic + data
        tx, signed = await ethutils.create_and_sign_transaction(
                key=sk,
                to=address,
                data=full_data,
                value=value
            )
        estimated_cost = tx['gas'] * tx['gasPrice']
        logger.debug(f"Payload is {len(full_data)} bytes")
        logger.debug(f"Estimated cost is "
                f"{Web3.fromWei(estimated_cost, 'ether')} ether")

        await self._funder.fund(
                ethutils.privkey_to_address(sk),
                estimated_cost + value)
        logger.debug("Funded, sending now")
        await ethutils.send(signed)

    async def recv_tx(self, address: str):
        transactions = await ethutils.get_transactions(to_addresses=[address])
        logger.debug(f"Found {len(transactions)} transactions, using last one.")
        tx = transactions[-1]

        # Check and strip identifiers.
        data = binascii.unhexlify(tx.input[2:])
        assert data.startswith(self._magic)
        data = data[len(self._magic):]

        return ethutils.ecrecover(tx), data

class ChannelState:
    def __init__(self, transport: EthereumTransport, handshakestate: HandshakeState):
        self._transport = transport
        self._cstates : Tuple[CipherState, CipherState] | None = None
        self._hstate = handshakestate;
        self._dh = SECP256K1DH()

    @property
    def chin(self) -> PrivateKey:
        return self._chin
    
    @property
    def chout(self) -> str:
        return self._chout

    def initialize(self,
            initiator: bool,
            pattern : HandshakePattern,
            s: KeyPair, rs: PublicKey):
        self._hstate.initialize(pattern, initiator, b"", s=s, rs=rs)


        self._m = s.private
        self._c = self._m
        self._rm = rs
        self._rc = self._rm

        self._chout: str = out_channel(self._c, self._rc, self._rm, 0)
        self._chin: PrivateKey = in_channel(self._c, self._rc, self._m, 0)

        # logger.debug("Determining out channel nonce")
        # test_chout: str = out_channel(self._c.private, self._rc, rs, 0)
        # chout_nonce = len(asyncio.run(
        #         ethutils.get_transactions(to_addresses=[test_chout])))

        # logger.debug(f"chout_nonce = {chout_nonce}")
        # logger.debug("Determining in channel nonce")
        # test_chin: PrivateKey = in_channel(self._c.private, self._rc,
        #         s.private, 0)
        # chin_nonce = len(asyncio.run(ethutils.get_transactions(
        #     to_addresses=[ethutils.privkey_to_address(test_chin)]
        #     )))
        # logger.debug(f"chin_nonce = {chin_nonce}")

    def send_message(self, m: bytes, value: int = 0):
        if self._cstates is None:
            message_buffer = bytearray()
            self._cstates = self._hstate.write_message(m , message_buffer)
            signing_keypair = self._hstate.e
            message_buffer = message_buffer[self._dh.pubkeylen:]
            # message_buffer = signing_keypair.public.data + message_buffer
        elif self._hstate._initiator:
            message_buffer = self._cstates[0].encrypt_with_ad(b"", m)
            signing_keypair = self._dh.generate_keypair()
        else:
            message_buffer = self._cstates[1].encrypt_with_ad(b"", m)
            signing_keypair = self._dh.generate_keypair()

        c = self._dh.generate_keypair()
        self._c = c.private
        data = c.public.data + message_buffer

        asyncio.run(self._transport.send_tx(
                signing_keypair.private,
                self._chout,
                data,
                value
                ))

        self._chout = out_channel(self._c, self._rc, self._rm, 0)
 
    def receive_message(self) -> Tuple[bytes, PrivateKey]:
        # TODO: Append to message before decryption during HS state.
        pk, data = asyncio.run(
            self._transport.recv_tx(ethutils.privkey_to_address(self._chin))
        )

        self._rc, payload = PublicKey(data[:33]), data[33:]

        if self._cstates is None:
            message_buffer = bytearray()
            self._cstates = self._hstate.read_message(pk.data + payload, message_buffer)
        elif self._hstate._initiator:
            message_buffer = self._cstates[1].decrypt_with_ad(b"", payload)
        else:
            message_buffer = self._cstates[0].decrypt_with_ad(b"", payload)

        prev_chin = self._chin
        self._chin = in_channel(self._c, self._rc, self._m, 0)

        return message_buffer, prev_chin
