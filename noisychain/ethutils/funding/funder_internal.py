from web3 import Web3
import asyncio
import logging
import binascii
from dissononce.extras.dh.experimental.secp256k1.private import PrivateKey
from .funder import Funder
from ... import ethutils

logger = logging.getLogger(__name__)


class InternalFunder:
    def __init__(self, key: PrivateKey):
        self._key = key

    async def fund(self, address: str, value: int) -> bool:
        logger.debug(f"fund_account({address}, {value})")
        balance = await ethutils.get_balance(address)

        if balance < value:
            _, signed = await ethutils.create_and_sign_transaction(
                    self._key, address, value=value)
            await ethutils.send(signed)

            logger.debug("Waiting for Tx Hash: "
                f"0x{binascii.hexlify(signed.hash).decode()}")

            while balance < value:
                await asyncio.sleep(5)
                balance = await ethutils.get_balance(address)

        return True
