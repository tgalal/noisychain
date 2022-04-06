from .funder import Funder
from web3 import Web3
import asyncio
import logging
from ... import ethutils

logger = logging.getLogger(__name__)


class ExternalFunder:
    async def fund(self, address: str, value: int) -> bool:
        logger.debug(f"fund_account({address}, {value})")
        balance = await ethutils.get_balance(address)

        if balance < value:
            logger.info(
                "Waiting for {address} to have {value} ETH, current balance is "
                "{balance} ETH"
                .format(address=address,
                    value=Web3.fromWei(value, "ether"),
                    balance=Web3.fromWei(balance, "ether"))
            )
            while balance < value:
                await asyncio.sleep(5)
                balance = await ethutils.get_balance(address)

        return True
