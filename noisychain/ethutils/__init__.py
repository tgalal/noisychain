from dissononce.extras.dh.experimental.secp256k1.public \
        import PublicKey
from dissononce.extras.dh.experimental.secp256k1.private \
        import PrivateKey
from dissononce.extras.dh.experimental.secp256k1.secp256k1 \
        import SECP256K1DH
import logging
import binascii
import hashlib
import ecdsa
from typing import Tuple
from web3 import Web3
from web3.eth import AsyncEth
from eth_account._utils.signing import to_standard_v, extract_chain_id
from eth_account._utils.legacy_transactions import ALLOWED_TRANSACTION_KEYS, serializable_unsigned_transaction_from_dict
import asyncio
import json

logger = logging.getLogger(__name__)

w3 = Web3(Web3.HTTPProvider('http://192.168.178.11:7545'))
# w3 = Web3(Web3.AsyncHTTPProvider("http://192.168.178.11:7545"), modules={'eth':
#     (AsyncEth,)}, middlewares=[])

async def get_balance(address: str) -> int:
    result = w3.eth.get_balance(address)
    return result

async def address_to_public(address: str) -> PublicKey | None:
    logger.debug(f"address_to_public({address})")
    blocks = w3.eth.get_block_number()
    for i in range(blocks, 0, -1):
        block = w3.eth.get_block(i)
        for txhash in block["transactions"]:
            t = w3.eth.get_transaction(txhash)
            if t["from"] == address:
                logger.debug("Located relevant tx:"
                        f"{binascii.hexlify(t.hash).decode()}")
                s = w3.eth.account._keys.Signature(
                        vrs=(to_standard_v(
                                extract_chain_id(t.v)[1]),
                    w3.toInt(t.r), w3.toInt(t.s)))

                tt = { k:t[k] for k in ALLOWED_TRANSACTION_KEYS - {'chainId', 'data'}}
                tt['data']=t.input
                tt['chainId']=extract_chain_id(t.v)[0]
                ut=serializable_unsigned_transaction_from_dict(tt)

                pubkey = s.recover_public_key_from_msg_hash(ut.hash())
                result = PublicKey(pubkey.to_compressed_bytes())

                assert pubkey_to_address(result) == address
                return result

def private_to_public(privatekey: PrivateKey) -> PublicKey:
    return SECP256K1DH().generate_keypair(privatekey).public

def decompress_publickey(publickey: PublicKey) -> Tuple[int, int]:
    ecdh = ecdsa.ECDH(curve=ecdsa.SECP256k1)
    ecdh.load_received_public_key_bytes(publickey.data)

    x = ecdh.public_key.pubkey.point.x()
    y = ecdh.public_key.pubkey.point.y()
    return (x, y)

def pubkey_to_address(publickey: PublicKey) -> str:
    x, y = decompress_publickey(publickey)
    hashed = Web3.keccak(x.to_bytes(32, 'big') + y.to_bytes(32, 'big'))
    return Web3.toChecksumAddress(binascii.hexlify(hashed[12:]).decode())

async def send(tx):
    w3.eth.send_raw_transaction(tx.rawTransaction)

async def create_and_sign_transaction(
        key: PrivateKey,
        to: str,
        data: bytes = b'',
        value: int=0):
    logger.debug(
        f"send_transaction(key=[..], to={to}, data=[..], value={value})")

    sender_address = pubkey_to_address(
        private_to_public(key)
    )
    tx = create_transaction(
            to, data, value,
            chain_id=1337,
            nonce=w3.eth.get_transaction_count(sender_address)
        )

    gas_estimate = w3.eth.estimate_gas(tx)
    tx['gas'] = gas_estimate

    # print(json.dumps(tx, indent=2))

    signed = w3.eth.account.sign_transaction(tx, key.data)
    # w3.eth.send_raw_transaction(signed.rawTransaction)
    # return binascii.hexlify(signed.hash)
    return tx, signed

def create_transaction(
        to: str,
        data: bytes,
        value: int,
        chain_id: int,
        nonce: int = 0) -> dict :
    return {
        'to': to,
        'value': value,
        'data': binascii.hexlify(data).decode(),
        'gasPrice': w3.eth.gasPrice,
        # 'maxFeePerGas': 2000000000,
        # 'maxPriorityFeePerGas': 1000000000,
        # 'type': '0x2',  # the type is optional and, if omitted, will be
        # interpreted based on the provided transaction parameters
        'nonce': nonce,
        'chainId': chain_id
        }
