from dissononce.dh import keypair
from dissononce.extras.dh.experimental.secp256k1.secp256k1 import SECP256K1DH
from dissononce.extras.dh.experimental.secp256k1.keypair import KeyPair
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hmac
import hashlib
import binascii
from web3 import Web3

def derive_channel(a: KeyPair, b: PublicKey, channel_id: int) -> str:
    s = SECP256K1DH().dh(a, b)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        info=b'CH'
    )
    key = hkdf.derive(s)

    return Web3.toChecksumAddress(binascii.hexlify(hmac.new(key,
            channel_id.to_bytes(4, 'big'),
            hashlib.sha256
            ).digest()[12:]).decode())
