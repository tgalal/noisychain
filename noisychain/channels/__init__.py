from ecdsa.ecdsa import Private_key
from noisychain import ethutils
from dissononce.dh import keypair
from dissononce.extras.dh.experimental.secp256k1.secp256k1 import SECP256K1DH
from dissononce.extras.dh.experimental.secp256k1.keypair import KeyPair
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from dissononce.extras.dh.experimental.secp256k1.private import PrivateKey
from dissononce.dh.keypair import KeyPair
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hmac
import hashlib
import binascii
import ecdsa
from ecdsa import ellipticcurve
from web3 import Web3
from typing import Tuple

def derive_payable_channel(a: PrivateKey, b: PublicKey, context_key: PublicKey,
        channel_id: int) -> str:
    a_keypair = SECP256K1DH().generate_keypair(a)
    s = SECP256K1DH().dh(a_keypair, b)
    chaincode = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        info=b'NZYCHAIN'
    ).derive(s)

    I = hmac.new(chaincode,
            context_key.data + channel_id.to_bytes(4, "big"),
            hashlib.sha256).digest()
    context_point = ellipticcurve.Point.from_bytes(
            ecdsa.SECP256k1.curve, context_key.data)
    generated_point = ecdsa.SECP256k1.generator * int.from_bytes(I, "big")
    sum_points = (context_point + generated_point).to_bytes(
            encoding="compressed")
    return ethutils.pubkey_to_address(PublicKey(sum_points))

def derive_payee_channel(a: PrivateKey, b: PublicKey, context_key: PrivateKey,
        channel_id: int) -> PrivateKey:
    a_keypair = SECP256K1DH().generate_keypair(a)
    s = SECP256K1DH().dh(a_keypair, b)
    chaincode = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        info=b'NZYCHAIN'
    ).derive(s)
    context_public : PublicKey = \
            SECP256K1DH().generate_keypair(context_key).public
    I = hmac.new(
        chaincode,
        context_public.data + channel_id.to_bytes(4, "big"),
        hashlib.sha256
    ).digest()

    sum = (int.from_bytes(I, "big") + \
            int.from_bytes(context_key.data, "big")) % ecdsa.SECP256k1.order

    return PrivateKey(sum.to_bytes(32, "big"))


derive_send_ch = derive_payable_channel
def derive_recv_ch(a: PrivateKey, b: PublicKey, context_key: PrivateKey,
        nonce: int) -> Tuple[PrivateKey, str]:
    private_key = derive_payee_channel(a, b, context_key, nonce)
    return (private_key, ethutils.privkey_to_address(private_key))

def xxderive_payable_channel(
        a: PrivateKey, b: PublicKey,
        context_key: PrivateKey | PublicKey,
        channel_id: int):
    a_keypair = SECP256K1DH().generate_keypair(a)
    s = SECP256K1DH().dh(a_keypair, b)
    chaincode = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        info=b'NZYCHAIN'
    ).derive(s)

    if type(context_key) is PublicKey:
        I = hmac.new(chaincode,
                context_key.data + channel_id.to_bytes(4, "big"),
                hashlib.sha256).digest()
        context_point = ellipticcurve.Point.from_bytes(
                ecdsa.SECP256k1.curve, context_key.data)
        generated_point = ellipticcurve.Point.from_bytes(
                ecdsa.SECP256k1.curve, I
        )
        sum_points = (context_point + generated_point).to_bytes(
                encoding="compressed")
        # return Web3.toChecksumAddress(
        #     binascii.hexlify(sum_points).decode()
        # )
        return PublicKey(sum_points)
    else:
        context_public : PublicKey = \
                SECP256K1DH().generate_keypair(context_key).public
        I = hmac.new(
            chaincode,
            context_public.data + channel_id.to_bytes(4, "big"),
            hashlib.sha256
        ).digest()

        sum = (int.from_bytes(I, "big") + \
                int.from_bytes(context_key.data, "big")) % ecdsa.SECP256k1.order

        return PrivateKey(sum.to_bytes(32, "big"))
 
def derive_channel(a: KeyPair | PrivateKey,
        b: PublicKey, channel_id: int) -> str:
    if type(a) is PrivateKey:
        a = SECP256K1DH().generate_keypair(a)
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
