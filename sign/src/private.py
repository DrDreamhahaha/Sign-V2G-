from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def private_key():
    # 生成ECDSA私钥
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    return private_key