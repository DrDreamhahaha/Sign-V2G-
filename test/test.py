from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# 生成ECDSA私钥
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

# 用于签名的数据
data = b"DDDDD"

# 计算签名
signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

print(signature)