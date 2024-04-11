import time
import memory_profiler
from ecdsa import SigningKey, SECP256k1

def schnorr_signature_efficiency():
    # 创建一个Schnorr签名密钥
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()

    # 准备要签名的消息
    message = b"Hello, world!"

    # 进行签名
    signature = private_key.sign(message)




    # 打印结果
    print(f"Schnorr签名算法测试结果:{signature}")

if __name__ == "__main__":
    schnorr_signature_efficiency()