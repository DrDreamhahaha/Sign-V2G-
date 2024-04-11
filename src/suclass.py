import hashlib
import private
from hashlib import sha256
import ecdsa

class Mv:
    def __init__(self, name, tel, idenv, rtime, statusv):
        self.name = name
        self.tel = tel
        self.idenv = idenv
        self.rtime = rtime
        self.statusv = statusv

    def calculate_schnorr_signature(self, pubkey):
        private_key_obj = private.private_key()  # 获取私钥对象
        rand_num = private_key_obj.private_numbers().private_value  # 获取私钥对象中的随机数
        temp_param = pow(2, rand_num, pubkey)  # 使用随机数生成临时参数
        hash_value = hashlib.sha256((self.idenv + str(temp_param)).encode()).hexdigest()  # 计算哈希值
        schnorr_signature = temp_param - pubkey * int(hash_value, 16)  # 计算Schnorr环签名
        return schnorr_signature
class Mc:
    def __init__(self, idenv, l, nump, info, statusc, infosafe):
        self.idenv = idenv
        self.l = l
        self.nump = nump
        self.info = info
        self.statusc = statusc
        self.infosafe = infosafe

    def calculate_schnorr_signature(self, pubkey):
        private_key_obj = private.private_key()  # 获取私钥对象
        rand_num = private_key_obj.private_numbers().private_value  # 获取私钥对象中的随机数
        temp_param = pow(2, rand_num, pubkey)  # 使用随机数生成临时参数
        hash_value = hashlib.sha256((self.idenv + str(temp_param)).encode()).hexdigest()  # 计算哈希值
        schnorr_signature = temp_param - pubkey * int(hash_value, 16)  # 计算Schnorr环签名
        return schnorr_signature
class Authority:
    def __init__(self):
        self.pubkey = 1234567890  # 假设权威机构的公钥是一个固定值，实际应用中应该是真正的公钥

    def generate_identity_code_and_signature(self, entity):
        identity_code = hashlib.sha256(entity.idenv.encode()).hexdigest()  # 计算哈希值作为身份标识码
        schnorr_signature = entity.calculate_schnorr_signature(self.pubkey)  # 计算Schnorr环签名
        return identity_code, schnorr_signature

class EdgeNode:
    def __init__(self):
        self.public_keys = {}  # 存储参与签名的实体的公钥

    def set_public_key(self, entity_id, public_key):
        """
        设置实体的公钥
        :param entity_id: 实体的身份标识码
        :param public_key: 实体的公钥
        """
        self.public_keys[entity_id] = public_key

    def aggregate_and_verify_signatures(self, signature_info):
        """
        聚合和验证签名
        :param signature_info: 签名信息列表，包括实体的身份标识码、时间戳和Schnorr环签名
        :return: 是否验证成功
        """
        aggregate_signature = 0
        aggregate_public_key = b""
        aggregate_timestamp = None

        # 遍历签名信息列表，进行聚合
        for entity_id, timestamp, signature in signature_info:
            if entity_id not in self.public_keys:
                print(f"Public key not found for entity {entity_id}")
                return False

            # 聚合公钥
            aggregate_public_key += self.public_keys[entity_id]

            # 聚合签名
            aggregate_signature += signature

            # 记录时间戳
            if aggregate_timestamp is None or timestamp > aggregate_timestamp:
                aggregate_timestamp = timestamp

        # 将整数转换为字节串，使用补码表示法处理负数
        def to_bytes(n):
            if n == 0:
                return b'\x00'
            elif n > 0:
                return n.to_bytes((n.bit_length() + 7) // 8, byteorder='big', signed=False)
            else:
                # 处理负数
                neg_n = abs(n)
                byte_length = (neg_n.bit_length() + 7) // 8 + 1  # 增加一个字节来存储符号位
                # 将负数转换为补码
                neg_n_bytes = neg_n.to_bytes(byte_length, byteorder='big', signed=True)
                # 反转所有位
                complement_bytes = bytes([255 - b for b in neg_n_bytes])
                # 添加1
                complement_bytes = bytearray(complement_bytes)
                for i in range(len(complement_bytes) - 1, -1, -1):
                    if complement_bytes[i] == 255:
                        complement_bytes[i] = 0
                    else:
                        complement_bytes[i] += 1
                        break
                return bytes(complement_bytes)

        aggregate_hash = hashlib.sha256(
            to_bytes(aggregate_signature) +
            aggregate_public_key +
            str(aggregate_timestamp).encode()
        ).digest()

    def query_qualification(self, entity_id):
        """
        查询资质信息
        :param entity_id: 实体的身份标识码
        :return: 资质信息
        """
        # 在区块链上查询实体的资质信息并返回
        # 这里简化为直接返回实体的身份标识码
        return entity_id
