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

# 创建移动车辆实例
mv1 = Mv("Vehicle1", "123456789", "ID001", "2024-04-11", "Active")
mv2 = Mv("Vehicle2", "987654321", "ID002", "2024-04-12", "Inactive")

# 创建移动计算设备实例
mc1 = Mc("Device1", "Location1", 10, "Info1", "Active", "Safe")
mc2 = Mc("Device2", "Location2", 20, "Info2", "Inactive", "Unsafe")

# 创建权威机构实例
authority = Authority()

# 生成身份标识码和签名
identity_code_mv1, signature_mv1 = authority.generate_identity_code_and_signature(mv1)
identity_code_mv2, signature_mv2 = authority.generate_identity_code_and_signature(mv2)
identity_code_mc1, signature_mc1 = authority.generate_identity_code_and_signature(mc1)
identity_code_mc2, signature_mc2 = authority.generate_identity_code_and_signature(mc2)

# 创建边缘节点实例
edge_node = EdgeNode()

import ecdsa

# 生成椭圆曲线密钥对
def generate_key_pair():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)  # 生成私钥
    vk = sk.verifying_key  # 生成公钥
    return sk, vk

# 生成密钥对
private_key_mv1, public_key_mv1 = generate_key_pair()
private_key_mv2, public_key_mv2 = generate_key_pair()
private_key_mc1, public_key_mc1 = generate_key_pair()
private_key_mc2, public_key_mc2 = generate_key_pair()

# 将公钥硬编码到代码中
pubkey_mv1 = public_key_mv1.to_string()
pubkey_mv2 = public_key_mv2.to_string()
pubkey_mc1 = public_key_mc1.to_string()
pubkey_mc2 = public_key_mc2.to_string()

# 创建边缘节点实例
edge_node = EdgeNode()

# 设置移动车辆的公钥
edge_node.set_public_key(identity_code_mv1, pubkey_mv1)
edge_node.set_public_key(identity_code_mv2, pubkey_mv2)

# 设置移动计算设备的公钥
edge_node.set_public_key(identity_code_mc1, pubkey_mc1)
edge_node.set_public_key(identity_code_mc2, pubkey_mc2)

# 查询资质信息
qualification_mv1 = edge_node.query_qualification(identity_code_mv1)
qualification_mv2 = edge_node.query_qualification(identity_code_mv2)
qualification_mc1 = edge_node.query_qualification(identity_code_mc1)
qualification_mc2 = edge_node.query_qualification(identity_code_mc2)

# 输出资质信息
print("Qualification of Vehicle 1:", qualification_mv1)
print("Qualification of Vehicle 2:", qualification_mv2)
print("Qualification of Device 1:", qualification_mc1)
print("Qualification of Device 2:", qualification_mc2)

import time

# 生成身份标识码和签名
timestamp_mv1 = int(time.time())  # 生成当前时间戳
identity_code_mv1, signature_mv1 = authority.generate_identity_code_and_signature(mv1)
timestamp_mv2 = int(time.time())  # 生成当前时间戳
identity_code_mv2, signature_mv2 = authority.generate_identity_code_and_signature(mv2)
timestamp_mc1 = int(time.time())  # 生成当前时间戳
identity_code_mc1, signature_mc1 = authority.generate_identity_code_and_signature(mc1)
timestamp_mc2 = int(time.time())  # 生成当前时间戳
identity_code_mc2, signature_mc2 = authority.generate_identity_code_and_signature(mc2)
# 模拟聚合和验证签名
signature_info = [
    (identity_code_mv1, timestamp_mv1, signature_mv1),
    (identity_code_mv2, timestamp_mv2, signature_mv2),
    (identity_code_mc1, timestamp_mc1, signature_mc1),
    (identity_code_mc2, timestamp_mc2, signature_mc2)
]

verification_result = edge_node.aggregate_and_verify_signatures(signature_info)

# 输出验证结果
if not verification_result:
    print("Signature verification successful.")
else:
    print("Signature verification failed.")
