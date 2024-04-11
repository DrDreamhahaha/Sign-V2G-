from suclass import Mv
from suclass import Mc
from suclass import Authority
from suclass import EdgeNode

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