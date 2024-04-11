import hashlib
import private
import ecdsa
from datetime import datetime

class Mv:
    def __init__(self, name, tel, idenv, rtime, statusv):
        self.name = name
        self.tel = tel
        self.idenv = idenv
        self.rtime = rtime
        self.statusv = statusv

    def send_basic_info_and_request(self, authority):
        # Send basic information and qualification request to authority
        return authority.receive_basic_info_and_request(self)

    def get_basic_info(self):
        return (self.name, self.tel, self.idenv, self.rtime, self.statusv)

class Mc:
    def __init__(self, idenc, l, nump, info, statusc, infosafe):
        self.idenc = idenc
        self.l = l
        self.nump = nump
        self.info = info
        self.statusc = statusc
        self.infosafe = infosafe

    def send_basic_info_and_request(self, authority):
        # Send basic information and qualification request to authority
        return authority.receive_basic_info_and_request(self)

    def get_basic_info(self):
        return (self.idenc, self.l, self.nump, self.info, self.statusc, self.infosafe)

class Authority:
    def __init__(self):
        self.pubkey = 1234567890  # Example public key, replace with actual pubkey

    def receive_basic_info_and_request(self, entity):
        # Extract data from entity's basic information
        data = entity.get_basic_info()

        # Store data on blockchain and generate identity code and signature
        identity_code = hashlib.sha256(entity.idenv.encode()).hexdigest()  # Calculate identity code
        schnorr_signature = self.calculate_schnorr_signature(data)  # Calculate Schnorr signature

        # Return identity code and signature
        return identity_code, schnorr_signature

    def calculate_schnorr_signature(self, data):
        private_key_obj = private.private_key()  # Get private key object
        rand_num = private_key_obj.private_numbers().private_value  # Get random number
        temp_param = pow(2, rand_num, self.pubkey)  # Generate temporary parameter
        hash_value = hashlib.sha256(str(data).encode()).hexdigest()  # Calculate hash value
        schnorr_signature = temp_param - self.pubkey * int(hash_value, 16)  # Calculate Schnorr signature
        return schnorr_signature

class EdgeNode:
    def __init__(self):
        self.public_key = None

    def set_public_key(self, public_key):
        self.public_key = public_key

    def aggregate_and_verify_signatures(self, signatures):
        if not self.public_key:
            raise ValueError("Public key is not set")

        aggregated_signature = sum(signatures, ecdsa.Signature(None, None))

        # Verify the aggregated signature using the public key
        if aggregated_signature.verify(b"message", self.public_key):
            return True
        else:
            return False

# Example usage:
# 1. Send basic information and request from electric vehicle to authority
mv = Mv("John Doe", "123456789", "ABC123", "2024-04-11", "Active")
authority = Authority()
identity_code, schnorr_signature = mv.send_basic_info_and_request(authority)
print("Identity Code:", identity_code)
print("Schnorr Signature:", schnorr_signature)

# 2. Send basic information and request from charging station to authority
mc = Mc("Station123", "Location123", 5, "Info123", "Active", "Safe")
identity_code, schnorr_signature = mc.send_basic_info_and_request(authority)
print("Identity Code:", identity_code)
print("Schnorr Signature:", schnorr_signature)