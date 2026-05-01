import hashlib
import ecdsa
import base58


def generate_btc_address():
    
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    private_key_bytes = private_key.to_string()

    
    public_key = private_key.get_verifying_key().to_string()
    public_key = b'\x04' + public_key  # uncompressed

    
    sha256_pk = hashlib.sha256(public_key).digest()

    
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pk)
    hashed_pk = ripemd160.digest()

    
    versioned_pk = b'\x00' + hashed_pk

    
    checksum = hashlib.sha256(hashlib.sha256(versioned_pk).digest()).digest()[:4]

    
    address = base58.b58encode(versioned_pk + checksum)

    return private_key_bytes.hex(), address.decode()


priv, addr = generate_btc_address()
print("Private Key:", priv)
print("Bitcoin Address:", addr)




def private_key_to_wif(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)

    
    extended_key = b'\x80' + private_key_bytes

    
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]

    
    wif = base58.b58encode(extended_key + checksum)

    return wif.decode()




def generate_compressed_address():
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    private_key_bytes = private_key.to_string()

    verifying_key = private_key.get_verifying_key()
    public_key = verifying_key.to_string()

    prefix = b'\x02' if public_key[-1] % 2 == 0 else b'\x03'
    compressed_pk = prefix + public_key[:32]

    sha256_pk = hashlib.sha256(compressed_pk).digest()

    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pk)
    hashed_pk = ripemd160.digest()

    versioned_pk = b'\x00' + hashed_pk

    checksum = hashlib.sha256(hashlib.sha256(versioned_pk).digest()).digest()[:4]

    address = base58.b58encode(versioned_pk + checksum)

    return private_key_bytes.hex(), address.decode()






def sign_message(private_key_hex, message):
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)

    message_hash = hashlib.sha256(message.encode()).digest()
    signature = sk.sign(message_hash)

    return signature.hex()