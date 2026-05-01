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