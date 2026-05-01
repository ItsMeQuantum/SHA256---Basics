import hashlib

def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

message = "Hello Bitcoin"
hashed = sha256_hash(message)

print("Original:", message)
print("SHA-256 Hash:", hashed)