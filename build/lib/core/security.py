import hashlib
import secrets
import math
import string

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a key from a password and salt using PBKDF2-HMAC-SHA256.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha256', password, salt, 100000)

def calculate_entropy(secret: str) -> float:
    """
    Calculate the Shannon entropy of a string.
    """
    if not secret:
        return 0.0
    
    # Determine pool size based on character sets used
    pool_size = 0
    if any(c.islower() for c in secret): pool_size += 26
    if any(c.isupper() for c in secret): pool_size += 26
    if any(c.isdigit() for c in secret): pool_size += 10
    if any(c in string.punctuation for c in secret): pool_size += 32 # approx
    
    if pool_size == 0:
        pool_size = 256 # Fallback for binary or unknown
        
    # Simple bit strength estimation: L * log2(N)
    # This is "password strength" entropy, not pure Shannon entropy of the string content distribution
    # But usually what's meant by "entropy" in password checkers.
    # Let's provide both or just the strength one.
    # The prompt asks for "entropy estimates".
    
    # Strength entropy
    strength_entropy = len(secret) * math.log2(pool_size) if pool_size > 0 else 0
    
    return strength_entropy

def generate_salt(length: int = 16) -> bytes:
    return secrets.token_bytes(length)

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    Simple XOR obfuscation for demo purposes.
    Repeats key if data is longer.
    """
    return bytes(a ^ b for a, b in zip(data, (key * (len(data) // len(key) + 1))[:len(data)]))
