import hashlib
import secrets
import math
import hmac
from typing import Tuple

def derive_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Derives a cryptographic key from a password using PBKDF2.
    
    Args:
        password: The user's password.
        salt: Optional salt. If not provided, a new random salt is generated.
        
    Returns:
        A tuple containing (derived_key, salt).
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    
    # Using 100,000 iterations of SHA-256
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return key, salt

def _generate_keystream(key: bytes, length: int) -> bytes:
    """
    Generates a pseudo-random keystream based on the key for XOR encryption.
    This is a DEMO implementation and is not cryptographically secure for high-value data.
    It uses repeated hashing to generate the stream.
    """
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        # Create a unique input for each block based on key and counter
        counter_bytes = counter.to_bytes(8, 'big')
        block_hash = hashlib.sha256(key + counter_bytes).digest()
        keystream.extend(block_hash)
        counter += 1
    return bytes(keystream[:length])

def encrypt_data(data: str, key: bytes) -> bytes:
    """
    Encrypts string data using a demo XOR stream cipher.
    """
    data_bytes = data.encode('utf-8')
    keystream = _generate_keystream(key, len(data_bytes))
    
    encrypted = bytearray(b ^ k for b, k in zip(data_bytes, keystream))
    return bytes(encrypted)

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """
    Decrypts data using the demo XOR stream cipher.
    """
    keystream = _generate_keystream(key, len(encrypted_data))
    
    decrypted_bytes = bytearray(b ^ k for b, k in zip(encrypted_data, keystream))
    return decrypted_bytes.decode('utf-8')

def calculate_entropy(secret: str) -> float:
    """
    Calculates the Shannon entropy of a string.
    """
    if not secret:
        return 0.0
    
    prob = [float(secret.count(c)) / len(secret) for c in dict.fromkeys(list(secret))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def estimate_strength(secret: str) -> str:
    """
    Returns a human-readable strength estimate based on length and character set.
    """
    length = len(secret)
    has_lower = any(c.islower() for c in secret)
    has_upper = any(c.isupper() for c in secret)
    has_digit = any(c.isdigit() for c in secret)
    has_special = any(not c.isalnum() for c in secret)
    
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if has_lower: score += 1
    if has_upper: score += 1
    if has_digit: score += 1
    if has_special: score += 1
    
    if score < 3: return "Weak"
    if score < 5: return "Moderate"
    return "Strong"
