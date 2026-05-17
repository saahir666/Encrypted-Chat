import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# In a real app, ensure the salt is the same across client/server if using a password,
# or securely share a 32-byte key directly. For this example, we use a fixed salt.
FIXED_SALT = b'\x00' * 16 

def derive_key(password: str) -> bytes:
    """Derives a secure 32-byte AES key from a password using Scrypt."""
    kdf = Scrypt(
        salt=FIXED_SALT,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    return kdf.derive(password.encode())

def encrypt_message(message: str, key: bytes) -> bytes:
    """
    Encrypts a message using AES-GCM.
    Returns: 12-byte IV + Ciphertext + 16-byte Auth Tag
    """
    aesgcm = AESGCM(key)
    iv = os.urandom(12)  # Safe, unique IV for every message
    ciphertext = aesgcm.encrypt(iv, message.encode(), None)
    return iv + ciphertext  # Prepend IV to the payload

def decrypt_message(payload: bytes, key: bytes) -> str:
    """Decrypts an AES-GCM payload."""
    aesgcm = AESGCM(key)
    iv = payload[:12]
    ciphertext = payload[12:]
    decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
    return decrypted_bytes.decode()