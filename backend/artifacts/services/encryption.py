
import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_KEY_SIZE = 32       # 256 bits
NONCE_SIZE = 12         # 96 bits


def generate_aes_key():
    """Generate a cryptographically secure 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_file_data(file_data: bytes, key: bytes) -> dict:
    """
    Encrypt file bytes using AES-256-GCM.

    Returns the nonce and ciphertext, both Base64 encoded.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        file_data,
        None
    )

    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def decrypt_file_data(encrypted_data: dict, key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext and authenticate its integrity.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )
