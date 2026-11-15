
import os
import base64

from communication.crypto import (
    generate_aes_key,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    NONCE_BYTES,
    AES_KEY_BYTES,
)


def encrypt_file_data(file_data: bytes, key: bytes) -> dict:
    """Encrypt file bytes using shared AES-256-GCM implementation."""

    if len(key) != AES_KEY_BYTES:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = os.urandom(NONCE_BYTES)
    ciphertext = aes_gcm_encrypt(key, nonce, file_data)

    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def decrypt_file_data(encrypted_data: dict, key: bytes) -> bytes:
    """Decrypt and authenticate AES-256-GCM encrypted file data."""

    if len(key) != AES_KEY_BYTES:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])

    return aes_gcm_decrypt(key, nonce, ciphertext)
