
import base64

from communication.crypto import (
    generate_rsa_private_key,
    load_public_key_pem,
    rsa_wrap_key,
    rsa_unwrap_key,
)


def generate_rsa_key_pair():
    """
    Generate an RSA key pair for local testing.

    In production, users own and protect their private keys.
    Never store private keys on the backend.
    """
    private_key = generate_rsa_private_key()
    return private_key, private_key.public_key()


def wrap_aes_key(aes_key: bytes, public_key) -> str:
    """Wrap an AES key using RSA-OAEP-SHA256."""
    wrapped_key = rsa_wrap_key(public_key, aes_key)
    return base64.b64encode(wrapped_key).decode("utf-8")


def unwrap_aes_key(wrapped_key: str, private_key) -> bytes:
    """Unwrap an AES key using the recipient's private key."""
    encrypted_key = base64.b64decode(wrapped_key)
    return rsa_unwrap_key(private_key, encrypted_key)


def load_recipient_public_key(public_key_pem: str):
    """Load a recipient's registered PEM-encoded public key."""
    return load_public_key_pem(public_key_pem)
