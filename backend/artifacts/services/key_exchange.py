
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


def generate_rsa_key_pair():
    """
    Generate an RSA-2048 key pair for testing.

    In production, the recipient owns and protects their
    private key. Never share or expose it.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    return private_key, public_key


def wrap_aes_key(aes_key: bytes, public_key) -> str:
    """Encrypt an AES session key using RSA-OAEP-SHA256."""

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return base64.b64encode(encrypted_key).decode("utf-8")


def unwrap_aes_key(wrapped_key: str, private_key) -> bytes:
    """Recover the AES session key using the recipient's private key."""

    encrypted_key = base64.b64decode(wrapped_key)

    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
