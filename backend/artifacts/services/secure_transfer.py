
from .encryption import (
    generate_aes_key,
    encrypt_file_data,
    decrypt_file_data,
)
from .key_exchange import (
    wrap_aes_key,
    unwrap_aes_key,
)


def encrypt_for_recipient(file_data: bytes, recipient_public_key) -> dict:
    """
    Encrypt file data using AES-256-GCM and wrap the AES key
    using the recipient's RSA public key.
    """
    aes_key = generate_aes_key()
    encrypted_file = encrypt_file_data(file_data, aes_key)
    wrapped_key = wrap_aes_key(aes_key, recipient_public_key)

    return {
        "encryption": "AES-256-GCM",
        "key_encryption": "RSA-OAEP-SHA256",
        "nonce": encrypted_file["nonce"],
        "ciphertext": encrypted_file["ciphertext"],
        "wrapped_key": wrapped_key,
    }


def decrypt_received_file(
    encrypted_package: dict,
    recipient_private_key
) -> bytes:
    """Unwrap the AES key and decrypt the received file."""

    if encrypted_package["encryption"] != "AES-256-GCM":
        raise ValueError("Unsupported encryption algorithm.")

    if encrypted_package["key_encryption"] != "RSA-OAEP-SHA256":
        raise ValueError("Unsupported key encryption algorithm.")

    aes_key = unwrap_aes_key(
        encrypted_package["wrapped_key"],
        recipient_private_key,
    )

    return decrypt_file_data(encrypted_package, aes_key)
