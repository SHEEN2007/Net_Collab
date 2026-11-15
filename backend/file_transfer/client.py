
import os
import json
import socket
import base64

from pathlib import Path
from dotenv import load_dotenv

from file_transfer.protocol import send_package, MAX_FILE_SIZE

from artifacts.services.secure_transfer import (
    encrypt_for_recipient,
    decrypt_received_file,
)

from artifacts.services.key_exchange import generate_rsa_key_pair


# Load environment variables from backend/.env
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

TCP_TRANSFER_TOKEN = os.getenv("TCP_TRANSFER_TOKEN")

HOST = "127.0.0.1"
PORT = 9000

CONNECTION_TIMEOUT = 30


def send_encrypted_file(file_path, recipient_public_key):
    """Encrypt a file and send it to the TCP server."""

    if not TCP_TRANSFER_TOKEN:
        raise RuntimeError(
            "TCP_TRANSFER_TOKEN is not configured."
        )

    file_path = Path(file_path)

    if not file_path.is_file():
        raise FileNotFoundError("File does not exist.")

    if file_path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError("File exceeds the 100 MB limit.")

    original_data = file_path.read_bytes()

    # Encrypt using AES-256-GCM and wrap AES key using RSA.
    package = encrypt_for_recipient(
        original_data,
        recipient_public_key,
    )

    metadata = {
        "encryption": package["encryption"],
        "key_encryption": package["key_encryption"],
        "nonce": package["nonce"],
        "wrapped_key": package["wrapped_key"],
        "auth_token": TCP_TRANSFER_TOKEN,
    }

    ciphertext = base64.b64decode(
        package["ciphertext"],
        validate=True,
    )

    with socket.create_connection(
        (HOST, PORT),
        timeout=10,
    ) as client:

        client.settimeout(CONNECTION_TIMEOUT)

        send_package(
            client,
            metadata,
            ciphertext,
        )

        response_data = client.recv(4096)

        if not response_data:
            raise ConnectionError(
                "Server closed connection without a response."
            )

        response = json.loads(
            response_data.decode("utf-8")
        )

    return response


def verify_received_file(file_id, original_data, recipient_private_key):
    """
    Local testing helper.

    Reads the file saved by the server and verifies that
    the recipient can decrypt the received ciphertext.

    This accesses local server storage and is not a
    production client download mechanism.
    """

    storage_dir = (
        Path(__file__).resolve().parent / "received_files"
    )

    file_path = storage_dir / f"{file_id}.enc"
    metadata_path = storage_dir / f"{file_id}.json"

    if not file_path.is_file() or not metadata_path.is_file():
        raise FileNotFoundError(
            "Received file or metadata not found."
        )

    received_ciphertext = file_path.read_bytes()

    received_metadata = json.loads(
        metadata_path.read_text(encoding="utf-8")
    )

    encrypted_package = {
        **received_metadata,
        "ciphertext": base64.b64encode(
            received_ciphertext
        ).decode("utf-8"),
    }

    recovered_data = decrypt_received_file(
        encrypted_package,
        recipient_private_key,
    )

    return recovered_data == original_data, len(received_ciphertext)


if __name__ == "__main__":

    # Temporary RSA key pair for local testing.
    recipient_private_key, recipient_public_key = (
        generate_rsa_key_pair()
    )

    test_file = Path("test_tcp_file.txt")

    original_data = (
        b"This is a secure NetCollab TCP transfer test."
    )

    test_file.write_bytes(original_data)

    print("Starting encrypted file transfer...")

    result = send_encrypted_file(
        test_file,
        recipient_public_key,
    )

    print("Server response:", result)

    if result.get("status") == "success":

        file_id = result["file_id"]

        successful, received_size = verify_received_file(
            file_id,
            original_data,
            recipient_private_key,
        )

        print("Received encrypted size:", received_size)

        print(
            "Decryption successful:",
            successful,
        )

    else:
        print("File transfer failed:", result.get("message"))
