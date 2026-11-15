
import os
import json
import socket
import uuid
import base64
import binascii
import secrets

from pathlib import Path
from dotenv import load_dotenv

from file_transfer.protocol import receive_package, MAX_FILE_SIZE


# Load environment variables from backend/.env
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

TCP_TRANSFER_TOKEN = os.getenv("TCP_TRANSFER_TOKEN")

HOST = "127.0.0.1"
PORT = 9000

STORAGE_DIR = Path(__file__).resolve().parent / "received_files"

CONNECTION_TIMEOUT = 30


def validate_metadata(metadata):
    """Validate encryption metadata and authenticate sender."""

    required_fields = {
        "encryption",
        "key_encryption",
        "nonce",
        "wrapped_key",
        "file_size",
        "auth_token",
    }

    if not isinstance(metadata, dict):
        raise ValueError("Metadata must be a JSON object.")

    if not required_fields.issubset(metadata):
        raise ValueError("Missing required metadata fields.")

    if not TCP_TRANSFER_TOKEN:
        raise RuntimeError("TCP authentication token is not configured.")

    auth_token = metadata["auth_token"]

    if not isinstance(auth_token, str):
        raise ValueError("Invalid authentication token.")

    if not secrets.compare_digest(auth_token, TCP_TRANSFER_TOKEN):
        raise ValueError("Authentication failed.")

    if metadata["encryption"] != "AES-256-GCM":
        raise ValueError("Unsupported encryption algorithm.")

    if metadata["key_encryption"] != "RSA-OAEP-SHA256":
        raise ValueError("Unsupported key encryption algorithm.")

    if not isinstance(metadata["nonce"], str):
        raise ValueError("Invalid nonce.")

    if not isinstance(metadata["wrapped_key"], str):
        raise ValueError("Invalid wrapped key.")

    try:
        nonce = base64.b64decode(
            metadata["nonce"],
            validate=True,
        )

        wrapped_key = base64.b64decode(
            metadata["wrapped_key"],
            validate=True,
        )

    except (ValueError, binascii.Error):
        raise ValueError("Invalid Base64 encryption metadata.")

    if len(nonce) != 12:
        raise ValueError("Invalid AES-GCM nonce length.")

    if not wrapped_key or len(wrapped_key) > 16 * 1024:
        raise ValueError("Invalid RSA-wrapped key.")

    file_size = metadata["file_size"]

    if type(file_size) is not int:
        raise ValueError("Invalid file size.")

    if file_size <= 0 or file_size > MAX_FILE_SIZE:
        raise ValueError("File size outside permitted limits.")


def handle_client(client_socket, client_address):
    """Receive and store one encrypted file."""

    try:
        client_socket.settimeout(CONNECTION_TIMEOUT)

        metadata, ciphertext = receive_package(client_socket)

        validate_metadata(metadata)

        if len(ciphertext) != metadata["file_size"]:
            raise ValueError("Received file size mismatch.")

        STORAGE_DIR.mkdir(parents=True, exist_ok=True)

        file_id = uuid.uuid4().hex

        file_path = STORAGE_DIR / f"{file_id}.enc"
        metadata_path = STORAGE_DIR / f"{file_id}.json"

        # Store encrypted payload only.
        file_path.write_bytes(ciphertext)

        # Save encryption metadata, including wrapped key.
        metadata_path.write_text(
            json.dumps(metadata, indent=4),
            encoding="utf-8",
        )

        response = {
            "status": "success",
            "message": "Encrypted file received.",
            "file_id": file_id,
            "file_size": len(ciphertext),
        }

        client_socket.sendall(
            json.dumps(response).encode("utf-8")
        )

        print(f"Received encrypted file from {client_address}")
        print(f"Stored as: {file_path.name}")

    except (ValueError, ConnectionError, OSError, RuntimeError) as error:

        print(f"Transfer failed from {client_address}: {error}")

        try:
            response = {
                "status": "error",
                "message": "File transfer failed.",
            }

            client_socket.sendall(
                json.dumps(response).encode("utf-8")
            )

        except OSError:
            pass

    finally:
        client_socket.close()


def start_server():
    """Start the TCP file-transfer server."""

    if not TCP_TRANSFER_TOKEN:
        raise RuntimeError(
            "TCP_TRANSFER_TOKEN missing from backend/.env"
        )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        server.bind((HOST, PORT))
        server.listen(5)

        print(
            f"TCP File Transfer Server running on {HOST}:{PORT}"
        )

        while True:
            client_socket, client_address = server.accept()

            handle_client(
                client_socket,
                client_address,
            )


if __name__ == "__main__":
    start_server()
