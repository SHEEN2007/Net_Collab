
import json
import struct


MAX_METADATA_SIZE = 64 * 1024       # 64 KB
MAX_FILE_SIZE = 100 * 1024 * 1024    # 100 MB


def recv_exact(sock, size):
    """
    Receive exactly 'size' bytes from a TCP socket.

    TCP does not guarantee that one recv() call returns
    the entire requested message.
    """
    if size < 0:
        raise ValueError("Invalid receive size.")

    chunks = []
    remaining = size

    while remaining > 0:
        chunk = sock.recv(remaining)

        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def send_package(sock, metadata, ciphertext):
    """
    Send metadata followed by encrypted binary file data.
    """
    if len(ciphertext) > MAX_FILE_SIZE:
        raise ValueError("File exceeds the 100 MB limit.")

    metadata = {
        **metadata,
        "file_size": len(ciphertext),
    }

    metadata_bytes = json.dumps(metadata).encode("utf-8")

    if len(metadata_bytes) > MAX_METADATA_SIZE:
        raise ValueError("Metadata exceeds the allowed size.")

    # Send 4-byte unsigned big-endian metadata length.
    sock.sendall(struct.pack("!I", len(metadata_bytes)))

    # Send JSON metadata.
    sock.sendall(metadata_bytes)

    # Send encrypted file contents.
    sock.sendall(ciphertext)


def receive_package(sock):
    """
    Receive and validate one encrypted file package.
    """
    # Read metadata length.
    metadata_length = struct.unpack(
        "!I",
        recv_exact(sock, 4)
    )[0]

    if metadata_length == 0 or metadata_length > MAX_METADATA_SIZE:
        raise ValueError("Invalid metadata length.")

    # Read and decode metadata.
    metadata_bytes = recv_exact(sock, metadata_length)

    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Invalid metadata format.")

    if not isinstance(metadata, dict):
        raise ValueError("Metadata must be a JSON object.")

    file_size = metadata.get("file_size")

    if type(file_size) is not int:
        raise ValueError("Invalid file size.")

    if file_size < 0 or file_size > MAX_FILE_SIZE:
        raise ValueError("File exceeds the allowed size.")

    # Read exactly the encrypted file size.
    ciphertext = recv_exact(sock, file_size)

    return metadata, ciphertext
