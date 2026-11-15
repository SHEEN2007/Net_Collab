"""
NetCollab - TCP wire protocol (Member 2).  Django-free, shared with Member 3.

Framing
-------
Every message on the TCP stream is one frame:

    +----------------------+-----------------------------+
    | 4 bytes, big-endian  |  payload (length bytes)     |
    | payload length       |                             |
    +----------------------+-----------------------------+

Handshake (plain frames until READY)
------------------------------------
    S -> C   {"type":"HELLO","version":1,"public_key":"<PEM>","fingerprint":"<sha256 hex>"}
    C -> S   {"type":"KEY_EXCHANGE","key":"<base64 RSA-OAEP(SHA-256) wrapped AES-256 key>"}
    S -> C   <encrypted> {"type":"READY"}          (proves the server holds the key)

After READY every payload is AES-256-GCM ciphertext (see crypto.py for the
implicit counter nonce).  `SecureChannel` implements that.

Member 3 (file transfer) can reuse `server_handshake` / `client_handshake` and
`SecureChannel.send_bytes / recv_bytes` for binary chunks (pass a larger
`max_frame` for file chunks).
"""
import base64
import json
import socket
import struct
import threading

from . import crypto

PROTOCOL_VERSION = 1
DEFAULT_MAX_FRAME = 1 * 1024 * 1024        # 1 MiB - plenty for chat
HANDSHAKE_TIMEOUT = 10.0


class ProtocolError(Exception):
    """The peer violated the protocol (bad frame, bad handshake, tampering...)."""


class ConnectionClosed(ProtocolError):
    """The peer closed the TCP connection."""


# --------------------------------------------------------------------------
# Framing
# --------------------------------------------------------------------------
def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionClosed("connection closed by peer")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: socket.socket, max_len: int = DEFAULT_MAX_FRAME) -> bytes:
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    if length > max_len:
        raise ProtocolError(f"frame too large ({length} > {max_len})")
    return recv_exact(sock, length) if length else b""


# --------------------------------------------------------------------------
# Encrypted channel
# --------------------------------------------------------------------------
class SecureChannel:
    """AES-256-GCM protected message channel on top of a connected socket."""

    def __init__(self, sock, key, role, max_frame=DEFAULT_MAX_FRAME):
        if role not in ("client", "server"):
            raise ValueError("role must be 'client' or 'server'")
        self.sock = sock
        self.max_frame = max_frame
        self.server_fingerprint = None
        self._key = key
        self._send_tag = crypto.DIR_C2S if role == "client" else crypto.DIR_S2C
        self._recv_tag = crypto.DIR_S2C if role == "client" else crypto.DIR_C2S
        self._send_ctr = 0
        self._recv_ctr = 0
        self._send_lock = threading.Lock()   # several threads may push to one client

    # ---- binary ----------------------------------------------------------
    def send_bytes(self, data: bytes) -> None:
        with self._send_lock:                # counter + sendall must stay atomic
            nonce = crypto.build_nonce(self._send_tag, self._send_ctr)
            ciphertext = crypto.aes_gcm_encrypt(self._key, nonce, data)
            send_frame(self.sock, ciphertext)
            self._send_ctr += 1

    def recv_bytes(self) -> bytes:
        frame = recv_frame(self.sock, self.max_frame + crypto.GCM_TAG_BYTES)
        nonce = crypto.build_nonce(self._recv_tag, self._recv_ctr)
        try:
            data = crypto.aes_gcm_decrypt(self._key, nonce, frame)
        except crypto.CryptoError as exc:
            raise ProtocolError(str(exc)) from exc
        self._recv_ctr += 1
        return data

    # ---- JSON ------------------------------------------------------------
    def send_json(self, obj: dict) -> None:
        self.send_bytes(json.dumps(obj, separators=(",", ":")).encode("utf-8"))

    def recv_json(self) -> dict:
        raw = self.recv_bytes()
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ProtocolError("invalid JSON message") from exc
        if not isinstance(obj, dict):
            raise ProtocolError("message must be a JSON object")
        return obj

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# Handshake
# --------------------------------------------------------------------------
def _recv_plain_json(sock, max_len=64 * 1024) -> dict:
    try:
        obj = json.loads(recv_frame(sock, max_len).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError("invalid handshake message") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("invalid handshake message")
    return obj


def server_handshake(sock, private_key, max_frame=DEFAULT_MAX_FRAME) -> SecureChannel:
    """Server side: advertise RSA public key, unwrap the client's AES key."""
    public_key = private_key.public_key()
    hello = {
        "type": "HELLO",
        "version": PROTOCOL_VERSION,
        "public_key": crypto.public_key_to_pem(public_key).decode(),
        "fingerprint": crypto.public_key_fingerprint(public_key),
    }
    send_frame(sock, json.dumps(hello).encode())

    msg = _recv_plain_json(sock)
    if msg.get("type") != "KEY_EXCHANGE" or not isinstance(msg.get("key"), str):
        raise ProtocolError("expected KEY_EXCHANGE")
    try:
        wrapped = base64.b64decode(msg["key"], validate=True)
        aes_key = crypto.rsa_unwrap_key(private_key, wrapped)
    except (ValueError, crypto.CryptoError) as exc:
        raise ProtocolError(f"key exchange failed: {exc}") from exc

    chan = SecureChannel(sock, aes_key, "server", max_frame)
    chan.send_json({"type": "READY"})
    return chan


def client_handshake(sock, pinned_fingerprint=None, max_frame=DEFAULT_MAX_FRAME) -> SecureChannel:
    """Client side: verify the server key (optionally pinned), send wrapped AES key."""
    hello = _recv_plain_json(sock)
    if hello.get("type") != "HELLO":
        raise ProtocolError("expected HELLO")
    if hello.get("version") != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version {hello.get('version')}")
    try:
        public_key = crypto.load_public_key_pem(hello["public_key"])
    except Exception as exc:
        raise ProtocolError("server sent an invalid public key") from exc

    fingerprint = crypto.public_key_fingerprint(public_key)
    if pinned_fingerprint and fingerprint != pinned_fingerprint.lower().replace(":", ""):
        raise ProtocolError(
            f"server key fingerprint mismatch (got {fingerprint}) - possible man-in-the-middle"
        )

    aes_key = crypto.generate_aes_key()
    wrapped = crypto.rsa_wrap_key(public_key, aes_key)
    send_frame(sock, json.dumps(
        {"type": "KEY_EXCHANGE", "key": base64.b64encode(wrapped).decode()}
    ).encode())

    chan = SecureChannel(sock, aes_key, "client", max_frame)
    chan.server_fingerprint = fingerprint
    if chan.recv_json().get("type") != "READY":
        raise ProtocolError("server did not confirm the session key")
    return chan
