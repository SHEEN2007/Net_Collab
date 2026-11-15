"""
NetCollab - shared cryptography primitives (Member 2, reused by Member 3).

IMPORTANT: this module is deliberately Django-free so that the TCP server, the
command-line client and the file-transfer code can all import it.

Algorithms
----------
* RSA-2048 with OAEP(SHA-256) .... secure key exchange (session key wrapping)
* AES-256-GCM .................... authenticated encryption of every frame/file

Nonce scheme
------------
GCM must never reuse a nonce with the same key.  Each direction of a session
uses a 12-byte nonce built from a 4-byte direction tag and an 8-byte counter:

    nonce = TAG ("C2S\\0" or "S2C\\0") || counter (big-endian uint64)

The nonce is *not* sent on the wire: both sides keep the counter, so a replayed,
dropped or re-ordered frame fails authentication.  The browser implementation
(frontend/src/comm/secureSocket.js) uses exactly the same scheme.
"""
import hashlib
import os
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_KEY_BITS = 2048
AES_KEY_BYTES = 32          # AES-256
NONCE_BYTES = 12
GCM_TAG_BYTES = 16

DIR_C2S = b"C2S\x00"        # client -> server
DIR_S2C = b"S2C\x00"        # server -> client


class CryptoError(Exception):
    """Raised for any failed encryption / decryption / key operation."""


# --------------------------------------------------------------------------
# RSA
# --------------------------------------------------------------------------
def _oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def generate_rsa_private_key(bits=RSA_KEY_BITS):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def private_key_to_pem(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key) -> bytes:
    """SubjectPublicKeyInfo PEM - importable by WebCrypto after PEM->DER."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_pem(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)


def load_public_key_pem(pem):
    if isinstance(pem, str):
        pem = pem.encode()
    return serialization.load_pem_public_key(pem)


def public_key_fingerprint(public_key) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo, as lowercase hex."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def load_or_create_private_key(path):
    """Load the server RSA key from *path*; create (and save) it if missing."""
    path = Path(path)
    if path.exists():
        return load_private_key_pem(path.read_bytes())
    path.parent.mkdir(parents=True, exist_ok=True)
    key = generate_rsa_private_key()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(private_key_to_pem(key))
    return key


def rsa_wrap_key(public_key, aes_key: bytes) -> bytes:
    """Encrypt a symmetric key for the owner of *public_key*."""
    try:
        return public_key.encrypt(aes_key, _oaep())
    except Exception as exc:  # pragma: no cover - defensive
        raise CryptoError(f"RSA wrap failed: {exc}") from exc


def rsa_unwrap_key(private_key, wrapped: bytes) -> bytes:
    try:
        key = private_key.decrypt(wrapped, _oaep())
    except Exception as exc:
        raise CryptoError("RSA unwrap failed (bad key exchange data)") from exc
    if len(key) != AES_KEY_BYTES:
        raise CryptoError("Session key has the wrong length")
    return key


# --------------------------------------------------------------------------
# AES-256-GCM
# --------------------------------------------------------------------------
def generate_aes_key() -> bytes:
    return os.urandom(AES_KEY_BYTES)


def build_nonce(direction_tag: bytes, counter: int) -> bytes:
    return struct.pack(">4sQ", direction_tag, counter)


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = None) -> bytes:
    """Returns ciphertext || 16-byte tag (same layout as WebCrypto)."""
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = None) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, data, aad)
    except InvalidTag as exc:
        raise CryptoError("Authentication failed (data was modified, replayed or re-ordered)") from exc


# Convenience for stand-alone blobs (files, data at rest): random nonce is prepended.
def aes_encrypt_blob(key: bytes, plaintext: bytes, aad: bytes = None) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return nonce + aes_gcm_encrypt(key, nonce, plaintext, aad)


def aes_decrypt_blob(key: bytes, blob: bytes, aad: bytes = None) -> bytes:
    if len(blob) < NONCE_BYTES + GCM_TAG_BYTES:
        raise CryptoError("Encrypted blob is too short")
    return aes_gcm_decrypt(key, blob[:NONCE_BYTES], blob[NONCE_BYTES:], aad)
