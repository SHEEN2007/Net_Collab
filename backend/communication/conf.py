"""Runtime configuration for the communication module (read from .env / environment)."""
import os
from pathlib import Path

from django.conf import settings

TCP_HOST = os.getenv("TCP_HOST", "127.0.0.1")
TCP_PORT = int(os.getenv("TCP_PORT", "9000"))

WS_HOST = os.getenv("WS_HOST", "127.0.0.1")
WS_PORT = int(os.getenv("WS_PORT", "9001"))
WS_ALLOWED_ORIGINS = [
    o.strip() for o in os.getenv("WS_ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()
]

KEY_PATH = Path(os.getenv("RSA_KEY_PATH", str(Path(settings.BASE_DIR) / "keys" / "server_rsa_private.pem")))

MAX_MESSAGE_CHARS = 4000
