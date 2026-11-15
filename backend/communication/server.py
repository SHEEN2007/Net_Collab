"""
NetCollab TCP chat server (Member 2).

* One accepting thread + one handler thread per connected client (threading).
* Every connection: RSA key exchange -> AES-256-GCM channel -> JWT login.
* Routing: channel messages go to every team member, direct messages only to the
  addressed user (plus the sender's own other sessions).
* Every message is stored encrypted and creates a Notification per recipient.

Message types (JSON, inside the encrypted channel)
--------------------------------------------------
client -> server
    AUTH          {"type":"AUTH","token":"<JWT access token>"}
    SEND_CHANNEL  {"type":"SEND_CHANNEL","channel_id":1,"content":"hi","client_id":"x"}
    SEND_DM       {"type":"SEND_DM","to_user_id":2,"content":"hi","client_id":"x"}
    PING          {"type":"PING"}
server -> client
    AUTH_OK       {"type":"AUTH_OK","user":{"id":1,"username":"alice"}}
    PRESENCE_LIST {"type":"PRESENCE_LIST","online":[2,3]}        (teammates online)
    PRESENCE      {"type":"PRESENCE","user_id":2,"online":true}
    MESSAGE       {"type":"MESSAGE","message":{...}}              (also echoed to sender)
    ACK           {"type":"ACK","client_id":"x","message_id":42}
    ERROR         {"type":"ERROR","code":"...","message":"...","client_id":"x"}
    PONG          {"type":"PONG"}
"""
import logging
import socket
import threading
import time
from collections import deque

from django.contrib.auth import get_user_model
from django.db import close_old_connections, connections
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import AccessToken

from . import protocol, services
from .conf import MAX_MESSAGE_CHARS

log = logging.getLogger("netcollab.tcp")
User = get_user_model()

AUTH_TIMEOUT = 15.0        # seconds a new client has to authenticate
IDLE_TIMEOUT = 120.0       # clients must send something (PING) at least this often
MAX_CLIENTS = 200
RATE_LIMIT_COUNT = 30      # messages ...
RATE_LIMIT_WINDOW = 10.0   # ... per this many seconds


class Connection:
    def __init__(self, chan, addr):
        self.chan = chan
        self.addr = addr
        self.user_id = None
        self.username = None
        self._sent = deque()

    def rate_limited(self) -> bool:
        now = time.monotonic()
        while self._sent and now - self._sent[0] > RATE_LIMIT_WINDOW:
            self._sent.popleft()
        if len(self._sent) >= RATE_LIMIT_COUNT:
            return True
        self._sent.append(now)
        return False

    def send(self, payload: dict) -> bool:
        try:
            self.chan.send_json(payload)
            return True
        except (OSError, protocol.ProtocolError):
            self.chan.close()          # reader thread will notice and clean up
            return False


class ChatServer:
    def __init__(self, host, port, private_key):
        self.host = host
        self.port = port
        self.private_key = private_key
        self._listener = None
        self._accept_thread = None
        self._stopping = threading.Event()
        self._lock = threading.Lock()
        self._clients = {}              # user_id -> set[Connection]
        self._active = 0

    # ------------------------------------------------------------ lifecycle
    def start(self):
        """Bind, listen and start accepting in a background thread."""
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, self.port))
        self._listener.listen(50)
        self._listener.settimeout(1.0)
        self.port = self._listener.getsockname()[1]      # resolves port 0
        self._accept_thread = threading.Thread(target=self._accept_loop, name="accept", daemon=True)
        self._accept_thread.start()
        log.info("TCP chat server listening on %s:%s", self.host, self.port)

    def stop(self):
        self._stopping.set()
        if self._listener:
            try:
                self._listener.close()
            except OSError:
                pass
        with self._lock:
            conns = [c for group in self._clients.values() for c in group]
        for c in conns:
            c.chan.close()
        if self._accept_thread:
            self._accept_thread.join(timeout=3)

    def online_user_ids(self):
        with self._lock:
            return set(self._clients)

    # ------------------------------------------------------------ accepting
    def _accept_loop(self):
        while not self._stopping.is_set():
            try:
                sock, addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                if self._active >= MAX_CLIENTS:
                    sock.close()
                    log.warning("Refused %s: too many clients", addr)
                    continue
                self._active += 1
            threading.Thread(target=self._handle_client, args=(sock, addr),
                             name=f"client-{addr[0]}:{addr[1]}", daemon=True).start()

    # ------------------------------------------------------------ one client
    def _handle_client(self, sock, addr):
        conn = None
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.settimeout(protocol.HANDSHAKE_TIMEOUT)
            chan = protocol.server_handshake(sock, self.private_key)
            conn = Connection(chan, addr)
            log.info("%s: secure channel established (RSA exchange + AES-256-GCM)", addr)

            sock.settimeout(AUTH_TIMEOUT)
            if not self._authenticate(conn):
                return
            sock.settimeout(IDLE_TIMEOUT)
            self._register(conn)
            self._message_loop(conn)
        except protocol.ConnectionClosed:
            pass
        except (protocol.ProtocolError, socket.timeout, OSError) as exc:
            log.info("%s: connection dropped (%s)", addr, exc)
        except Exception:
            log.exception("%s: unexpected error", addr)
        finally:
            if conn is not None and conn.user_id is not None:
                self._unregister(conn)
            try:
                sock.close()
            except OSError:
                pass
            with self._lock:
                self._active -= 1
            connections.close_all()          # this thread's DB connections

    def _authenticate(self, conn) -> bool:
        msg = conn.chan.recv_json()
        if msg.get("type") != "AUTH" or not isinstance(msg.get("token"), str):
            conn.send({"type": "ERROR", "code": "auth_required", "message": "Send AUTH first."})
            return False
        try:
            token = AccessToken(msg["token"])
            user = User.objects.get(pk=token[api_settings.USER_ID_CLAIM], is_active=True)
        except (TokenError, User.DoesNotExist, KeyError):
            conn.send({"type": "ERROR", "code": "auth_failed", "message": "Invalid or expired token."})
            return False
        conn.user_id, conn.username = user.id, user.username
        conn.send({"type": "AUTH_OK", "user": {"id": user.id, "username": user.username}})
        log.info("%s: authenticated as %s (id=%s)", conn.addr, user.username, user.id)
        return True

    # ------------------------------------------------------------ presence
    def _register(self, conn):
        with self._lock:
            first = conn.user_id not in self._clients
            self._clients.setdefault(conn.user_id, set()).add(conn)
        mates = services.teammate_ids(conn.user_id)
        conn.send({"type": "PRESENCE_LIST", "online": sorted(mates & self.online_user_ids())})
        if first:
            for uid in mates:
                self.push_to_user(uid, {"type": "PRESENCE", "user_id": conn.user_id, "online": True})

    def _unregister(self, conn):
        with self._lock:
            group = self._clients.get(conn.user_id, set())
            group.discard(conn)
            last = not group
            if last:
                self._clients.pop(conn.user_id, None)
        log.info("%s: %s disconnected", conn.addr, conn.username)
        if last:
            try:
                close_old_connections()
                for uid in services.teammate_ids(conn.user_id):
                    self.push_to_user(uid, {"type": "PRESENCE", "user_id": conn.user_id, "online": False})
            except Exception:
                log.exception("presence broadcast failed")

    # ------------------------------------------------------------ routing
    def push_to_user(self, user_id, payload) -> int:
        """Send *payload* to every live session of a user. Returns sessions reached."""
        with self._lock:
            targets = list(self._clients.get(user_id, ()))
        return sum(1 for c in targets if c.send(payload))

    def _message_loop(self, conn):
        while True:
            msg = conn.chan.recv_json()
            close_old_connections()                 # survive MySQL idle timeouts
            kind = msg.get("type")
            client_id = msg.get("client_id")
            try:
                if kind == "PING":
                    conn.send({"type": "PONG"})
                elif kind in ("SEND_CHANNEL", "SEND_DM"):
                    self._handle_send(conn, msg, client_id)
                else:
                    conn.send({"type": "ERROR", "code": "unknown_type",
                               "message": f"Unknown message type: {kind!r}", "client_id": client_id})
            except Exception:
                log.exception("error while handling %s from %s", kind, conn.username)
                conn.send({"type": "ERROR", "code": "server_error",
                           "message": "Internal server error.", "client_id": client_id})

    def _error(self, conn, code, message, client_id):
        conn.send({"type": "ERROR", "code": code, "message": message, "client_id": client_id})

    def _handle_send(self, conn, msg, client_id):
        content = msg.get("content")
        if not isinstance(content, str) or not content.strip():
            return self._error(conn, "empty_message", "Message cannot be empty.", client_id)
        content = content.strip()
        if len(content) > MAX_MESSAGE_CHARS:
            return self._error(conn, "too_long", f"Max {MAX_MESSAGE_CHARS} characters.", client_id)
        if conn.rate_limited():
            return self._error(conn, "rate_limited", "Slow down - too many messages.", client_id)

        sender = User.objects.get(pk=conn.user_id)

        if msg["type"] == "SEND_CHANNEL":
            channel_id = msg.get("channel_id")
            if not isinstance(channel_id, int) or isinstance(channel_id, bool):
                return self._error(conn, "bad_request", "channel_id must be an integer.", client_id)
            channel = services.get_channel_for_user(conn.user_id, channel_id)
            if channel is None:
                return self._error(conn, "forbidden", "You are not a member of that channel.", client_id)
            message, recipients = services.create_channel_message(sender, channel, content)
        else:
            to_id = msg.get("to_user_id")
            if not isinstance(to_id, int) or isinstance(to_id, bool) or to_id == conn.user_id:
                return self._error(conn, "bad_request", "to_user_id must be another user's id.", client_id)
            if not User.objects.filter(pk=to_id, is_active=True).exists() or not services.shares_team(conn.user_id, to_id):
                return self._error(conn, "forbidden", "You can only message people in your teams.", client_id)
            message = services.create_direct_message(sender, to_id, content)
            recipients = [to_id]

        payload = {"type": "MESSAGE", "message": services.serialize_message(message)}
        for uid in [conn.user_id, *recipients]:     # sender's sessions get it too
            self.push_to_user(uid, payload)
        conn.send({"type": "ACK", "client_id": client_id, "message_id": message.id})
