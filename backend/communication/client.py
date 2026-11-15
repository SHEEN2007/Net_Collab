"""
NetCollab command-line chat client (Member 2 - Computer Networks lab demo).

A plain TCP client: it performs the RSA key exchange, switches to AES-256-GCM,
logs in with the same JWT the web app uses and then chats in real time.

    cd backend
    python -m communication.client --username alice

Commands inside the client:
    /teams                    list your teams and channels (needs the REST API)
    /contacts                 list people you can DM
    /ch <channel_id> <text>   send to a team channel
    /dm <user_id> <text>      send a direct message
    /who                      who is online
    /help, /quit
"""
import argparse
import getpass
import json
import socket
import sys
import threading
import urllib.error
import urllib.request

from . import protocol

PING_EVERY = 30


def _http(method, url, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"HTTP {exc.code} from {url}: {exc.read().decode()[:200]}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"Cannot reach {url}: {exc.reason}")


def login(api_base, username, password):
    return _http("POST", f"{api_base}/accounts/login/", body={"username": username, "password": password})["access"]


class ChatClient:
    """Reusable client object (also used by the automated tests)."""

    def __init__(self, host, port, token, fingerprint=None, on_event=None):
        self.on_event = on_event or (lambda ev: None)
        self.sock = socket.create_connection((host, port), timeout=protocol.HANDSHAKE_TIMEOUT)
        self.chan = protocol.client_handshake(self.sock, pinned_fingerprint=fingerprint)
        self.chan.send_json({"type": "AUTH", "token": token})
        reply = self.chan.recv_json()
        if reply.get("type") != "AUTH_OK":
            self.chan.close()
            raise protocol.ProtocolError(f"login rejected: {reply.get('message')}")
        self.user = reply["user"]
        self.sock.settimeout(None)
        self._stop = threading.Event()
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._pinger, daemon=True).start()

    def _reader(self):
        try:
            while True:
                self.on_event(self.chan.recv_json())
        except (protocol.ProtocolError, OSError):
            pass
        finally:
            self._stop.set()
            self.on_event({"type": "DISCONNECTED"})

    def _pinger(self):
        # keep-alive: the server drops sessions that stay silent for 2 minutes
        while not self._stop.wait(PING_EVERY):
            try:
                self.chan.send_json({"type": "PING"})
            except (protocol.ProtocolError, OSError):
                return

    def send_channel(self, channel_id, text, client_id=None):
        self.chan.send_json({"type": "SEND_CHANNEL", "channel_id": channel_id, "content": text, "client_id": client_id})

    def send_dm(self, user_id, text, client_id=None):
        self.chan.send_json({"type": "SEND_DM", "to_user_id": user_id, "content": text, "client_id": client_id})

    def close(self):
        self._stop.set()
        self.chan.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description="NetCollab TCP chat client")
    ap.add_argument("--api", default="http://127.0.0.1:8000/api", help="Django REST base URL")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", help="omit to be prompted")
    ap.add_argument("--fingerprint", help="pin the server's RSA key fingerprint (SHA-256 hex)")
    args = ap.parse_args(argv)

    password = args.password or getpass.getpass("Password: ")
    token = login(args.api, args.username, password)
    online = set()
    print_lock = threading.Lock()

    def say(text):
        with print_lock:
            print(text)

    def on_event(ev):
        t = ev.get("type")
        if t == "MESSAGE":
            m = ev["message"]
            where = f"#channel {m['channel_id']}" if m["kind"] == "channel" else "DM"
            say(f"\n[{m['created_at'][11:19]}] {where} <{m['sender_username']}> {m['content']}")
        elif t == "PRESENCE_LIST":
            online.update(ev["online"]); say(f"online teammates: {sorted(online) or 'none'}")
        elif t == "PRESENCE":
            (online.add if ev["online"] else online.discard)(ev["user_id"])
            say(f"* user {ev['user_id']} is now {'online' if ev['online'] else 'offline'}")
        elif t == "ERROR":
            say(f"! {ev.get('code')}: {ev.get('message')}")
        elif t == "ACK":
            say(f"  (delivered, id {ev['message_id']})")
        elif t == "DISCONNECTED":
            say("Disconnected from server.")

    try:
        client = ChatClient(args.host, args.port, token, args.fingerprint, on_event)
    except (protocol.ProtocolError, OSError) as exc:
        raise SystemExit(f"Could not connect: {exc}")
    say(f"Secure channel up (RSA key exchange + AES-256-GCM). Server key fingerprint:\n  {client.chan.server_fingerprint}")
    say(f"Logged in as {client.user['username']} (id {client.user['id']}). Type /help.")

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            if line in ("/quit", "/exit"):
                break
            if line == "/help":
                say(__doc__)
            elif line == "/who":
                say(f"online teammates: {sorted(online) or 'none'}")
            elif line == "/teams":
                for team in _http("GET", f"{args.api}/teams/", token):
                    chans = _http("GET", f"{args.api}/teams/{team['id']}/channels/", token)
                    say(f"team {team['id']}: {team['name']}  channels: " + ", ".join(f"{c['id']}={c['name']}" for c in chans))
            elif line == "/contacts":
                for u in _http("GET", f"{args.api}/comm/contacts/", token):
                    say(f"user {u['id']}: {u['username']} ({u['full_name']})")
            elif line.startswith("/ch "):
                parts = line.split(" ", 2)
                if len(parts) == 3 and parts[1].isdigit():
                    client.send_channel(int(parts[1]), parts[2])
                else:
                    say("usage: /ch <channel_id> <text>")
            elif line.startswith("/dm "):
                parts = line.split(" ", 2)
                if len(parts) == 3 and parts[1].isdigit():
                    client.send_dm(int(parts[1]), parts[2])
                else:
                    say("usage: /dm <user_id> <text>")
            else:
                say("unknown command - /help")
    except (KeyboardInterrupt, protocol.ProtocolError, OSError):
        pass
    finally:
        client.close()


if __name__ == "__main__":
    main()
