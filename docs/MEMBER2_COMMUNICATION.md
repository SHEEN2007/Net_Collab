# Member 2 - Real-Time Communication & TCP Server

Secure, real-time messaging for NetCollab: a multi-client **TCP server**
(threads), **RSA key exchange**, **AES-256-GCM** encrypted traffic, team
**channels**, **direct messages**, **presence**, **notifications** and
encrypted **message storage**.

## 1. Architecture

```
 React (browser)                       Python CLI client
   WebCrypto: RSA + AES-GCM              cryptography: RSA + AES-GCM
        |  WebSocket (binary frames)           |  raw TCP
        v                                      |
 WebSocket<->TCP bridge  (opaque relay:        |
 never sees keys or plaintext)                 |
        |  raw TCP                             |
        +------------------+-------------------+
                           v
                TCP chat server  (one thread per client)
         RSA handshake -> AES-256-GCM -> JWT login -> routing
                           |
                  Django ORM  ->  MySQL
        Message (encrypted at rest), Notification, teams.Channel/Membership
```

Browsers cannot open raw TCP sockets, hence the bridge. It only copies bytes, so
encryption is still end-to-end between the browser and the TCP server.

Everything lives in `backend/communication/`; Member 1's apps are untouched
apart from two lines in `config/settings.py` / `config/urls.py` and the Chat
page in the React app.

## 2. Running it (4 terminals)

```powershell
# 0. once:  pip install -r requirements.txt ; python manage.py migrate
# 1. REST API
cd backend ; python manage.py runserver
# 2. TCP chat server (creates backend/keys/server_rsa_private.pem on first run)
cd backend ; python manage.py runtcpserver
# 3. WebSocket bridge for the browser
cd backend ; python manage.py runbridge
# 4. Frontend
cd frontend ; npm install ; npm run dev        # open http://localhost:5173 -> Chat
```

Command-line TCP client (Computer Networks demo - run in two terminals):

```powershell
cd backend
python -m communication.client --username alice
python -m communication.client --username bob
#   /teams   /contacts   /ch <channel_id> <text>   /dm <user_id> <text>   /who   /quit
```

Settings (all optional, in `backend/.env`): `TCP_HOST TCP_PORT WS_HOST WS_PORT WS_ALLOWED_ORIGINS RSA_KEY_PATH`.

## 3. Wire protocol

Frame = 4-byte big-endian length + payload.

| Step | Direction | Content |
|------|-----------|---------|
| 1 | S -> C | `HELLO {version, public_key (PEM), fingerprint}` (plain) |
| 2 | C -> S | `KEY_EXCHANGE {key = base64(RSA-OAEP-SHA256(AES-256 session key))}` (plain) |
| 3 | S -> C | `READY` - first AES-GCM frame, proves the server unwrapped the key |
| 4 | C -> S | `AUTH {token}` - the same JWT access token the web app uses |
| 5 | S -> C | `AUTH_OK {user}`, then `PRESENCE_LIST` |

AES-GCM nonce = 4-byte direction tag (`C2S\0`/`S2C\0`) + 8-byte counter, kept
implicitly by both sides - **never sent**, so replayed, dropped, re-ordered or
modified frames fail authentication and the connection is closed.

Messages (JSON inside the encrypted channel):

| Client -> server | Server -> client |
|---|---|
| `SEND_CHANNEL {channel_id, content, client_id}` | `MESSAGE {message}` (to all recipients **and** sender's sessions) |
| `SEND_DM {to_user_id, content, client_id}` | `ACK {client_id, message_id}` |
| `PING` | `PONG`, `PRESENCE {user_id, online}`, `ERROR {code, message, client_id}` |

Error codes: `auth_failed, forbidden, bad_request, empty_message, too_long, rate_limited, unknown_type, server_error`.

Routing / access control (checked against the DB on **every** send):
channel message -> every member of the channel's team; DM -> only the addressed
user and only if both share a team. Limits: 4000 chars, 30 msgs / 10 s, 200
clients, 15 s to log in, 2 min idle timeout (clients ping every 30 s).

## 4. REST API (`/api/comm/`, JWT required)

| Endpoint | Purpose |
|---|---|
| `GET server-info/` | TCP/WS address + server key fingerprint (browser pins it) |
| `GET contacts/` | users sharing a team with you (DM list) |
| `GET channels/<id>/messages/?before=&limit=` | channel history (members only) |
| `GET dm/<user_id>/messages/?before=&limit=` | DM history with a teammate |
| `GET unread/` | `{channels:{id:n}, dms:{user_id:n}, total}` |
| `GET notifications/?unread=1` | notification list |
| `POST notifications/read/` | `{channel_id}` or `{dm_user_id}` or `{all:true}` |

Database: `communication_message` (sender, channel *or* recipient, `body` =
base64(nonce + AES-GCM ciphertext)) and `communication_notification`
(user, message, is_read). The DB / Django admin never shows plaintext.

## 5. For Member 3 (file transfer) - the shared RSA/AES mechanism

`communication/crypto.py` and `communication/protocol.py` have **no Django
imports** and can be used as-is:

```python
from communication.protocol import server_handshake, client_handshake
from communication import crypto

# server side, after accept():
chan = server_handshake(conn, private_key, max_frame=4 * 1024 * 1024)   # RSA exchange done
meta = chan.recv_json()            # e.g. {"type":"UPLOAD","name":..., "size":...}
chunk = chan.recv_bytes()          # AES-GCM protected binary chunks
chan.send_json({"type": "OK"})

# client side:
chan = client_handshake(sock, pinned_fingerprint=None, max_frame=4 * 1024 * 1024)
chan.send_bytes(chunk)

# load the server key (same file the chat server uses):
private_key = crypto.load_or_create_private_key("backend/keys/server_rsa_private.pem")
```

Also available: `aes_encrypt_blob / aes_decrypt_blob` for encrypting stored files, and
`crypto.public_key_fingerprint`. The JWT login (`AUTH`) is implemented in
`server.py::_authenticate` if M3 wants the same authentication on its own port.

## 6. Tests

```powershell
cd backend ; python manage.py test communication        # needs the MySQL user to create test_netcollab_db
```
21 tests: RSA/AES, tamper + replay rejection, key pinning, oversized frames, real
multi-client routing, outsiders blocked, DM isolation, notifications, presence,
8 concurrent senders, REST access control, and a browser-style client through the bridge.

## 7. Viva / demo script

1. Start the three backend processes; show the server log with the RSA fingerprint.
2. Two CLI clients (alice, bob) -> `/ch 1 hello` -> both see it; `/dm` -> only bob sees it.
3. Log in to the web app as a third user *not* in the team: channel/DM sends are refused (`forbidden`).
4. Open Wireshark on loopback port 9000: after `HELLO`/`KEY_EXCHANGE` the payload is ciphertext.
5. Show `communication_message.body` in MySQL: ciphertext. Kill the TCP server -> UI shows "offline" and reconnects when it returns.

## 8. Known limitations (be upfront about these)

* RSA key *transport* has no forward secrecy: someone who records traffic and later steals the server private key can decrypt it. (Production fix: ECDHE.)
* The JWT is verified when the connection opens; a session is not dropped when the token later expires.
* Encryption at rest uses a key derived from Django's `SECRET_KEY` - rotate it and old messages become unreadable.
* Run the bridge behind TLS (`wss://`) outside localhost; the pinned fingerprint protects the key exchange, not the bridge's availability.
* `backend/keys/` is git-ignored: each machine generates its own server key.
