"""
Automated tests for Member 2.   Run:  python manage.py test communication

The end-to-end tests start a real ChatServer on a random port and connect real
TCP clients (and a WebSocket client through the bridge).
"""
import asyncio
import base64
import json
import queue
import socket
import struct
import threading
import time

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TransactionTestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken
from teams.models import Channel, Team, TeamMembership

from . import bridge, crypto, protocol
from .client import ChatClient
from .models import Message, Notification
from .server import ChatServer

User = get_user_model()


# ----------------------------------------------------------------- crypto
class CryptoTests(SimpleTestCase):
    def test_rsa_wrap_roundtrip_and_wrong_key_fails(self):
        priv, other = crypto.generate_rsa_private_key(), crypto.generate_rsa_private_key()
        key = crypto.generate_aes_key()
        wrapped = crypto.rsa_wrap_key(priv.public_key(), key)
        self.assertEqual(crypto.rsa_unwrap_key(priv, wrapped), key)
        with self.assertRaises(crypto.CryptoError):
            crypto.rsa_unwrap_key(other, wrapped)

    def test_aes_roundtrip_and_tamper_detection(self):
        key = crypto.generate_aes_key()
        blob = crypto.aes_encrypt_blob(key, b"secret")
        self.assertEqual(crypto.aes_decrypt_blob(key, blob), b"secret")
        bad = bytearray(blob); bad[-1] ^= 1
        with self.assertRaises(crypto.CryptoError):
            crypto.aes_decrypt_blob(key, bytes(bad))

    def test_fingerprint_is_stable(self):
        pub = crypto.generate_rsa_private_key().public_key()
        self.assertEqual(crypto.public_key_fingerprint(pub), crypto.public_key_fingerprint(crypto.load_public_key_pem(crypto.public_key_to_pem(pub))))


class ProtocolTests(SimpleTestCase):
    def _pair(self, pinned=None):
        key = crypto.generate_rsa_private_key()
        a, b = socket.socketpair()
        out = {}

        def serve():
            try:
                out["s"] = protocol.server_handshake(a, key)
            except protocol.ProtocolError:
                pass                      # client aborted (e.g. fingerprint mismatch)

        t = threading.Thread(target=serve)
        t.start()
        try:
            client = protocol.client_handshake(b, pinned_fingerprint=pinned)
        finally:
            if pinned:
                b.close()                 # lets the server thread finish
            t.join()
        return out["s"], client

    def test_encrypted_roundtrip_both_directions(self):
        server, client = self._pair()
        client.send_json({"a": 1}); self.assertEqual(server.recv_json(), {"a": 1})
        server.send_json({"b": 2}); self.assertEqual(client.recv_json(), {"b": 2})

    def test_ciphertext_on_the_wire_is_not_plaintext(self):
        server, client = self._pair()
        client.send_bytes(b"TOP-SECRET-PAYLOAD")
        raw = protocol.recv_frame(server.sock)
        self.assertNotIn(b"TOP-SECRET", raw)

    def test_replayed_frame_is_rejected(self):
        server, client = self._pair()
        client.send_bytes(b"one")
        frame = protocol.recv_frame(server.sock)           # steal ciphertext
        # feed it twice
        a, b = socket.socketpair()
        server.sock = a
        protocol.send_frame(b, frame); protocol.send_frame(b, frame)
        self.assertEqual(server.recv_bytes(), b"one")
        with self.assertRaises(protocol.ProtocolError):
            server.recv_bytes()

    def test_wrong_pinned_fingerprint_is_rejected(self):
        with self.assertRaises(protocol.ProtocolError):
            self._pair(pinned="00" * 32)

    def test_oversized_frame_rejected(self):
        a, b = socket.socketpair()
        b.sendall(struct.pack(">I", 10 ** 9))
        with self.assertRaises(protocol.ProtocolError):
            protocol.recv_frame(a)


# ----------------------------------------------------------------- end-to-end
class Collector:
    """Collects server events for a ChatClient so tests can wait for them."""

    def __init__(self):
        self.q = queue.Queue()

    def __call__(self, ev):
        self.q.put(ev)

    def wait(self, type_, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            try:
                ev = self.q.get(timeout=0.2)
            except queue.Empty:
                continue
            if ev.get("type") == type_:
                return ev
        raise AssertionError(f"no {type_} event within {timeout}s")

    def none_of(self, type_, wait=0.6):
        end = time.time() + wait
        while time.time() < end:
            try:
                if self.q.get(timeout=0.1).get("type") == type_:
                    return False
            except queue.Empty:
                pass
        return True


class EndToEndTests(TransactionTestCase):
    def setUp(self):
        self.alice = User.objects.create_user("alice", password="pw-alice-123")
        self.bob = User.objects.create_user("bob", password="pw-bob-12345")
        self.carol = User.objects.create_user("carol", password="pw-carol-123")   # other team
        self.team = Team.objects.create(name="Core", owner=self.alice)
        for u in (self.alice, self.bob):
            TeamMembership.objects.create(team=self.team, user=u, role="owner" if u == self.alice else "member")
        self.other_team = Team.objects.create(name="Other", owner=self.carol)
        TeamMembership.objects.create(team=self.other_team, user=self.carol, role="owner")
        self.channel = Channel.objects.create(team=self.team, name="general", created_by=self.alice)

        self.server = ChatServer("127.0.0.1", 0, crypto.generate_rsa_private_key())
        self.server.start()
        self.clients = []

    def tearDown(self):
        for c in self.clients:
            c.close()
        self.server.stop()

    def connect(self, user):
        col = Collector()
        client = ChatClient("127.0.0.1", self.server.port, str(AccessToken.for_user(user)), on_event=col)
        self.clients.append(client)
        return client, col

    # ---- auth
    def test_bad_token_is_rejected(self):
        with self.assertRaises(protocol.ProtocolError):
            ChatClient("127.0.0.1", self.server.port, "not-a-jwt")

    # ---- channel routing
    def test_channel_message_reaches_team_members_only(self):
        a, ca = self.connect(self.alice)
        b, cb = self.connect(self.bob)
        c, cc = self.connect(self.carol)

        a.send_channel(self.channel.id, "hello team", client_id="c1")
        self.assertEqual(cb.wait("MESSAGE")["message"]["content"], "hello team")
        self.assertEqual(ca.wait("MESSAGE")["message"]["sender_username"], "alice")   # echo to sender
        self.assertEqual(ca.wait("ACK")["client_id"], "c1")
        self.assertTrue(cc.none_of("MESSAGE"))                                          # outsider gets nothing

        msg = Message.objects.get()
        self.assertNotIn("hello team", msg.body)           # stored encrypted
        self.assertEqual(msg.content, "hello team")
        self.assertEqual(Notification.objects.filter(user=self.bob, is_read=False).count(), 1)
        self.assertEqual(Notification.objects.filter(user=self.alice).count(), 0)

    def test_outsider_cannot_post_to_channel(self):
        c, cc = self.connect(self.carol)
        c.send_channel(self.channel.id, "let me in", client_id="x")
        err = cc.wait("ERROR")
        self.assertEqual((err["code"], err["client_id"]), ("forbidden", "x"))
        self.assertEqual(Message.objects.count(), 0)

    # ---- direct messages
    def test_direct_message_only_reaches_recipient(self):
        a, ca = self.connect(self.alice)
        b, cb = self.connect(self.bob)
        a.send_dm(self.bob.id, "psst")
        self.assertEqual(cb.wait("MESSAGE")["message"]["content"], "psst")
        self.assertEqual(Notification.objects.filter(user=self.bob).count(), 1)

    def test_dm_to_non_teammate_rejected(self):
        a, ca = self.connect(self.alice)
        a.send_dm(self.carol.id, "hi stranger")
        self.assertEqual(ca.wait("ERROR")["code"], "forbidden")

    def test_validation_errors(self):
        a, ca = self.connect(self.alice)
        a.send_channel(self.channel.id, "   ")
        self.assertEqual(ca.wait("ERROR")["code"], "empty_message")
        a.send_channel("nope", "x")
        self.assertEqual(ca.wait("ERROR")["code"], "bad_request")
        a.send_dm(self.alice.id, "to myself")
        self.assertEqual(ca.wait("ERROR")["code"], "bad_request")

    # ---- presence + concurrency
    def test_presence_updates(self):
        a, ca = self.connect(self.alice)
        self.assertEqual(ca.wait("PRESENCE_LIST")["online"], [])
        b, cb = self.connect(self.bob)
        self.assertEqual(ca.wait("PRESENCE"), {"type": "PRESENCE", "user_id": self.bob.id, "online": True})
        self.assertEqual(cb.wait("PRESENCE_LIST")["online"], [self.alice.id])
        b.close()
        self.assertFalse(ca.wait("PRESENCE")["online"])

    def test_many_concurrent_clients(self):
        users = [User.objects.create_user(f"u{i}", password="pw-12345678") for i in range(8)]
        for u in users:
            TeamMembership.objects.create(team=self.team, user=u)
        cols = [self.connect(u) for u in users]
        for i, (cl, _) in enumerate(cols):
            threading.Thread(target=cl.send_channel, args=(self.channel.id, f"m{i}")).start()
        for _, col in cols:
            seen = {col.wait("MESSAGE")["message"]["content"] for _ in range(8)}
            self.assertEqual(seen, {f"m{i}" for i in range(8)})

    # ---- REST
    def test_rest_history_unread_and_mark_read(self):
        a, ca = self.connect(self.alice)
        a.send_channel(self.channel.id, "one"); a.send_channel(self.channel.id, "two")
        a.send_dm(self.bob.id, "dm-1")
        ca.wait("ACK"); ca.wait("ACK"); ca.wait("ACK")

        api = APIClient(); api.force_authenticate(self.bob)
        hist = api.get(f"/api/comm/channels/{self.channel.id}/messages/").json()
        self.assertEqual([m["content"] for m in hist["results"]], ["one", "two"])
        dm = api.get(f"/api/comm/dm/{self.alice.id}/messages/").json()
        self.assertEqual([m["content"] for m in dm["results"]], ["dm-1"])

        unread = api.get("/api/comm/unread/").json()
        self.assertEqual(unread["total"], 3)
        self.assertEqual(unread["channels"][str(self.channel.id)], 2)
        self.assertEqual(unread["dms"][str(self.alice.id)], 1)

        api.post("/api/comm/notifications/read/", {"channel_id": self.channel.id}, format="json")
        self.assertEqual(api.get("/api/comm/unread/").json()["total"], 1)
        self.assertEqual(len(api.get("/api/comm/notifications/?unread=1").json()), 1)

    def test_rest_access_control(self):
        api = APIClient(); api.force_authenticate(self.carol)
        self.assertEqual(api.get(f"/api/comm/channels/{self.channel.id}/messages/").status_code, 403)
        self.assertEqual(api.get(f"/api/comm/dm/{self.alice.id}/messages/").status_code, 403)
        self.assertEqual(APIClient().get("/api/comm/unread/").status_code, 401)

    def test_contacts_lists_only_teammates(self):
        api = APIClient(); api.force_authenticate(self.alice)
        self.assertEqual([c["username"] for c in api.get("/api/comm/contacts/").json()], ["bob"])


# ----------------------------------------------------------------- bridge

def start_bridge(tcp_port):
    """Run the bridge in a thread; returns (ws_port, stop_function)."""
    free = socket.socket(); free.bind(("127.0.0.1", 0)); ws_port = free.getsockname()[1]; free.close()
    ready, holder = threading.Event(), {}

    def run():
        async def main():
            holder["loop"], holder["task"] = asyncio.get_running_loop(), asyncio.current_task()
            ready.set()
            await bridge.run_bridge("127.0.0.1", ws_port, "127.0.0.1", tcp_port, ["http://localhost:5173"])
        try:
            asyncio.run(main())
        except asyncio.CancelledError:
            pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start(); ready.wait(3); time.sleep(0.5)

    def stop():
        holder["loop"].call_soon_threadsafe(holder["task"].cancel)
        thread.join(3)
    return ws_port, stop

class BridgeTests(TransactionTestCase):
    """A WebSocket client (stand-in for the browser) goes through the opaque bridge."""

    def test_browser_path_through_bridge(self):
        from websockets.sync.client import connect

        alice = User.objects.create_user("alice", password="pw-alice-123")
        bob = User.objects.create_user("bob", password="pw-bob-12345")
        team = Team.objects.create(name="T", owner=alice)
        for u in (alice, bob):
            TeamMembership.objects.create(team=team, user=u)
        channel = Channel.objects.create(team=team, name="general", created_by=alice)

        server = ChatServer("127.0.0.1", 0, crypto.generate_rsa_private_key()); server.start()

        ws_port, stop_bridge = start_bridge(server.port)

        bob_events = Collector()
        bob_client = ChatClient("127.0.0.1", server.port, str(AccessToken.for_user(bob)), on_event=bob_events)

        try:
            with connect(f"ws://127.0.0.1:{ws_port}", origin="http://localhost:5173") as ws:
                # --- act like the browser: parse HELLO, wrap AES key, then speak AES-GCM
                hello = json.loads(ws.recv())
                pub = crypto.load_public_key_pem(hello["public_key"])
                key = crypto.generate_aes_key()
                ws.send(json.dumps({"type": "KEY_EXCHANGE", "key": base64.b64encode(crypto.rsa_wrap_key(pub, key)).decode()}).encode())
                sctr = rctr = 0

                def send(obj):
                    nonlocal sctr
                    ws.send(crypto.aes_gcm_encrypt(key, crypto.build_nonce(crypto.DIR_C2S, sctr), json.dumps(obj).encode())); sctr += 1

                def recv():
                    nonlocal rctr
                    data = crypto.aes_gcm_decrypt(key, crypto.build_nonce(crypto.DIR_S2C, rctr), ws.recv()); rctr += 1
                    return json.loads(data)

                self.assertEqual(recv()["type"], "READY")
                send({"type": "AUTH", "token": str(AccessToken.for_user(alice))})
                self.assertEqual(recv()["user"]["username"], "alice")
                send({"type": "SEND_CHANNEL", "channel_id": channel.id, "content": "via websocket", "client_id": "w1"})
                self.assertEqual(bob_events.wait("MESSAGE")["message"]["content"], "via websocket")
        finally:
            bob_client.close(); server.stop(); stop_bridge()

    def test_bridge_rejects_foreign_origin(self):
        from websockets.exceptions import InvalidStatus
        from websockets.sync.client import connect

        import logging
        logging.getLogger("websockets.server").setLevel(logging.CRITICAL)   # expected rejection noise
        ws_port, stop_bridge = start_bridge(1)
        try:
            with self.assertRaises(InvalidStatus):
                connect(f"ws://127.0.0.1:{ws_port}", origin="http://evil.example")
        finally:
            stop_bridge()
