// NetCollab - browser side of the secure chat channel (Member 2).
//
// WebSocket -> (opaque bridge) -> TCP chat server.   Same protocol as
// backend/communication/protocol.py:
//   1. server sends HELLO  {public_key (PEM), fingerprint}
//   2. we generate an AES-256 key, wrap it with RSA-OAEP(SHA-256) and send KEY_EXCHANGE
//   3. server answers READY encrypted with AES-256-GCM
//   4. every later frame is AES-GCM.  The 12-byte nonce is implicit:
//        4-byte direction tag ("C2S\0" / "S2C\0") + 8-byte big-endian counter
//      so replayed / reordered / modified frames fail authentication.

const TAG_C2S = [0x43, 0x32, 0x53, 0x00];
const TAG_S2C = [0x53, 0x32, 0x43, 0x00];
const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = globalThis.crypto.subtle;

const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function b64(bytes) {
  let s = "";
  new Uint8Array(bytes).forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s);
}

function nonce(tag, counter) {
  const n = new Uint8Array(12);
  n.set(tag, 0);
  const view = new DataView(n.buffer);
  view.setUint32(4, Math.floor(counter / 2 ** 32));
  view.setUint32(8, counter >>> 0);
  return n;
}

export class SecureSocket {
  /**
   * @param {string} url       ws://host:port of the bridge
   * @param {object} handlers  { onMessage(obj), onClose(reason) }
   */
  constructor(url, { onMessage = () => {}, onClose = () => {} } = {}) {
    this.url = url;
    this.onMessage = onMessage;
    this.onClose = onClose;
    this.state = "connecting";
    this.sendCtr = 0;
    this.recvCtr = 0;
    this.key = null;
    this.serverFingerprint = null;
    this._rx = Promise.resolve();   // frames are processed strictly in order
    this._tx = Promise.resolve();   // ... and sent strictly in order
  }

  /** Opens the socket, does the RSA/AES handshake and logs in with the JWT. */
  connect(token, expectedFingerprint = null) {
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err) => {
        if (!settled) { settled = true; reject(err instanceof Error ? err : new Error(String(err))); }
        this.close();
      };

      const ws = new WebSocket(this.url);
      ws.binaryType = "arraybuffer";
      this.ws = ws;

      ws.onerror = () => fail(new Error("Cannot reach the chat bridge"));
      ws.onclose = (ev) => {
        const wasOpen = this.state === "open";
        this.state = "closed";
        if (!settled) fail(new Error(ev.reason || "Connection closed during handshake"));
        else if (wasOpen) this.onClose(ev.reason || "closed");
      };

      ws.onmessage = (ev) => {
        const data = ev.data;
        this._rx = this._rx.then(async () => {
          try {
            if (this.state === "connecting") {
              await this._onHello(JSON.parse(dec.decode(data)), expectedFingerprint);
              this.state = "keyed";
            } else {
              const msg = await this._decrypt(data);
              if (this.state === "keyed") {
                if (msg.type !== "READY") throw new Error("Server did not confirm the session key");
                this.state = "authenticating";
                await this.send({ type: "AUTH", token });
              } else if (this.state === "authenticating") {
                if (msg.type === "AUTH_OK") {
                  this.state = "open";
                  settled = true;
                  resolve(msg.user);
                } else {
                  throw new Error(msg.message || "Login rejected");
                }
              } else {
                this.onMessage(msg);
              }
            }
          } catch (err) {
            fail(err);
          }
        });
      };
    });
  }

  async _onHello(hello, expectedFingerprint) {
    if (hello.type !== "HELLO" || hello.version !== 1) throw new Error("Unsupported server protocol");
    const der = pemToDer(hello.public_key);
    this.serverFingerprint = toHex(await subtle.digest("SHA-256", der));
    if (expectedFingerprint && this.serverFingerprint !== expectedFingerprint.toLowerCase()) {
      throw new Error("Server key fingerprint mismatch - possible man-in-the-middle");
    }
    const rsaKey = await subtle.importKey("spki", der, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    this.key = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const raw = await subtle.exportKey("raw", this.key);
    const wrapped = await subtle.encrypt({ name: "RSA-OAEP" }, rsaKey, raw);
    this.ws.send(enc.encode(JSON.stringify({ type: "KEY_EXCHANGE", key: b64(wrapped) })));
  }

  async _decrypt(data) {
    const iv = nonce(TAG_S2C, this.recvCtr++);
    const plain = await subtle.decrypt({ name: "AES-GCM", iv }, this.key, data);
    return JSON.parse(dec.decode(plain));
  }

  /** Encrypts and sends one JSON message (order is preserved). */
  send(obj) {
    this._tx = this._tx.then(async () => {
      const iv = nonce(TAG_C2S, this.sendCtr++);
      const cipher = await subtle.encrypt({ name: "AES-GCM", iv }, this.key, enc.encode(JSON.stringify(obj)));
      this.ws.send(cipher);
    });
    return this._tx;
  }

  close() {
    this.state = "closed";
    try { this.ws && this.ws.close(); } catch { /* already closed */ }
  }
}
