"""
WebSocket <-> TCP bridge (Member 2).

Browsers cannot open raw TCP sockets, so the React app talks WebSocket to this
bridge and the bridge opens one TCP connection to the chat server per browser
tab.  The bridge is *opaque*: it only copies frames between the two sides and
never sees keys or plaintext - the RSA handshake and AES-256-GCM encryption
happen end-to-end between the browser (WebCrypto) and the TCP server.

    TCP frame  = 4-byte length + payload   <->   WebSocket binary message = payload
"""
import argparse
import asyncio
import logging
import struct

from websockets.asyncio.server import serve

log = logging.getLogger("netcollab.bridge")
MAX_FRAME = 2 * 1024 * 1024


async def _relay(ws, tcp_host, tcp_port):
    try:
        reader, writer = await asyncio.open_connection(tcp_host, tcp_port)
    except OSError:
        await ws.close(code=1011, reason="chat server unavailable")
        return

    async def tcp_to_ws():
        while True:
            (length,) = struct.unpack(">I", await reader.readexactly(4))
            if length > MAX_FRAME:
                return
            await ws.send(await reader.readexactly(length))

    async def ws_to_tcp():
        async for message in ws:
            if not isinstance(message, (bytes, bytearray)) or len(message) > MAX_FRAME:
                return
            writer.write(struct.pack(">I", len(message)) + bytes(message))
            await writer.drain()

    tasks = [asyncio.create_task(tcp_to_ws()), asyncio.create_task(ws_to_tcp())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def run_bridge(host, port, tcp_host, tcp_port, origins):
    async def handler(ws):
        log.info("browser connected: %s", ws.remote_address)
        await _relay(ws, tcp_host, tcp_port)
        log.info("browser disconnected: %s", ws.remote_address)

    async with serve(handler, host, port, origins=origins, max_size=MAX_FRAME):
        log.info("WebSocket bridge ws://%s:%s  ->  TCP %s:%s", host, port, tcp_host, tcp_port)
        await asyncio.get_running_loop().create_future()      # run forever


def main(argv=None):
    ap = argparse.ArgumentParser(description="NetCollab WebSocket<->TCP bridge")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9001)
    ap.add_argument("--tcp-host", default="127.0.0.1")
    ap.add_argument("--tcp-port", type=int, default=9000)
    ap.add_argument("--origin", action="append", default=None,
                    help="allowed browser origin (repeatable); default http://localhost:5173")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        asyncio.run(run_bridge(a.host, a.port, a.tcp_host, a.tcp_port, a.origin or ["http://localhost:5173"]))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
