import logging
import time

from django.core.management.base import BaseCommand

from communication import conf, crypto
from communication.server import ChatServer


class Command(BaseCommand):
    help = "Run the NetCollab multi-client TCP chat server (RSA key exchange + AES-256-GCM)."

    def add_arguments(self, parser):
        parser.add_argument("--host", default=conf.TCP_HOST)
        parser.add_argument("--port", type=int, default=conf.TCP_PORT)

    def handle(self, *args, **opts):
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        private_key = crypto.load_or_create_private_key(conf.KEY_PATH)
        fingerprint = crypto.public_key_fingerprint(private_key.public_key())
        self.stdout.write(self.style.SUCCESS(f"Server RSA key: {conf.KEY_PATH}"))
        self.stdout.write(f"Public key fingerprint (SHA-256): {fingerprint}")

        server = ChatServer(opts["host"], opts["port"], private_key)
        server.start()
        self.stdout.write(self.style.SUCCESS(f"Listening on {opts['host']}:{server.port}  (Ctrl+C to stop)"))
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stdout.write("Shutting down...")
        finally:
            server.stop()
