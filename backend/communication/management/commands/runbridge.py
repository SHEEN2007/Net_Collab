from django.core.management.base import BaseCommand

from communication import bridge, conf


class Command(BaseCommand):
    help = "Run the WebSocket<->TCP bridge that lets the React app reach the TCP chat server."

    def add_arguments(self, parser):
        parser.add_argument("--host", default=conf.WS_HOST)
        parser.add_argument("--port", type=int, default=conf.WS_PORT)

    def handle(self, *args, **opts):
        argv = ["--host", opts["host"], "--port", str(opts["port"]),
                "--tcp-host", conf.TCP_HOST, "--tcp-port", str(conf.TCP_PORT)]
        for origin in conf.WS_ALLOWED_ORIGINS:
            argv += ["--origin", origin]
        bridge.main(argv)
