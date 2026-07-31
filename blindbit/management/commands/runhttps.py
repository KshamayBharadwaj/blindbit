import os
import ssl

from django.conf import settings
from django.contrib.staticfiles.management.commands.runserver import Command as RunserverCommand
from django.core.servers.basehttp import WSGIServer


class SecureWSGIServer(WSGIServer):
    def __init__(self, *args, **kwargs):
        cert = os.environ.get('BLINDBIT_SSL_CERT', str(settings.BASE_DIR / 'devcerts' / 'cert.pem'))
        key = os.environ.get('BLINDBIT_SSL_KEY', str(settings.BASE_DIR / 'devcerts' / 'key.pem'))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.ssl_context = context
        super().__init__(*args, **kwargs)

    def get_request(self):
        sock, addr = super().get_request()
        return self.ssl_context.wrap_socket(sock, server_side=True), addr


class Command(RunserverCommand):
    help = 'Run the development server over HTTPS with a self-signed certificate.'

    server_cls = SecureWSGIServer
