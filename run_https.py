#!/usr/bin/env venv/bin/python
"""HTTPS dev server using the self-signed devcerts.

Django's `manage.py runserver` is HTTP only, so https://localhost:8000
always fails with:
  Bad HTTP/0.9 request type ('\\x16\\x03\\x01...')  <- TLS ClientHello

Use this instead when you need HTTPS (e.g. testing on LAN IP or
with BLINDBIT_ENABLE_SSL=true where Secure cookies require HTTPS).

Certs: devcerts/cert.pem + devcerts/key.pem (CN=localhost, 1yr)

Usage:
  venv/bin/python run_https.py              # https://localhost:8000
  venv/bin/python run_https.py 0.0.0.0:8443  # custom host:port
"""
import os, sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'blindbit.settings')

# Django setup before importing WSGI app
import django
django.setup()
from django.core.wsgi import get_wsgi_application

from werkzeug.serving import run_simple

def main():
    host_port = sys.argv[1] if len(sys.argv) > 1 else "localhost:8000"
    if ":" in host_port:
        host, port = host_port.rsplit(":", 1)
        port = int(port)
    else:
        host, port = host_port, 8000

    cert = BASE_DIR / "devcerts" / "cert.pem"
    key  = BASE_DIR / "devcerts" / "key.pem"
    if not cert.exists() or not key.exists():
        print(f"Missing {cert} or {key}", file=sys.stderr)
        sys.exit(1)

    app = get_wsgi_application()
    print(f"Serving HTTPS on https://{host}:{port}/  (ctrl+c to quit)")
    print(f"  cert={cert}  key={key}")
    # Werkzeug's reloader forks; disable if it causes issues with Django autoreload
    run_simple(host, port, app, use_reloader=True, use_debugger=True, ssl_context=(str(cert), str(key)))

if __name__ == "__main__":
    main()
