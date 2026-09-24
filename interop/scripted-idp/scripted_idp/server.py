#
# Copyright 2026 Revetware LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""HTTPS server (stdlib only). At M0 it serves GET /health and nothing else.

The TLS certificate chain and key are PEM files named by SCRIPTED_IDP_TLS_CERT and
SCRIPTED_IDP_TLS_KEY. There is no plaintext fallback: startup fails without them.
"""

import http.server
import json
import os
import signal
import ssl
import sys

from . import versions

PORT = 8443
TLS_CERT_ENV = "SCRIPTED_IDP_TLS_CERT"
TLS_KEY_ENV = "SCRIPTED_IDP_TLS_KEY"
READY_MARKER = "SCRIPTED_IDP_READY"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30

    def version_string(self):
        return "scripted-idp"

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "versions": self.server.health})
        else:
            self._send_json(404, {"error": "not found"})

    def _send_json(self, status, body):
        payload = json.dumps(body, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, tls_context, health):
        super().__init__(address, Handler)
        self.tls_context = tls_context
        self.health = health

    def get_request(self):
        # Wrap per connection and handshake on the handler thread, so one slow client
        # cannot stall accept().
        connection, address = self.socket.accept()
        return self.tls_context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False), address

    def handle_error(self, request, client_address):
        # One line per failed connection (for example a TLS handshake), not a traceback.
        print(f"connection from {client_address[0]} failed: {sys.exc_info()[1]!r}", file=sys.stderr, flush=True)


def tls_context():
    cert, key = os.environ.get(TLS_CERT_ENV), os.environ.get(TLS_KEY_ENV)
    if not cert or not key:
        raise SystemExit(f"{TLS_CERT_ENV} and {TLS_KEY_ENV} must name the TLS certificate chain and key (PEM)")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return context


def _exit_on_sigterm(signum, frame):
    # As PID 1 in a container, Python would otherwise ignore docker stop's SIGTERM.
    raise SystemExit(0)


def main(argv):
    if argv:
        raise SystemExit("usage: python -m scripted_idp serve")
    versions.check_libxml2_pairing()
    server = Server(("0.0.0.0", PORT), tls_context(), versions.versions())
    signal.signal(signal.SIGTERM, _exit_on_sigterm)
    print(f"{READY_MARKER} port={PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
