"""A stand-in for the Weedout scan API.

Exists so the action's scripts can be tested end to end without a network, an
account, or a real key. It speaks the same shape as `POST /api/v1/scan` and
nothing else -- the point is to exercise install/scan/render, not to
reimplement the product.

Usage:

    python3 test/mock_api.py <port> <fixture.json>

Responds 401 without a bearer token, so the "did not run" path is reachable too.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    payload: dict = {}

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        if self.path != "/api/v1/scan":
            self._json(404, {"error": "not_found"})
            return
        auth = self.headers.get("Authorization", "")
        # One key is always refused, so the "could not run" path -- the one a
        # scanner must never confuse with "found nothing" -- can be tested.
        if not auth.startswith("Bearer ") or auth == "Bearer wo_bad_key":
            self._json(401, {"error": "invalid_key", "message": "That key was not accepted."})
            return

        # Drain the upload. Not reading it leaves the client writing into a
        # closed pipe, which surfaces as a connection error rather than a 200.
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)

        self._json(200, self.payload)

    def _json(self, status: int, body: dict) -> None:
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args: object) -> None:
        """Quiet. The test's own output is the thing worth reading."""


def main() -> None:
    port = int(sys.argv[1])
    with open(sys.argv[2], encoding="utf-8") as handle:
        Handler.payload = json.load(handle)
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
