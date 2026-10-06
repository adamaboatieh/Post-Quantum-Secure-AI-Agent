"""Small localhost HTTP boundary around ``ToolServer`` for the demo."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from server.tool_server import RequestRejected, ToolServer


def create_http_server(service: ToolServer, *, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *args) -> None:
            return

        def send_json(self, status: int, document: dict) -> None:
            body = json.dumps(document, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            if self.path != "/tool":
                self.send_json(404, {"status": "rejected", "code": "NOT_FOUND"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 128 * 1024:
                    raise ValueError
                envelope = json.loads(self.rfile.read(length).decode("utf-8"))
                self.send_json(200, service.execute(envelope))
            except RequestRejected as exc:
                status = {
                    "INVALID_SIGNATURE": 401,
                    "UNTRUSTED_KEY": 401,
                    "AUTHORIZATION_DENIED": 403,
                    "EXECUTION_DENIED": 403,
                    "REPLAY_DETECTED": 409,
                    "EXPIRED": 422,
                    "NOT_YET_VALID": 422,
                    "REPLAY_UNAVAILABLE": 503,
                }.get(exc.code, 400)
                self.send_json(status, {"status": "rejected", "code": exc.code, "error": str(exc)})
            except (ValueError, UnicodeError, json.JSONDecodeError):
                self.send_json(400, {"status": "rejected", "code": "MALFORMED_REQUEST"})

    return ThreadingHTTPServer((host, port), Handler)
