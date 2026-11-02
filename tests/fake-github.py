#!/usr/bin/env python3
import json
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not self.path.startswith("/app/installations/"):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        with open("/tmp/fake-github-request.json", "wb") as f:
            f.write(body)
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        response = json.dumps({"token": "ghs_test_token", "expires_at": expires}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        pass


HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
