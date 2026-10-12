#!/usr/bin/env python3
"""Mock OpenAI-compatible upstream for anyhop smoke tests.

- key "bad-429"  -> 429 + Retry-After: 30
- key "bad-401"  -> 401
- anything else  -> 200 with the key tail echoed back
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        auth = self.headers.get("Authorization", "")
        if "bad-429" in auth:
            self.send_response(429)
            self.send_header("Retry-After", "30")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":{"message":"rate limited"}}')
            return
        if "bad-401" in auth:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":{"message":"invalid key"}}')
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "model": body.get("model"),
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": f"ok via {auth[-9:]}"},
                "finish_reason": "stop",
            }],
        }
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9100), H).serve_forever()
