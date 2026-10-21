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
        if self.path.endswith("/embeddings"):
            self.embeddings(body, auth)
            return
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
        if "bad-500" in auth:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":{"message":"upstream exploded"}}')
            return
        if "drain-key" in auth:
            # Nearly exhausted limit: 1/100, resets in 2s
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("x-ratelimit-remaining-requests", "1")
            self.send_header("x-ratelimit-limit-requests", "100")
            self.send_header("x-ratelimit-reset-requests", "2s")
            self.end_headers()
            self.wfile.write(json.dumps({
                "id": "chatcmpl-mock", "object": "chat.completion",
                "model": body.get("model"),
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "drain ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            }).encode())
            return
        if body.get("stream"):
            # Real SSE framing so streaming pass-through is actually exercised.
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            for tok in ("ok", " via", " mock"):
                chunk = {
                    "id": "chatcmpl-mock", "object": "chat.completion.chunk",
                    "model": body.get("model"),
                    "choices": [{"index": 0, "delta": {"content": tok}, "finish_reason": None}],
                }
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                self.wfile.flush()
            done = {
                "id": "chatcmpl-mock", "object": "chat.completion.chunk",
                "model": body.get("model"),
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
            self.wfile.write(f"data: {json.dumps(done)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
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

    def embeddings(self, body, auth):
        """OpenAI-shaped /v1/embeddings: one 3-dim vector per input."""
        if "bad-401" in auth:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":{"message":"invalid key"}}')
            return
        if "bad-500" in auth:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":{"message":"upstream exploded"}}')
            return
        inp = body.get("input")
        texts = [inp] if isinstance(inp, str) else (inp or [])
        data = [
            {"object": "embedding", "index": i, "embedding": [0.1 * (i + 1), 0.2, 0.3]}
            for i in range(len(texts))
        ]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "object": "list",
            "data": data,
            "model": body.get("model"),
            "usage": {"prompt_tokens": len(texts) * 2, "total_tokens": len(texts) * 2},
        }).encode())

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9100), H).serve_forever()
