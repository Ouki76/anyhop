#!/usr/bin/env python3
"""Mock Gemini upstream for anyhop smoke tests (port 9101).

- key "gkey-bad" -> 429 RESOURCE_EXHAUSTED
- streamGenerateContent?alt=sse -> Gemini SSE chunks
- generateContent -> Gemini JSON echoing last user text + system instruction
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        key = self.headers.get("x-goog-api-key", "")

        if "bad" in key:
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}')
            return

        last_text = ""
        for c in reversed(body.get("contents", [])):
            for p in c.get("parts", []):
                if "text" in p:
                    last_text = p["text"]
                    break
            if last_text:
                break
        sys_txt = "".join(
            p.get("text", "")
            for p in body.get("system_instruction", {}).get("parts", [])
        )
        reply = f"[sys:{sys_txt}] echo:{last_text} (key:{key[-4:]})"

        if ":streamGenerateContent" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for word in ["Hello", " from", " mock-gemini"]:
                self.wfile.write(
                    f"data: {json.dumps({'candidates': [{'content': {'role': 'model', 'parts': [{'text': word}]}}]})}\n\n".encode()
                )
                self.wfile.flush()
            final = {
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": "!"}]},
                    "finishReason": "STOP",
                }],
                "usageMetadata": {
                    "promptTokenCount": 5,
                    "candidatesTokenCount": 4,
                    "totalTokenCount": 9,
                },
            }
            self.wfile.write(f"data: {json.dumps(final)}\n\n".encode())
            self.wfile.flush()
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": reply}]},
                "finishReason": "STOP",
            }],
            "usageMetadata": {
                "promptTokenCount": 5,
                "candidatesTokenCount": 6,
                "totalTokenCount": 11,
            },
        }
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9101), H).serve_forever()
