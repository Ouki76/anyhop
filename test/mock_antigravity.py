#!/usr/bin/env python3
"""Mock Antigravity (cloudcode-pa v1internal) upstream for anyhop smoke tests (port 9102).

- POST /v1internal:fetchAvailableModels -> {"models": {...}}
- POST /v1internal:generateContent     -> {"response": <gemini body>}
- POST /v1internal:streamGenerateContent -> SSE chunks wrapped in {"response": ...}
- Bearer token "ag-bad" -> 429
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


def gemini_response(text):
    return {
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": text}]},
            "finishReason": "STOP",
        }],
        "usageMetadata": {
            "promptTokenCount": 12,
            "candidatesTokenCount": 7,
            "totalTokenCount": 19,
        },
    }


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        auth = self.headers.get("Authorization", "")
        ua = self.headers.get("User-Agent", "")
        assert ua.startswith("antigravity/"), f"bad UA: {ua}"

        if "ag-bad" in auth:
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}')
            return

        if self.path.endswith(":fetchAvailableModels"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "models": {
                    "gemini-3-pro-high": {"displayName": "Gemini 3 Pro High"},
                    "gemini-3-flash": {"displayName": "Gemini 3 Flash"},
                }
            }).encode())
            return

        # Envelope checks
        assert body.get("project") == "test-project", f"missing project: {body}"
        assert body.get("userAgent") == "antigravity"
        inner = body.get("request", {})
        model = body.get("model", "?")
        last_text = ""
        for c in reversed(inner.get("contents", [])):
            for p in c.get("parts", []):
                if "text" in p:
                    last_text = p["text"]
                    break
            if last_text:
                break
        sys_txt = "".join(
            p.get("text", "") for p in inner.get("systemInstruction", {}).get("parts", [])
        )

        if ":streamGenerateContent" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for word in ["Antigravity", " stream", " works"]:
                chunk = {"response": {"candidates": [{"content": {"role": "model", "parts": [{"text": word}]}}]}}
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                self.wfile.flush()
            final = gemini_response("!")
            self.wfile.write(f"data: {json.dumps({'response': final})}\n\n".encode())
            self.wfile.flush()
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        reply = f"[{model}][sys:{sys_txt}] echo:{last_text}"
        self.wfile.write(json.dumps({"response": gemini_response(reply)}).encode())

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9102), H).serve_forever()
