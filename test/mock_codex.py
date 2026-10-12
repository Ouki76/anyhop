#!/usr/bin/env python3
"""Mock Codex (Responses API) upstream for anyhop smoke tests (port 9104)."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        auth = self.headers.get("Authorization", "")
        assert self.headers.get("Originator") == "codex_cli_rs"
        assert body.get("stream") is True, "codex backend requires stream"
        assert body.get("store") is False
        acc = self.headers.get("Chatgpt-Account-Id", "")

        with open("/tmp/codex-last-request.json", "w") as f:
            json.dump(body, f)

        if "cx-bad" in auth:
            self.send_response(429)
            self.send_header("Retry-After", "30")
            self.end_headers()
            self.wfile.write(b'{"error":{"type":"rate_limit"}}')
            return

        instr = body.get("instructions", "")
        last_text = ""
        for item in reversed(body.get("input", [])):
            if item.get("type") == "message":
                for c in item.get("content", []):
                    t = c.get("text")
                    if t:
                        last_text = t
                        break
            if last_text:
                break
        reply = f"[acc:{acc}][instr:{instr}] echo:{last_text}"

        want_tool = "call tool" in last_text

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()

        def send(d):
            self.wfile.write(f"data: {json.dumps(d)}\n\n".encode())
            self.wfile.flush()

        send({"type": "response.created", "response": {"id": "resp_mock"}})
        if want_tool:
            send({"type": "response.output_item.added", "item": {
                "type": "function_call", "id": "item_1", "call_id": "call_cx1",
                "name": "get_weather"}})
            send({"type": "response.function_call_arguments.delta", "item_id": "item_1",
                  "delta": "{\"ci"})
            send({"type": "response.function_call_arguments.delta", "item_id": "item_1",
                  "delta": "ty\":\"Moscow\"}"})
            send({"type": "response.completed", "response": {
                "usage": {"input_tokens": 20, "output_tokens": 9},
                "output": [{"type": "function_call"}]}})
        else:
            for word in ["Codex", " works", "!"]:
                send({"type": "response.output_text.delta", "delta": word})
            send({"type": "response.completed", "response": {
                "usage": {"input_tokens": 20, "output_tokens": 5},
                "output": [{"type": "message"}]}})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9104), H).serve_forever()
