#!/usr/bin/env python3
"""Mock Anthropic (/v1/messages) upstream for anyhop smoke tests (port 9103)."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        key = self.headers.get("x-api-key", "")
        assert self.headers.get("anthropic-version") == "2023-06-01"
        assert body.get("max_tokens"), "anthropic requires max_tokens"

        if "cl-bad" in key:
            self.send_response(429)
            self.send_header("Retry-After", "30")
            self.end_headers()
            self.wfile.write(b'{"type":"error","error":{"type":"rate_limit_error"}}')
            return

        with open("/tmp/anthropic-last-request.json", "w") as f:
            json.dump(body, f)

        last_text = ""
        for m in reversed(body.get("messages", [])):
            c = m.get("content")
            if isinstance(c, str):
                last_text = c
                break
            for b in c or []:
                if b.get("type") == "text" and b.get("text"):
                    last_text = b["text"]
                    break
            if last_text:
                break

        sys_txt = body.get("system", "")
        reply = f"[sys:{sys_txt}] echo:{last_text} (key:{key[-4:]})"

        want_tool = "call tool" in last_text
        content = []
        if want_tool:
            content.append({"type": "thinking", "thinking": "надо вызвать погоду"})
            content.append({"type": "tool_use", "id": "toolu_01", "name": "get_weather",
                            "input": {"city": "Moscow"}})
        else:
            content.append({"type": "text", "text": reply})

        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            def ev(t, d):
                self.wfile.write(f"event: {t}\ndata: {json.dumps(d)}\n\n".encode())
                self.wfile.flush()
            ev("message_start", {"type": "message_start", "message": {"usage": {"input_tokens": 10}}})
            if want_tool:
                ev("content_block_start", {"type": "content_block_start", "index": 0,
                   "content_block": {"type": "thinking", "thinking": ""}})
                ev("content_block_delta", {"type": "content_block_delta", "index": 0,
                   "delta": {"type": "thinking_delta", "thinking": "надо вызвать"}})
                ev("content_block_stop", {"type": "content_block_stop", "index": 0})
                ev("content_block_start", {"type": "content_block_start", "index": 1,
                   "content_block": {"type": "tool_use", "id": "toolu_01", "name": "get_weather"}})
                ev("content_block_delta", {"type": "content_block_delta", "index": 1,
                   "delta": {"type": "input_json_delta", "partial_json": "{\"ci"}})
                ev("content_block_delta", {"type": "content_block_delta", "index": 1,
                   "delta": {"type": "input_json_delta", "partial_json": "ty\":\"Moscow\"}"}})
                ev("content_block_stop", {"type": "content_block_stop", "index": 1})
                ev("message_delta", {"type": "message_delta",
                   "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 15}})
            else:
                ev("content_block_start", {"type": "content_block_start", "index": 0,
                   "content_block": {"type": "text", "text": ""}})
                ev("content_block_delta", {"type": "content_block_delta", "index": 0,
                   "delta": {"type": "text_delta", "text": reply}})
                ev("content_block_stop", {"type": "content_block_stop", "index": 0})
                ev("message_delta", {"type": "message_delta",
                   "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 8}})
            ev("message_stop", {"type": "message_stop"})
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "id": "msg_mock", "type": "message", "role": "assistant",
            "content": content,
            "stop_reason": "tool_use" if want_tool else "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 8},
        }).encode())

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9103), H).serve_forever()
