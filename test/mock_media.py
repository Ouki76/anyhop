#!/usr/bin/env python3
"""
Mock openai_compat provider for the pass-through endpoints: images, audio and a
minimal WebSocket endpoint for /v1/realtime. Stdlib only.

    python3 test/mock_media.py 9105
"""
import base64
import hashlib
import json
import socket
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9105
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _body(self):
        n = int(self.headers.get("content-length") or 0)
        return self.rfile.read(n) if n else b""

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self._body()
        auth = self.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return self._json(401, {"error": {"message": "no key", "type": "authentication_error"}})
        if self.path.startswith("/v1/images/generations"):
            req = json.loads(body or b"{}")
            return self._json(
                200,
                {
                    "created": 1,
                    "data": [{"b64_json": base64.b64encode(PNG).decode(), "revised_prompt": req.get("prompt", "")}],
                },
            )
        if self.path.startswith("/v1/images/edits"):
            # Echo the boundary so the test can prove the body was not re-encoded.
            ctype = self.headers.get("content-type", "")
            return self._json(200, {"created": 1, "data": [{"b64_json": base64.b64encode(PNG).decode()}], "echo_content_type": ctype, "echo_len": len(body)})
        if self.path.startswith("/v1/audio/speech"):
            data = b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\xff\xfb\x90\x00" * 8
            self.send_response(200)
            self.send_header("content-type", "audio/mpeg")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/v1/audio/transcriptions"):
            ctype = self.headers.get("content-type", "")
            return self._json(200, {"text": "hello", "echo_content_type": ctype, "echo_len": len(body)})
        if self.path.startswith("/v1/audio/translations"):
            return self._json(200, {"text": "hello"})
        return self._json(404, {"error": {"message": f"no route {self.path}", "type": "not_found_error"}})

    def do_GET(self):
        if self.path.startswith("/v1/realtime"):
            return self._websocket()
        # Model listing for catalog refreshes.
        if self.path.startswith("/v1/models"):
            return self._json(200, {"object": "list", "data": [{"id": "test-model", "object": "model"}]})
        return self._json(404, {"error": {"message": "nope", "type": "not_found_error"}})

    # --- minimal RFC 6455 server ---
    def _websocket(self):
        key = self.headers.get("sec-websocket-key")
        if not key:
            return self._json(400, {"error": {"message": "not a websocket request"}})
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("upgrade", "websocket")
        self.send_header("connection", "Upgrade")
        self.send_header("sec-websocket-accept", accept)
        self.end_headers()
        self.wfile.flush()
        sock = self.connection
        # First frame: prove the provider key arrived.
        auth = self.headers.get("authorization", "")
        self._send_text(sock, json.dumps({"type": "session.created", "key": auth.replace("Bearer ", "")}))
        while True:
            frame = self._read_frame(sock)
            if frame is None:
                return
            opcode, payload = frame
            if opcode == 8:  # close
                self._write_frame(sock, 8, payload)
                return
            if opcode == 9:  # ping
                self._write_frame(sock, 10, payload)
                continue
            if opcode in (1, 2):
                self._write_frame(sock, opcode, payload)  # echo

    def _send_text(self, sock, text):
        self._write_frame(sock, 1, text.encode())

    @staticmethod
    def _read_frame(sock):
        header = sock.recv(2)
        if len(header) < 2:
            return None
        b1, b2 = header[0], header[1]
        opcode = b1 & 0x0F
        masked = b2 & 0x80
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack(">H", sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", sock.recv(8))[0]
        mask = sock.recv(4) if masked else b"\x00" * 4
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        if masked:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return opcode, data

    @staticmethod
    def _write_frame(sock, opcode, payload):
        head = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            head += bytes([n])
        elif n < 65536:
            head += bytes([126]) + struct.pack(">H", n)
        else:
            head += bytes([127]) + struct.pack(">Q", n)
        sock.sendall(head + payload)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    srv = Server(("127.0.0.1", PORT), Handler)
    print(f"mock media on http://127.0.0.1:{PORT}", flush=True)
    srv.serve_forever()