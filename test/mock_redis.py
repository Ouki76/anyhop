#!/usr/bin/env python3
"""
Minimal Redis stand-in for the multi-instance rate-limit check.

Speaks just enough RESP2 (PING, AUTH, SELECT, GET, SET..EX, DEL, EVAL) and
emulates the token-bucket Lua script the gateway ships, so the suite can prove
that two gateway *processes* share one budget without needing a real Redis.

    python3 test/mock_redis.py 6399
"""
import socket
import socketserver
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 6399
STORE = {}
LOCK = threading.Lock()


def encode_bulk(b):
    if b is None:
        return b"$-1\r\n"
    if isinstance(b, str):
        b = b.encode()
    return b"$%d\r\n%s\r\n" % (len(b), b)


def encode_int(n):
    return b":%d\r\n" % n


def encode_array(items):
    out = b"*%d\r\n" % len(items)
    for i in items:
        if isinstance(i, int):
            out += encode_int(i)
        else:
            out += encode_bulk(i)
    return out


def read_command(f):
    line = f.readline()
    if not line:
        return None
    if not line.startswith(b"*"):
        # Inline command (PING from some clients).
        return line.strip().split()
    n = int(line[1:])
    parts = []
    for _ in range(n):
        head = f.readline()
        if not head.startswith(b"$"):
            return None
        size = int(head[1:])
        parts.append(f.read(size))
        f.read(2)  # trailing CRLF
    return parts


def token_bucket(key, cap, rate, now_ms, ttl):
    """Mirror of TOKEN_BUCKET_LUA: returns (allowed, retry_ms)."""
    raw = STORE.get(key)
    tokens, last = cap, now_ms
    if raw:
        try:
            t, l = raw.split(b":")
            tokens, last = float(t), float(l)
        except ValueError:
            tokens, last = cap, now_ms
    elapsed = (now_ms - last) / 1000.0
    if elapsed < 0:
        elapsed = 0.0
    tokens = min(cap, tokens + elapsed * rate)
    if tokens >= 1:
        tokens -= 1
        allowed, retry = 1, 0
    else:
        allowed = 0
        retry = max(1, int(-(-((1 - tokens) / rate * 1000) // 1)))
    STORE[key] = b"%.6f:%.0f" % (tokens, now_ms)
    return allowed, retry


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            try:
                cmd = read_command(self.rfile)
            except (ValueError, OSError):
                return
            if not cmd:
                return
            name = cmd[0].upper()
            if name == b"PING":
                self.wfile.write(b"+PONG\r\n")
            elif name == b"AUTH":
                self.wfile.write(b"+OK\r\n")
            elif name == b"SELECT":
                self.wfile.write(b"+OK\r\n")
            elif name == b"GET":
                with LOCK:
                    val = STORE.get(cmd[1])
                self.wfile.write(encode_bulk(val))
            elif name == b"SET":
                with LOCK:
                    STORE[cmd[1]] = cmd[2]
                self.wfile.write(b"+OK\r\n")
            elif name == b"DEL":
                with LOCK:
                    STORE.pop(cmd[1], None)
                self.wfile.write(encode_int(1))
            elif name == b"EVAL":
                # EVAL script numkeys KEYS... ARGV...
                numkeys = int(cmd[2])
                key = cmd[3]
                argv = cmd[3 + numkeys:]
                try:
                    cap = float(argv[0])
                    rate = float(argv[1])
                    now_ms = float(argv[2])
                except (IndexError, ValueError):
                    self.wfile.write(b"-ERR bad args\r\n")
                    continue
                with LOCK:
                    allowed, retry = token_bucket(key, cap, rate, now_ms, 120)
                self.wfile.write(encode_array([allowed, retry]))
            elif name == b"COMMAND":
                self.wfile.write(encode_array([]))
            else:
                self.wfile.write(b"-ERR unknown command\r\n")
            self.wfile.flush()


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    srv = Server(("127.0.0.1", PORT), Handler)
    print(f"fake redis on 127.0.0.1:{PORT}", flush=True)
    srv.serve_forever()