#!/usr/bin/env python3
"""
Chaos / resilience harness for the anyhop gateway.  **stdlib only.**

What it does
------------
Starts its own gateway instance(s) on free ports with a throwaway config and
state file, points them at an in-process mock upstream whose behaviour is
selected by the *model name* (one misbehaviour per model), then drives the
scenarios below and prints one `ok`/`FAIL` line per check plus a final
`CHAOS PASS=n FAIL=m`.

Scenarios
---------
1. upstream misbehaviour   500 forever, 429 ±Retry-After, body cut mid-stream,
                           headers-then-silence, garbage instead of SSE, a
                           Content-Length longer than the body, socket closed
                           mid-response, 200 with an HTML page.
1b. cooldown tuning        whether [tuning] base_backoff / rate_limit_cooldown /
                           max_cooldown actually reach the key pool.
2. slow / hostile clients  a 1 B/s reader, a client that disconnects mid-stream
                           (is the upstream cancelled? does the in-flight
                           counter return to 0?), a huge body sent slowly.
3. concurrency             200 parallel chat requests through 2 keys with
                           max_concurrent limits.
4. config churn            PUT /api/config x50 under traffic, then a config that
                           drops a key that is in use, then puts it back.
5. restart                 SIGTERM idle, SIGTERM mid-stream, SIGKILL, restart.
6. rate limits             rpm boundary, Retry-After accuracy, redis backend
                           while Redis is down (fail_open true and false).
7. metrics                 /metrics stays servable; histogram counts match the
                           requests actually made; exposition is well-formed.

Safety
------
Every instance gets its own free port, its own config copy and its own redb
state file inside a private temp dir, so this can run next to other gateways
and mocks.  All processes are killed on exit (also on Ctrl-C).

Usage
-----
    python3 test/chaos_test.py                 # everything
    python3 test/chaos_test.py --only 1,6      # selected scenarios
    python3 test/chaos_test.py --keep          # keep the temp dir + logs
    ANYHOP_BIN=/path/to/anyhop python3 test/chaos_test.py

Exit code: 0 when every check passed, 1 otherwise.
"""

from __future__ import annotations

import collections
import http.client
import json
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("ANYHOP_BIN", os.path.join(ROOT, "target/release/anyhop"))
GW_KEY = "chaos-gw-api-key"
ADMIN_KEY = "chaos-admin-key"

PASS = 0
FAIL = 0
FINDINGS = []          # dicts: tag, sev, title, request, expected, observed
GATEWAYS = []          # every Gateway we started (cleanup)
TMPDIR = None
MOCK = None

# How long a response may take before we call it a hang.
SHORT = 4.0


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def ok(tag: str, msg: str) -> None:
    global PASS
    PASS += 1
    print(f"  ok   [{tag}] {msg}", flush=True)


def fail(tag: str, msg: str, sev: str = "MEDIUM", request: str = "",
         expected: str = "", observed: str = "") -> None:
    global FAIL
    FAIL += 1
    FINDINGS.append({
        "tag": tag, "sev": sev, "title": msg, "request": request,
        "expected": expected, "observed": observed,
    })
    print(f"  FAIL [{tag}] {msg}", flush=True)


def note(msg: str) -> None:
    print(f"  ..   {msg}", flush=True)


def check(tag: str, cond: bool, good: str, bad: str, **kw) -> bool:
    if cond:
        ok(tag, good)
        return True
    fail(tag, bad, **kw)
    return False


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------

def free_port() -> int:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def dead_port():
    """A port that is *bound but not listening* → connects get ECONNREFUSED.

    Holding the socket keeps the port reserved for the duration of the run, so
    nothing else can start listening there and make the "Redis is down"
    scenario pass for the wrong reason.
    """
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    return s, s.getsockname()[1]


def wait_for(pred, timeout: float, interval: float = 0.05) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if pred():
                return True
        except Exception:  # noqa: BLE001 - a probe that throws is just "not yet"
            pass
        time.sleep(interval)
    return False


class Resp:
    def __init__(self, status=None, headers=None, body=b"", truncated=False,
                 error=None, elapsed=0.0):
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.truncated = truncated
        self.error = error
        self.elapsed = elapsed

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        try:
            return json.loads(self.body)
        except Exception:  # noqa: BLE001
            return None

    def err_type(self):
        v = self.json()
        if isinstance(v, dict) and isinstance(v.get("error"), dict):
            return v["error"].get("type")
        return None

    def __repr__(self) -> str:
        extra = " truncated" if self.truncated else ""
        if self.error:
            extra += f" err={self.error}"
        return f"<Resp {self.status} {len(self.body)}B{extra} {self.elapsed:.2f}s>"


def request(port: int, method: str, path: str, body=None, token=None,
            timeout: float = 10.0, raw_body: bytes | None = None,
            headers: dict | None = None) -> Resp:
    """One HTTP request; never raises (errors land in Resp.error)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    hdrs = {"Content-Type": "application/json"}
    if token:
        hdrs["Authorization"] = "Bearer " + token
    if headers:
        hdrs.update(headers)
    payload = raw_body if raw_body is not None else (
        json.dumps(body).encode() if body is not None else None)
    t0 = time.time()
    try:
        conn.request(method, path, body=payload, headers=hdrs)
        r = conn.getresponse()
        hdrs_in = {k.lower(): v for k, v in r.getheaders()}
        try:
            data = r.read()
            trunc = False
        except http.client.IncompleteRead as e:
            data, trunc = e.partial, True
        except (socket.timeout, TimeoutError):
            return Resp(None, hdrs_in, b"", False, "timeout", time.time() - t0)
        except (ConnectionResetError, BrokenPipeError) as e:
            return Resp(None, hdrs_in, b"", True, f"reset:{e}", time.time() - t0)
        return Resp(r.status, hdrs_in, data, trunc, None, time.time() - t0)
    except (socket.timeout, TimeoutError):
        return Resp(None, {}, b"", False, "timeout", time.time() - t0)
    except (ConnectionResetError, BrokenPipeError) as e:
        return Resp(None, {}, b"", True, f"reset:{e}", time.time() - t0)
    except Exception as e:  # noqa: BLE001 - connection refused and friends
        return Resp(None, {}, b"", False, f"{type(e).__name__}:{e}", time.time() - t0)
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def chat(port: int, model: str, token: str = GW_KEY, stream: bool = False,
         timeout: float = 10.0, content: str = "hi") -> Resp:
    return request(port, "POST", "/v1/chat/completions", {
        "model": f"mock/{model}",
        "messages": [{"role": "user", "content": content}],
        "stream": stream,
    }, token=token, timeout=timeout)


class Stream:
    """An open streaming response: headers already read, body read on demand."""

    def __init__(self, port: int, model: str, token: str = GW_KEY,
                 timeout: float = 10.0):
        self.conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        body = json.dumps({
            "model": f"mock/{model}",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": True,
        }).encode()
        self.conn.request("POST", "/v1/chat/completions", body=body,
                          headers={"Content-Type": "application/json",
                                   "Authorization": "Bearer " + token})
        self.t0 = time.time()
        self.resp = self.conn.getresponse()
        self.status = self.resp.status
        self.headers = {k.lower(): v for k, v in self.resp.getheaders()}
        self.data = b""
        self.eof = False
        self.error = None

    def read1(self, n: int = 65536) -> bytes:
        """Read up to n bytes; b'' means EOF. Records errors instead of raising."""
        try:
            chunk = self.resp.read1(n)
            if not chunk:
                self.eof = True
            self.data += chunk
            return chunk
        except http.client.IncompleteRead as e:
            self.data += e.partial
            self.eof = True
            self.error = "incomplete_read"
            return b""
        except (socket.timeout, TimeoutError):
            self.error = "timeout"
            return b""
        except (ConnectionResetError, BrokenPipeError) as e:
            self.eof = True
            self.error = f"reset:{e}"
            return b""
        except Exception as e:  # noqa: BLE001
            self.eof = True
            self.error = f"{type(e).__name__}:{e}"
            return b""

    def read_for(self, seconds: float) -> bytes:
        """Read whatever arrives within `seconds` (or until EOF)."""
        deadline = time.time() + seconds
        out = b""
        while time.time() < deadline and not self.eof:
            chunk = self.read1(4096)
            if not chunk:
                break
            out += chunk
        return out

    def abort(self) -> None:
        """What a browser tab does: vanish without reading to the end."""
        try:
            if self.conn.sock:
                self.conn.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# mock upstream: one misbehaviour per model name
# ---------------------------------------------------------------------------

class MockState:
    def __init__(self):
        self.lock = threading.Lock()
        self.hits = collections.Counter()        # mode -> requests
        self.key_hits = collections.Counter()    # upstream bearer key -> requests
        self.last_key_by_mode = {}               # mode -> the key of the last request
        self.stream_frames = 0                   # frames written by slow-stream
        self.stream_aborted = 0                  # upstream write failed
        self.active_streams = 0
        self.stop = threading.Event()

    def record(self, mode: str, key: str):
        with self.lock:
            self.hits[mode] += 1
            if key:
                self.key_hits[key] += 1
                self.last_key_by_mode[mode] = key

    def snap(self):
        with self.lock:
            return {
                "hits": dict(self.hits),
                "key_hits": dict(self.key_hits),
                "stream_frames": self.stream_frames,
                "stream_aborted": self.stream_aborted,
            }


def _sse(content: str, model: str) -> bytes:
    chunk = {
        "id": "chatcmpl-mock", "object": "chat.completion.chunk", "model": model,
        "choices": [{"index": 0, "delta": {"content": content},
                     "finish_reason": None}],
    }
    return f"data: {json.dumps(chunk)}\n\n".encode()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------
    def log_message(self, *a):
        pass

    def _head(self, status, ctype=None, clen=None, extra=None, chunked=False):
        self.send_response(status)
        if ctype:
            self.send_header("Content-Type", ctype)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        elif clen is not None:
            self.send_header("Content-Length", str(clen))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _chunk(self, data: bytes):
        self.wfile.write(b"%X\r\n" % len(data) + data + b"\r\n")
        self.wfile.flush()

    def _json(self, status, payload: bytes, ctype="application/json", extra=None):
        self._head(status, ctype, len(payload), extra)
        self.wfile.write(payload)

    def _die(self, rst=False):
        """Close the connection abruptly (RST when asked)."""
        self.close_connection = True
        try:
            if rst:
                self.connection.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            self.connection.close()
        except OSError:
            pass

    # -- entry points ------------------------------------------------------
    def do_GET(self):
        if self.path.rstrip("/").endswith("/models"):
            body = json.dumps({"object": "list", "data": [
                {"id": "ok", "object": "model"}]}).encode()
            self._json(200, body)
        else:
            self._json(404, b'{"error":{"message":"no such path"}}')

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            body = json.loads(raw or b"{}")
        except Exception:  # noqa: BLE001
            body = {}
        model = str(body.get("model") or "")
        mode = model.rsplit("/", 1)[-1]
        key = (self.headers.get("Authorization") or "").replace("Bearer ", "").strip()
        MOCK.state.record(mode, key)
        fn = getattr(self, "m_" + mode.replace("-", "_"), self.m_ok)
        try:
            fn(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:  # noqa: BLE001 - a mock bug must not kill the server
            traceback.print_exc()

    # -- behaviours --------------------------------------------------------
    def m_ok(self, body):
        time.sleep(0.05)
        payload = json.dumps({
            "id": "chatcmpl-mock", "object": "chat.completion",
            "model": body.get("model"),
            "choices": [{"index": 0, "message": {"role": "assistant",
                                                 "content": "ok"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2,
                      "total_tokens": 5},
        }).encode()
        self._json(200, payload)

    def m_fast(self, body):
        """Like ok, but 100 ms: keeps 200 parallel requests genuinely overlapping."""
        time.sleep(0.1)
        self.m_ok(body)

    def m_stream(self, body):
        self._head(200, "text/event-stream", chunked=True)
        for tok in ("ok", " via", " mock"):
            self._chunk(_sse(tok, str(body.get("model"))))
        self._chunk(b"data: [DONE]\n\n")
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def m_slow_stream(self, body):
        with MOCK.state.lock:
            MOCK.state.active_streams += 1
        try:
            self._head(200, "text/event-stream", chunked=True)
            for i in range(300):          # 30 s max, 10 frames/s
                if MOCK.state.stop.is_set():
                    return
                try:
                    self._chunk(_sse(f"tok{i} ", str(body.get("model"))))
                except (BrokenPipeError, ConnectionResetError, OSError):
                    # The gateway dropped our response: it noticed the client left.
                    with MOCK.state.lock:
                        MOCK.state.stream_aborted += 1
                    return
                with MOCK.state.lock:
                    MOCK.state.stream_frames += 1
                time.sleep(0.1)
        finally:
            with MOCK.state.lock:
                MOCK.state.active_streams -= 1

    def m_midstream_cut(self, body):
        self._head(200, "text/event-stream", chunked=True)
        self._chunk(_sse("first ", str(body.get("model"))))
        self._chunk(_sse("second ", str(body.get("model"))))
        self._die()                        # no terminating chunk

    def m_rst_mid(self, body):
        self._head(200, "application/json", chunked=True)
        self._chunk(b'{"id":"chatcmpl-mock","choices":[')
        self._die(rst=True)

    def m_noreply(self, body):
        """Accept the request and never answer: not even headers."""
        MOCK.state.stop.wait(25)

    def m_silent(self, body):
        """200 + headers, then nothing at all: no body, no close."""
        self._head(200, "text/event-stream", chunked=True)
        MOCK.state.stop.wait(25)

    def m_garbage(self, body):
        """Non-SSE junk labelled as an event stream, close-delimited."""
        junk = b"<html><body>502 Bad Gateway from a CDN</body></html>"
        self._head(200, "text/event-stream", extra={"Connection": "close"})
        self.wfile.write(junk)
        self.wfile.flush()
        self.close_connection = True

    def m_cl_short(self, body):
        """Content-Length says 4096, we send 32 bytes and hang up."""
        self._head(200, "application/json", clen=4096)
        self.wfile.write(b'{"id":"truncated","choices":[]}   ')
        self.wfile.flush()
        self._die()

    def m_html200(self, body):
        page = (b"<!doctype html><html><head><title>Welcome</title></head>"
                b"<body><h1>nginx</h1><p>Please enable JavaScript.</p>"
                b"</body></html>")
        self._json(200, page, ctype="text/html; charset=utf-8")

    def m_fail500(self, body):
        self._json(500, b'{"error":{"message":"upstream exploded"}}')

    def m_rate429ra(self, body):
        self._json(429, b'{"error":{"message":"rate limited"}}',
                   extra={"Retry-After": "4"})

    def m_rate429nora(self, body):
        self._json(429, b'{"error":{"message":"slow down"}}')

    def m_rate429long(self, body):
        self._json(429, b'{"error":{"message":"come back tomorrow"}}',
                   extra={"Retry-After": "999"})


class Mock:
    def __init__(self, port: int):
        self.port = port
        self.state = MockState()
        self.srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
        self.srv.daemon_threads = True
        self.thread = threading.Thread(target=self.srv.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.state.stop.set()
        try:
            self.srv.shutdown()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.srv.server_close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# gateway instances
# ---------------------------------------------------------------------------

class Gateway:
    def __init__(self, cfg_path: str, port: int, name: str):
        self.cfg_path = cfg_path
        self.port = port
        self.name = name
        self.log_path = os.path.join(TMPDIR, f"{name}.log")
        self._log = open(self.log_path, "wb")
        env = {**os.environ, "ANYHOP_CONFIG": cfg_path, "RUST_LOG": "info"}
        self.proc = subprocess.Popen(
            [BIN], env=env, stdout=self._log, stderr=subprocess.STDOUT,
            start_new_session=True)
        GATEWAYS.append(self)

    # -- lifecycle ---------------------------------------------------------
    def wait(self, timeout: float = 20.0) -> bool:
        def up():
            if self.proc.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", self.port),
                                              timeout=0.3):
                    return True
            except OSError:
                return False
        return wait_for(up, timeout)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def terminate(self, timeout: float = 10.0):
        """SIGTERM; returns (exited_within_timeout, seconds, exit_code)."""
        t0 = time.time()
        if self.proc.poll() is not None:
            return True, 0.0, self.proc.returncode
        try:
            self.proc.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            return True, 0.0, self.proc.returncode
        try:
            code = self.proc.wait(timeout=timeout)
            return True, time.time() - t0, code
        except subprocess.TimeoutExpired:
            return False, time.time() - t0, None

    def kill9(self):
        try:
            self.proc.send_signal(signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    def stop(self):
        """Deterministic teardown from the cleanup path."""
        if self.proc.poll() is None:
            try:
                self.proc.send_signal(signal.SIGTERM)
                self.proc.wait(timeout=4)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                self.kill9()
        try:
            self._log.close()
        except Exception:  # noqa: BLE001
            pass

    # -- introspection -----------------------------------------------------
    def log_text(self) -> str:
        try:
            with open(self.log_path, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def log_tail(self, n=4) -> str:
        lines = [l for l in self.log_text().splitlines() if l.strip()]
        return " | ".join(lines[-n:])


# ---------------------------------------------------------------------------
# gateway helpers
# ---------------------------------------------------------------------------

def admin(port: int, path: str, method: str = "GET", body=None, timeout=10.0) -> Resp:
    return request(port, method, path, body, token=ADMIN_KEY, timeout=timeout)


def providers(port: int) -> list:
    r = admin(port, "/api/providers")
    if r.status != 200:
        raise RuntimeError(f"/api/providers -> {r.status} {r.text()[:200]}")
    return r.json()


def key_snaps(port: int, provider="mock") -> list:
    for p in providers(port):
        if p["name"] == provider:
            return p["keys"]
    return []


def keys_settled(port: int) -> bool:
    try:
        ks = key_snaps(port)
    except Exception:  # noqa: BLE001
        return False
    return bool(ks) and all(k["status"] == "active" and k["in_flight"] == 0
                            for k in ks)


def wait_keys(port: int, timeout: float = 8.0) -> bool:
    return wait_for(lambda: keys_settled(port), timeout, 0.1)


def metrics(port: int, timeout=10.0) -> str:
    r = admin(port, "/metrics", timeout=timeout)
    if r.status != 200:
        raise RuntimeError(f"/metrics -> {r.status}")
    return r.text()


def parse_samples(text: str):
    """[(name, labels_str, value)] for every sample line."""
    out = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name = line.split("{")[0].split(" ")[0]
        labels = ""
        if "{" in line:
            labels = line[line.index("{") + 1:line.rindex("}")]
        try:
            value = float(line.rsplit(" ", 1)[1])
        except (ValueError, IndexError):
            continue
        out.append((name, labels, value))
    return out


def metric_sum(text: str, name: str, contains: str = "") -> float:
    return sum(v for n, labels, v in parse_samples(text)
               if n == name and contains in labels)


def histogram_counts(text: str) -> dict:
    """labels -> _count for anyhop_http_request_duration_seconds."""
    out = {}
    for name, labels, value in parse_samples(text):
        if name == "anyhop_http_request_duration_seconds_count":
            out[labels] = int(value)
    return out


def in_flight_all_zero(port: int) -> bool:
    vals = [v for n, labels, v in parse_samples(metrics(port))
            if n == "anyhop_key_in_flight"]
    return bool(vals) and all(v == 0 for v in vals)


def prom_problems(text: str):
    """Sample lines that appear before their family's `# TYPE` line."""
    typed = set()
    problems = []
    for line in text.splitlines():
        if line.startswith("# TYPE "):
            parts = line.split()
            if len(parts) >= 3:
                typed.add(parts[2])
        elif line and not line.startswith("#"):
            name = line.split("{")[0].split(" ")[0]
            base = name
            for suf in ("_bucket", "_sum", "_count"):
                if name.endswith(suf):
                    base = name[:-len(suf)]
                    break
            if base not in typed:
                problems.append((base, line[:100]))
    return problems


def toml_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def base_config(port: int, *, state_file="", keys=("chaos-key-1", "chaos-key-2"),
                models=("ok",), provider_max_concurrent=0,
                max_retries=2, tuning=None, client_keys="",
                mock_port=None) -> str:
    """A minimal, fully explicit config (no wildcard model list, so the gateway
    never polls /v1/models from the mock)."""
    key_block = "[" + ", ".join(toml_str(k) for k in keys) + "]"
    model_block = "[" + ", ".join(toml_str(m) for m in models) + "]"
    mc = f"max_concurrent = {provider_max_concurrent}\n" if provider_max_concurrent else ""
    knobs = {
        "base_backoff_secs": 1,
        "rate_limit_cooldown_secs": 3,
        "max_cooldown_secs": 60,
        "connect_timeout_secs": 2,
        "persist_interval_secs": 1,
        "client_body_timeout_secs": 1,
        "shutdown_grace_secs": 2,
    }
    knobs.update(tuning or {})
    tuning_block = "\n".join(f"{k} = {v}" for k, v in knobs.items())
    return f"""[server]
listen = "127.0.0.1:{port}"
api_key = {toml_str(GW_KEY)}
admin_key = {toml_str(ADMIN_KEY)}
state_file = {toml_str(state_file)}
max_retries = {max_retries}
attempt_timeout_secs = 3
max_body_bytes = 1048576
events_history = 50
requests_history = 50
models_refresh_secs = 0

[tuning]
{tuning_block}

[[providers]]
name = "mock"
type = "openai_compat"
base_url = {toml_str(f"http://127.0.0.1:{mock_port}/v1")}
strategy = "round_robin"
keys = {key_block}
models = {model_block}
{mc}{client_keys}
"""


def write_file(path: str, text: str) -> str:
    with open(path, "w") as f:
        f.write(text)
    return path


def start_gateway(name: str, cfg_text: str, port: int) -> Gateway:
    cfg_path = os.path.join(TMPDIR, f"{name}.toml")
    write_file(cfg_path, cfg_text)
    gw = Gateway(cfg_path, port, name)
    if not gw.wait():
        raise RuntimeError(f"gateway {name} did not start on port {port}:\n"
                           f"{gw.log_tail(8)}")
    return gw


# ---------------------------------------------------------------------------
# scenario 1 — upstream misbehaviour
# ---------------------------------------------------------------------------

def scenario1(gw: Gateway) -> None:
    port = gw.port
    print("\n== 1. upstream misbehaviour ==", flush=True)

    # --- 500 forever ------------------------------------------------------
    r = chat(port, "fail500", timeout=SHORT + 6)
    if r.status == 500:
        fail("1.1", "upstream 500 leaked to the client as 500 (should be the "
                    "designed 503 exhaustion)", "HIGH",
             "POST /v1/chat/completions model=mock/fail500 (max_retries=2, 2 keys)",
             "503 + {'error':{'type':'provider_unavailable'}}",
             f"{r.status} {r.text()[:120]}")
    else:
        check("1.1",
              r.status == 503 and r.err_type() == "provider_unavailable",
              f"500-forever → {r.status} {r.err_type()} with Retry-After "
              f"{r.headers.get('retry-after', '-')}",
              f"500-forever gave an unexpected answer: {r!r} {r.text()[:120]}",
              sev="HIGH", request="POST /v1/chat/completions model=mock/fail500",
              expected="503 provider_unavailable",
              observed=f"{r!r} {r.text()[:120]}")

    # --- gateway health while both keys are benched -----------------------
    h = admin(port, "/healthz")
    p = admin(port, "/api/providers")
    m = admin(port, "/metrics")
    check("1.2", h.status == 200 and p.status == 200 and m.status == 200,
          "/healthz, /api/providers and /metrics all 200 with every key benched",
          f"control plane unhealthy after an upstream 5xx storm: health={h.status} "
          f"providers={p.status} metrics={m.status}",
          sev="HIGH", request="GET /healthz + /api/providers + /metrics",
          expected="200/200/200", observed=f"{h.status}/{p.status}/{m.status}")

    ks = key_snaps(port)
    bad = [k for k in ks if k["status"] not in ("active", "cooldown")]
    check("1.3", len(ks) == 2 and not bad,
          "both keys in cooldown after 5xx (none dead, none lost)",
          f"key health after 5xx is wrong: "
          f"{[(k['masked'], k['status']) for k in ks]}",
          sev="HIGH", request="GET /api/providers after 500-forever",
          expected="2 keys, status active|cooldown",
          observed=str([(k["masked"], k["status"]) for k in ks]))

    # --- recovery ---------------------------------------------------------
    recovered = wait_keys(port, 8)
    r = chat(port, "ok", timeout=SHORT + 4)
    check("1.4", recovered and r.status == 200,
          "keys leave the 5xx cooldown on their own and serve again",
          f"keys did not recover from the 5xx backoff (recovered={recovered}, "
          f"next request {r.status})",
          sev="HIGH", request="wait for the cooldown, then POST model=mock/ok",
          expected="both keys active, then 200",
          observed=f"recovered={recovered} status={r.status}")

    # --- stream that stops mid-body --------------------------------------
    st = Stream(port, "midstream-cut", timeout=SHORT + 6)
    st.read_for(SHORT)
    signalled = st.error == "incomplete_read" or st.eof
    check("1.5", st.status == 200 and signalled and st.error != "timeout",
          f"upstream cut mid-stream → client saw a premature EOF "
          f"({len(st.data)}B, error={st.error})",
          f"mid-stream cut was not surfaced as a premature EOF: status={st.status} "
          f"error={st.error} got={st.data[:80]!r}",
          sev="HIGH",
          request="POST /v1/chat/completions stream=true model=mock/midstream-cut",
          expected="200 then EOF with a truncated body",
          observed=f"status={st.status} eof={st.eof} error={st.error} "
                   f"bytes={len(st.data)}")
    check("1.6", wait_for(lambda: in_flight_all_zero(port), 4),
          "in-flight counter back to 0 after the truncated stream",
          "in-flight slot leaked after a truncated stream "
          f"({[k['in_flight'] for k in key_snaps(port)]})",
          sev="HIGH", request="GET /metrics after the cut stream",
          expected="anyhop_key_in_flight == 0",
          observed=str([k["in_flight"] for k in key_snaps(port)]))

    # --- headers then silence --------------------------------------------
    # Wait well past the 3 s attempt timeout: if nothing arrives, the request has
    # no body timeout at all (the mock holds the socket for 25 s).
    hang_budget = 7.0
    t0 = time.time()
    st = Stream(port, "silent", timeout=hang_budget)
    first = st.read1(1)
    waited = time.time() - t0
    if not first and waited >= hang_budget - 0.5:
        fail("1.7", f"no response-body timeout: the client hung {waited:.1f}s with "
                    "zero bytes after the upstream sent headers and went silent",
             "HIGH",
             "POST /v1/chat/completions stream=true model=mock/silent "
             "(attempt_timeout_secs=3)",
             "the request must fail or close within a few seconds instead of hanging",
             f"status={st.status}, first byte never arrived "
             f"({waited:.1f}s, error={st.error})")
    else:
        ok("1.7", f"headers-then-silence closed after {waited:.1f}s "
                  f"(status={st.status})")
    st.abort()
    check("1.8", wait_for(lambda: in_flight_all_zero(port), 5),
          "key slot released after the silent-upstream client gave up",
          "in-flight slot still held after the client gave up on a silent upstream "
          f"({[k['in_flight'] for k in key_snaps(port)]})",
          sev="HIGH", request="GET /metrics after aborting the silent stream",
          expected="in_flight 0",
          observed=str([k["in_flight"] for k in key_snaps(port)]))
    wait_keys(port, 6)

    # --- silence *before* any header: the attempt timeout must fire --------
    t0 = time.time()
    r = chat(port, "noreply", timeout=SHORT + 8)
    dt = time.time() - t0
    check("1.8b", r.status == 503 and dt < 10,
          f"an upstream that never answers is cut off by attempt_timeout "
          f"({r.status} after {dt:.1f}s)",
          f"an upstream that never sends headers was not timed out cleanly: "
          f"status={r.status} after {dt:.1f}s (attempt_timeout_secs=3)",
          sev="HIGH", request="POST model=mock/noreply (no response at all)",
          expected="503 within ~2 x attempt_timeout", observed=f"{r.status} in {dt:.1f}s")
    note("(the attempt timeout covers the wait for headers only: the same silence "
         "after a 200 head hangs forever, see 1.7)")
    wait_keys(port, 10)

    # --- garbage instead of SSE ------------------------------------------
    st = Stream(port, "garbage", timeout=SHORT)
    data = st.read_for(SHORT)
    check("1.9", st.status == 200 and b"<html>" in data and st.error != "timeout",
          f"non-SSE garbage relayed verbatim ({len(data)}B) and the response closed",
          f"garbage response behaved badly: status={st.status} error={st.error} "
          f"bytes={len(data)}",
          sev="MEDIUM",
          request="POST /v1/chat/completions stream=true model=mock/garbage",
          expected="pass-through then clean close",
          observed=f"status={st.status} error={st.error} bytes={len(data)}")
    if st.status == 200:
        note("garbage was delivered as text/event-stream (the proxy does not "
             "validate SSE framing)")

    # --- Content-Length larger than the body ------------------------------
    r = chat(port, "cl-short", timeout=SHORT + 4)
    check("1.10", r.status in (502, 503, 504) and not r.truncated,
          f"Content-Length > body → clean {r.status} {r.err_type()}",
          f"short body leaked as status={r.status} truncated={r.truncated} "
          f"({len(r.body)}B) — the client cannot tell it is incomplete",
          sev="HIGH",
          request="POST /v1/chat/completions model=mock/cl-short "
                  "(Content-Length 4096, 32 bytes sent)",
          expected="502/503 with a JSON error", observed=f"{r!r}")

    # --- socket reset mid-response ---------------------------------------
    r = chat(port, "rst-mid", timeout=SHORT + 4)
    check("1.11", r.status in (502, 503, 504),
          f"socket reset mid-response → {r.status} {r.err_type()}",
          f"RST mid-response gave status={r.status} truncated={r.truncated}",
          sev="HIGH", request="POST /v1/chat/completions model=mock/rst-mid",
          expected="502/503", observed=f"{r!r}")

    # --- 200 with an HTML page -------------------------------------------
    r = chat(port, "html200", timeout=SHORT)
    ct = r.headers.get("content-type", "")
    if r.status == 200 and ct.startswith("text/html"):
        fail("1.12", "a 200 text/html page is relayed as a successful chat "
                     "completion (no upstream body validation — clients, LB health "
                     "checks and dashboards all see 200)",
             "MEDIUM",
             "POST /v1/chat/completions model=mock/html200 (upstream answers 200 "
             "with an nginx HTML page)",
             "a non-JSON body on /v1/chat/completions should surface as an upstream "
             "error, or at least be counted as a failure",
             f"200, content-type={ct}, {len(r.body)}B, key counted as a success")
    else:
        ok("1.12", f"HTML page answered with {r.status} {ct}")

    # The 429 paths (and the cooldown maths) live in scenario1b: they bench the
    # keys for a long time, which would poison the rest of this instance.


# ---------------------------------------------------------------------------
# scenario 1b — upstream 429 handling and the [tuning] cooldowns
# ---------------------------------------------------------------------------

def tuning_instance(name: str, knobs: dict, models=("ok", "fail500",
                                                          "rate429ra",
                                                          "rate429nora",
                                                          "rate429long")) -> Gateway:
    """A throwaway instance so a 60 s/999 s cooldown cannot leak into other checks."""
    port = free_port()
    cfg = base_config(port, state_file=os.path.join(TMPDIR, f"{name}.redb"),
                      models=models, provider_max_concurrent=4,
                      tuning=knobs, mock_port=MOCK.port)
    return start_gateway(name, cfg, port)


def scenario1b() -> None:
    print("\n== 1b. upstream 429 handling / [tuning] cooldowns ==", flush=True)
    tuning = {"base_backoff_secs": 1, "rate_limit_cooldown_secs": 3,
              "max_cooldown_secs": 20, "client_body_timeout_secs": 1}

    # T0: prove the config was loaded and reported back.
    gw = tuning_instance("gw1b0", tuning)
    try:
        srv = admin(gw.port, "/api/server").json() or {}
        t = (srv.get("tuning") or {})
        check("1.13", t.get("base_backoff_secs") == 1
              and t.get("rate_limit_cooldown_secs") == 3
              and t.get("max_cooldown_secs") == 20,
              f"/api/server reports the configured [tuning] "
              f"(base_backoff={t.get('base_backoff_secs')}, "
              f"rate_limit_cooldown={t.get('rate_limit_cooldown_secs')}, "
              f"max_cooldown={t.get('max_cooldown_secs')})",
              f"/api/server does not report the configured [tuning]: {t}",
              sev="LOW", request="GET /api/server",
              expected="{base_backoff_secs:1, rate_limit_cooldown_secs:3, "
                       "max_cooldown_secs:20}",
              observed=str(t))

        # T1: 5xx backoff must start at base_backoff_secs (1 s), not at 5 s.
        chat(gw.port, "fail500", timeout=SHORT)
        ks = key_snaps(gw.port)
        remaining = max((k["cooldown_remaining_secs"] for k in ks), default=0)
        check("1.14", remaining <= 2,
              f"5xx backoff uses base_backoff_secs=1 (cooldown {remaining}s)",
              f"5xx backoff ignores [tuning] base_backoff_secs=1: the key was benched "
              f"for {remaining}s (the built-in default is 5 s). KeyPool::new() is "
              "called without the configured Tuning, so every pool-level tuning value "
              "silently reverts to the default",
              sev="HIGH", request="POST model=mock/fail500 on a config with "
                                 "base_backoff_secs = 1",
              expected="cooldown ≈ 1s", observed=f"{remaining}s")
    finally:
        gw.stop()

    # T2: Retry-After is honoured (this path does work).
    gw = tuning_instance("gw1b2", tuning)
    try:
        r = chat(gw.port, "rate429ra", timeout=SHORT)
        ks = key_snaps(gw.port)
        remaining = max((k["cooldown_remaining_secs"] for k in ks), default=0)
        check("1.15", r.status == 503 and 2 <= remaining <= 5,
              f"429 + Retry-After: 4 → {r.status}, cooldown {remaining}s "
              f"(the upstream value was honoured)",
              f"429 + Retry-After: 4 handled wrongly: status={r.status} "
              f"cooldowns={[k['cooldown_remaining_secs'] for k in ks]} (expected ≈4s)",
              sev="MEDIUM", request="POST model=mock/rate429ra (Retry-After: 4)",
              expected="503 + cooldown ≈ 4s",
              observed=f"status={r.status} "
                       f"cooldowns={[k['cooldown_remaining_secs'] for k in ks]}")
    finally:
        gw.stop()

    # T3: 429 without Retry-After must use rate_limit_cooldown_secs (3 s).
    gw = tuning_instance("gw1b3", tuning)
    try:
        r = chat(gw.port, "rate429nora", timeout=SHORT)
        ks = key_snaps(gw.port)
        remaining = max((k["cooldown_remaining_secs"] for k in ks), default=0)
        check("1.16", r.status == 503 and 1 <= remaining <= 3,
              f"429 without Retry-After → {r.status}, cooldown {remaining}s "
              f"(rate_limit_cooldown_secs=3)",
              f"429 without Retry-After ignores rate_limit_cooldown_secs=3: the keys "
              f"were benched {remaining}s (built-in default 60 s), so a single 429 "
              "takes a key out for a minute even though the operator configured 3 s",
              sev="HIGH", request="POST model=mock/rate429nora with "
                                 "rate_limit_cooldown_secs = 3",
              expected="503 + cooldown 3s",
              observed=f"status={r.status} cooldowns="
                       f"{[k['cooldown_remaining_secs'] for k in ks]}")
    finally:
        gw.stop()

    # T4: a huge Retry-After must be clamped to max_cooldown_secs (20 s).
    gw = tuning_instance("gw1b4", tuning)
    try:
        r = chat(gw.port, "rate429long", timeout=SHORT)
        ks = key_snaps(gw.port)
        remaining = max((k["cooldown_remaining_secs"] for k in ks), default=0)
        check("1.17", remaining <= 20,
              f"Retry-After: 999 clamped to max_cooldown_secs=20 ({remaining}s)",
              f"Retry-After: 999 is not clamped to max_cooldown_secs=20: the keys "
              f"were benched {remaining}s (the clamp silently uses the 3600 s "
              "default), so one hostile/buggy upstream header can bench the whole "
              "pool for an hour",
              sev="HIGH", request="POST model=mock/rate429long (Retry-After: 999) "
                                 "with max_cooldown_secs = 20",
              expected="cooldown ≤ 20s", observed=f"{remaining}s")
    finally:
        gw.stop()


# ---------------------------------------------------------------------------
# scenario 2 — slow / hostile clients
# ---------------------------------------------------------------------------

def scenario2(gw: Gateway) -> None:
    port = gw.port
    print("\n== 2. slow / hostile clients ==", flush=True)
    # Scenario 1 hammers the same instance with 5xx/429s, so its keys may still be
    # cooling down. Starting here without waiting made every check report "no key
    # was ever picked" — an artefact, not a gateway fault.
    if not wait_keys(port, 15):
        note("scenario 2: keys still cooling from scenario 1; waiting for recovery")

    # --- a 1 B/s reader must not block anybody ---------------------------
    slow = Stream(port, "slow-stream", timeout=15)
    got = slow.read1(1)
    t0 = time.time()
    r = chat(port, "ok", timeout=SHORT + 2)
    dt = time.time() - t0
    check("2.1", bool(got) and r.status == 200 and dt < 4,
          f"a 1 B/s reader does not block other clients (next request 200 in {dt:.2f}s)",
          f"a slow reader blocked the pool: second request {r.status} after {dt:.1f}s",
          sev="HIGH", request="open a slow stream, then POST model=mock/ok",
          expected="200 quickly", observed=f"{r.status} in {dt:.1f}s")

    h = admin(port, "/healthz", timeout=2)
    m = admin(port, "/metrics", timeout=3)
    check("2.2", h.status == 200 and m.status == 200,
          "control plane still answers while a client trickles reads",
          f"slow reader stalled the control plane: health={h.status} "
          f"metrics={m.status}",
          sev="MEDIUM",
          request="GET /healthz + /metrics with a slow reader attached",
          expected="200/200", observed=f"{h.status}/{m.status}")

    in_fl = [k["in_flight"] for k in key_snaps(port)]
    check("2.3", sum(in_fl) == 1,
          f"exactly one key slot held by the slow stream {in_fl}",
          f"slow stream holds {sum(in_fl)} slots (expected 1) {in_fl}",
          sev="MEDIUM", request="GET /api/providers with one slow stream open",
          expected="sum(in_flight) == 1", observed=str(in_fl))
    slow.abort()
    wait_for(lambda: in_flight_all_zero(port), 5)

    # --- client disconnects mid-stream -----------------------------------
    before = MOCK.state.snap()
    st = Stream(port, "slow-stream", timeout=15)
    st.read_for(1.0)
    st.abort()

    def upstream_stopped():
        return MOCK.state.snap()["stream_aborted"] > before["stream_aborted"]

    cancelled = wait_for(upstream_stopped, 5, 0.1)
    after = MOCK.state.snap()
    check("2.4", cancelled,
          "a client disconnect cancels the upstream request (write aborted)",
          "the upstream request keeps streaming after the client disconnected "
          f"(frames {before['stream_frames']} → {after['stream_frames']}, no abort "
          "recorded) — it burns quota and a key slot for nothing",
          sev="HIGH",
          request="open stream model=mock/slow-stream, read 1s, close the socket",
          expected="the mock observes a broken pipe shortly after",
          observed=f"aborted={after['stream_aborted'] - before['stream_aborted']} "
                   f"frames={after['stream_frames'] - before['stream_frames']}")

    check("2.5", wait_for(lambda: in_flight_all_zero(port), 5),
          "key in-flight counter returns to 0 after a mid-stream disconnect",
          "key slot leaked after a mid-stream disconnect "
          f"({[k['in_flight'] for k in key_snaps(port)]})",
          sev="HIGH", request="GET /metrics after the disconnect",
          expected="anyhop_key_in_flight == 0",
          observed=str([k["in_flight"] for k in key_snaps(port)]))

    st2 = Stream(port, "slow-stream", token="sk-chaos-one", timeout=15)
    st2.read_for(0.6)
    st2.abort()
    time.sleep(0.3)
    r = chat(port, "ok", token="sk-chaos-one", timeout=SHORT + 2)
    check("2.6", r.status == 200,
          "client-key concurrency slot released after a mid-stream disconnect",
          "a client key with max_concurrent=1 stayed saturated after a disconnect "
          f"(next request {r.status})",
          sev="HIGH",
          request="disconnect, then POST model=mock/ok with sk-chaos-one",
          expected="200", observed=f"{r.status} {r.text()[:80]}")

    # --- huge body sent slowly (slowloris) -------------------------------
    hdrs = (f"POST /v1/chat/completions HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Authorization: Bearer sk-chaos-one\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: 524288\r\n\r\n").encode()
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(hdrs + b'{"model":"mock/ok","messages":[')
    time.sleep(0.2)
    r = chat(port, "ok", token="sk-chaos-one", timeout=3)
    held = r.status == 429
    rdy, _, _ = select.select([s], [], [], 3)
    still_open = True
    if rdy:
        try:
            # A 4xx reply (or any data) followed by a close IS the guard working:
            # what we are looking for is a server that never reacts at all.
            got = s.recv(65536)
            if got:
                # Drain whatever is left and require the peer to hang up.
                s.settimeout(2)
                try:
                    while s.recv(65536):
                        pass
                except OSError:
                    pass
                still_open = False
            else:
                still_open = False
        except OSError:
            still_open = False
    if still_open:
        fail("2.7", "no read/idle timeout on the request body: a client sending a "
                    "body at ~100 B/s holds a connection (and a client-key "
                    "concurrency slot) indefinitely — slowloris",
             "MEDIUM",
             "POST /v1/chat/completions with Content-Length: 524288, body trickled, "
             "socket kept open",
             "the request should be aborted once the body stops arriving",
             "after 3s the connection was still open and the 1-slot client key was "
             f"still charged (second request → {r.status})")
    else:
        ok("2.7", "a half-sent body is eventually closed by the server")

    h = admin(port, "/healthz", timeout=2)
    check("2.8", h.status == 200,
          "/healthz answers while a body is being dribbled in",
          f"/healthz stalled ({h.status}) while a slow body was in flight",
          sev="MEDIUM", request="GET /healthz during the slow upload",
          expected="200", observed=str(h.status))
    if held:
        note("the half-sent body holds the client-key slot (concurrency is charged "
             "before the body is read) — correct for the cap, but it makes the "
             "slowloris cheap")
    s.close()
    time.sleep(0.3)
    r = chat(port, "ok", token="sk-chaos-one", timeout=SHORT + 2)
    check("2.9", r.status == 200,
          "client-key slot reclaimed after an abandoned half-sent body",
          f"slot leaked after an abandoned upload (next request {r.status})",
          sev="HIGH", request="close the half-sent body, then POST with sk-chaos-one",
          expected="200", observed=str(r.status))

    # --- oversized body is refused -------------------------------------
    t0 = time.time()
    status = send_oversized(port, 2 * 1024 * 1024)
    dt = time.time() - t0
    check("2.10", status == 413 and dt < 3,
          f"a 2 MiB body → 413 in {dt:.2f}s (max_body_bytes = 1 MiB)",
          f"an oversized body was not rejected with 413: status={status} after "
          f"{dt:.1f}s",
          sev="LOW", request="POST /v1/chat/completions with a 2 MiB body "
                            "(max_body_bytes = 1 MiB)",
          expected="413", observed=f"{status} in {dt:.1f}s")
    wait_keys(port, 6)


def send_oversized(port: int, total: int, chunk: int = 65536):
    """Upload more than max_body_bytes, watching for an early 413.

    Returns the HTTP status (or None). A 413 may arrive while we are still
    writing, so the socket is polled between chunks and a write error after a
    413 has been seen still counts as a 413.
    """
    head = (f"POST /v1/chat/completions HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Authorization: Bearer {GW_KEY}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {total}\r\n\r\n").encode()
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    status = None
    try:
        s.sendall(head)
        payload = b"x" * chunk
        sent = 0
        while sent < total:
            rdy, _, _ = select.select([s], [], [], 0)
            if rdy:
                status = _status_of(s.recv(4096))
                break
            s.sendall(payload)
            sent += len(payload)
        if status is None:
            rdy, _, _ = select.select([s], [], [], 3)
            if rdy:
                status = _status_of(s.recv(4096))
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    return status


def _status_of(blob: bytes):
    try:
        line = blob.split(b"\r\n", 1)[0].decode("latin-1")
        return int(line.split()[1])
    except (IndexError, ValueError):
        return None


# ---------------------------------------------------------------------------
# scenario 3 — concurrency
# ---------------------------------------------------------------------------

def scenario3(gw: Gateway) -> None:
    port = gw.port
    print("\n== 3. concurrency (200 parallel, 2 keys, max_concurrent=2 each) ==",
          flush=True)

    results = []
    lock = threading.Lock()
    probe = {}
    keys_before = MOCK.state.snap()["key_hits"]

    def one(_i):
        t_req = time.time()
        r = chat(port, "fast", token="sk-load", timeout=30)
        # How long the client waited matters as much as the status: a 429 from the
        # queue deadline ("come back shortly") and a 429 that fails in 1 ms
        # ("saturation fails fast") look identical in a counter.
        r.elapsed = time.time() - t_req
        with lock:
            results.append(r)

    def probe_control_plane():
        t0 = time.time()
        h = admin(port, "/healthz", timeout=6)
        m = admin(port, "/metrics", timeout=6)
        probe["health"] = (h.status, time.time() - t0)
        probe["metrics"] = (m.status, time.time() - t0)

    threads = [threading.Thread(target=one, args=(i,)) for i in range(200)]
    t0 = time.time()
    for t in threads:
        t.start()
    time.sleep(0.15)
    pt = threading.Thread(target=probe_control_plane)
    pt.start()
    for t in threads:
        t.join(timeout=60)
    elapsed = time.time() - t0
    pt.join(timeout=10)

    codes = collections.Counter(r.status for r in results)
    note(f"200 requests in {elapsed:.1f}s → {dict(codes)}")

    check("3.1", len(results) == 200,
          "all 200 requests got an answer (no client-side hangs)",
          f"only {len(results)}/200 requests answered within 30s",
          sev="HIGH", request="200 x POST /v1/chat/completions model=mock/fast",
          expected="200 responses", observed=f"{len(results)}")

    unexpected = [r for r in results if r.status not in (200, 429, 503)]
    check("3.2", not unexpected,
          "no unexpected status under load (only 200 / designed 429 / designed 503)",
          f"unexpected statuses under load: "
          f"{collections.Counter(r.status for r in unexpected)} "
          f"(e.g. {unexpected[0].text()[:120] if unexpected else ''})",
          sev="HIGH",
          request="200 x POST /v1/chat/completions, 2 keys x max_concurrent=2",
          expected="⊆ {200, 429, 503}",
          observed=str(dict(collections.Counter(r.status for r in results))))

    bad_503 = [r for r in results
               if r.status == 503 and r.err_type() != "provider_unavailable"]
    check("3.3", not bad_503,
          "every 503 carries the designed provider_unavailable envelope",
          f"{len(bad_503)} 503(s) without the designed body: "
          f"{bad_503[0].text()[:120] if bad_503 else ''}",
          sev="MEDIUM", request="inspect the 503 bodies",
          expected="{'error':{'type':'provider_unavailable'}}",
          observed=f"{len(bad_503)} malformed")

    bad_429 = [r for r in results
               if r.status == 429 and r.err_type() != "rate_limit_exceeded"]
    check("3.4", not bad_429,
          "every 429 carries the designed rate_limit_exceeded envelope",
          f"{len(bad_429)} 429(s) without the designed body",
          sev="MEDIUM", request="inspect the 429 bodies",
          expected="rate_limit_exceeded", observed=f"{len(bad_429)} malformed")

    sample_503 = next((r for r in results if r.status == 503), None)
    if sample_503 is not None:
        note(f"sample 503 body: {sample_503.text()[:110]} "
             f"(retry-after={sample_503.headers.get('retry-after', 'absent')})")
    served = codes.get(200, 0)
    limited = [r for r in results if r.status == 429]
    n_429 = len(limited)
    # Saturation contract, not a throughput wish: 4 slots at 100 ms is ~40 rps, so
    # 200 requests need ~5 s — exactly the queue budget. What must hold is that the
    # overflow was *queued first* (a 429 that waited ~the budget, carrying
    # Retry-After) rather than failed in a millisecond, and that the pool used all
    # of its capacity (asserted by 3.10 and by the served count).
    waited = sorted(r.elapsed for r in limited)
    median_wait = waited[len(waited) // 2] if waited else 0.0
    ra_on_429 = sum(1 for r in limited if "retry-after" in r.headers)
    fast_fails = sum(1 for r in limited if r.elapsed < 0.5)
    ok_contract = (
        n_429 == 0
        or (fast_fails == 0 and ra_on_429 == n_429 and median_wait >= 1.0)
    )
    if ok_contract:
        ok("3.5", f"{served}/200 served, {n_429} queued out with 429 + "
                  f"Retry-After after {median_wait:.1f}s ({dict(codes)})")
    else:
        fail("3.5", f"saturation fails fast: {fast_fails}/{n_429} 429s in <0.5 s, "
                   f"{ra_on_429}/{n_429} carry Retry-After, median wait "
                   f"{median_wait:.2f}s ({dict(codes)})",
             "HIGH",
             "200 parallel POST /v1/chat/completions, pool = 2 keys x "
             "max_concurrent=2, upstream latency 100 ms",
             "overflow beyond [tuning] capacity_wait_ms is a 429 + Retry-After "
             "after the queue budget, never an instant rejection",
             f"{served}/200 served, {dict(codes)}, median 429 wait {median_wait:.2f}s")

    ks = key_snaps(port)
    dead = [k for k in ks if k["status"] == "dead"]
    check("3.6", len(ks) == 2 and not dead,
          "key health sane after the storm (2 keys, none dead)",
          f"key health after load: {[(k['masked'], k['status']) for k in ks]}",
          sev="HIGH", request="GET /api/providers after the storm",
          expected="2 keys, none dead",
          observed=str([(k["masked"], k["status"]) for k in ks]))

    check("3.7", wait_for(lambda: all(k["in_flight"] == 0 for k in key_snaps(port)), 6),
          "in-flight counters return to 0 after the storm",
          "in-flight leaked after the storm: "
          f"{[(k['masked'], k['in_flight']) for k in key_snaps(port)]}",
          sev="HIGH", request="GET /api/providers after the storm",
          expected="all in_flight 0",
          observed=str([k["in_flight"] for k in key_snaps(port)]))

    if "health" in probe:
        hs, ht = probe["health"]
        ms, mt = probe["metrics"]
        check("3.8", hs == 200 and ms == 200 and ht < 5 and mt < 5,
              f"control plane served under load (healthz {ht:.2f}s, metrics {mt:.2f}s)",
              f"control plane slow/failed under load: healthz {hs} {ht:.1f}s, "
              f"metrics {ms} {mt:.1f}s",
              sev="MEDIUM",
              request="GET /healthz + /metrics during the 200-request storm",
              expected="200 within a couple of seconds",
              observed=f"{hs} {ht:.1f}s / {ms} {mt:.1f}s")

    r = chat(port, "fast", token="sk-load", timeout=SHORT + 4)
    check("3.9", r.status == 200,
          "a normal request succeeds right after the storm",
          f"gateway is not usable after the storm ({r.status})",
          sev="HIGH", request="POST after the storm", expected="200",
          observed=str(r.status))

    snap = MOCK.state.snap()
    spread = {k: snap["key_hits"].get(k, 0) - keys_before.get(k, 0)
              for k in ("chaos-key-1", "chaos-key-2")}
    used = [k for k, n in spread.items() if n > 0]
    check("3.10", len(used) == 2,
          f"load spread across both keys ({spread})",
          f"only {used} received upstream traffic during the storm ({spread})",
          sev="LOW", request="mock key usage during the storm (delta)",
          expected="both keys used", observed=str(spread))


# ---------------------------------------------------------------------------
# scenario 4 — config churn
# ---------------------------------------------------------------------------

def scenario4(gw: Gateway, cfg_text: str) -> None:
    port = gw.port
    print("\n== 4. config churn (hot reload under load) ==", flush=True)

    ids_before = sorted(k["id"] for k in key_snaps(port))
    stop = threading.Event()
    traffic = {"statuses": [], "errors": []}

    def load_thread(_n):
        while not stop.is_set():
            r = chat(port, "fast", token="sk-load", timeout=15)
            traffic["statuses"].append(r.status)
            if r.status is None:
                traffic["errors"].append(r.error)
            time.sleep(0.02)

    threads = [threading.Thread(target=load_thread, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()

    put_codes = []
    t0 = time.time()
    for _ in range(50):
        r = admin(port, "/api/config", "PUT", {"toml": cfg_text})
        put_codes.append(r.status)
        # Pace the churn so the reloads really overlap with the traffic instead
        # of finishing inside one request's latency.
        time.sleep(0.02)
    churn_secs = time.time() - t0
    stop.set()
    for t in threads:
        t.join(timeout=20)

    bad_puts = [c for c in put_codes if c != 200]
    check("4.1", not bad_puts,
          f"50 identical PUT /api/config in {churn_secs:.2f}s → all 200",
          f"{len(bad_puts)} of 50 reloads failed: {set(bad_puts)}",
          sev="HIGH",
          request="50 x PUT /api/config (identical body) while 4 threads send chat",
          expected="200 for all 50", observed=str(collections.Counter(put_codes)))

    st = collections.Counter(traffic["statuses"])
    hard = [c for c in traffic["statuses"] if c is None or c >= 500]
    check("4.2", not hard,
          f"no request failed during 50 hot reloads ({dict(st)})",
          f"traffic saw {len(hard)} hard failures during reload: {dict(st)} "
          f"errors={traffic['errors'][:3]}",
          sev="HIGH",
          request="chat traffic concurrent with 50 x PUT /api/config",
          expected="only 200 (429/503 at worst)", observed=f"{dict(st)}")

    ids_after = sorted(k["id"] for k in key_snaps(port))
    check("4.3", ids_before == ids_after and len(ids_after) == 2,
          "no keys lost across 50 reloads (same key ids)",
          f"key set changed across reloads: {ids_before} → {ids_after}",
          sev="HIGH", request="GET /api/providers before/after the churn",
          expected="identical 2-key set",
          observed=f"{ids_before} → {ids_after}")

    got = admin(port, "/api/config")
    check("4.4", got.status == 200 and got.text() == cfg_text,
          "config file is byte-identical to what was PUT 50 times",
          "PUT /api/config mutated the file it was given "
          f"(status={got.status}, {len(got.body)}B vs {len(cfg_text)}B)",
          sev="MEDIUM", request="GET /api/config after the churn",
          expected="byte-identical TOML",
          observed=f"{len(got.body)}B vs {len(cfg_text)}B")

    # --- invalid config is rejected, the running one survives -------------
    broken = cfg_text.replace('keys = ["chaos-key-1", "chaos-key-2"]', "keys = []")
    r = admin(port, "/api/config", "PUT", {"toml": broken})
    got = admin(port, "/api/config")
    still_ok = chat(port, "fast", token="sk-load", timeout=SHORT)
    check("4.5", r.status == 400 and got.text() == cfg_text and still_ok.status == 200,
          f"invalid config rejected with {r.status} and the running config was kept",
          f"invalid config handling is wrong: status={r.status}, "
          f"file_changed={got.text() != cfg_text}, next_request={still_ok.status}",
          sev="HIGH", request="PUT /api/config with keys = [] (no credentials)",
          expected="400, file unchanged, traffic unaffected",
          observed=f"{r.status} file_changed={got.text() != cfg_text} "
                   f"next={still_ok.status}")

    # --- remove the key that is in use, then put it back ------------------
    st = Stream(port, "slow-stream", token="sk-load", timeout=15)
    st.read_for(0.8)
    in_flight = [k for k in key_snaps(port) if k["in_flight"] > 0]
    hot_key = MOCK.state.last_key_by_mode.get("slow-stream")
    if not in_flight or hot_key not in ("chaos-key-1", "chaos-key-2"):
        fail("4.6", "could not identify the key used by the in-flight stream "
                    f"(in_flight={[k['in_flight'] for k in key_snaps(port)]}, "
                    f"mock saw {hot_key})", "LOW",
             "GET /api/providers + the mock's per-key counter during a stream",
             "one key with in_flight=1", f"{hot_key}")
        st.abort()
    else:
        other = "chaos-key-2" if hot_key == "chaos-key-1" else "chaos-key-1"
        note(f"the in-flight stream is on {hot_key}")
        one_key_cfg = cfg_text.replace(
            'keys = ["chaos-key-1", "chaos-key-2"]', f'keys = ["{other}"]')
        r = admin(port, "/api/config", "PUT", {"toml": one_key_cfg})
        n_after = len(key_snaps(port))
        frames = st.read_for(1.5)
        st.abort()
        check("4.6", r.status == 200 and n_after == 1,
              f"removing the in-use key ({hot_key}) hot-reloads to 1 key "
              f"({r.status}, {n_after} key)",
              f"removing the in-use key did not apply: status={r.status}, "
              f"keys={n_after}",
              sev="HIGH",
              request=f"PUT /api/config with only {other} while a stream runs on "
                      f"{hot_key}",
              expected="200 and 1 key", observed=f"{r.status}, {n_after} keys")
        check("4.7", len(frames) > 0,
              f"the in-flight stream keeps streaming after its key was removed "
              f"({len(frames)}B more)",
              "the in-flight stream broke when its key was removed from the config",
              sev="MEDIUM", request=f"stream on {hot_key} while PUT removes {hot_key}",
              expected="the response continues", observed=f"{len(frames)}B")

        r = admin(port, "/api/config", "PUT", {"toml": cfg_text})
        n_back = len(key_snaps(port))
        r2 = chat(port, "fast", token="sk-load", timeout=SHORT)
        check("4.8", r.status == 200 and n_back == 2 and r2.status == 200,
              "adding the key back restores the 2-key pool and traffic",
              f"restoring the key failed: put={r.status} keys={n_back} "
              f"request={r2.status}",
              sev="HIGH", request="PUT the original config back",
              expected="200, 2 keys, 200", observed=f"{r.status}/{n_back}/{r2.status}")

    # --- concurrent reloads ----------------------------------------------
    codes = []
    lock = threading.Lock()

    def put_once():
        r = admin(port, "/api/config", "PUT", {"toml": cfg_text}, timeout=20)
        with lock:
            codes.append(r.status if r.status is not None else r.error)

    ts = [threading.Thread(target=put_once) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=30)
    check("4.9", len(codes) == 8 and all(c == 200 for c in codes),
          f"8 concurrent identical reloads → all 200 ({codes})",
          f"concurrent reloads failed: {collections.Counter(codes)}",
          sev="MEDIUM", request="8 parallel PUT /api/config, same body",
          expected="all 200", observed=str(collections.Counter(codes)))

    got = admin(port, "/api/config")
    check("4.10", got.text() == cfg_text,
          "config file still valid and complete after concurrent reloads",
          "concurrent reloads corrupted the config file",
          sev="HIGH", request="GET /api/config after 8 concurrent PUTs",
          expected="the original TOML",
          observed=f"{len(got.body)}B vs {len(cfg_text)}B")


# ---------------------------------------------------------------------------
# scenario 5 — restart behaviour
# ---------------------------------------------------------------------------

def scenario5(gw: Gateway, cfg_text: str, state_file: str) -> None:
    port = gw.port
    print("\n== 5. restart behaviour ==", flush=True)

    for _ in range(5):
        chat(port, "ok", timeout=SHORT)
    exited, secs, code = gw.terminate(timeout=10)
    check("5.1", exited and secs < 8,
          f"idle SIGTERM → exit in {secs:.1f}s (code {code})",
          f"idle SIGTERM did not exit within 10s (still running: {gw.alive()})",
          sev="HIGH", request="SIGTERM with no in-flight request",
          expected="exit 0 within a couple of seconds",
          observed=f"exited={exited} {secs:.1f}s")
    if not exited:
        gw.kill9()

    size = os.path.getsize(state_file) if os.path.exists(state_file) else 0
    check("5.2", size > 0,
          f"state file flushed on shutdown ({size} bytes)",
          f"state file missing or empty after a graceful stop ({state_file})",
          sev="HIGH", request="SIGTERM, then stat the redb state file",
          expected="non-empty file", observed=f"size={size}")

    gw_b = start_gateway("gw5b", cfg_text, port)
    h = admin(port, "/healthz")
    reqs = admin(port, "/api/requests")
    hist = reqs.json() if reqs.status == 200 else None
    check("5.3", h.status == 200,
          "gateway restarts on the same port and state file",
          f"restart failed: /healthz {h.status}",
          sev="HIGH", request="start again with the same config + state",
          expected="200", observed=str(h.status))
    check("5.4", isinstance(hist, list) and len(hist) > 0,
          f"request history survived the restart "
          f"({len(hist) if isinstance(hist, list) else '?'} records)",
          "the request/event history was lost across a graceful restart "
          f"(/api/requests → {type(hist).__name__})",
          sev="MEDIUM", request="GET /api/requests right after the restart",
          expected="non-empty history (requests_history=50)",
          observed=str(reqs.text()[:120]))

    # --- SIGTERM mid-stream ----------------------------------------------
    st = Stream(port, "slow-stream", timeout=20)
    st.read_for(0.8)
    t0 = time.time()
    try:
        gw_b.proc.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        pass
    eof_at = None
    while time.time() - t0 < 10:
        chunk = st.read1(4096)
        if not chunk or st.eof:
            eof_at = time.time() - t0
            break
        time.sleep(0.05)
        if not gw_b.alive():
            break
    # EOF can arrive a moment before the process is reaped: give it a fair window
    # instead of asserting immediately (that race made this check flaky).
    for _ in range(60):
        if not gw_b.alive():
            break
        time.sleep(0.05)
    if gw_b.alive():
        # Prove the stream is what blocks shutdown: drop the client and time the exit.
        st.abort()
        exited2, secs2, code2 = gw_b.terminate(timeout=8)
        if not exited2:
            gw_b.kill9()
        fail("5.5", "graceful shutdown does not terminate while a response is "
                    "streaming: SIGTERM left the process running for >10s, and it "
                    "only exited once the client disconnected "
                    f"({secs2:.1f}s later) — one long SSE stream blocks the whole "
                    "shutdown and the final state flush",
             "HIGH",
             "open stream model=mock/slow-stream (30 s of frames), SIGTERM, client "
             "keeps reading",
             "stop accepting, close the stream and exit within the shutdown budget",
             f"still alive 10s after SIGTERM (client never got a close, "
             f"eof_at={eof_at}); exit came {secs2:.1f}s after the client left; "
             f"log tail: {gw_b.log_tail(3)}")
    else:
        secs2 = time.time() - t0
        code2 = gw_b.proc.returncode
        ok("5.5", f"SIGTERM mid-stream → exit in {secs2:.1f}s (code {code2}), "
                  f"client EOF at {eof_at if eof_at is not None else 'n/a'}")
        st.abort()

    try:
        gw_c = start_gateway("gw5c", cfg_text, port)
    except RuntimeError as e:
        fail("5.6", "gateway does not start after a SIGTERM that interrupted a stream",
             "HIGH", "start after SIGTERM mid-stream", "starts and serves",
             str(e)[:300])
        return
    r = chat(port, "ok", timeout=SHORT + 2)
    check("5.6", r.status == 200,
          "gateway restarts and serves after the interrupted shutdown",
          f"gateway restarted but cannot serve ({r.status})",
          sev="HIGH", request="POST after the restart", expected="200",
          observed=str(r.status))

    # --- kill -9 (redb integrity) ----------------------------------------
    for _ in range(10):
        chat(port, "ok", timeout=SHORT)
    gw_c.kill9()
    size = os.path.getsize(state_file) if os.path.exists(state_file) else 0
    check("5.7", not gw_c.alive() and size > 0,
          f"SIGKILL leaves a {size}-byte state file behind",
          f"SIGKILL left nothing usable: alive={gw_c.alive()} size={size}",
          sev="MEDIUM", request="SIGKILL, then stat the state file",
          expected="process gone, file present",
          observed=f"alive={gw_c.alive()} size={size}")

    try:
        gw_d = start_gateway("gw5d", cfg_text, port)
    except RuntimeError as e:
        fail("5.8", "gateway does not start after SIGKILL: the redb state file is "
                    "not recoverable", "HIGH", "start after SIGKILL",
             "starts and serves", str(e)[:400])
        return
    log = gw_d.log_text()
    opened = "state storage:" in log
    cannot = "cannot open state file" in log
    r = chat(port, "ok", timeout=SHORT + 2)
    check("5.8", opened and not cannot and r.status == 200,
          "redb survives SIGKILL: reopened on restart and serving",
          f"redb state unusable after SIGKILL: opened={opened} warn={cannot} "
          f"request={r.status}",
          sev="HIGH", request="restart after SIGKILL, then POST",
          expected="state storage opened, 200",
          observed=f"opened={opened} cannot_open={cannot} status={r.status}")
    check("5.9", "panicked" not in log,
          "no panic in the log after the kill -9 restart",
          "the restarted gateway logged a panic",
          sev="HIGH", request="grep the restarted gateway log",
          expected="no panics", observed=gw_d.log_tail(3))


# ---------------------------------------------------------------------------
# scenario 6 — rate limits
# ---------------------------------------------------------------------------

RL_KEYS = """
[[client_keys]]
key = "sk-rl-boundary"
name = "boundary"
models = []
rpm = 6
burst = 6

[[client_keys]]
key = "sk-rl-retry"
name = "retry"
models = []
rpm = 24
burst = 1

[[client_keys]]
key = "sk-nolimit"
name = "nolimit"
models = []
"""


def scenario6_rpm() -> None:
    print("\n== 6. rate limits ==", flush=True)
    port = free_port()
    cfg = base_config(port, state_file=os.path.join(TMPDIR, "gw6.redb"),
                      models=("fast", "ok"), client_keys=RL_KEYS,
                      mock_port=MOCK.port)
    gw = start_gateway("gw6", cfg, port)
    try:
        codes = []
        for _ in range(8):
            codes.append(chat(port, "fast", token="sk-rl-boundary",
                              timeout=SHORT + 2).status)
        allowed = codes.count(200)
        check("6.1", allowed == 6 and codes[6] == 429 and codes[7] == 429,
              f"rpm=6/burst=6 → exactly 6 allowed then 429 ({codes})",
              f"rpm boundary is off: {codes} (expected 6 x 200 then 429, 429)",
              sev="HIGH", request="8 x POST with sk-rl-boundary (rpm=6, burst=6)",
              expected="[200]*6 + [429, 429]", observed=str(codes))

        r = chat(port, "fast", token="sk-rl-boundary", timeout=SHORT + 2)
        ra = r.headers.get("retry-after")
        check("6.2", r.status == 429 and r.err_type() == "rate_limit_exceeded"
              and int(ra or 0) >= 1,
              f"429 body/headers are the documented envelope "
              f"(type={r.err_type()}, Retry-After={ra})",
              f"429 shape wrong: status={r.status} type={r.err_type()} "
              f"retry-after={ra}",
              sev="MEDIUM", request="POST with the exhausted key",
              expected="rate_limit_exceeded + Retry-After >= 1",
              observed=str(r.headers))

        r0 = admin(port, "/api/config", "PUT", {"toml": cfg})
        r1 = chat(port, "fast", token="sk-rl-boundary", timeout=SHORT + 2)
        check("6.3", r0.status == 200 and r1.status == 429,
              "a config reload does not refill the key's bucket",
              f"reload reset the client-key quota (put={r0.status}, "
              f"next request={r1.status})",
              sev="MEDIUM", request="PUT the same config, then POST with the "
                                    "exhausted key",
              expected="still 429", observed=f"{r1.status}")

        # Retry-After accuracy: rpm=24 → 0.4 tokens/s → ~2.5 s per token.
        t0 = time.time()
        a = chat(port, "fast", token="sk-rl-retry", timeout=SHORT + 2)
        b = chat(port, "fast", token="sk-rl-retry", timeout=SHORT + 2)
        ra = b.headers.get("retry-after")
        if b.status != 429 or not ra:
            fail("6.4", "the second request on a burst=1 key was not rate limited",
                 "HIGH", "2 x POST with sk-rl-retry (rpm=24, burst=1)",
                 "first 200, second 429 with Retry-After",
                 f"statuses={a.status},{b.status} ra={ra}")
        else:
            time.sleep(float(ra))
            c = chat(port, "fast", token="sk-rl-retry", timeout=SHORT + 2)
            waited = time.time() - t0
            check("6.4", c.status == 200,
                  f"Retry-After={ra}s is accurate: the retry after {waited:.1f}s "
                  f"was served",
                  f"Retry-After={ra}s under-reports: the client waited {waited:.1f}s "
                  f"and still got {c.status}. The local bucket floors the wait to "
                  "whole seconds (as_secs) while the Redis limiter rounds up, so a "
                  "well-behaved client retries into another 429",
                  sev="MEDIUM",
                  request="POST sk-rl-retry → 429 → sleep(Retry-After) → POST again",
                  expected="200 after the advertised wait",
                  observed=f"got {c.status} after {waited:.1f}s")

        okc = [chat(port, "fast", token="sk-nolimit",
                    timeout=SHORT + 2).status for _ in range(3)]
        check("6.5", all(c == 200 for c in okc),
              "a key with no rpm is not limited",
              f"an unlimited key got limited: {okc}",
              sev="MEDIUM", request="3 x POST with an rpm-less key",
              expected="all 200", observed=str(okc))

        text = metrics(port)
        problems = prom_problems(text)
        check("6.6", not problems,
              "Prometheus exposition is well formed (every sample follows its # TYPE)",
              f"/metrics exposition order is invalid for "
              f"{sorted({p[0] for p in problems})[:5]} (first bad line: "
              f"{problems[0][1] if problems else ''})",
              sev="MEDIUM", request="GET /metrics with a rate-limited client key",
              expected="# TYPE before the first sample of each family",
              observed=f"{len(problems)} out-of-order samples")
    finally:
        gw.stop()


def scenario6_redis() -> None:
    holder, dead = dead_port()
    try:
        for fail_open, label, tag in ((True, "fail_open=true", "6.7"),
                                      (False, "fail_open=false", "6.8")):
            port = free_port()
            cfg = base_config(
                port,
                state_file=os.path.join(TMPDIR, f"gw6-{int(fail_open)}.redb"),
                models=("fast",), mock_port=MOCK.port,
            ) + (f"\n[ratelimit]\nbackend = \"redis\"\n"
                 f"redis_url = \"redis://127.0.0.1:{dead}/0\"\n"
                 f"fail_open = {str(fail_open).lower()}\ntimeout_ms = 50\n"
                 "\n[[client_keys]]\nkey = \"sk-redis\"\nname = \"redis\"\n"
                 "models = []\nrpm = 60\nburst = 60\n")
            gw = start_gateway(f"gw6r{int(fail_open)}", cfg, port)
            try:
                t0 = time.time()
                r = chat(port, "fast", token="sk-redis", timeout=SHORT + 2)
                dt = time.time() - t0
                h = admin(port, "/healthz", timeout=2)
                m = admin(port, "/metrics", timeout=3)
                if fail_open:
                    check(tag, r.status == 200 and h.status == 200 and m.status == 200,
                          f"redis down + {label} → traffic allowed "
                          f"({r.status} in {dt * 1000:.0f}ms), control plane healthy",
                          f"redis down + {label} is not fail-open: request={r.status}, "
                          f"health={h.status}, metrics={m.status}",
                          sev="HIGH",
                          request="POST with [ratelimit] backend=redis, redis_url at "
                                  "a closed port, fail_open=true",
                          expected="200 (degraded to fail-open)",
                          observed=f"{r.status} {r.text()[:100]}")
                else:
                    ra = int(r.headers.get("retry-after", "0") or 0)
                    check(tag,
                          r.status == 429 and ra == 1
                          and r.err_type() == "rate_limit_exceeded",
                          f"redis down + {label} → 429 with Retry-After: 1 "
                          f"(denied in {dt * 1000:.0f}ms)",
                          f"redis down + {label} did not deny correctly: "
                          f"status={r.status} retry-after="
                          f"{r.headers.get('retry-after')} type={r.err_type()}",
                          sev="HIGH",
                          request="POST with [ratelimit] backend=redis, redis_url at "
                                  "a closed port, fail_open=false",
                          expected="429 + Retry-After: 1",
                          observed=f"{r.status} ra={r.headers.get('retry-after')} "
                                   f"type={r.err_type()}")
                    r2 = chat(port, "fast", token="sk-redis", timeout=SHORT + 2)
                    check(tag + "b", r2.status == 429,
                          "the deny path is stable across repeated requests",
                          "the second request with redis down changed behaviour: "
                          f"{r2.status}",
                          sev="LOW", request="2nd POST with fail_open=false",
                          expected="429", observed=str(r2.status))
                lg = gw.log_text()
                check(tag + "-log",
                      "redis" in lg and ("allowing" in lg or "denying" in lg),
                      f"the redis outage is reported in the log ({label})",
                      "the redis outage is not logged (silent degradation)",
                      sev="LOW", request="inspect the gateway log",
                      expected="a 'redis ... failed ... allowing|denying' warning",
                      observed=gw.log_tail(3))
            finally:
                gw.stop()
    finally:
        holder.close()


# ---------------------------------------------------------------------------
# scenario 7 — metrics under chaos
# ---------------------------------------------------------------------------

def scenario7(gw: Gateway, churn_gw: Gateway) -> None:
    port = gw.port
    print("\n== 7. metrics / observability ==", flush=True)
    wait_keys(port, 8)

    before = metrics(port)
    mock_before = MOCK.state.snap()
    hist_before = histogram_counts(before)

    statuses = []
    for _ in range(8):
        statuses.append(chat(port, "ok", timeout=SHORT + 2).status)
    for _ in range(2):
        statuses.append(chat(port, "fail500", timeout=SHORT + 4).status)
    for _ in range(2):
        statuses.append(request(port, "POST", "/v1/chat/completions",
                                {"model": "mock/ok", "messages": []},
                                token="definitely-wrong", timeout=SHORT).status)
    made = len(statuses)
    expected = collections.Counter(statuses)

    after = metrics(port)
    hist_after = histogram_counts(after)
    mock_after = MOCK.state.snap()

    delta = {}
    for k, v in hist_after.items():
        d = v - hist_before.get(k, 0)
        if d:
            delta[k] = d
    total = sum(v for k, v in delta.items() if 'route="/v1/chat/completions"' in k)
    check("7.1", total == made,
          f"histogram _count for /v1/chat/completions moved by exactly {made}",
          f"histogram counts do not match the traffic: expected {made}, "
          f"counted {total} ({delta})",
          sev="HIGH", request=f"{made} requests to /v1/chat/completions",
          expected=f"sum(_count) delta == {made}", observed=f"{total}")

    per_status = {}
    bad = []
    for status, n in expected.items():
        key = f'route="/v1/chat/completions",method="POST",status="{status}"'
        got = hist_after.get(key, 0) - hist_before.get(key, 0)
        per_status[status] = got
        if got != n:
            bad.append((status, n, got))
    check("7.2", not bad,
          f"per-status histogram counts match ({per_status})",
          f"per-status counts are wrong: expected {dict(expected)}, got {per_status}",
          sev="HIGH",
          request="compare the histogram series with the client-side statuses",
          expected=str(dict(expected)), observed=str(per_status))

    attempts = sum(mock_after["hits"].get(m, 0) - mock_before["hits"].get(m, 0)
                   for m in ("ok", "fail500"))
    key_requests = metric_sum(after, "anyhop_key_requests_total") - \
        metric_sum(before, "anyhop_key_requests_total")
    check("7.3", int(key_requests) == attempts,
          f"anyhop_key_requests_total matches the {attempts} real upstream attempts",
          f"credential counters disagree with reality: metrics say "
          f"{int(key_requests)}, the upstream saw {attempts}",
          sev="HIGH", request="8 ok + 2 fail500 requests, compared with the mock",
          expected=str(attempts), observed=str(int(key_requests)))

    counts = histogram_counts(after)
    inf = {}
    for name, labels, value in parse_samples(after):
        if (name == "anyhop_http_request_duration_seconds_bucket"
                and 'le="+Inf"' in labels):
            inf[labels.replace(',le="+Inf"', "")] = int(value)
    mismatch = {k: (inf.get(k), v) for k, v in counts.items() if inf.get(k) != v}
    check("7.4", not mismatch,
          "every histogram's +Inf bucket equals its _count",
          f"inconsistent histograms: {list(mismatch.items())[:3]}",
          sev="MEDIUM", request="GET /metrics", expected="+Inf == _count",
          observed=str(list(mismatch.items())[:3]))

    check("7.5", "anyhop_up 1" in after,
          "/metrics reports anyhop_up 1",
          "/metrics does not report anyhop_up 1",
          sev="MEDIUM", request="GET /metrics", expected="anyhop_up 1",
          observed=after[:200])

    # The 5xx requests above put both keys into their backoff: let them recover so
    # the gauge is read from a healthy pool.
    wait_keys(port, 10)
    after = metrics(port)
    keys_total = metric_sum(after, "anyhop_keys_total")
    avail = metric_sum(after, "anyhop_keys_available")
    check("7.6", keys_total == 2 and avail == 2,
          f"/metrics key gauges sane (total={int(keys_total)}, "
          f"available={int(avail)})",
          f"/metrics key gauges wrong: total={keys_total} available={avail}",
          sev="MEDIUM", request="GET /metrics", expected="total=2, available=2",
          observed=f"{keys_total}/{avail}")

    problems = prom_problems(after)
    check("7.7", not problems,
          "/metrics exposition well formed on the chaos instance",
          f"out-of-order exposition: {sorted({p[0] for p in problems})[:5]}",
          sev="MEDIUM", request="GET /metrics", expected="TYPE precedes samples",
          observed=f"{len(problems)} samples")

    t0 = time.time()
    r = admin(churn_gw.port, "/metrics", timeout=5)
    ms = (time.time() - t0) * 1000
    check("7.8", r.status == 200,
          f"/metrics served on the loaded instance ({ms:.0f}ms)",
          f"/metrics failed on the loaded instance ({r.status}, {ms:.0f}ms)",
          sev="MEDIUM", request="GET /metrics on gw2 during traffic",
          expected="200", observed=str(r.status))


# ---------------------------------------------------------------------------
# global checks
# ---------------------------------------------------------------------------

def global_log_checks() -> None:
    print("\n== gateway logs ==", flush=True)
    bad = []
    for gw in GATEWAYS:
        for line in gw.log_text().splitlines():
            low = line.lower()
            if "panicked" in low or "fatal runtime error" in low:
                bad.append((gw.name, line.strip()[:160]))
    check("L1", not bad,
          f"no panic / fatal error in {len(GATEWAYS)} gateway logs",
          f"gateway logs contain crashes: {bad[:3]}",
          sev="HIGH", request="grep every gateway log for panics",
          expected="no panic lines", observed=str(bad[:3]))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def run(label: str, fn, *a) -> None:
    """A scenario must never take the whole harness down."""
    try:
        fn(*a)
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        fail(f"{label}-ERR", f"the {label} scenario itself crashed (see traceback)",
             "LOW", request=label, expected="scenario completes",
             observed="harness exception")


def main(argv) -> int:
    global TMPDIR, MOCK
    only = None
    keep = "--keep" in argv
    for i, a in enumerate(argv):
        if a == "--only" and i + 1 < len(argv):
            only = {s.strip() for s in argv[i + 1].split(",") if s.strip()}

    def want(*names: str) -> bool:
        return only is None or any(n in only for n in names)

    if not os.path.exists(BIN):
        print(f"missing binary: {BIN}\nbuild it with: CARGO_HOME=/tmp/ch "
              f"CARGO_NET_OFFLINE=true cargo build --release", file=sys.stderr)
        return 2

    TMPDIR = tempfile.mkdtemp(prefix="anyhop-chaos-")
    print(f"chaos harness: bin={BIN}\n  tmp={TMPDIR}", flush=True)

    mock_port = free_port()
    MOCK = Mock(mock_port).start()
    print(f"  mock upstream on 127.0.0.1:{mock_port}", flush=True)

    try:
        need_gw2 = want("3", "4", "7")
        gw2 = None
        if need_gw2:
            port2 = free_port()
            cfg2 = base_config(
                port2,
                state_file=os.path.join(TMPDIR, "gw2.redb"),
                models=("fast", "ok", "slow-stream"),
                provider_max_concurrent=2, max_retries=4,
                client_keys='\n[[client_keys]]\nkey = "sk-load"\n'
                            'name = "load"\nmodels = []\n',
                mock_port=mock_port)
            gw2 = start_gateway("gw2", cfg2, port2)

        if want("1", "1b"):
            run("1b", scenario1b)

        if want("1", "2", "7"):
            port = free_port()
            cfg1 = base_config(
                port,
                state_file=os.path.join(TMPDIR, "gw1.redb"),
                models=("ok", "slow-stream", "midstream-cut", "silent", "noreply",
                        "garbage", "cl-short", "rst-mid", "html200", "fail500"),
                provider_max_concurrent=4,
                client_keys="""
[[client_keys]]
key = "sk-chaos-all"
name = "all"
models = []

[[client_keys]]
key = "sk-chaos-one"
name = "one-slot"
models = []
max_concurrent = 1
""",
                mock_port=mock_port)
            gw1 = start_gateway("gw1", cfg1, port)
            try:
                if want("1"):
                    run("1", scenario1, gw1)
                if want("2"):
                    run("2", scenario2, gw1)
                if want("7"):
                    run("7", scenario7, gw1, gw2)
            finally:
                gw1.stop()

        if want("3", "4"):
            if want("3"):
                run("3", scenario3, gw2)
            if want("4"):
                run("4", scenario4, gw2, cfg2)

        if want("5"):
            port3 = free_port()
            state3 = os.path.join(TMPDIR, "gw3.redb")
            cfg3 = base_config(
                port3, state_file=state3,
                models=("ok", "slow-stream", "fast"),
                client_keys='\n[[client_keys]]\nkey = "sk-load"\n'
                            'name = "load"\nmodels = []\n',
                mock_port=mock_port)
            gw3 = start_gateway("gw5a", cfg3, port3)
            run("5", scenario5, gw3, cfg3, state3)

        if want("6"):
            run("6", scenario6_rpm)
            run("6", scenario6_redis)

        global_log_checks()
    finally:
        if gw2 is not None:
            gw2.stop()
        for gw in GATEWAYS:
            try:
                gw.stop()
            except Exception:  # noqa: BLE001
                pass
        try:
            MOCK.stop()
        except Exception:  # noqa: BLE001
            pass

    print("\n== findings ==", flush=True)
    if not FINDINGS:
        print("  none — every check passed", flush=True)
    else:
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for i, f in enumerate(sorted(FINDINGS,
                                     key=lambda x: order.get(x["sev"], 3)), 1):
            print(f"\n[{i}] {f['sev']:6} {f['tag']}  {f['title']}")
            if f["request"]:
                print(f"    request : {f['request']}")
            if f["expected"]:
                print(f"    expected: {f['expected']}")
            if f["observed"]:
                print(f"    observed: {f['observed']}")
    print(f"\nCHAOS PASS={PASS} FAIL={FAIL}", flush=True)

    if keep:
        print(f"kept: {TMPDIR}")
    else:
        shutil.rmtree(TMPDIR, ignore_errors=True)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)