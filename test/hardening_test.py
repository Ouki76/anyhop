#!/usr/bin/env python3
"""
Hardening checks that need their own gateway instance.

The main suite runs against a shared instance, but these deliberately trip
protective limits (auth lockout, per-key concurrency) or change transport (TLS),
so they must not poison the shared state.

Each check starts a throwaway gateway with a temp config, exercises the feature
and tears it down. Mocks from run_all.sh are already listening on their ports.
"""
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("ANYHOP_BIN", os.path.join(ROOT, "target/release/anyhop"))
MOCK_URL = "http://127.0.0.1:9100/v1"
KEY = "hardening-gw-key"

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  ok   {msg}")


def fail(msg):
    global FAIL
    FAIL += 1
    print(f"  FAIL {msg}")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def write_config(path, port, extra_server=""):
    with open(path, "w") as f:
        f.write(
            f"""[server]
listen = "127.0.0.1:{port}"
api_key = "{KEY}"
state_file = ""
{extra_server}
[[providers]]
name = "mock"
type = "openai_compat"
base_url = "{MOCK_URL}"
strategy = "round_robin"
keys = ["hardening-key-1"]
models = ["test-model"]
"""
        )


class Gateway:
    def __init__(self, config, port):
        self.port = port
        self.proc = subprocess.Popen(
            [BIN], env={**os.environ, "ANYHOP_CONFIG": config}, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def wait(self, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def request(port, path, data=None, token=KEY, method=None, timeout=10):
    url = f"http://127.0.0.1:{port}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method or ("GET" if data is None else "POST"))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def check_auth_lockout():
    """Repeated bad keys must be throttled, not compared forever."""
    port = free_port()
    cfg = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    write_config(cfg.name, port, "auth_fail_burst = 3\nauth_fail_window_secs = 30")
    gw = Gateway(cfg.name, port)
    try:
        if not gw.wait():
            fail("auth lockout: gateway did not start")
            return
        codes = []
        for _ in range(5):
            status, _ = request(port, "/api/providers", token="wrong-key")
            codes.append(status)
        if codes[0] != 401:
            fail(f"auth lockout: first bad key should be 401, got {codes[0]}")
            return
        if 429 not in codes:
            fail(f"auth lockout: never throttled, codes={codes}")
            return
        # A correct key from the same IP is also refused while the window lasts —
        # that is the point of a lockout (attacker and victim share a NAT).
        status, _ = request(port, "/api/providers")
        if status != 429:
            fail(f"auth lockout: valid key still allowed during lockout ({status})")
            return
        ok(f"auth lockout (401 → 429 after 3 failures; codes={codes[:3]}…)")
    finally:
        gw.stop()
        os.unlink(cfg.name)


def check_per_key_concurrency():
    """A client key's in-flight cap must return 429 rather than queue."""
    port = free_port()
    cfg = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    write_config(cfg.name, port, "")
    gw = Gateway(cfg.name, port)
    try:
        if not gw.wait():
            fail("concurrency: gateway did not start")
            return
        status, body = request(
            port,
            "/api/client-keys/add",
            {"name": "cap", "key": "sk-hop-cap-key", "models": [], "max_concurrent": 1},
        )
        if status != 200:
            fail(f"concurrency: cannot create the key ({status}: {body[:80]})")
            return
        # Hold one request open by pointing it at a mock that streams slowly is
        # overkill: fire two concurrently and require at least one 429.
        import threading

        results = []

        def hit():
            results.append(request(port, "/v1/chat/completions",
                                   {"model": "mock/test-model",
                                    "messages": [{"role": "user", "content": "hi"}]},
                                   token="sk-hop-cap-key"))

        threads = [threading.Thread(target=hit) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        codes = sorted({status for status, _ in results})
        if 429 not in codes:
            fail(f"concurrency: cap never hit, codes={codes}")
            return
        if 200 not in codes:
            fail(f"concurrency: nothing succeeded, codes={codes}")
            return
        ok(f"per-key concurrency cap (codes={codes})")
    finally:
        gw.stop()
        os.unlink(cfg.name)


def check_tls():
    """The gateway must speak HTTPS itself when cert/key are configured."""
    port = free_port()
    cfg = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    cert = os.path.join(ROOT, "test/certs/localhost.crt")
    key = os.path.join(ROOT, "test/certs/localhost.key")
    write_config(cfg.name, port, f'tls_cert = "{cert}"\ntls_key = "{key}"')
    gw = Gateway(cfg.name, port)
    try:
        if not gw.wait():
            fail("tls: gateway did not start")
            return
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with ctx.wrap_socket(raw) as tls:
                    tls.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    data = tls.recv(4096)
            text = data.decode("latin-1", "replace")
        except Exception as e:  # noqa: BLE001 - any failure is a failed check
            fail(f"tls: handshake failed: {e}")
            return
        if "200 OK" not in text:
            fail(f"tls: unexpected response: {text.splitlines()[:1]}")
            return
        ok("TLS in-process (handshake + /healthz over https)")
    finally:
        gw.stop()
        os.unlink(cfg.name)


def check_observability():
    """Histograms and the new endpoints on a plain instance."""
    port = free_port()
    cfg = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    write_config(cfg.name, port, "")
    gw = Gateway(cfg.name, port)
    try:
        if not gw.wait():
            fail("observability: gateway did not start")
            return
        status, body = request(port, "/v1/responses",
                               {"model": "mock/test-model", "input": "hi"})
        if status != 200:
            fail(f"/v1/responses returned {status}: {body[:100]}")
        elif json.loads(body).get("object") != "response":
            fail(f"/v1/responses shape: {body[:100]}")
        else:
            ok("/v1/responses returns a Response object")

        status, body = request(port, "/v1/models/mock/test-model")
        if status != 200 or json.loads(body).get("id") != "mock/test-model":
            fail(f"/v1/models/{{id}} returned {status}: {body[:100]}")
        else:
            ok("/v1/models/{id} resolves a single model")

        status, body = request(port, "/metrics")
        if status != 200:
            fail(f"/metrics returned {status}")
        elif "anyhop_http_request_duration_seconds_bucket" not in body:
            fail("no latency histograms in /metrics")
        else:
            ok("Prometheus latency histograms exposed")
    finally:
        gw.stop()
        os.unlink(cfg.name)


def main():
    print("== hardening (own gateway instances) ==")
    check_tls()
    check_auth_lockout()
    check_per_key_concurrency()
    check_observability()
    print(f"HARDENING PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())