#!/usr/bin/env python3
"""Execute the shipped Redis token-bucket Lua against a REAL Redis server.

Why this exists: `src/distributed/limiter.rs` ships a Lua script, but every test
in the tree used one of two *re-implementations* (the Rust fallback path and
`test/mock_redis.py`). Those can only prove that the doubles agree with each
other — a Lua syntax error, a wrong `SET … EX` argument, or a divergence in the
rounding would have gone unnoticed. This test runs the exact script text from the
source file inside `redis:7-alpine` and checks fixed input → output vectors, plus
end-to-end parity with the local token bucket through the gateway.

Requires docker with the `redis:7-alpine` image (pulled on demand). When docker or
the image is unavailable the test prints SKIP and exits 2, so a caller can report
"not verified" instead of a silent pass.

    python3 test/redis_lua_test.py [--binary ./target/release/anyhop]
"""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE = "redis:7-alpine"
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


class Resp:
    """The ~40 lines of RESP needed to talk to redis-cli-free Redis."""

    def __init__(self, port, timeout=5.0):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.buf = b""

    def _readline(self):
        while b"\r\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise OSError("redis closed the connection")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _read(self):
        line = self._readline()
        kind, rest = line[:1], line[1:]
        if kind == b"+":
            return rest.decode()
        if kind == b"-":
            raise OSError(f"redis error: {rest.decode()}")
        if kind == b":":
            return int(rest)
        if kind == b"$":
            n = int(rest)
            if n == -1:
                return None
            while len(self.buf) < n + 2:
                self.buf += self.sock.recv(65536)
            data, self.buf = self.buf[:n], self.buf[n + 2:]
            return data.decode()
        if kind == b"*":
            n = int(rest)
            return None if n == -1 else [self._read() for _ in range(n)]
        raise OSError(f"unexpected RESP reply: {line[:40]!r}")

    def cmd(self, *args):
        out = [f"*{len(args)}\r\n".encode()]
        for a in args:
            b = a if isinstance(a, bytes) else str(a).encode()
            out.append(f"${len(b)}\r\n".encode() + b + b"\r\n")
        self.sock.sendall(b"".join(out))
        return self._read()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def shipped_lua():
    """The script text exactly as the gateway sends it."""
    src = open(os.path.join(ROOT, "src/distributed/limiter.rs")).read()
    m = re.search(r'TOKEN_BUCKET_LUA: &str = r"(.*?)";\n', src, re.S)
    if not m:
        raise SystemExit("cannot find TOKEN_BUCKET_LUA in src/distributed/limiter.rs")
    return m.group(1)


def start_redis(name, port):
    # 127.0.0.1 binding: the test must not expose a Redis without AUTH anywhere.
    return subprocess.run(
        ["docker", "run", "--rm", "-d", "--name", name,
         "-p", f"127.0.0.1:{port}:6379", IMAGE],
        capture_output=True, text=True, timeout=120,
    )


def wait_ping(port, seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            c = Resp(port, timeout=1)
            if c.cmd("PING") == "PONG":
                c.close()
                return True
            c.close()
        except OSError:
            pass
        time.sleep(0.2)
    return False


def run_vectors(port, lua):
    """Fixed input -> output vectors for the script itself."""
    c = Resp(port)
    key = "anyhop:test:bucket"

    def take(cap, rate, now_ms, ttl=120):
        return c.cmd("EVAL", lua, 1, key, cap, rate, now_ms, ttl)

    c.cmd("DEL", key)
    # Empty bucket starts full: `cap` requests, then one denial whose retry is the
    # exact time to refill one token (rate 0.1/s -> 10 s).
    t0 = 1_700_000_000_000
    allowed = [take(6, 0.1, t0)[0] for _ in range(6)]
    if allowed == [1] * 6:
        ok("fresh bucket allows exactly the capacity (6)")
    else:
        fail(f"fresh bucket allowed {allowed}, expected six 1s")
    first = take(6, 0.1, t0)
    if first[0] == 0 and 9_000 <= first[1] <= 10_000:
        ok(f"the request past capacity is denied with retry_after={first[1]}ms (~10 s)")
    else:
        fail(f"expected denied with ~10000 ms retry, got {first}")

    # Refill is continuous: 5 s of credit is 0.5 token -> still denied, 5 s to go.
    mid = take(6, 0.1, t0 + 5_000)
    if mid[0] == 0 and 4_000 <= mid[1] <= 5_000:
        ok(f"a half-refilled bucket still denies, retry_after={mid[1]}ms (~5 s)")
    else:
        fail(f"expected denied with ~5000 ms retry, got {mid}")
    # 10 s later exactly one token is back.
    after = take(6, 0.1, t0 + 10_000)
    if after[0] == 1:
        ok("one refilled token admits the next request")
    else:
        fail(f"expected one token to be available after 10 s, got {after}")

    # Never above capacity, even after an hour of idling.
    c.cmd("DEL", key)
    for _ in range(6):
        take(6, 0.1, t0)
    burst_after_idle = [take(6, 0.1, t0 + 3_600_000)[0] for _ in range(7)]
    if burst_after_idle == [1] * 6 + [0]:
        ok("idling refills to capacity and never beyond it")
    else:
        fail(f"idle refill gave {burst_after_idle}, expected 6x1 then 0")

    # Burst > rpm: `ARGV[1]` is the capacity, `ARGV[2]` the rate.
    c.cmd("DEL", key)
    allowed = [take(20, 0.5, t0)[0] for _ in range(21)]
    if allowed == [1] * 20 + [0]:
        ok("burst above rpm is honoured as the capacity")
    else:
        fail(f"burst capacity gave {sum(allowed)} admissions, expected 20")

    # The key must expire by itself (SET … EX), or a deleted client key would leak
    # its bucket forever.
    c.cmd("DEL", key)
    take(6, 0.1, t0, ttl=60)
    ttl = c.cmd("TTL", key)
    if 50 <= ttl <= 60:
        ok(f"the bucket carries a TTL ({ttl}s, refreshed on every write)")
    else:
        fail(f"expected TTL 50..60, got {ttl}")

    # The stored value must stay parseable by the script on the next call: a
    # `%.6f:%.0f` format that lost the separator would silently reset the bucket.
    c.cmd("DEL", key)
    for _ in range(4):
        take(6, 0.1, t0)
    raw = c.cmd("GET", key)
    if raw and re.fullmatch(r"-?\d+\.\d{6}:\d+", raw):
        ok(f"state stays '<tokens>:<last_ms>' ({raw})")
    else:
        fail(f"unexpected bucket state {raw!r}")
    c.close()


def run_atomicity(port, lua):
    """Concurrent EVALs must never admit more than the capacity."""
    import threading

    cap, threads = 10, 40
    key = "anyhop:test:atomic"
    c = Resp(port)
    c.cmd("DEL", key)
    c.close()
    t0 = 1_700_000_000_000
    results = []
    lock = threading.Lock()

    def one():
        cl = Resp(port)
        try:
            r = cl.cmd("EVAL", lua, 1, key, cap, 0.001, t0, 120)
            with lock:
                results.append(r[0])
        finally:
            cl.close()

    ts = [threading.Thread(target=one) for _ in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    admitted = sum(1 for r in results if r == 1)
    if admitted == cap:
        ok(f"{threads} concurrent EVALs admitted exactly {cap} (atomic)")
    else:
        fail(f"{threads} concurrent EVALs admitted {admitted}, expected {cap}")


def gateway_parity(binary, port, workers):
    """End-to-end: the same config through the local and the redis backend must
    reject the same request."""
    results = {}
    for backend in ("local", "redis"):
        gw_port = free_port()
        state = tempfile.NamedTemporaryFile(suffix=".redb", delete=False)
        state.close()
        os.unlink(state.name)
        cfg = f"""
[server]
listen = "127.0.0.1:{gw_port}"
api_key = "parity-key"
state_file = ""
max_retries = 1
attempt_timeout_secs = 5
client_key_max_concurrent = 0

[ratelimit]
backend = "{backend}"
redis_url = "redis://127.0.0.1:{port}"
fail_open = false
key_prefix = "anyhop-parity"
timeout_ms = 1000

[[providers]]
name = "mock"
type = "openai_compat"
base_url = "http://127.0.0.1:{workers}/v1"
strategy = "fill_first"
keys = ["k1"]
models = ["test-model"]

[[client_keys]]
key = "sk-parity-{backend}"
name = "parity"
models = []
rpm = 6
burst = 6
"""
        path = tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False)
        path.write(cfg)
        path.close()
        env = dict(os.environ, ANYHOP_CONFIG=path.name)
        proc = subprocess.Popen([binary], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            up = False
            for _ in range(80):
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{gw_port}/healthz", timeout=1).read()
                    up = True
                    break
                except OSError:
                    time.sleep(0.1)
            if not up:
                fail(f"{backend} backend: the gateway did not start")
                continue
            codes = []
            for _ in range(8):
                req = urllib.request.Request(
                    f"http://127.0.0.1:{gw_port}/v1/chat/completions",
                    data=json.dumps({"model": "mock/test-model",
                                     "messages": [{"role": "user", "content": "hi"}]}).encode(),
                    headers={"content-type": "application/json",
                             "authorization": f"Bearer sk-parity-{backend}"})
                try:
                    with urllib.request.urlopen(req, timeout=10) as r:
                        codes.append(r.status)
                except urllib.error.HTTPError as e:
                    codes.append(e.code)
            results[backend] = codes
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            os.unlink(path.name)
    local, redis = results.get("local", []), results.get("redis", [])
    if local and local == redis:
        ok(f"gateway parity: local and redis backends both answer {local}")
    else:
        fail(f"gateway parity: local={local} redis={redis}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=os.path.join(ROOT, "target/release/anyhop"))
    args = ap.parse_args()

    try:
        probe = subprocess.run(["docker", "image", "inspect", IMAGE],
                               capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        print("SKIP: docker is not available")
        return 2
    if probe.returncode != 0:
        # CI has network: pull the server instead of silently skipping the only test
        # that ever executes the shipped Lua.
        print(f"pulling {IMAGE} …")
        try:
            pull = subprocess.run(["docker", "pull", IMAGE],
                                  capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            print("SKIP: docker pull timed out")
            return 2
        if pull.returncode != 0:
            print(f"SKIP: cannot pull {IMAGE}: {pull.stderr.strip()[:200]}")
            return 2

    port = free_port()
    name = f"anyhop-lua-{port}"
    try:
        started = start_redis(name, port)
    except subprocess.TimeoutExpired:
        print("SKIP: docker run timed out")
        return 2
    if started.returncode != 0:
        print(f"SKIP: cannot start {IMAGE}: {started.stderr.strip()[:200]}")
        return 2
    try:
        if not wait_ping(port):
            print("SKIP: redis did not answer PING")
            return 2
        lua = shipped_lua()
        print("== token bucket Lua (real redis) ==")
        run_vectors(port, lua)
        run_atomicity(port, lua)

        # A mock upstream for the parity run: reuse the project's own mock.
        mock_port = free_port()
        mock = subprocess.Popen([sys.executable, os.path.join(ROOT, "test/mock_upstream.py"),
                                 str(mock_port)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                try:
                    socket.create_connection(("127.0.0.1", mock_port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
            print("== backend parity (gateway: local vs redis) ==")
            gateway_parity(args.binary, port, mock_port)
        finally:
            mock.terminate()
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)

    print(f"\nREDIS-LUA PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())