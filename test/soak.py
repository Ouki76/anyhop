#!/usr/bin/env python3
"""Load/soak test for anyhop: sustained mixed traffic, reports rps, latency
percentiles, RSS and fd growth.

    python3 test/soak.py --duration 60 --workers 32
    python3 test/soak.py --duration 30 --url http://127.0.0.1:18080 --key test-gw-key
    python3 test/soak.py --duration 30 --pid 12345        # also sample that process

Exits non-zero on errors, a memory/fd leak, or p99 above --max-p99-ms.
Uses one keep-alive connection per worker (urllib does not reuse sockets, which
made the old version client-bound at ~4k rps).
"""
import argparse
import http.client
import json
import os
import ssl
import sys
import threading
import time
import urllib.parse

MODELS = [
    "mock/test-model",
    "gemini/test-gemini",
    "ag/gemini-3-flash",
    "claude/claude-test",
    "codex/gpt-codex-test",
    "testcombo",
]


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.ok = 0
        self.err = 0
        self.lat = []
        self.statuses = {}

    def record(self, ok, dt):
        with self.lock:
            if ok:
                self.ok += 1
            else:
                self.err += 1
            self.lat.append(dt)

    def bump(self, status):
        with self.lock:
            self.statuses[status] = self.statuses.get(status, 0) + 1


def worker(idx, args, stop, stats, payloads):
    parsed = urllib.parse.urlparse(args.url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = (parsed.path or "") + "/v1/chat/completions"
    conn = None
    n = 0
    while time.time() < stop:
        model = MODELS[(idx + n) % len(MODELS)]
        stream = n % 3 == 0
        body = payloads[(model, stream)]
        try:
            if conn is None:
                if parsed.scheme == "https":
                    conn = http.client.HTTPSConnection(
                        host, port, timeout=30, context=ssl.create_default_context()
                    )
                else:
                    conn = http.client.HTTPConnection(host, port, timeout=30)
            t0 = time.perf_counter()
            conn.request(
                "POST",
                path,
                body=body,
                headers={
                    "Authorization": f"Bearer {args.key}",
                    "Content-Type": "application/json",
                    "Connection": "keep-alive",
                },
            )
            resp = conn.getresponse()
            # Drain the body: for streams this measures time-to-last-byte.
            while resp.read(65536):
                pass
            dt = time.perf_counter() - t0
            ok = resp.status == 200
            stats.bump(resp.status)
            stats.record(ok, dt)
            if not ok:
                # A non-200 can leave unread state on the connection; recycle it.
                conn.close()
                conn = None
        except Exception:
            stats.record(False, 0.0)
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
            time.sleep(0.01)  # do not spin on a dead server
        n += 1
    if conn is not None:
        conn.close()


def sample(pid):
    """(RSS MB, open fds) for a pid, or (None, None) on non-Linux/denied."""
    try:
        with open(f"/proc/{pid}/status") as f:
            rss = next(int(l.split()[1]) for l in f if l.startswith("VmRSS"))
        return rss / 1024, len(os.listdir(f"/proc/{pid}/fd"))
    except Exception:
        return None, None


def find_pid():
    """Best-effort: find a running anyhop process."""
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            cmd = open(f"/proc/{name}/cmdline", "rb").read()
        except Exception:
            continue
        if b"anyhop" in cmd and b"soak.py" not in cmd:
            return int(name)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:18080")
    ap.add_argument("--key", default="test-gw-key")
    ap.add_argument("--duration", type=int, default=60, help="seconds")
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--max-p99-ms", type=float, default=1000.0)
    ap.add_argument("--max-rss-growth-mb", type=float, default=150.0)
    args = ap.parse_args()

    pid = args.pid or find_pid()
    if pid is None:
        print("warning: no anyhop process found — skipping RSS/fd sampling",
              file=sys.stderr)

    payloads = {
        (m, s): json.dumps(
            {
                "model": m,
                "stream": s,
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "ping " + "x" * 64},
                ],
            }
        ).encode()
        for m in MODELS
        for s in (False, True)
    }

    stats = Stats()
    stop = time.time() + args.duration
    rss0 = fd0 = None
    if pid:
        rss0, fd0 = sample(pid)
        if rss0 is not None:
            print(f"start: RSS {rss0:.0f}MB, {fd0} fds (pid {pid})")

    threads = [
        threading.Thread(target=worker, args=(i, args, stop, stats, payloads), daemon=True)
        for i in range(args.workers)
    ]
    t_start = time.time()
    for t in threads:
        t.start()

    max_rss, max_fd = rss0, fd0
    while any(t.is_alive() for t in threads):
        time.sleep(5)
        if pid:
            r, f = sample(pid)
            if r is not None:
                max_rss = max(max_rss or 0, r)
                max_fd = max(max_fd or 0, f)
                with stats.lock:
                    print(f"  t+{int(time.time() - t_start)}s: ok={stats.ok} "
                          f"err={stats.err} RSS={r:.0f}MB fds={f}")
    elapsed = time.time() - t_start

    lat = sorted(stats.lat)
    n = len(lat) or 1
    p50 = lat[n // 2] * 1000
    p95 = lat[min(n - 1, max(0, int(n * 0.95) - 1))] * 1000
    p99 = lat[min(n - 1, int(n * 0.99))] * 1000
    total = stats.ok + stats.err
    rps = total / elapsed if elapsed else 0

    print(f"\n=== {total} requests in {elapsed:.1f}s -> {rps:,.0f} req/s "
          f"({stats.ok} ok, {stats.err} err)")
    print(f"latency p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms")
    if stats.statuses:
        print("statuses:", dict(sorted(stats.statuses.items())))
    if rss0 is not None:
        print(f"RSS: {rss0:.0f}MB -> max {max_rss:.0f}MB (delta {max_rss - rss0:+.0f}MB)")
        print(f"fds: {fd0} -> max {max_fd}")

    problems = []
    if stats.err:
        problems.append(f"{stats.err} failed requests")
    if rss0 is not None and max_rss - rss0 > args.max_rss_growth_mb:
        problems.append(f"RSS grew {max_rss - rss0:.0f}MB")
    if fd0 is not None and max_fd > fd0 + 500:
        problems.append(f"fds grew {max_fd - fd0}")
    if p99 > args.max_p99_ms:
        problems.append(f"p99 {p99:.0f}ms > {args.max_p99_ms:.0f}ms")

    if problems:
        print("VERDICT: FAIL -", "; ".join(problems))
        return 1
    print("VERDICT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())