#!/usr/bin/env python3
"""Soak test: sustained mixed load against anyhop, watches RSS/fd/errors/latency."""
import json, subprocess, sys, threading, time, urllib.request

BASE = "http://127.0.0.1:18080"
H = {"Authorization": "Bearer test-gw-key", "Content-Type": "application/json"}
DURATION = 180  # секунд
WORKERS = 20

stats = {"ok": 0, "err": 0, "lat": []}
lock = threading.Lock()
stop = time.time() + DURATION

def one(model, stream=False):
    body = json.dumps({"model": model, "stream": stream,
                       "messages": [{"role": "user", "content": "ping"}]}).encode()
    req = urllib.request.Request(f"{BASE}/v1/chat/completions", data=body, headers=H)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            while r.read(65536):
                pass
        ok = r.status == 200
    except Exception:
        ok = False
    dt = time.perf_counter() - t0
    with lock:
        if ok: stats["ok"] += 1
        else: stats["err"] += 1
        stats["lat"].append(dt)

MODELS = ["mock/test-model", "gemini/test-gemini", "ag/gemini-3-flash",
          "claude/claude-test", "codex/gpt-codex-test", "testcombo"]

def worker(i):
    n = 0
    while time.time() < stop:
        m = MODELS[(i + n) % len(MODELS)]
        one(m, stream=(n % 3 == 0))
        n += 1

pid = int(sys.argv[1])
def sample():
    with open(f"/proc/{pid}/status") as f:
        rss = next(int(l.split()[1]) for l in f if l.startswith("VmRSS"))
    fds = len(__import__("os").listdir(f"/proc/{pid}/fd"))
    return rss / 1024, fds

threads = [threading.Thread(target=worker, args=(i,)) for i in range(WORKERS)]
for t in threads: t.start()

rss0, fd0 = sample()
print(f"start: RSS {rss0:.0f}MB, {fd0} fds")
max_rss, max_fd = rss0, fd0
while any(t.is_alive() for t in threads):
    time.sleep(10)
    r, f = sample()
    max_rss, max_fd = max(max_rss, r), max(max_fd, f)
    with lock:
        print(f"t+{int(time.time()-(stop-DURATION))}s: ok={stats['ok']} err={stats['err']} RSS={r:.0f}MB fds={f}")
for t in threads: t.join()

lat = sorted(stats["lat"])
n = len(lat)
print(f"\n=== DONE: {stats['ok']} ok, {stats['err']} err ===")
print(f"latency p50={lat[n//2]*1000:.0f}ms p95={lat[int(n*.95)]*1000:.0f}ms p99={lat[int(n*.99)]*1000:.0f}ms")
print(f"RSS: start {rss0:.0f}MB → max {max_rss:.0f}MB (delta {max_rss-rss0:+.0f}MB)")
print(f"FDs: start {fd0} → max {max_fd}")
ok = stats["err"] == 0 and (max_rss - rss0) < 150 and max_fd < fd0 + 500
print("VERDICT:", "PASS ✓" if ok else "FAIL ✗")
sys.exit(0 if ok else 1)
