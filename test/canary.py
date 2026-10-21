#!/usr/bin/env python3
"""Canary test against the *real* providers configured in a production TOML.

The mock-based suite in `run_all.sh` proves the translation layers are wired up;
this script proves the upstream APIs still answer the way we expect. Run it after
a provider changes something, or on a schedule from a box that holds the real keys.

    python3 test/canary.py --config anyhop.toml
    python3 test/canary.py --config anyhop.toml --models 2 --max-tokens 16
    python3 test/canary.py --config anyhop.toml --only gemini,antigravity

What it does:
  1. copies the config to a temp file with an ephemeral port and `state_file = ""`
     (so it never touches the live state or the live listener);
  2. starts the gateway binary against that copy;
  3. for every provider it sends a non-streaming chat, a streaming chat and (for
     kinds that have the API) an embeddings request;
  4. prints a per-provider verdict and exits non-zero if anything required failed.

Secrets are never printed: every configured key/refresh token found in the config
is replaced with *** in the output.
"""
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    print("python 3.11+ required (tomllib)", file=sys.stderr)
    sys.exit(2)

EMBEDDING_KINDS = {"openai_compat", "gemini"}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def secrets_of(cfg):
    """Every secret string we must redact from output."""
    out = []
    server = cfg.get("server", {})
    for k in ("api_key", "admin_key"):
        if server.get(k):
            out.append(server[k])
    for p in cfg.get("providers", []):
        out.extend(str(x) for x in p.get("keys", []))
        for acc in p.get("accounts", []):
            for k in ("refresh_token", "access_token", "account_id"):
                if acc.get(k):
                    out.append(acc[k])
    for ck in cfg.get("client_keys", []):
        if ck.get("key"):
            out.append(ck["key"])
    return sorted({s for s in out if len(s) >= 6}, key=len, reverse=True)


class Redactor:
    def __init__(self, secrets):
        self.secrets = secrets

    def __call__(self, text):
        text = str(text)
        for s in self.secrets:
            text = text.replace(s, "***")
        # Any leftover bearer-ish token in an upstream error message.
        return re.sub(r"\b(sk-|AIza|1//)[\w\-./]{6,}", r"\1***", text)


def http(url, payload, key, timeout=60, stream=False):
    """Returns (status, body_text_or_none, latency_ms)."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if stream:
                chunks = 0
                while True:
                    line = resp.readline()
                    if not line:
                        break
                    if line.startswith(b"data:"):
                        chunks += 1
                return resp.status, f"{chunks} chunks", (time.perf_counter() - t0) * 1000
            body = resp.read()
            return resp.status, body.decode("utf-8", "replace"), (time.perf_counter() - t0) * 1000
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), (time.perf_counter() - t0) * 1000
    except Exception as e:  # noqa: BLE001 - network errors are results too
        return 0, repr(e), (time.perf_counter() - t0) * 1000


def discover_models(base, key, providers, count):
    """Provider -> (kind, [models]) using the gateway's live /v1/models.

    Wildcard providers (models = []) only know their catalogue at runtime, and
    hardcoding model names in the canary would rot fast — so ask the gateway.
    """
    kinds = {p.get("name"): p.get("type", "openai_compat") for p in providers}
    req = urllib.request.Request(f"{base}/v1/models")
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())["data"]

    out = {name: (kinds[name], []) for name in kinds}
    for item in data:
        ident = item.get("id", "")
        provider, _, model = ident.partition("/")
        if provider in out and len(out[provider][1]) < count:
            out[provider][1].append(model)
    # Providers with no models left in the catalogue still get reported.
    return out


def run_checks(base, key, models_by_provider, max_tokens, redact, timeout):
    results = []  # (provider, model, check, ok, detail, ms)
    for provider, (kind, models) in models_by_provider.items():
        provider_down = False
        for model in models:
            if provider_down:
                break
            full = f"{provider}/{model}"
            status, body, ms = http(
                f"{base}/v1/chat/completions",
                {
                    "model": full,
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": "Reply with the single word: ok"}],
                },
                key,
                timeout=timeout,
            )
            ok = status == 200 and '"content"' in body
            detail = body if not ok else ""
            results.append((provider, full, "chat", ok, redact(detail)[:300], ms))

            if not ok:
                # Every key for this provider is cooling down: the remaining models
                # would produce identical 503s and only obscure the report.
                if status == 503 and "provider_unavailable" in body:
                    provider_down = True
                continue

            status, body, ms = http(
                f"{base}/v1/chat/completions",
                {
                    "model": full,
                    "max_tokens": max_tokens,
                    "stream": True,
                    "messages": [{"role": "user", "content": "Say: ok"}],
                },
                key,
                timeout=timeout,
                stream=True,
            )
            chunks = int(body.split()[0]) if body.endswith("chunks") else 0
            results.append(
                (provider, full, "stream", status == 200 and chunks >= 2, redact(body)[:300], ms)
            )

            if kind in EMBEDDING_KINDS:
                status, body, ms = http(
                    f"{base}/v1/embeddings",
                    {"model": full, "input": ["canary"]},
                    key,
                    timeout=timeout,
                )
                ok = status == 200 and '"embedding"' in body
                results.append(
                    (provider, full, "embeddings", ok, "" if ok else redact(body)[:300], ms)
                )
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="anyhop.toml")
    ap.add_argument("--bin", default="./target/release/anyhop")
    ap.add_argument("--models", type=int, default=1, help="models per provider")
    ap.add_argument("--max-tokens", type=int, default=16)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--only", default="", help="comma-separated provider names")
    ap.add_argument("--keep-running", action="store_true", help="do not stop the gateway")
    args = ap.parse_args()

    if not os.path.exists(args.config):
        print(f"canary: config {args.config} not found", file=sys.stderr)
        return 2
    with open(args.config, "rb") as f:
        cfg = tomllib.load(f)

    redact = Redactor(secrets_of(cfg))
    server = cfg.get("server", {})
    # No api_key means the gateway runs open; the checks then run unauthenticated.
    api_key = server.get("api_key") or ""

    providers = cfg.get("providers", [])
    if args.only:
        wanted = {s.strip() for s in args.only.split(",") if s.strip()}
        providers = [p for p in providers if p.get("name") in wanted]
    if not providers:
        print("canary: no providers to test", file=sys.stderr)
        return 2

    # Temp config: ephemeral port, no state file, same providers as production.
    port = free_port()
    tmpdir = tempfile.mkdtemp(prefix="anyhop-canary-")
    tmp_cfg = os.path.join(tmpdir, "canary.toml")
    text = open(args.config, encoding="utf-8").read()

    def set_server_key(text, key, value):
        """Set `key = value` inside [server], adding it without duplicating the table."""
        pattern = rf'(?m)^\s*{key}\s*=\s*".*?"'
        if re.search(pattern, text):
            return re.sub(pattern, f'{key} = "{value}"', text, count=1)
        m = re.search(r'(?m)^\[server\]\s*$', text)
        if m:
            at = m.end()
            return text[:at] + f'\n{key} = "{value}"' + text[at:]
        return f'[server]\n{key} = "{value}"\n' + text

    text = set_server_key(text, "listen", f"127.0.0.1:{port}")
    text = set_server_key(text, "state_file", "")
    with open(tmp_cfg, "w", encoding="utf-8") as f:
        f.write(text)

    base = f"http://127.0.0.1:{port}"
    env = dict(os.environ, ANYHOP_CONFIG=tmp_cfg, RUST_LOG="warn")
    # cwd=tmpdir: nothing (state file, logs) can land in the repo.
    proc = subprocess.Popen(
        [os.path.abspath(args.bin)],
        env=env,
        cwd=tmpdir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        # Wait for readiness (the OAuth model-list warm-up may take a moment).
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"{base}/healthz", timeout=1) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(0.5)
        else:
            err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
            print(f"canary: gateway did not start\n{redact(err)[:1000]}", file=sys.stderr)
            return 2

        models_by_provider = discover_models(base, api_key, providers, args.models)
        missing = [p for p, (_, ms) in models_by_provider.items() if not ms]
        if missing:
            print(f"canary: no models advertised for {', '.join(missing)}", file=sys.stderr)
        results = run_checks(
            base, api_key, models_by_provider, args.max_tokens, redact, args.timeout
        )

        print(f"{'provider':<14} {'model':<34} {'check':<11} {'':<4} {'ms':>7}")
        for provider, model, check, ok, detail, ms in results:
            mark = "ok" if ok else "FAIL"
            print(f"{provider:<14} {model:<34} {check:<11} {mark:<4} {ms:>7.0f}")
            if not ok and detail:
                print(f"    └─ {detail}")

        # A provider is healthy when at least one chat check passes: per-model
        # failures (retired models, models needing a different endpoint) are noted
        # but do not mean the integration is broken.
        by_provider = {}
        for provider, _model, check, ok, _detail, _ms in results:
            if check == "chat":
                by_provider.setdefault(provider, []).append(ok)
        unhealthy = [p for p, oks in by_provider.items() if not any(oks)]
        total = len(results)
        passed = sum(1 for r in results if r[3])
        print(f"\n{passed}/{total} checks passed")
        print(f"providers healthy: {len(by_provider) - len(unhealthy)}/{len(by_provider)}")
        if unhealthy:
            print(f"UNHEALTHY: {', '.join(unhealthy)}")
            print("CANARY FAILED")
            return 1
        print("CANARY PASSED")
        return 0
    finally:
        if not args.keep_running:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())