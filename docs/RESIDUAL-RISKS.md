# Residual risks and operating assumptions

As of the `v0.1.0` tag (2026-10-26). This is the honest list: what the gateway
does not do, what it deliberately refuses, and what the operator has to get right.

## What the gateway does not do

1. **Bare-CR (`\r`) SSE line terminators are not event boundaries.** The spec allows
   them; no mainstream provider emits them. An upstream that did would have its
   stream buffered into one oversized event and fail on the idle deadline instead
   of streaming. Fixing it means touching the boundary finder and the line splitter
   together; not worth the blast radius for a case nobody produces.
2. **Anthropic JSON mode and Gemini `responseSchema` are refused** rather than
   emulated through a forced tool call. A 400 that says so is better than silently
   unconstrained text — but a client that needs structured output on Anthropic
   cannot use this gateway for it.
3. **Hosted tools** (`web_search`, `file_search`, `code_interpreter`) are named in a
   400, never forwarded. The provider's service, not the gateway, would have to run
   them.
4. **Embeddings cover `openai_compat` and `gemini` only.** A combo that mixes them
   with other kinds skips those targets rather than failing the request.

## What the gateway does not do (continued)

5. ~~**A request head that never finishes is not timed out.**~~ **Closed.**
   `axum::serve` builds its hyper connections without a timer, so hyper's
   `header_read_timeout` is ignored — that part was true. The bound now lives
   where it can actually be enforced: a `HeaderDeadline` listener reads the whole
   header block (`\r\n\r\n`) under `[tuning] client_header_timeout_secs`
   (default 10 s) and drops the connection otherwise, handing hyper a stream that
   begins exactly where the request does. Measured against a 3 s setting, four
   slowloris shapes — silent, one byte, half a request line, headers without a
   terminator — all closed at 3.0 s while a normal request returned 200.
   Three designs failed first (a timer inside `poll_read`, an absolute deadline
   inside `poll_read`, a first-byte deadline); see the audit report §3.6i.

6. ~~**Per-request bytes are capped, in-flight bytes are not.**~~ **Closed.**
   `[server] max_inflight_body_bytes` (default 256 MiB, `0` = off) now bounds the
   **sum** across requests: the size is taken from `Content-Length` and reserved by
   compare-and-swap *before* the body is read, so the decision precedes the memory
   commitment. A request that would exceed the budget gets `503 server_overloaded`
   with a `Retry-After`, not a silent OOM. Chunked uploads reserve a placeholder and
   settle up afterwards, so under-declaring cannot bypass the budget. Measured with
   a 3 MiB budget and 8 concurrent 900 KiB requests: exactly 3 succeeded and 5 were
   refused at 503, then the budget released cleanly.
   What this does **not** do: bound the memory a single *response* holds (a buffered
   upstream reply is still governed by the streaming/`max_body_bytes` rules), and it
   does not count websocket frames after the upgrade.

7. **Client-key concurrency now has a finite default (64).** A key that sets nothing
   used to mean "no counter at all" — the `in_flight` counter was never incremented,
   so a runaway client was invisible in the metrics *and* could head-of-line-block
   other tenants for up to `capacity_wait_ms` (5 s) before their requests turned into
   429s. `[server] client_key_max_concurrent = 0` restores the old unlimited
   behaviour for deployments that rely on it.

## Assumptions the operator has to keep

- **`api_key` and `admin_key` are different credentials.** `/v1/*` accepts
  `api_key` or a client key; `/api/*` accepts `admin_key` **only**. That is
  deliberate — the gateway key is pasted into every client, so it must not be
  able to read provider secrets. A config with `[[client_keys]]` and no
  `admin_key` is refused at load time rather than silently locking the dashboard.
- **No ambient proxy.** httpx/reqwest would otherwise honour `HTTPS_PROXY` from
  the environment for every upstream call — including the `Authorization` header
  carrying a provider key. The client builder disables that; a proxy must be
  configured explicitly in `[server] proxy` or per provider.
- **TLS.** With no reverse proxy and no `[server] tls_cert`, API keys travel in
  clear text. The gateway warns at startup; it cannot fix it.
- **Secrets are plaintext in `anyhop.toml`.** `chmod 600`, and keep it out of git
  (`.gitignore` covers `anyhop.toml`; `audit.sh` fails if a credential-looking
  string is tracked).
- **One process per state file.** Rate limits and health state are in memory; the
  token bucket can be shared through Redis (`[ratelimit] backend = "redis"`), but
  the model catalogue, cooldowns and the response store are per process.
- **`/api/*` is a root-equivalent API.** The admin key can rewrite the config, add
  providers and reveal client keys (each reveal is logged as an event). Treat it
  like an SSH key, not like a dashboard password. It is a *separate* credential
  from `api_key` on purpose (see above).
- **`GET /api/config` returns the raw TOML**, provider keys and OAuth refresh
  tokens included, while `/api/server` and `/api/client-keys` mask theirs. That
  asymmetry is deliberate — the raw editor exists so an operator can fix a config
  they broke — but it means the admin key must never be shared, and the response
  is served with `Cache-Control: no-store` so no intermediary keeps a copy.
- **The dashboard is same-origin by default.** A cross-origin client needs its
  origin listed in `[server] cors_origins`; `"*"` is possible and safe for
  bearer-key clients (no credentials are allowed), but it also means any page can
  make a *keyless* preflight succeed.

## Known-good evidence at this tag

| Check | Result |
| --- | --- |
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets --all-features` | 0 diagnostics |
| `cargo test --all-features` (lib + integration + doc) | 688 + 18 + 3 ignored |
| `cargo test --no-default-features` | 662 (the minimal image is tested, not just built) |
| `cargo-deny check advisories` / `bans` / `sources` | clean |
| `test/run_all.sh` | PASS=58 FAIL=0 (hardening 19/0, Redis Lua 10/0) |
| `test/chaos_test.py` | PASS=77 FAIL=0 |
| soak, 12 workers × 20 s | 6 641 req/s, p50 1.6 ms, p99 3.7 ms, RSS +6 MB |
| CI + docker workflows on `v0.1.0` | success; image `ghcr.io/ouki76/anyhop:0.1.0` multi-arch |

Two of the checks above were verified by mutation: removing the CORS header and
re-leaking the client-key secret each turned the suite red before the code was
restored (see `docs/TEST-COVERAGE.md`).
