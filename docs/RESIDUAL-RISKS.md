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

## Assumptions the operator has to keep

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
  like an SSH key, not like a dashboard password.
- **The dashboard is same-origin by default.** A cross-origin client needs its
  origin listed in `[server] cors_origins`; `"*"` is possible and safe for
  bearer-key clients (no credentials are allowed), but it also means any page can
  make a *keyless* preflight succeed.

## Known-good evidence at this tag

| Check | Result |
| --- | --- |
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets` | 0 warnings |
| `cargo test` (lib + integration + doc) | 617 + 18 + 3 ignored |
| `test/audit.sh` (incl. `cargo audit`) | PASSED, 0 advisories over 204 crates |
| `test/run_all.sh` | PASS=58 FAIL=0 (hardening 19/0) |
| `test/chaos_test.py` | PASS=77 FAIL=0 |
| soak, 12 workers × 20 s | 6 754 req/s, p50 1.6 ms, p99 3.5 ms, RSS +2 MB |
| CI + docker workflows on `v0.1.0` | success; image `ghcr.io/ouki76/anyhop:0.1.0` multi-arch |

Two of the checks above were verified by mutation: removing the CORS header and
re-leaking the client-key secret each turned the suite red before the code was
restored (see `docs/TEST-COVERAGE.md`).
