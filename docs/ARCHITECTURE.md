# Architecture

## What this is

A single process that sits between OpenAI-compatible clients and one or more
upstream providers, adding credential rotation, failover, format translation and
observability. No database, no external services — one binary, one TOML file, one
`redb` state file.

```
client ──HTTP──▶ axum router ──▶ auth ──▶ routing ──▶ key pool ──▶ provider ──▶ upstream
                                  │         │           │            │
                                  │         │           │            └─ translation layer
                                  │         │           └─ cooldowns, stats, admission control
                                  │         └─ provider/model, combos, allowlists
                                  └─ master key / client keys / admin key
```

## Module map

| Path | Responsibility |
| --- | --- |
| `src/lib.rs` | Everything except the allocator: runtime bootstrap, router assembly, config reload, shutdown |
| `src/main.rs` | Global allocator (jemalloc/mimalloc) + `anyhop::run()` |
| `src/config.rs` | `Config` types, TOML load, `validate()`, atomic writes |
| `src/providers.rs` | `Provider` (HTTP client, pool, model list cache), routing (`resolve`), quota probing |
| `src/pool.rs` | Key pool: strategies, health state machine, cooldowns, sticky sessions, admission control |
| `src/proxy/chat.rs` | `POST /v1/chat/completions`: the retry/failover core of the gateway |
| `src/proxy/embeddings.rs` | `POST /v1/embeddings`: pass-through (openai_compat) or translation (gemini) |
| `src/ratelimit.rs` | Per-client-key token bucket |
| `src/proxy/mod.rs` | `AppState`, `RtConfig`, request log |
| `src/proxy/access.rs` | Client-key allowlist and `disabled_models` matching |
| `src/scan.rs` | Byte-level JSON scanner (model/stream peek, in-place model splice) |
| `src/sse.rs` | SSE parser/serializer shared by the translation layers |
| `src/{gemini,anthropic,antigravity,codex}.rs` | Per-provider request/response translation, incl. streaming and tool calls |
| `src/api/*` | JSON management API (`/api/*`), `/metrics`, config persistence |
| `src/dashboard.rs` | Embedded dashboard assets + per-request CSP |
| `ui/` | Sycamore (Rust→WASM) SPA: a thin client over `/api/*` (no logic of its own) |
| `src/middleware.rs` | Auth middlewares, constant-time compare, security headers |
| `src/storage.rs` | `redb` persistence (health, OAuth tokens, stats, runtime keys, event feed) |
| `src/api/client_keys.rs` | Client key CRUD; the runtime struct holds the key's live rate-limit bucket |
| `src/api/combos.rs` | Combo (fallback chain) CRUD, written into `[[combos]]` |
| `src/api/provider_keys.rs` | Provider add/update/delete, key add/enable/delete |
| `ui/` | Sycamore (Rust→WASM) dashboard, a pure client of `/api/*` |

## Request path (chat completions)

1. **Body → peek.** `scan::peek_request` extracts `model` and `stream` with a
   single byte-level walk (no JSON DOM). Only if the body is not a flat object,
   or a translating provider is a target, does `serde_json` build a `Value`.
2. **Resolve.** `ProviderRouter::resolve` maps `provider/model` (or a bare name,
   or a combo) to one target or an ordered fallback chain.
3. **Policy.** `disabled_models` and the client key's model allowlist are checked
   against the qualified id, the bare name and the upstream name.
4. **Attempt loop** (`run_target`). Up to `max_retries` attempts; each one:
   - `pool.pick(model, session)` chooses a credential honouring strategy,
     cooldowns, per-model quotas and `max_concurrent`;
   - `KeyGuard` reserves the in-flight slot (released on drop, including when a
     client disconnects mid-stream);
   - the request is built per provider kind — `openai_compat` is a byte splice
     (body copy is skipped when the model name already matches), the rest are
     translated;
   - the response is classified: `2xx` → success (streams are passed through
     zero-copy), `429` → key or model cooldown, `401/403` (and Gemini's
     `400 API key not valid`) → credential dead, `5xx` → backoff, other `4xx` →
     returned to the client unchanged.
5. **Combo fallback.** If a target exhausts its retries, the next chain entry is
   tried; each transition emits a dashboard event.

Embeddings follow the same path with two differences: providers without an
embeddings API are skipped instead of failing the chain, and the response is either
forwarded verbatim (`openai_compat`, keeps the provider's `usage`) or rebuilt from
Gemini's `batchEmbedContents` payload.

## Admission and quotas

Two independent gates, both before any upstream call:

- **Per-credential admission control** (`max_concurrent` on a provider): caps parallel
  requests per upstream key, so one noisy client cannot burn a shared quota.
- **Per-client-key rate limit** (`rpm`/`burst`): a token bucket per credential in
  `src/ratelimit.rs`. Refills continuously, so `rpm` is a true sustained rate. The
  bucket survives config reloads unless the limits change.

Both reject with `429`/`503` plus `Retry-After`, and both are visible in `/metrics`
(`anyhop_keys_available`, `anyhop_client_key_rate_limited_total`).

## Failure model

| Signal | Effect | Recovery |
| --- | --- | --- |
| `429` + `Retry-After` | key cooldown for that exact duration | automatic |
| `429` on Antigravity | **per-model** cooldown (other models keep working) | automatic |
| `x-ratelimit-remaining` below `drain_below_pct` | proactive cooldown before hitting the limit | automatic |
| `401/403` | credential marked dead | manual (`/api/keys/enable`) or config reload |
| `5xx` / timeout / reset | exponential backoff (5s → 320s, capped at 1h) | automatic |
| all keys unavailable | `503` + `Retry-After` (time to the earliest recovery), `anyhop_keys_available = 0` | when a cooldown expires |

Health and counters persist in `redb`, so a restart does not resurrect dead keys
or forget statistics.

## Concurrency model

- Tokio multi-thread runtime, `ANYHOP_WORKERS` (default `min(4, cores)`).
- The router is swapped atomically on reload (`arc-swap`), so readers never block.
- Per-key state is atomic; the only locks are the key vector, per-key model
  cooldowns and the sticky-session map, all held for the length of a map lookup.
- `TCP_NODELAY` is set on accepted sockets — without it Nagle + delayed ACK added
  ~40 ms to a fraction of keep-alive requests (see the benchmarks in the README).
- The JSON API, dashboard and metrics read the same live state, so nothing is
  duplicated for observability.

## Why no framework-level magic

There is no middleware stack of third-party layers: auth, body limits, security
headers and routing are explicit in `src/lib.rs` and `src/middleware.rs`, so the
full behaviour of a request is readable in two files.