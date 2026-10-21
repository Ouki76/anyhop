# anyhop

OpenAI-compatible LLM gateway with automatic account and API key rotation.
Single binary (~6MB), minimal resource footprint.

## Features

- **Single endpoint** `POST /v1/chat/completions` (OpenAI format) for all providers
- **Providers**: `openai_compat` (OpenRouter, DeepSeek, Groq, ...), `gemini` (API keys),
  `antigravity` (Google OAuth accounts via cloudcode-pa), `anthropic` (API keys),
  `codex` (ChatGPT OAuth accounts)
- **Combos**: virtual models with a fallback chain across providers (`[[combos]]`)
- **Rotation strategies**: `round_robin`, `least_used`, `fill_first` (exhaust a key's quota → next)
- **Failover**: 429 + Retry-After → precise cooldown, 401/403 → dead, 5xx/timeout → backoff;
  per-model cooldowns for Antigravity (one model's quota doesn't block the others);
  when every key is cooling the client gets `503` **with `Retry-After`**
- **Proactive drain**: reads x-ratelimit-* headers, leaves a key before the limit is hit
- **Admission control**: `max_concurrent` per key
- **Gateway auth & client API keys**: `[server] api_key` (master key) + client API keys
  (`[[client_keys]]` or via UI/API) with per-model access control
- **Model management**: enable/disable models (`disabled_models` or via UI/API) —
  disabled models are hidden from `GET /v1/models` and rejected in `/v1/chat/completions`
- **Automatic model refresh**: periodic `/models` polling of all providers
  (`[server] models_refresh_secs`, default 300s) + a "Refresh models" button in the dashboard
- **Hot reload**: `kill -HUP` re-reads the config without a restart
- **Persistence** (redb): key health, OAuth tokens, stats, runtime-added keys
- **JSON API** `/api/*`: providers, quotas, SSE events, key management — always on
- **Metrics**: `GET /metrics` in Prometheus text format (keys available, cooldowns, dead keys, error ratios)
- **Dashboard** `/dashboard` (optional): Sycamore (Rust→WASM) SPA on top of the JSON API.
  Configured entirely from the browser: providers (add/edit settings/delete, add/disable/delete
  keys, OAuth accounts), models (enable/disable/refresh), combos (create/edit chain/reorder/delete),
  client keys (names, model allowlists, rate limits), live events and a raw-TOML editor.
  Runtime: `[server] dashboard = false`. Build without UI: `cargo build --no-default-features`.
  Build the UI: `cd ui && trunk build --release`
- **FIM endpoint** `/v1/fim/completions` (+ alias `/v1/completions`) for IDE autocomplete
- **Embeddings** `/v1/embeddings` — passed through for `openai_compat`, translated for `gemini`
  (`:batchEmbedContents`); OAuth kinds report a clear 400
- **Per-key rate limiting** — `rpm`(+ optional `burst`) on any client key, token bucket,
  `429` with `Retry-After`, visible in `/metrics`
- **Streaming** without buffering in all modes (SSE→SSE for gemini/antigravity with translation)
- **Tool calls**: full cycle (tools, tool_choice, parallel calls, functionResponse)
- **Thinking**: reasoning_effort → thinkingConfig, thoughts are returned as reasoning_content,
  thoughtSignature is captured and replayed back (Gemini 3)

## Quick start

```bash
cp anyhop.example.toml anyhop.toml   # fill in the keys
cargo run --release
```

Add an Antigravity account (Google OAuth):

```bash
anyhop auth antigravity              # opens a browser, prints a TOML snippet
```

Clients address a model as `provider/model`, e.g. `antigravity/gemini-3-flash`,
or by the bare model name from the provider's model list.

## Production deployment

### 1. TLS is mandatory

anyhop speaks **plain HTTP** and has no built-in TLS. API keys, client keys and the
admin key travel in clear text, so the gateway must always sit behind a TLS
terminator:

- nginx: [`packaging/nginx.conf.example`](packaging/nginx.conf.example) (TLS, SSE-safe
  proxying, `?key=` kept out of the access log, `/metrics` restricted)
- or Caddy/traefik with the same idea: no buffering for `/api/events`, long read
  timeouts for streaming.

Bind the gateway to loopback (`listen = "127.0.0.1:8080"`) so it is not reachable
without the proxy.

### 2. Docker

```bash
cp anyhop.example.toml anyhop.toml && chmod 600 anyhop.toml
# A container must listen on all interfaces for the published port to work:
sed -i 's|^listen = .*|listen = "0.0.0.0:8080"|' anyhop.toml
docker compose up -d          # builds the image, mounts the config read-only, /data volume
```

The image also works standalone; the healthcheck probes `$ANYHOP_HEALTH_URL`
(default `http://127.0.0.1:8080/healthz`) — override it if you change
`[server] listen`.

The image is a multi-stage build: Sycamore dashboard → WASM, then the gateway, then a
Debian slim runtime running as UID 10001 with a healthcheck. State (`anyhop.redb`)
lives in the `/data` volume.

### 3. systemd

```bash
sudo install -m 755 target/release/anyhop /usr/local/bin/anyhop
sudo install -m 644 packaging/anyhop.service /etc/systemd/system/anyhop.service
sudo useradd --system --home-dir /var/lib/anyhop --shell /usr/sbin/nologin anyhop
sudo install -d -o anyhop -g anyhop -m 750 /var/lib/anyhop
sudo install -d -m 750 /etc/anyhop
sudo install -o root -g anyhop -m 640 anyhop.toml /etc/anyhop/anyhop.toml
sudo systemctl daemon-reload && sudo systemctl enable --now anyhop
```

The unit runs with `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`,
`SystemCallFilter=@system-service` and `UMask=0077`; only `/var/lib/anyhop` is
writable. `systemctl reload anyhop` sends SIGHUP (config hot reload).

### 4. Metrics and alerting

`GET /metrics` exposes Prometheus text format (admin-authenticated; a scraper sends
`authorization: bearer <admin_key>`).

| Series | Why it matters |
| --- | --- |
| `anyhop_keys_available` | **0 means every credential is dead or cooling** — the gateway can only return 503 |
| `anyhop_key_status{state="dead"}` | Revoked/expired keys; they never recover by themselves |
| `anyhop_key_cooldown_seconds` | Who is rate-limited, and for how long |
| `anyhop_key_failures_total` / `anyhop_key_requests_total` | Per-credential error ratio |
| `anyhop_process_resident_memory_bytes` | Should stay flat (~10–20 MB); growth means a leak |

```yaml
groups:
  - name: anyhop
    rules:
      - alert: AnyhopNoKeysAvailable
        expr: anyhop_keys_available == 0
        for: 2m
        annotations: { summary: "all upstream credentials are exhausted" }
      - alert: AnyhopDeadKeys
        expr: max(anyhop_key_status{state="dead"}) == 1
        for: 10m
        annotations: { summary: "a credential was rejected by the upstream" }
```

### 5. Security notes

- **`?key=`**: the dashboard's EventSource and Prometheus scrapers cannot set an
  `Authorization` header, so the admin key is accepted as `?key=` for **GET only**.
  It therefore appears in URLs — keep query strings out of proxy access logs
  (the example nginx config does) and use `Referrer-Policy: no-referrer` (sent by
  default).
- **Dashboard CSP**: the SPA document ships a strict `Content-Security-Policy` whose
  `script-src` lists the SHA-256 of every inline script trunk emits. If you edit the
  UI and serve a stale `ui/dist`, the page will refuse to boot — always rebuild the
  bundle (`cd ui && trunk build --release`) and the binary.
- Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Strict-Transport-Security`.
- Secrets live in plaintext TOML. Keep it `chmod 600`/`640`; the binary logs a warning
  when it is world-readable.

### 6. Backups

Everything persistent is the redb file (`[server] state_file`, default
`anyhop.redb` in the working directory): key health, OAuth tokens, stats, runtime
added keys. Copying it while the process runs is fine (redb is crash-safe), but stop
the service for a consistent snapshot.

## Configuration

See `anyhop.example.toml`. Path: `ANYHOP_CONFIG` (default `anyhop.toml`).

| Env | Default | Meaning |
| --- | --- | --- |
| `ANYHOP_CONFIG` | `anyhop.toml` | Config file path |
| `ANYHOP_WORKERS` | `min(4, cores)` | Tokio worker threads — raise it on many-core boxes (see benchmarks) |
| `RUST_LOG` | `info` | Log filter (`RUST_LOG=debug anyhop`) |

## Tuning

Every timing and limit that used to be a `const` is now a config value (`[tuning]`), editable
from the dashboard (Settings → Tuning) or the file:

```toml
[tuning]
max_cooldown_secs = 3600        # hard cap on a benched key
base_backoff_secs = 5           # 5xx backoff base, doubles per consecutive failure
rate_limit_cooldown_secs = 60   # 429 without Retry-After
models_cache_ttl_secs = 600     # upstream model list freshness
sticky_ttl_secs = 1800          # conversation → key stickiness
sticky_max_entries = 10000      # sticky map size
session_prefix_bytes = 4096     # body bytes hashed into the session id
event_channel_capacity = 256    # SSE broadcast buffer
persist_interval_secs = 30      # history flush interval
oauth_http_timeout_secs = 30    # token refresh timeout
token_refresh_window_secs = 300 # refresh this early (0 = on expiry)
ui_refresh_secs = 3             # dashboard poll interval
sse_keepalive_secs = 15         # SSE ping interval
quota_cache_ttl_secs = 60       # quota snapshot reuse
```

Per-provider overrides of the attempt budget:

```toml
[[providers]]
name = "slow-upstream"
timeout_secs = 300   # default: [server] attempt_timeout_secs
max_retries = 2      # default: [server] max_retries
```

## HTTP API

Everything the dashboard does is a plain HTTP call, so the whole surface is scriptable.
`/v1/*` authenticates with the gateway key, `/api/*` and `/metrics` with the admin key
(both accept `Authorization: Bearer <key>`; GET also accepts `?key=`).

Errors are always the same envelope, including for malformed bodies:

```json
{"error": {"code": 422, "message": "…", "type": "invalid_request_error"}}
```

| Gateway (`/v1`) | Method | Purpose |
| --- | --- | --- |
| `/v1/chat/completions` | POST | chat, streaming via `"stream": true` |
| `/v1/completions` | POST | legacy completion / FIM |
| `/v1/fim/completions` | POST | fill-in-the-middle |
| `/v1/embeddings` | POST | embeddings (openai_compat, gemini) |
| `/v1/models` | GET | everything enabled, combos included |

| Admin (`/api`) | Method | Purpose |
| --- | --- | --- |
| `/api/providers` | GET | providers, keys, live stats, editable settings |
| `/api/providers/add`, `/api/providers/update`, `/api/providers/delete` | POST | provider lifecycle |
| `/api/keys/add`, `/api/keys/enable`, `/api/keys/disable`, `/api/keys/delete` | POST | upstream credentials |
| `/api/models`, `/api/models/refresh` | GET/POST | catalogue |
| `/api/models/enable`, `/api/models/disable`, `/api/models/toggle` | POST | per-model switch (`{"model": "provider/model"}`) |
| `/api/models/enable-all`, `/api/models/disable-all` | POST | bulk switch |
| `/api/combos` | GET | virtual models and their chains |
| `/api/combos/add`, `/api/combos/update`, `/api/combos/delete` | POST | combo lifecycle |
| `/api/client-keys` | GET/POST | list / create client keys |
| `/api/client-keys/add`, `/api/client-keys/update`, `/api/client-keys/delete` | POST | client key lifecycle (incl. `rpm`/`burst`) |
| `/api/requests`, `/api/quotas` | GET | recent attempts and quota snapshots |
| `/api/events` | GET | live events (SSE stream) |
| `/api/server`, `/api/server/update` | GET/POST | `[server]` + `[tuning]`, secrets write-only |
| `/api/config` | GET/PUT | raw TOML (validated before it is written) |
| `/api/reload` | POST | re-read the config from disk |
| `/api/auth/start`, `/api/auth/status`, `/api/auth/cancel` | POST/GET/POST | OAuth flow; `{"kind":"antigravity","provider":"ag-work"}` targets (or creates) a named provider, `/cancel` frees the callback port |
| `/metrics` | GET | Prometheus exposition |
| `/healthz` | GET | liveness, no auth |

## Dashboard

`/dashboard` is a pure client of the JSON API — everything it does is also available over HTTP.

| Tab | What you can do |
| --- | --- |
| Overview | health rollup, per-account quota cards, recent events |
| Providers | add a provider (key-based or OAuth, **several of the same type** with separate account pools), edit base URL / strategy / `max_concurrent` / drain threshold / attempt budget / proxy, add a key, disable or **delete** a key, delete the provider |
| Models | enable/disable models (individually or all), refresh the catalogue, create/edit/delete **combos** with an ordered fallback chain |
| API Keys | create client keys (name, model allowlist, `rpm`/`burst`), edit the allowlist and the rate limit, delete with confirmation |
| Settings | `[server]` — listen, attempts/timeouts, body limit, history depth, refresh interval, proxy, state file, dashboard toggle, gateway/admin API keys (secrets are write-only) |
| Quotas / Events / Requests | live views (events arrive over SSE) |
| Config | raw TOML editor with validation + hot reload (the escape hatch for anything not covered above) |

Destructive actions (delete key / combo / provider) ask for confirmation: a misclick revokes
credentials that clients are using right now.

The dashboard is responsive: a full sidebar above 900px, a collapsible burger menu below it, a
2×2 KPI grid under 1100px, and on phones the Requests table becomes a stacked card list instead
of a horizontally scrolling 720px table.

Proxy credentials (`http://user:pass@host`) are masked as `http://***:***@host` in every API
response — the form can never round-trip them back to the browser. For OAuth providers the
credential list shows the account e-mail, not a prefix of the refresh token.

## Client keys: quotas and limits

Each `[[client_keys]]` entry can carry a sustained rate:

```toml
[[client_keys]]
name = "Cursor IDE"
key = "sk-hop-cursor"
models = ["antigravity/gemini-3-flash"]   # [] = all models
rpm = 120        # sustained requests per minute (omit = unlimited)
burst = 20       # optional spike allowance (default: same as rpm)
```

- Token bucket, refilled continuously — not a counter reset on the wall-clock minute,
  so there is no double burst around a minute boundary.
- Over the limit: `429` with `Retry-After`, OpenAI-style error body
  (`"type": "rate_limit_exceeded"`), and `anyhop_client_key_rate_limited_total`
  increments.
- The live bucket survives a config reload (`SIGHUP`) as long as the limits did not
  change, so editing one key does not hand every tenant a fresh quota.
- Visible/edit in the dashboard (API Keys tab) and via `POST /api/client-keys/add|update`.

## Benchmarks

All numbers below were measured on a 16-core machine, gateway in release mode,
64 keep-alive connections, load generated by `benches/load.rs` (Rust — a Python
load generator caps out around 8k rps on its own and would hide the real capacity).

**Request handling** (no upstream involved):

| Endpoint | Throughput | p50 | p99 |
| --- | --- | --- | --- |
| `GET /healthz` | **207,000 req/s** | 0.28 ms | 0.75 ms |
| `GET /v1/models` | **152,000 req/s** | 0.40 ms | 0.94 ms |
| `GET /metrics` | **82,000 req/s** | 0.77 ms | 1.49 ms |

**Proxying** (`POST /v1/chat/completions` through the mock providers — the Python
mocks are the bottleneck there, not the gateway):

| Scenario | Throughput | p50 | p99 |
| --- | --- | --- | --- |
| Chat, mixed providers | ~4,800 req/s | 0.92 ms | 1.4 ms |
| Chat, streaming | ~4,500 req/s | 0.95 ms | 1.5 ms |

**Hot-path micro-benchmarks** (`cargo bench`):

| Operation | Time | Throughput |
| --- | --- | --- |
| `peek_request`, 172 B body | 140 ns | — |
| `peek_request`, 64 KiB body | 2.4 µs | 26 GB/s |
| `peek_request`, 1 MiB body | 45 µs | 22 GB/s |
| `session_key` (4 KiB hash) | 1.8 µs | 2.1 GB/s (SHA-NI) |
| SSE parse, one event | 80 ns | — |
| `pool.pick`, round robin | 12 ns | — |
| `pool.pick`, sticky session | 54 ns | — |

**Memory**: 9 MB idle, 16–22 MB under sustained load, flat over a 90 s soak with
~360k requests (`test/soak.py`, no leak, no fd growth).

The Python providers used by the test suite are the bottleneck for the chat path
(a single Python HTTP server), which is why chat numbers are an order of magnitude
below the gateway's own capacity.

### Reproducing

```bash
# micro-benchmarks (no server needed)
cargo bench --bench hot_paths

# endpoint throughput (needs a running gateway + test mocks)
./test/run_all.sh                     # starts mocks+gateway, runs checks, exits
ANYHOP_CONFIG=test/anyhop.test.toml ./target/release/anyhop &
ANYHOP_LOAD_URL=http://127.0.0.1:18080 ANYHOP_LOAD_PATH=/v1/models \
  ANYHOP_LOAD_CONCURRENCY=64 ANYHOP_LOAD_DURATION=10 cargo bench --bench load

# sustained load, latency percentiles, RSS/fd leak detection
python3 test/soak.py --duration 90 --workers 32
```

Tuning notes:

- `ANYHOP_WORKERS=8` on a 16-core box gave +17% on JSON-heavy endpoints
  (147k → 172k req/s) for +0.5 MB idle RSS; the default stays at 4 to keep the
  footprint minimal.
- Two changes matter for tail latency and bulk payloads: `TCP_NODELAY` on
  accepted sockets (p95 42 ms → 7 ms under keep-alive) and the single-pass body
  scanner (10× faster on large bodies).

## Tests

```bash
cargo test               # unit tests: rotation, cooldowns, error classification,
                         #   scanner, SSE, CSP, metrics, token comparison
./test/run_all.sh        # full suite: mocks + gateway; 37 checks / 72 assertions
                         #   (routing, rotation, streaming, embeddings, rate limits,
                         #    combos, provider & key lifecycle, tuning, SSE, dashboard)
```

CI (`.github/workflows/ci.yml`) runs the same on every push: build, unit tests, the
no-dashboard build, the integration suite, and the dashboard WASM build.

### Canary against real providers

The mocks prove the wiring; only the live APIs prove the contracts:

```bash
python3 test/canary.py --config anyhop.toml            # 1 model per provider
python3 test/canary.py --config anyhop.toml --only gemini,antigravity --models 2
```

It copies the config to a temp file (ephemeral port, `state_file = ""`), starts the
binary, and for every provider runs a non-streaming chat, a streaming chat and an
embeddings request where the provider supports it. Exit code is non-zero on any
failure, so it can run from cron/CI with real keys. Every configured secret is
redacted from the output.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the request flow, failure model
and module map.

## Limitations

Honest list — none of these are accidents:

- **Embeddings cover two provider kinds** (`openai_compat`, `gemini`). Anthropic and the
  OAuth kinds have no embeddings API, so a combo that mixes them skips those targets.
- **Rate limits are per process.** They live in memory and reset on restart; with several
  gateways in front of the same upstream, each enforces its own budget.
- **Single node.** State lives in one `redb` file; there is no clustering, no shared
  counter between instances. Run one gateway per state file.
- **Plaintext secrets in `anyhop.toml`.** Keep it `chmod 600`; there is no secret
  manager integration.
- **Upstream format coverage is best-effort.** Provider APIs drift; the translation
  layers are covered by mocks in CI, not by live-provider canary tests.
