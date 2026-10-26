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
- **Failover**: 429 + `Retry-After` (seconds *or* an HTTP-date) → precise cooldown,
  401 → dead, 403 → dead unless the body names a model/region/billing policy (then a
  cooldown, so one forbidden model cannot take the whole provider down), 5xx/timeout → backoff;
  an OAuth 401 also drops the cached access token so the next attempt refreshes instead of
  replaying the rejected one;
  per-model cooldowns for Antigravity (one model's quota doesn't block the others);
  when every key is cooling the client gets `503` **with `Retry-After`**
- **Proactive drain**: reads x-ratelimit-* headers, leaves a key before the limit is hit
- **Admission control**: `max_concurrent` per key
- **Gateway auth & client API keys**: `[server] api_key` (master key) + client API keys
  (`[[client_keys]]` or via UI/API) with per-model access control
- **Model management**: enable/disable models (`disabled_models` or via UI/API) —
  disabled models are hidden from `GET /v1/models` and rejected in `/v1/chat/completions`
- **Per-model limits**: context window, max output and max input tokens, resolved
  from two sources and published in `/v1/models` as `context_length` /
  `max_completion_tokens` / `max_input_tokens`:

  | Source | Where it comes from |
  | --- | --- |
  | `provider` | the provider's own model listing — Antigravity's `maxTokens`/`maxOutputTokens`, Gemini's `inputTokenLimit`/`outputTokenLimit`, OpenRouter-style `context_length`/`top_provider`, vLLM's `max_model_len`, llama.cpp's `n_ctx`, DashScope's native `model_info` |
  | `override` | `[[model_limits]]` in the config, or Models → the limits chip on a row |
  | `unknown` | nobody states it — no field is published rather than a guess |

  The editor shows the effective value with its source badge, an input for your own
  number, and a **Reset** per field that only appears while that field is overridden.

  Nothing about specific vendors is compiled in: a provider whose OpenAI-compatible
  `/models` is bare (DashScope returns only `id/object/created/owned_by`) is pointed
  at its richer catalogue once, in the config:

  ```toml
  [[providers]]
  name = "dashscope"
  ...
  limits_url = "https://dashscope-intl.aliyuncs.com/api/v1/models"
  ```

  ![Model limits editor](docs/img/model-limits.png)
- **`/v1/models` metadata**: a model id, owner and its limits — served from a
  per-catalogue cache and filtered by the client key's allowlist
- **Automatic model refresh**: periodic `/models` polling of all providers
  (`[server] models_refresh_secs`, default 300s) + a "Refresh models" button in the dashboard
- **Hot reload**: `kill -HUP` re-reads the config without a restart
- **Persistence** (redb): key health, OAuth tokens, stats, runtime-added keys
- **JSON API** `/api/*`: providers, quotas, SSE events, key management — always on
- **CORS**: opt-in per origin (`[server] cors_origins`), with real preflight
  handling, so a browser-based client on another origin works; unlisted origins get
  no CORS headers at all
- **Metrics**: `GET /metrics` in Prometheus text format — counters per key, plus latency
  histograms (`anyhop_http_request_duration_seconds`) per route/method/status
- **TLS**: in-process via `rustls` (`[server] tls_cert`/`tls_key`) or terminated at a
  reverse proxy — both documented, HSTS emitted only over HTTPS.
- **Dashboard** `/dashboard` (optional): Sycamore (Rust→WASM) SPA on top of the JSON API.
  Configured entirely from the browser: providers (add/edit settings/delete, add/disable/delete
  keys, OAuth accounts), models (enable/disable/refresh), combos (create/edit chain/reorder/delete),
  client keys (names, model allowlists, rate limits), live events and a raw-TOML editor.
  Runtime: `[server] dashboard = false`. Build without UI: `cargo build --no-default-features`.
  Build the UI: `cd ui && trunk build --release`
- **FIM endpoint** `/v1/fim/completions` (+ alias `/v1/completions`) for IDE
  autocomplete: native pass-through to an OpenAI-compatible provider's own
  `/completions` (so code models keep their `<|fim_prefix|>…` tokens and `suffix`),
  marker-wrapped chat only for providers that have no such endpoint
- **Embeddings** `/v1/embeddings` — passed through for `openai_compat`, translated for `gemini`
  (`:batchEmbedContents`); OAuth kinds report a clear 400
- **Per-key rate limiting** — `rpm`(+ optional `burst`) on any client key, token bucket,
  `429` with `Retry-After`, visible in `/metrics`
- **Memory is bounded end to end**: `max_body_bytes` caps one request,
  `max_inflight_body_bytes` caps the sum across all in-flight requests (the case
  that used to reach the container limit while no single limit was exceeded),
  and client keys are capped at 64 concurrent requests by default (set
  `[server] client_key_max_concurrent = 0` for the old unlimited behaviour).
- **Streaming** without buffering in all modes (SSE→SSE for gemini/antigravity with translation)
- **Tool calls**: full cycle (tools, tool_choice, parallel calls, functionResponse),
  on `/v1/chat/completions` and on `/v1/responses` (`function_call` in and out, in
  streaming too)
- **Model objects** carry the full OpenAI shape (`id`, `object`, `created`, `owned_by`)
  plus the limit spellings clients read; `created` is stamped when the process first
  serves the model, so it does not churn between requests.
- **Thinking**: thoughts always come back for models that have them (as
  `reasoning_content`), with or without a `reasoning_effort` — `includeThoughts` is
  what makes the provider emit them at all, and a gateway that swallowed them made
  every reasoning panel look empty. An explicit `reasoning_effort` still wins:
  `none` hides them, `high` also raises the budget. `thoughtSignature` is captured
  and replayed back (Gemini 3)

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

A prebuilt multi-arch image (`linux/amd64` + `linux/arm64`) is published to the
GitHub Container Registry by
[`.github/workflows/docker.yml`](.github/workflows/docker.yml) on every push to
`main` and on `v*` tags — both architectures are built on native runners and
joined into one manifest, so `docker pull` picks the right one on an x86 server, an
ARM VPS or a Raspberry Pi:

```bash
# pull the published image (public package; on an older GHCR setup run
# `echo $PAT | docker login ghcr.io -u <user> --password-stdin` first)
docker pull ghcr.io/ouki76/anyhop:latest

cp anyhop.example.toml anyhop.toml && chmod 600 anyhop.toml
# A container must listen on all interfaces for the published port to work:
sed -i 's|^listen = .*|listen = "0.0.0.0:8080"|' anyhop.toml

docker run -d --name anyhop --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/anyhop.toml:/etc/anyhop/anyhop.toml:ro,z" \
  -v anyhop-data:/data \
  --read-only --tmpfs /tmp --security-opt no-new-privileges:true \
  --memory 256m \
  ghcr.io/ouki76/anyhop:latest
```

#### Docker Compose on a server

[`docker-compose.server.yml`](docker-compose.server.yml) runs the published image:

```bash
mkdir -p config
cp anyhop.example.toml config/anyhop.toml && chmod 600 config/anyhop.toml
sed -i 's|^listen = .*|listen = "0.0.0.0:8080"|' config/anyhop.toml
# set [server] api_key = "a-long-secret" — without it /api/* is open
sudo chown -R 10001:10001 config     # uid 10001 = the image's `anyhop` user

docker compose -f docker-compose.server.yml up -d
docker compose -f docker-compose.server.yml logs -f
curl -s localhost:8080/healthz       # ok
```

Two details that are easy to get wrong:

* **Mount the config as a directory** (`./config:/etc/anyhop`) if you want the
  dashboard to manage it. A rewrite is atomic — it renames a temp file over the
  config — and a single-file bind mount cannot be renamed onto. A file mount still
  works: the writer detects `EBUSY` and rewrites in place (logged as
  "not atomic"), so a dashboard edit lands, but a crash mid-write could truncate
  the file. The directory mount keeps the atomic guarantee.
* The directory must be **writable by uid 10001** (the image runs as that user,
  never as root) — that is the `chown` above.

`docker compose up -d` (the plain [`docker-compose.yml`](docker-compose.yml))
builds from the checkout instead, which is the developer path.

The `,z` on the config mount relabels it for the container's SELinux domain. On a
host with SELinux enforcing (Fedora, RHEL, CentOS) the `z` is required — without it
the gateway cannot read the mounted file and exits with `Permission denied`.
Pin a server to one build with the commit tag, e.g. `:sha-1a2b3c4`, or a release tag
`:1.2.3`.

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
  `Referrer-Policy: no-referrer`; `Strict-Transport-Security` only when the request came in
  over HTTPS (own TLS listener or `X-Forwarded-Proto: https`), so plain-HTTP curl output
  does not claim otherwise.
- **Auth lockout**: `auth_fail_burst` (default 10) failed attempts from one IP within
  `auth_fail_window_secs` (default 60) turn every subsequent request from that address into
  `429 + Retry-After`, on `/v1` and `/api` alike. Keys are compared in constant time
  (`token_eq`), and the lockout triggers before the comparison.
- **Concurrency caps**: `[server] client_key_max_concurrent` (or per-key `max_concurrent`)
  bounds in-flight requests per client key; the counter is released when the response —
  including a streamed body — is dropped.
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

## Running more than one instance

Every instance can run the same config (only `listen` differs) behind a load balancer:

```toml
[ratelimit]
backend = "redis"                 # "local" (default) keeps buckets in-process
redis_url = "redis://127.0.0.1:6379/0"
key_prefix = "anyhop"
fail_open = false                 # deny when Redis is down instead of allowing

[tuning]
sticky_mode = "hash"              # rendezvous hashing: no shared state at all
```

- **Rate limits** — with `backend = "redis"` every instance runs the same atomic Lua
  token bucket, so two gateways behind an LB still enforce one budget.
  `fail_open = true` (default) degrades to allowing traffic when Redis is unreachable;
  `false` denies with `Retry-After: 1`.
  Bucket names are `<prefix>:rl:<sha256(key)[..16]>:<rpm>:<burst>` — the client's
  bearer token never reaches Redis (it would otherwise sit in `MONITOR`, `KEYS`,
  RDB/AOF and every backup). The digest is unsalted, so it is a *name*, not a
  password hash: anyone holding both Redis and a candidate token can confirm a
  match. To map a bucket back while debugging:
  `printf '%s' "$KEY" | sha256sum | cut -c1-32`. Redis bucket names are not
  carried over from the pre-digest format, so an upgrade starts every client with
  one fresh bucket.
- **Sticky sessions** — `sticky_mode = "hash"` makes the choice a pure function of
  (session, key id), so all instances agree without coordination. `sticky_mode = "map"`
  restores the historical per-process map (single instance only, TTL-bounded).
- **What stays per-instance** — key health/cooldowns and the event/request logs are
  local. Each instance therefore learns about a dead key on its own; that is a
  correctness-preserving trade-off (an extra failed attempt, not a wrong answer),
  and `[server] state_file` can point at a per-instance file.

## Known limits

Honest list — every item is a deliberate boundary, not a bug:

| Area | Limit |
| --- | --- |
| Media/realtime | pass-through only, and only for `openai_compat` providers that declare the capability. Translating Gemini/DashScope-native image or speech APIs is not implemented; the gateway answers `400 unsupported_capability` instead of guessing. |
| Realtime | the provider connection ignores `[server] proxy`/SOCKS (reqwest cannot hand out an upgraded stream); `wss://` upstreams verify against the system CA bundle; no permessage-deflate. |
| Response store | capped by `[tuning] response_store_max` (default 1000) and stored per instance in `state_file`; there is no cross-instance response store. |
| Multi-instance | rate limits and sticky routing are shared/shm-consistent; key health, cooldowns, event and request history stay per instance. |
| OAuth | token exchange is covered by unit tests with fixed payloads; the live exchange is verified manually, not in CI (it needs real credentials). |
| i18n | the dashboard is English only. |

## TLS

Two supported shapes — pick one:

```toml
# A. TLS in this process (no reverse proxy needed)
[server]
tls_cert = "/etc/anyhop/fullchain.pem"
tls_key  = "/etc/anyhop/privkey.pem"
```

```nginx
# B. Terminate TLS at a proxy (nginx config in packaging/nginx.conf.example)
#    Remember to forward X-Forwarded-Proto so HSTS is emitted.
```

`rustls` with TLS 1.3 + 1.2, ALPN `http/1.1`, certificate chain read from PEM (leaf first, then
intermediates; PKCS#8/PKCS#1/SEC1 keys). A certificate/key mismatch fails at startup rather than
at the first handshake. When TLS is on, HSTS is sent; behind a proxy it is sent when
`X-Forwarded-Proto: https` arrives.

### Bursts and saturation

A request that finds every key at its `max_concurrent` cap waits for a slot
(`[tuning] capacity_wait_ms`, default 5000, `0` = fail fast) instead of being
refused at once; when the budget expires the answer is `429` + `Retry-After: 1`.
A pool with no live key, or a model under a quota cooldown, still answers `503`
immediately with the reset time — waiting there would be lying.

### Limits inside the Redis client

The RESP client parses untrusted bytes with hard caps: 64 KiB per line, 8 MiB per
bulk, 1024 elements per array, depth 8, and **32 MiB per reply in total**.
Exceeding any of them is a protocol error and drops the connection. Adding a
command with a wide reply (MGET/KEYS-style) means raising `MAX_ARRAY` /
`MAX_REPLY_BYTES`, not just the per-field caps. Unexpected replies are logged as
`array(2)` / `bulk(8388608)` and `-ERR` text is truncated to 200 bytes, so the
gateway log is not a substitute for Redis' own log.

## Logging

Human-readable by default; `[server] log_format = "json"` switches to one JSON object per
line (`ts`, `level`, `target`, `message` plus every structured field), which is what filebeat /
Loki / CloudWatch expect:

```json
{"level":"INFO","message":"provider 'mock' (4 keys, strategy RoundRobin)","target":"anyhop","ts":1792609921}
```

`RUST_LOG` still controls verbosity (`RUST_LOG=info,anyhop::proxy=debug`).

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
| `/v1/completions` | POST | legacy completion / FIM (alias of `/v1/fim/completions`) |
| `/v1/fim/completions` | POST | fill-in-the-middle: `{model, prompt, suffix?, max_tokens?}`. OpenAI-compatible providers get the request forwarded to their own `/completions` untouched (native FIM tokens/`suffix`); Gemini/Anthropic/Codex/Antigravity have no such endpoint and are asked with a `<FILL_HERE>` marker |
| `/v1/embeddings` | POST | embeddings (openai_compat, gemini) |
| `/v1/models` | GET | everything enabled, combos included (cached per catalogue epoch) |
| `/v1/models/{id}` | GET | one model, `provider/model` or a combo name |
| `/v1/responses` | POST | OpenAI Responses API: `input` (messages, `function_call`, `function_call_output`), `tools`/`tool_choice`/`parallel_tool_calls`, `reasoning.effort`, `instructions`, `max_output_tokens`, `store`/`metadata`, streaming events, `previous_response_id` replays a stored conversation (tool calls included) |
| `/v1/images/generations` | POST | pass-through, needs `capabilities = ["images"]` on an openai_compat provider |
| `/v1/images/edits` | POST | multipart pass-through (body forwarded byte-identical) |
| `/v1/audio/speech` | POST | TTS pass-through, binary relayed as-is (`capabilities = ["audio"]`) |
| `/v1/audio/transcriptions` | POST | multipart pass-through |
| `/v1/audio/translations` | POST | multipart pass-through |
| `/v1/realtime` | GET·WS | WebSocket proxy to a provider with `capabilities = ["realtime"]` |

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
| `/api/client-keys` | GET/POST | list / create client keys — the listing carries `id` + `masked`, never the secret |
| `/api/client-keys/add`, `/api/client-keys/update`, `/api/client-keys/delete` | POST | client key lifecycle (incl. `rpm`/`burst`; `id` or the raw `key`) |
| `/api/client-keys/reveal` | POST | `{"id": "…"}` → the secret, admin-only, recorded as an event |
| `/api/models/limits` | GET/POST | per-model context window / token caps; `null` clears a field, clearing the last one removes the entry |
| `/api/requests`, `/api/quotas` | GET | recent attempts and quota snapshots |
| `/api/events` | GET | live events (SSE stream) |
| `/api/server`, `/api/server/update` | GET/POST | `[server]` + `[tuning]`, secrets write-only |
| `/api/config` | GET/PUT | raw TOML (validated before it is written) |
| `/api/reload` | POST | re-read the config from disk |
| `/api/auth/start`, `/api/auth/status`, `/api/auth/cancel` | POST/GET/POST | OAuth flow; `{"kind":"antigravity","provider":"ag-work"}` targets (or creates) a named provider, `/cancel` frees the callback port |
| `/metrics` | GET | Prometheus exposition, including `anyhop_http_request_duration_seconds` histograms |
| `/healthz` | GET | liveness, no auth |

## OAuth sign-in (account providers)

Antigravity and Codex accounts are added through the provider's OAuth flow. Two transports
are supported, chosen automatically:

| Situation | Transport |
| --- | --- |
| Panel opened on the gateway host (default) | loopback listener on `127.0.0.1:51121` (`codex`: `:1455`) |
| `[server] public_url = "https://gw.example.com"` | the provider redirects to `<public_url>/api/auth/callback`, which the gateway serves itself |

Google and OpenAI only allow a loopback redirect for their installed-app clients, so when the
browser runs on another machine it lands on `http://localhost:51121/oauth-callback?code=…` and
shows "connection refused". That is fine: copy the **whole address** from the address bar and
paste it into the panel ("Browser could not reach this gateway?" → *Complete sign-in*). The code
is exchanged server-side either way, and the OAuth `state` is verified before use.

### Token refresh

Access tokens are renewed automatically, before every upstream call that needs one
(chat, FIM, model listing, quota probes):

- the cached token is used until `token_refresh_window_secs` before expiry (default 300 s), so a
  request never pays the refresh round-trip;
- the exchange uses the refresh token, and **if the issuer rotates it the replacement is kept** —
  it is written to the state file immediately (not in the 2 s batch) and wins over the stale value
  in `anyhop.toml` on the next start;
- `invalid_grant` / 401 marks the account dead and emits an event; transient failures back off and
  retry, so a network blip does not burn the account;
- refreshes are serialized per account by its mutex, so a burst of requests triggers one exchange.

Caveat: with `state_file = ""` the rotated refresh token cannot be persisted — the gateway warns
about this at startup when an OAuth provider is configured.

```bash
# what the panel does under the hood
curl -X POST localhost:8080/api/auth/complete -H "Authorization: Bearer $ADMIN" \
     -d '{"url":"http://localhost:51121/oauth-callback?code=…&state=…"}'
```

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
- `[[client_keys]]` requires `[server] admin_key`. `api_key` and `admin_key` are
  **different credentials with different powers**: `api_key` (or a client key) opens `/v1/*`,
  while `/api/*` — the raw TOML editor, provider CRUD, client-key reveal and the OAuth
  endpoints — accepts `admin_key` *only*. That split is deliberate: the gateway key is pasted
  into every client, so equating the two meant one leaked client credential could read every
  provider secret. `Config::validate` refuses a config with client keys and no `admin_key`.
- The per-key concurrency cap (`max_concurrent`) counts a request until its **body** is done,
  so a long SSE stream holds its slot for as long as it is open.

## Connecting clients

Everything speaks the OpenAI wire format, so most clients only need a base URL and a key.

### OpenAI Responses clients (including DSH)

- Base URL: `https://<host>/v1`, key: a client key (`sk-hop-…`) or `[server] api_key`.
- Model: any id from `GET /v1/models` (`dashscope/qwen3.8-max`, a combo name, …).
- Function tools work end to end: `tools` (function tools only), `tool_choice`,
  `parallel_tool_calls`, `function_call` / `function_call_output` items in `input`,
  `reasoning.effort`. The answer carries `function_call` output items, in streaming
  too, and `previous_response_id` replays a stored turn — tool calls included.

```bash
curl -s https://<host>/v1/responses \
  -H "Authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d '{"model":"dashscope/qwen3.8-max","input":"weather in Omsk?",
       "tools":[{"type":"function","name":"get_weather",
                 "parameters":{"type":"object","properties":{"city":{"type":"string"}}}}]}'
```

### Browser clients (Open WebUI, LobeChat, Chatbox)

A page on another origin needs CORS. Add its origin to the config and restart:

```toml
[server]
cors_origins = ["https://chat.example.com"]
```

The preflight is answered by the gateway itself, so the client's own "test
connection" button works. `"*"` allows every origin; the API key is still required
and credentials are never allowed cross-origin.

### IDE autocomplete (Continue, Cline, Zed)

Point the FIM/autocomplete endpoint at `/v1/fim/completions` (alias `/v1/completions`)
with `{"model": "...", "prompt": "...", "suffix": "..."}`:

- an `openai_compat` provider gets the request forwarded to its own `/completions`,
  so code models keep their native `<|fim_prefix|>…<|fim_suffix|>…<|fim_middle|>`
  tokens (vLLM, SGLang, Together, LM Studio, llama.cpp);
- providers without that endpoint (Gemini, Anthropic, Antigravity's `tab_*`
  completion models) are asked through a `<FILL_HERE>` marker, and the answer is
  cleaned of fences and of the text that already exists around the cursor.

### Plain chat

```bash
curl -s https://<host>/v1/chat/completions \
  -H "Authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d '{"model":"dashscope/qwen3.8-max","messages":[{"role":"user","content":"hi"}]}'
```

## Benchmarks

All numbers below were measured on a 16-core machine, gateway in release mode,
64 keep-alive connections, load generated by `benches/load.rs` (Rust — a Python
load generator caps out around 8k rps on its own and would hide the real capacity).

**Request handling** (no upstream involved):

| Endpoint | Throughput | p50 | p99 |
| --- | --- | --- | --- |
| `GET /healthz` | **197,000 req/s** | 0.30 ms | ~1 ms |
| `GET /v1/models` (124 models, cached) | **172,000 req/s** | 0.35 ms | ~1 ms |
| `GET /metrics` (with histograms) | **65,000 req/s** | 0.98 ms | ~2 ms |

RSS 17 MB with the gateway and the load generator sharing the same 16 cores — the
client steals roughly half the machine, so these are a floor, not a ceiling.
`/v1/models` served a cached body per catalogue epoch; before that cache it measured
38k req/s, and `/metrics` lost ~25k req/s when the latency histograms were added
(they are rendered per scrape — that is the price of p50/p95/p99 per route).
`/v1/models` is dominated by serialising 124 model records; with a 9-model config
it reaches ~150k req/s.

**Proxying** (`POST /v1/chat/completions` through the mock providers — the Python
mocks are the bottleneck there, not the gateway):

| Scenario | Throughput | p50 | p99 |
| --- | --- | --- | --- |
| Chat, mixed providers (Python mocks) | 6 785 req/s | 1.6 ms | 3.5 ms |
| Chat, streaming (Python mocks) | included above | — | — |

**Hot-path micro-benchmarks** (`cargo bench --bench hot_paths`, measured
2026-10-26 on this workstation's CPU; a core *without* SHA extensions is the slow
case for hashing, a SHA-NI machine is several times faster):

| Operation | Time | Throughput |
| --- | --- | --- |
| `peek_request`, 172 B body | 116 ns | — |
| `peek_request`, 64 KiB body | 2.3 µs | 26.7 GB/s |
| `peek_request`, 1 MiB body | 43.5 µs | 23.0 GB/s |
| `string_field_span`, 64 KiB | 2.3 µs | 26.7 GB/s |
| `session_key` (4 KiB of sticky-session hashing) | 1.3 µs | 2.9 GB/s |
| SSE parse, one event | 75 ns | — |
| SSE feed + extend into `VecDeque` | 630 ns | — |
| `pool.pick`, round robin | 10 ns | — |
| `pool.pick`, sticky session | 98 ns | — |
| `pool.snapshot` (dashboard poll) | 163 ns | — |

**End-to-end soak** (`test/soak.py`, 12 workers, 20 s, mock upstreams, release
build): **6 785 req/s**, p50 1.6 ms, p95 2.8 ms, p99 3.5 ms, RSS 11 → 16 MB,
fds 12 → 29, zero errors.

The sticky-session hash is a non-cryptographic 64-bit hash (FNV-1a + splitmix64
finaliser): it only chooses which key serves a conversation, is never compared
against a secret, and SHA-256 over 4 KiB cost 23 µs on this CPU — 15 % of a core at
6 k rps for a cache-affinity decision.

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
cargo test               # 143 unit tests: rotation, cooldowns, error classification,
                         #   scanner, SSE, CSP, metrics, TLS PEM parsing, Responses
                         #   translation, histograms, typed errors
./test/run_all.sh        # full suite: mocks + gateway; 38 checks / 80 assertions
ANYHOP_TEST_PORT=18091 ./test/run_all.sh   # if 18080 is taken by something else
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
- **Hosted tools are refused, not emulated.** `web_search`, `file_search` and
  `code_interpreter` run on the provider's side; a request naming one gets a 400 that
  says so, because forwarding the name without the service would change the meaning.
- **Anthropic JSON mode and Gemini `responseSchema`** are not translated: a request
  asking for structured output gets a 400 rather than silently unconstrained text.
- **SSE parsing expects `\n` or `\r\n` line endings.** A bare `\r` (some exotic
  proxies rewrite the stream) is not treated as a line break.
