# integration failure — 2026-10-24T21:12:12Z — cb7f72f106b38b15780c0b47c8ef3e794410ed0b

## suite tail
```
  ok   dashboard CSP allows wasm
  ok   path traversal rejected (404/404)
== metrics ==
  ok   /metrics up
  ok   /metrics per-key series
  ok   /metrics available keys
  ok   /metrics requires auth
== exhaustion carries Retry-After ==
  ok   exhausted provider -> 503
  ok   503 carries Retry-After
== routing integrity ==
  ok   duplicate model key routes by the last value
== responses store flag ==
  ok   store:false still returns an id (resp_6ac329dedcb298b710c1e40f021b0c56)
  ok   an unstored response cannot be chained
== embeddings ==
  ok   embeddings openai_compat
  ok   embeddings batch size
  ok   embeddings gemini translated
  ok   embeddings openai shape
  ok   embeddings unsupported provider -> 400
  ok   embeddings requires auth
  ok   embeddings without model -> 400
== fim ==
  ok   /v1/fim/completions answers
  ok   /v1/completions alias answers
  ok   fim requires auth
== soak (latency + leaks) ==
  ok   soak 5s: 2,670 req/s, p99=3.4ms p99, delta +0MB RSS
== redis token bucket (real server) ==
  ok   redis token bucket Lua: PASS=10
== hot reload (SIGHUP) ==
  ok   gateway survives SIGHUP
  ok   SIGHUP reloaded the config
  ok   requests still served after SIGHUP
== hardening (tls, lockout, concurrency, histograms) ==
== hardening (own gateway instances) ==
  ok   TLS in-process (handshake + /healthz over https)
  ok   auth lockout (401 → 429 after 3 failures; codes=[401, 401, 429]…; valid key still 200)
  ok   per-key concurrency cap (codes=[200, 429])
  ok   /v1/responses returns a Response object
  ok   /v1/models/{id} resolves a single model
  ok   previous_response_id replays a stored conversation
  ok   unknown previous_response_id is a 400
  ok   /v1/responses streams 7 events with usage 7/3
  ok   Prometheus latency histograms exposed
  ok   /v1/images/generations relays an image payload
  ok   /v1/images/edits forwards multipart untouched
  ok   /v1/audio/speech relays 42 bytes of audio
  ok   /v1/audio/transcriptions relays a multipart upload untouched
  ok   /v1/audio/translations relays a multipart upload untouched
  ok   /v1/images/generations refuses a provider without the capability
  ok   /v1/realtime upgrades, forwards to the provider and streams back
  ok   two instances share one Redis budget (codes=[200, 200, 200, 429, 429, 429])
HARDENING PASS=17 FAIL=0
  ok   hardening checks (tls, lockout, concurrency, histograms, media, realtime)
== client keys & models ==
=== Testing Client Keys and Models Functionality ===
  ok /api/models returned 9 models
  ok /v1/models with master key returns 9 models
  ok created client key with restricted models
  ok created auto-generated key: sk-hop-...d6f3
  ok /api/client-keys listed 2 keys
  ok /v1/models with restricted client key returned ONLY allowed models
  ok /v1/models/{id} honours the client-key allowlist
  ok /v1/models/{id} honours the disabled set
  ok chat/completions with allowed model succeeded (200)
  ok chat/completions with disallowed model was blocked (403 model_not_allowed)
  ok chat/completions with invalid key was blocked (401)
  ok chat/completions with all-models client key succeeded (200)
  ok disabled mock/test-model via /api/models/disable
  ok disabled model excluded from /v1/models
  ok request to disabled model returned 404 disabled
  ok re-enabled mock/test-model via /api/models/enable
  ok re-enabled model is back in /v1/models
  ok request to re-enabled model succeeded (200)
  ok updated client key allowed models
  ok previously restricted key now succeeds on newly allowed model
  ok deleted client keys
  ok deleted key is rejected with 401
  ok /api/models/refresh succeeded and returned 9 models
  ok qualified allowlist entry does not leak across providers (403)
  ok bare allowlist entry matches provider-qualified request
  ok bare disabled_models entry blocks provider-qualified request
  ok reload removes client keys that are gone from the config
  ok ?key= is GET-only and percent-decoded
  ok per-key rate limit (burst, 429 + Retry-After, metrics)
  ok clearing the rate limit restores unlimited access
  ok combos API (add/list/update/delete + validation)
  ok provider settings API (update + validation)
  ok provider + key lifecycle (create/add/delete/delete-provider)
  ok [server] settings API (read/validate/restart_required, no-op save)
  ok [tuning] readable, editable, validated
  ok per-provider timeout/max_retries
  ok requests carry the client key name
  ok input bounds (names, urls, secrets)
  ok OAuth targets a named provider (collision/validation guarded)
  ok public OAuth callback (state-checked, no admin key needed)

ALL CLIENT KEYS AND MODELS TESTS PASSED!
  ok   client keys and models access control
== canary (mock providers) ==
provider       model                              check                 ms
mock           mock/test-model                    chat        ok         1
mock           mock/test-model                    stream      ok         1
mock           mock/test-model                    embeddings  ok         1
gemini         gemini/test-gemini                 chat        ok         1
gemini         gemini/test-gemini                 stream      ok         1
gemini         gemini/test-gemini                 embeddings  ok         1
claude         claude/claude-test                 chat        ok         1
claude         claude/claude-test                 stream      ok         1

8/8 checks passed
providers healthy: 3/3
CANARY PASSED
  ok   canary harness (chat/stream/embeddings per provider)
== ui navigation (CDP) ==
  skip ui navigation (chromium/websocket-client missing)

PASS=47 FAIL=1 SKIP=1
```
## failing checks
```
  FAIL CSP script hashes
```
## gateway log tail
```
[2m2026-10-24T21:11:56.829274Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m loaded config from /tmp/tmp.nopx3UIHvf.toml
[2m2026-10-24T21:11:56.829303Z[0m [33m WARN[0m [2manyhop[0m[2m:[0m state_file is empty: refreshed OAuth tokens will not survive a restart (rotated refresh tokens may then be lost) — set [server] state_file
[2m2026-10-24T21:11:56.829408Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m provider 'mock' (4 keys, strategy RoundRobin)
[2m2026-10-24T21:11:56.829413Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m provider 'gemini' (2 keys, strategy FillFirst)
[2m2026-10-24T21:11:56.829415Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m provider 'ag' (2 keys, strategy FillFirst)
[2m2026-10-24T21:11:56.829416Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m provider 'drainmock' (1 keys, strategy FillFirst)
[2m2026-10-24T21:11:56.829417Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m provider 'err500' (1 keys, strategy FillFirst)
[2m2026-10-24T21:11:56.829419Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m provider 'claude' (2 keys, strategy FillFirst)
[2m2026-10-24T21:11:56.829420Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m provider 'codex' (2 keys, strategy FillFirst)
[2m2026-10-24T21:11:56.829422Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m combo 'testcombo' (2 targets)
[2m2026-10-24T21:11:56.829423Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m gateway API key auth enabled for /v1/*
[2m2026-10-24T21:11:56.829695Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m dashboard: /dashboard (Sycamore UI)
[2m2026-10-24T21:11:56.829770Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m anyhop listening on http://127.0.0.1:18080
[2m2026-10-24T21:11:56.842667Z[0m [33m WARN[0m [2manyhop::proxy::chat[0m[2m:[0m auth failed, key marked dead [3mprovider[0m[2m=[0mmock [3mkey[0m[2m=[0m****
[2m2026-10-24T21:11:56.850526Z[0m [33m WARN[0m [2manyhop::proxy::chat[0m[2m:[0m rate limited, key on cooldown [3mprovider[0m[2m=[0mgemini [3mkey[0m[2m=[0m**** [3mretry_after[0m[2m=[0mNone
[2m2026-10-24T21:11:56.858345Z[0m [33m WARN[0m [2manyhop::proxy::chat[0m[2m:[0m model quota exhausted [3mprovider[0m[2m=[0mag [3mkey[0m[2m=[0mb***@test.dev [3mmodel[0m[2m=[0m"gemini-3-flash"
[2m2026-10-24T21:11:56.865851Z[0m [33m WARN[0m [2manyhop::proxy::chat[0m[2m:[0m rate limited, key on cooldown [3mprovider[0m[2m=[0mclaude [3mkey[0m[2m=[0m**** [3mretry_after[0m[2m=[0mSome(30)
[2m2026-10-24T21:11:56.873804Z[0m [33m WARN[0m [2manyhop::proxy::chat[0m[2m:[0m rate limited, key on cooldown [3mprovider[0m[2m=[0mcodex [3mkey[0m[2m=[0mc***@test.dev [3mretry_after[0m[2m=[0mSome(30)
[2m2026-10-24T21:11:56.985314Z[0m [33m WARN[0m [2manyhop::proxy::chat[0m[2m:[0m upstream 5xx, key on cooldown [3mprovider[0m[2m=[0merr500 [3mkey[0m[2m=[0m**** [3mstatus[0m[2m=[0m500
[2m2026-10-24T21:11:56.985333Z[0m [33m WARN[0m [2manyhop::proxy::chat[0m[2m:[0m no available key (empty pool or cooling down) [3mprovider[0m[2m=[0merr500 [3mmodel[0m[2m=[0m"err-model"
[2m2026-10-24T21:11:57.067607Z[0m [33m WARN[0m [2manyhop::proxy::chat[0m[2m:[0m rate limited, key on cooldown [3mprovider[0m[2m=[0mmock [3mkey[0m[2m=[0m**** [3mretry_after[0m[2m=[0mSome(30)
[2m2026-10-24T21:12:09.090570Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m SIGHUP: config reloaded (7 providers)
[2m2026-10-24T21:12:12.185740Z[0m [32m INFO[0m [2manyhop[0m[2m:[0m shutting down gracefully
```
