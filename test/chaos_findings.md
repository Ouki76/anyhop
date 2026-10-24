# Chaos / resilience findings — anyhop gateway

Produced by `test/chaos_test.py` (stdlib only, own ports + own config + own
redb state file; safe to run next to other gateways and mocks).

```
python3 test/chaos_test.py                 # everything, ~55 s
python3 test/chaos_test.py --only 1,6      # selected scenarios
python3 test/chaos_test.py --keep          # keep temp dir + per-instance logs
```

Result at the time of the audit (`target/release/anyhop`, built 2026-10-22):
**CHAOS PASS=67 FAIL=10**, identical outcome across three consecutive runs.

> **Status 2026-10-24: all eight findings below are fixed and the run is green.**
> F1 `[tuning]` now reaches the pool (`providers.rs`/`pool/mod.rs`); F2 response-body
> idle deadline (`proxy/chat/stream.rs::open_body` + `idle_body`); F3 bounded
> shutdown (`[tuning] shutdown_grace_secs`); F4 saturation answers 429 + `Retry-After`;
> F5 request-body read idle timeout (`[tuning] client_body_timeout_secs`); F6
> `accept_2xx` rejects a wrong content type; F7 `Retry-After` is rounded up in both
> limiters; F8 `/metrics` emits `# HELP`/`# TYPE` before its samples.
> The table is kept as the historical record of the run.

Nine findings are real defects; `1.14`, `1.16`, `1.17` are three symptoms of the
same root cause, so there are **8 distinct bugs**:

| # | Sev | Checks | One line |
|---|-----|--------|----------|
| F1 | **HIGH** | 1.14, 1.16, 1.17 | `[tuning]` backoff/cooldown values never reach the key pool — an operator-set 3 s cooldown silently becomes 60 s, a `Retry-After: 999` is not clamped |
| F2 | **HIGH** | 1.7 | No response-**body** timeout: after upstream headers a silent upstream hangs the client (and a key slot) indefinitely |
| F3 | **HIGH** | 5.5 | Graceful shutdown waits for in-flight streams forever → SIGTERM never completes, final state flush never runs |
| F4 | **HIGH** | 3.5 | With `max_concurrent` set, saturation fails fast: 196/200 parallel requests got an instant 503 with no `Retry-After` and a misleading "unavailable after 4 attempts" |
| F5 | MEDIUM | 2.7 | No request-body read/idle timeout: a 100 B/s upload holds a connection and a client-key concurrency slot indefinitely (slowloris) |
| F6 | MEDIUM | 1.12 | A `200 text/html` page from the upstream is relayed as a **successful** chat completion (no body validation, key counted as a success) |
| F7 | MEDIUM | 6.4 | Local client-key limiter floors `Retry-After` to whole seconds (`as_secs`) while the Redis limiter rounds up → a client that obeys `Retry-After` is rejected again |
| F8 | MEDIUM | 6.6 | `/metrics` is not valid Prometheus exposition for `anyhop_client_key_rate_limit_tokens`: the samples are emitted **before** their `# HELP`/`# TYPE` lines |

---

## F1 — `[tuning]` backoff / cooldown settings are silently ignored (HIGH)

**Checks:** 1.14, 1.16, 1.17 (three symptoms, one cause).

**Repro** (each in its own throwaway instance, two keys):

```toml
[tuning]
base_backoff_secs = 1
rate_limit_cooldown_secs = 3
max_cooldown_secs = 20
```

1. `POST /v1/chat/completions {"model":"mock/fail500"}` (upstream always 500)
   → `GET /api/providers` → `cooldown_remaining_secs` = **5**, expected **1**.
2. `POST {"model":"mock/rate429nora"}` (429 without `Retry-After`)
   → `cooldown_remaining_secs` = **59/60**, expected **3**.
3. `POST {"model":"mock/rate429long"}` (429 with `Retry-After: 999`)
   → `cooldown_remaining_secs` = **999**, expected **≤ 20**.

`GET /api/server` does report the configured values
(`tuning.base_backoff_secs = 1`, …), so the config is parsed and hot-reloaded
correctly — it just never reaches the pool.

**Root cause** — `src/providers.rs:153` builds the pool with the *default* tuning:

```rust
let pool = KeyPool::new(          // src/pool/mod.rs:57
    cfg.name.clone(), secrets, cfg.strategy, cfg.max_concurrent,
    storage.cloned(), events.cloned(),
);
```

and `KeyPool::new` is a shortcut that forwards to
`KeyPool::new_with_tuning(…, Tuning::default())` (`src/pool/mod.rs:66-75`). The
`tuning` argument that `Provider::from_config` already has (it is used for the
HTTP client and the meta timeouts) is dropped here. Consequences:

* `base_backoff_secs`, `rate_limit_cooldown_secs`, `max_cooldown_secs` — all
  read from `KeyPool::tuning` (`src/pool/mod.rs:269-290`,
  `src/pool/key.rs:150`) — always use the built-in defaults (5 s / 60 s /
  3600 s). A single 429 benches a key for a minute when the operator asked for
  three seconds; one bogus `Retry-After` from a provider can bench the whole
  pool for an hour.
* `sticky_mode` / `sticky_ttl_secs` / `sticky_max_entries` are equally dead:
  `StickySessions::new(tuning)` is called inside `new_with_tuning`, so it also
  receives `Tuning::default()`.

**Suggested fix:** in `Provider::from_config`, call
`KeyPool::new_with_tuning(…, tuning.clone())`; drop or deprecate the
`KeyPool::new` shortcut so this cannot regress; add a unit test asserting
`pool.tuning.base_backoff_secs` equals the configured value.

---

## F2 — no response-body timeout after the upstream headers (HIGH)

**Check:** 1.7.

**Repro:** upstream sends `200 OK` + `Content-Type: text/event-stream` headers
and then nothing at all (no body, no FIN). Client:

```
POST /v1/chat/completions  {"model":"mock/silent","stream":true}
```

* Observed: status 200 with **0 bytes for 7 s** (`attempt_timeout_secs = 3`);
  a separate 14 s probe also returned nothing (≈5× the attempt timeout). The
  only reason it ends is that the client gives up.
* Expected: the request fails or the stream is closed after the attempt budget.

`attempt_timeout_secs` only wraps the wait for **headers**:
`src/proxy/chat/mod.rs:479` `tokio::time::timeout(attempt_timeout, req.send())`.
Once the response head is in, `stream_upstream` (`src/proxy/chat/stream.rs:174`)
pipes `resp.bytes_stream()` with no per-chunk or first-byte deadline, and the
non-stream path (`stream.rs:40`, `resp.bytes().await`) has none either.

Note the contrast the harness also proves (check 1.8b): silence **before** the
headers *is* handled — two attempts × 3 s → `503` after 6.0 s.

While the client waits, one key slot stays charged
(`anyhop_key_in_flight = 1`); it is released correctly when the client leaves
(check 1.8 — that part is healthy).

**Suggested fix:** add an upstream body budget (e.g.
`[tuning] upstream_body_timeout_secs`, default ~60 s for non-stream and an
inter-chunk idle timeout for streams — `sse_keepalive_secs` is a natural
starting point), implemented as a `Stream` adapter that errors after the
deadline so the client gets a premature EOF instead of a hang.

---

## F3 — SIGTERM never completes while a response streams (HIGH)

**Check:** 5.5.

**Repro:** open `POST /v1/chat/completions {"model":"mock/slow-stream","stream":true}`
(the mock emits one SSE frame every 100 ms for up to 30 s), read one frame, send
`SIGTERM`, keep reading like a browser tab.

* Observed: log says `shutting down gracefully`, then the process stays alive
  **>10 s**; the client never gets a close (`eof_at = None`). It exited only
  after the harness dropped the client connection (0.0 s later).
* Expected: stop accepting, terminate/close in-flight streams, exit within a
  bounded grace period.

`src/lib.rs:269` / `src/lib.rs:280` call `axum::serve(…).with_graceful_shutdown(
shutdown_signal())` with no timeout. Hyper's graceful shutdown waits for every
in-flight response, so one long SSE stream blocks the whole shutdown — and with
it `persist_feeds()` + `storage.flush_async()` (`src/lib.rs:285-289`), which run
only after `serve()` returns. Under Kubernetes/systemd the SIGKILL arrives first
and those flushes are skipped.

**Suggested fix:** wrap the serve future in `tokio::time::timeout(grace, …)`
after the signal (e.g. `[tuning] shutdown_grace_secs`), or drive
`serve` with a `CancellationToken` that also aborts streaming bodies, then flush
state regardless.

**Related, healthy:** an *idle* SIGTERM is clean (0.0 s, exit code 0), the redb
state is flushed (3.7 MB), request history is restored on the next start, and
`kill -9` leaves a redb file that reopens without complaint (checks 5.1–5.4,
5.6–5.9).

---

## F4 — saturation fails fast: 196/200 instant 503, no `Retry-After` (HIGH)

**Check:** 3.5 (3.1–3.4 and 3.6–3.10 pass).

**Repro:** 2 keys × `max_concurrent = 2`, upstream latency 100 ms, 200 parallel
`POST /v1/chat/completions` with one client key.

* Observed, in **0.2 s total**: `{200: 4, 503: 196}`. The mock saw only **5**
  upstream attempts for 200 requests. Every 503 body is

  ```json
  {"error":{"code":503,"message":"provider 'mock' unavailable after 4 attempts","type":"provider_unavailable"}}
  ```

  and **0/196** carry `Retry-After`.
* Expected: either serve most of them (queue/briefly wait — capacity frees up
  every 100 ms) or reject the genuine overflow with a 429/503 **and**
  `Retry-After`, and without pretending four attempts were made.

Mechanics: `KeyPool::is_available` includes admission control
(`src/pool/key.rs:128`), so `pick()` returns `None` as soon as both keys are at
their cap; `run_target` then `break`s on the first attempt
(`src/proxy/chat/mod.rs:331-334`) and `exhausted_response` is called with
`wake_after()` = `None` (`mod.rs:227`), which is why no `Retry-After` is
attached. The message counts configured attempts, not real ones.

The gateway stays *correct* (no 500s, keys not dead, in-flight returns to 0, a
normal request succeeds immediately afterwards, control plane fast under load) —
it is the burst behaviour that is unusable: a 100 ms blip is indistinguishable
from a provider outage for the client.

**Suggested fix:** distinguish "no capacity" from "no healthy key": wait a few
ms for a slot (or answer `429` + `Retry-After: 1`), and use the actual attempt
count in the message.

---

## F5 — no request-body read timeout (slowloris) (MEDIUM)

**Check:** 2.7.

**Repro:** `POST /v1/chat/completions` with `Content-Length: 524288`, send
`{"model":"mock/ok","messages":[` and then ~100 B/s, keep the socket open.

* Observed: after 3 s the connection is still open and the 1-slot client key is
  still charged (a concurrent request on that key gets `429`). Nothing in the
  gateway ever times the body out; only the client can end it.
* Expected: an idle/read deadline aborts the upload.

`DefaultBodyLimit` (`src/lib.rs:468`) caps the *size* only. Because the auth
middleware charges the client-key concurrency slot before the body is read
(`src/middleware.rs:189-203`), a handful of slow uploads can occupy a tenant's
whole concurrency budget for free.

**Suggested fix:** a body-read timeout (`hyper` `http1_header_read_timeout` for
the head, plus a `TimeoutLayer`/`timeout` around body consumption, or an
`http_body_util` wrapper), exposed as `[tuning] client_body_timeout_secs`.

**Healthy counterpart:** an oversized body is refused with `413` in ~0 ms
(check 2.10), and the slot comes back when the abandoned upload is closed
(check 2.9).

---

## F6 — `200 text/html` is relayed as a successful completion (MEDIUM)

**Check:** 1.12.

**Repro:** upstream answers `200` + `text/html` + an nginx error page for
`POST /v1/chat/completions {"model":"mock/html200"}`.

* Observed: client gets `200`, `content-type: text/html; charset=utf-8`,
  122 B of HTML. `report_success` runs, `anyhop_key_requests_total` is bumped,
  `anyhop_key_failures_total` is not.
* Expected: an upstream error (502/503), or at minimum a failure recorded and a
  non-200 status, since the response is not an OpenAI chat completion.

This is the zero-copy pass-through design (`src/proxy/chat/stream.rs:32-64`
returns the upstream bytes as-is; only the non-stream path even tries
`serde_json::from_slice` for `usage`). Captive portals, CDN error pages and
misconfigured proxies all produce this, and it is invisible to any monitoring
that looks at status codes.

**Suggested fix:** on `/v1/chat/completions` require the upstream
`content-type` to be JSON (non-stream) or `text/event-stream` (stream); if not,
classify as `FailKind::Server`, retry the next key and surface 502.

---

## F7 — local `Retry-After` floors instead of ceilings (MEDIUM)

**Check:** 6.4.

**Repro:** client key `rpm = 24, burst = 1`.

1. `POST` → `200` (token consumed).
2. `POST` → `429`, `Retry-After: 2` (the bucket needs ≈2.4 s).
3. `sleep(2)`, `POST` → **`429` again**.

The two backends disagree: `src/middleware.rs:157` uses
`d.as_secs().max(1)` (floor, so 2.4 s is advertised as 2 s) while the Redis
limiter rounds up on purpose (`src/distributed/limiter.rs:280-283`,
`secs_from_ms` → `div_ceil`). The same floor is used for the
provider-unavailable `Retry-After` (`src/proxy/chat/errors.rs:35`), where it
makes an exhausted pool look ready ~1 s early.

**Suggested fix:** use one helper that rounds **up** (`as_secs_f64().ceil()`)
everywhere a `Retry-After` is produced.

**Healthy:** the bucket boundary itself is exact — with `rpm=6/burst=6` exactly
6 requests pass and request 7 and 8 are `429` (check 6.1); a config reload does
not refill the bucket (6.3); a key without `rpm` is never limited (6.5); Redis
down honours `fail_open` in both directions with `Retry-After: 1` when closed
and one log line per minute (6.7/6.8).

---

## F8 — `/metrics`: samples before their `# TYPE` (MEDIUM)

**Check:** 6.6.

**Repro:** a config with at least one client key that has `rpm` set, then
`GET /metrics`.

The result contains, in this order:

```
anyhop_client_key_rate_limit_tokens{key="retry"} 0.861      <- sample
...
# HELP anyhop_client_key_rate_limit_tokens Tokens left in the key's bucket.
# TYPE anyhop_client_key_rate_limit_tokens gauge              <- metadata AFTER
```

Prometheus' text format requires the `# TYPE` line before the first sample of a
family; strict parsers (`promtool check metrics`, several scrapers) reject the
whole exposition. `src/api/metrics.rs:157` writes the samples inside the loop,
`src/api/metrics.rs:161-165` writes the `HELP`/`TYPE` after it.

**Suggested fix:** emit the `HELP`/`TYPE` block before the loop (like the
`rate_limited_total` family just above it).

**Healthy:** on an instance without rate-limited keys the rest of the exposition
is well-formed, histogram `_count` matched the 12 requests the harness made
(8 × 200, 2 × 503, 2 × 401 — per-status exact), `anyhop_key_requests_total`
matched the 10 real upstream attempts, `+Inf` equals `_count` for every series,
`/metrics` stayed servable during the 200-request storm and during config churn
(checks 7.1–7.8).

---

## Verified as behaving correctly

Upstream misbehaviour

* 500-forever → `503` + `provider_unavailable` + `Retry-After`; keys go to
  **cooldown, never dead**; both recover on their own and serve again (1.1–1.4).
* A stream cut mid-frame → the client sees a **premature EOF**
  (`IncompleteRead`), not a silently "completed" body; the key slot returns to 0
  (1.5, 1.6).
* Silence **before** headers → the attempt timeout fires (2 × 3 s → 503, 1.8b).
* Non-SSE garbage → relayed verbatim and closed, no hang (1.9).
* `Content-Length` > body, and a socket reset mid-response → clean `502` with a
  JSON error envelope, never a truncated `200` (1.10, 1.11).
* 429 **with** `Retry-After: 4` → key benched exactly 4 s (1.15).

Clients

* A 1 B/s reader holds exactly one key slot and delays nobody (2.1–2.3).
* A mid-stream disconnect **cancels the upstream request** (the mock sees the
  broken pipe instead of streaming to the end) and both the key slot and the
  client-key slot are released (2.4–2.6, 2.9).
* `/healthz` and `/metrics` stay responsive with a slow reader or a dribbling
  upload attached (2.2, 2.8).
* Oversized bodies are refused from the streamed limit (413, 2.10).

Load

* 200 parallel: every request answered, no 500/502, only the designed 503/429
  envelopes, keys not dead, in-flight back to 0, control plane sub-ms, next
  request fine (3.1–3.4, 3.6–3.10).

Config churn

* 50 identical `PUT /api/config` under traffic: all 200, **zero** request
  failures, no key lost, file byte-identical afterwards (4.1–4.4).
* An invalid config (`keys = []`) is rejected with 400 and the running config is
  kept — no bricked file, traffic unaffected (4.5).
* Removing the key that an in-flight stream is using hot-reloads to 1 key and
  **the stream keeps streaming**; adding it back restores the pool (4.6–4.8).
* 8 concurrent reloads: all 200, file intact (4.9, 4.10).

Restart

* Idle SIGTERM: exit 0 in <0.1 s, state flushed, request history restored
  (5.1–5.4).
* `kill -9`: redb reopens on the next start, serves traffic, no panic (5.7–5.9).
* Restart after an interrupted shutdown works (5.6).

---

## Coverage map

| Scenario | Checks |
|---|---|
| 1 upstream misbehaviour | 1.1–1.12 (429 + cooldown maths in 1b: 1.13–1.17) |
| 2 slow / hostile clients | 2.1–2.10 |
| 3 concurrency | 3.1–3.10 |
| 4 config churn | 4.1–4.10 |
| 5 restart | 5.1–5.9 |
| 6 rate limits | 6.1–6.8 (+ log checks) |
| 7 metrics | 7.1–7.8 |
| logs | L1 (no panic in any instance) |

## Notes / limitations

* Everything runs against a mock upstream; no real provider quotas are touched.
  `CARGO_HOME=/tmp/ch`, network off, no rebuild needed.
* Each instance: own free port, own config copy, own redb file in a private
  `tempfile.mkdtemp()`; all processes are SIGTERM'ed (then SIGKILL'ed) on exit,
  also on Ctrl-C. Leftover check: `pgrep -f target/release/anyhop` after a run
  shows only pre-existing gateways.
* The harness deliberately does **not** touch `src/`, `ui/` or the other test
  files. Findings above cite the source lines responsible.
* Timing assertions use generous windows (e.g. cooldown ±2 s), so the suite is
  stable: three consecutive runs produced the same 67 ok / 10 fail with the same
  ten check ids.