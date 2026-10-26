# Test-suite and CI audit — anyhop

**Audit date:** 2026-10-26
**Baseline commit:** `86b1d5a` (tree as audited), working tree **detached** from that
base by an in-flight change to `src/lib.rs` + `Cargo.toml` (see §0).
**Method:** read/grep/glob over the tree; `cargo test --locked --no-run`;
`cargo test --locked` (full run, ~2.5 s); targeted repeat runs for flake
detection; `bash -n` on every shell script; every claim below was checked against
the file and line cited.

---

## 0. State of the tree at audit time — read this first

While this audit ran, `src/lib.rs` and `Cargo.toml` were modified in place
(`hyper-util` + `tower` added, `serve_connections` introduced). **That tree does
not compile**, so no test could be run against it:

```
error[E0599]: no method named `into_service` found for associated type
  `<M as tower::Service<ConnectInfo<<L as Listener>::Addr>>>::Future`
   --> src/lib.rs:898:21
error[E0277]: the trait bound `<L as axum::serve::Listener>::Io: hyper::rt::Read`
  is not satisfied
   --> src/lib.rs:913:67   (serve_connection_with_upgrades)
```

Every number in this report was measured against the **last tree that built**
(the test binary produced at 13:53 from `86b1d5a` + the pre-change working tree):

```
$ cargo test --locked --offline
  unittests src/lib.rs          617 passed; 0 failed
  unittests src/main.rs           0 passed
  tests/fuzz_parsers.rs          18 passed; 0 failed   (0.47 s)
  Doc-tests anyhop                0 passed; 3 ignored
```

This is itself the first finding of the audit: **a red build was not visible to
the agent that caused it**, because there is no cheap, always-on "does it still
compile" feedback loop outside CI (§B-1).

---

## A. Module → test count → coverage assessment

Counts are `#[test]` + `#[tokio::test]` from the built binary's `--list`, so they
include every `#[cfg(test)]` block in each file. `items` = `pub`/`pub(crate)`
functions in non-test code. "Integration" = reachable only through `test/run_all.sh`
e2e; "unit" = executable by `cargo test`.

| module | tests | items | assessment | notable untested behaviour |
|---|---:|---:|---|---|
| `ws.rs` | 36 | 23 | **Strong.** RFC 6455 vectors, masking policy both directions, 7/16/64-bit lengths, fragmentation, control-frame strictness, UTF-8 across fragments, hostile-length prefixes, 5001-continuation bound, plus 1 of the 8 fuzz targets. | Nothing material on the codec. The *relay* (who may write whom) lives in `realtime.rs`. |
| `proxy/realtime.rs` | 39 | 1 | **Strong.** Real hyper upgrade round-trip, header-injection refusal, allowlist 403, disabled 404, capability 400, per-direction byte budget, idle + lifetime timeouts, session slot for the whole session, PEM extraction. | The handler's own `max_message`/backpressure numbers are asserted only at caps. |
| `proxy/responses.rs` | 43 | 3 | **Strong.** Translation, replay, storage, streaming, `store:false` chain refusal, saturation, 10 MiB input refusal. | — |
| `distributed/redis.rs` | 35 | 24 | **Strong.** Full RESP2 matrix, depth cap, bulk cap from the header, reply budget, fragmentation, AUTH/SELECT ordering, pool identity, redacted URL, 4-connection cap. | **No test of the per-command timeout against a server that accepts and then never answers at the pool level with the *config* timeout** (the one at `a_stalled_server_times_out_and_the_socket_is_dropped` uses a 1 s explicit value — fine). |
| `pool/mod.rs` | 34 | 20 | **Strong.** Rotation strategies, both cooldown kinds, drain, wake-after, discovered/quota paths, sticky, persistence-restore. | `persist_stats`, `secret_by_id`, `set_label` (thin). |
| `gemini.rs` | 33 | 6 | **Strong.** Translation + stream state machine + fuzz target. | — |
| `proxy/media.rs` | 31 | 6 | **Strong on the helpers** (multipart span, routing, capability, allowlist, disabled). | The five handlers themselves only in e2e; `multipart_field_span` fuzz target exists. |
| `antigravity.rs` | 23 | 26 | **Good but OAuth path untested.** PKCE vector, state randomness, quota-reset parse (incl. the out-of-range fix), envelope, token rotation. | `build_auth_url`, `exchange_code`, `wait_for_callback`, `run_auth_flow`, `ensure_project_id`, `fetch_email`, `loopback_redirect_uri` — mostly needs a live IdP, **except** `percent_decode`/`urlencoded`, which are pure and untested. |
| `distributed/limiter.rs` | 14 | 6 | **Good.** Two-instance shared budget, one-EVAL atomicity, TTL floor, digest naming, fail-open/closed, local fallback, reload reuse. | `try_acquire` clock-skew clamps in the Lua are **only tested against the Rust fake**, whose Lua is re-implemented (§B-11). |
| `scan.rs` | 19 | 2 | **Strong.** Includes the duplicate-key and escaped-key bypass regressions. | `peek_request`'s cost on a 32 MiB body is not bounded by a test. |
| `api/auth.rs` | 18 | 18 | **Good.** State lifecycle, PKCE, callback parsing, HTML escaping, account append. | `auth_start`/`auth_status`/`auth_cancel` handlers themselves — e2e only. |
| `api/histograms.rs` | 12 | 3 | **Good.** Cardinality cap, folding, escaping, route collapsing. | — |
| `api/client_keys.rs` | 12 | 16 | **Good.** Masking, generation, listing-never-leaks, round-trip. | `client_keys_list` handler — e2e only. |
| `api/server.rs` | 11 | 5 | **Good.** Loopback-only key clearing, basenames, owner-only file. | — |
| `middleware.rs` | 16 | 13 | **Adequate — one important blank** (§B-4). `token_eq`, `?key=` GET-only, IP precedence, lockout window, per-key cap, streamed slot, upgrade handoff, hardening headers, CORS allow-list **as a pure function**. | The **`cors` middleware itself** (preflight short-circuit, `Vary`, no-headers-for-unlisted-origin) has **no test**; only `cors_allow()` does. No test of the `MAX_FAIL_ENTRIES` eviction added in the last round. |
| `config.rs` | 15 | 20 | **Good.** Every tuning range by name, TLS pair, write_atomic permissions + unique temp. | — |
| `tls.rs` | 14 | 5 | **Good** (PEM parsing, EC/PKCS8/SEC1/RSA, mismatch, real TLS round-trip) **but** handshake-timeout path untested (§B-6). | `spawn_handshake` timeout / failed-handshake drop; SNI with a mismatched name; expired cert. |
| `dashboard.rs` | 10 | 3 | **Good.** CSP hashing, traversal 404, no-cache policy. | — |
| `codex.rs` | 10 | 14 | **Partial.** Request translation + SSE event mapping + state randomness. | `translate_sse_stream` assembly loop, `collect_non_stream`, all OAuth. |
| `sse.rs` | 9 | 6 | **Adequate.** LF/CRLF/lone-CR, split CRLF, multi-line, cap + sticky release. | — |
| `fim.rs` | 9 | 1 | **Good.** Prefix/suffix overlap, native pass-through, multibyte. | — |
| `anthropic.rs` | 9 | 4 | **Partial.** Event mapping + saturation regression + fuzz target. | `translate_sse_stream_from` assembly loop only. |
| `ratelimit.rs` | 8 | 6 | **Good** — and correctly uses an injected clock (`try_take_at`). | — |
| `events.rs` | 6 | 9 | **Good.** Ring cap/order, subscribers, `Lagged`. | — |
| `pool/sticky.rs` | 6 | 6 | Good. | — |
| `pool/key.rs` | 5 | 7 | Good (redaction). | — |
| `api/persist.rs` | 5 | 6 | Good (build-before-write). | — |
| `proxy/chat/stream.rs` | 12 | 5 | **Good.** Header allowlist (pure fn), content-type, slot-holding for live/translated streams, stalled body, first-chunk replay. | The **actual relay** of `forward_header` across `axum`→`reqwest` (i.e. that `Set-Cookie` never *really* leaves) — the test is on the predicate only (§B-9). |
| `proxy/chat/mod.rs` | 12 | 2 | **Good on the decision helpers** (capacity, exhaustion, splice). | `chat_completions`/`run_target_pub` handlers. |
| `proxy/chat/errors.rs` | 12 | 6 | **Good.** Retry-After both spellings, 4xx/5xx classification, saturation. | — |
| `api/models.rs` | 10 | 8 | **Good.** Every spelling, toggle idempotence, limit sources. | `models_refresh`/`refresh_all_providers` (network). |
| `proxy/access.rs` | 4 | 3 | **Good** — this is the authorization boundary and it is pinned, incl. the cross-provider bypass. | — |
| `api/combos.rs` | 4 | 4 | Helpers only. | All four handlers (§B-8). |
| `api/provider_keys.rs` | 6 | 7 | Add/update/delete helpers. | **`key_add`/`key_delete`/`key_enable`/`key_disable`** (§B-8) — they rewrite the credential list. |
| `providers.rs` | 4 | 11 | **Weak.** Only capability/effective-models helpers. | `build_http_client*`, `refresh_models`, `fetch_upstream_models`, `quotas`. |
| `limits.rs` | 4 | — | Small, adequate. | — |
| `api/errors.rs` | 7 | — | Good. | — |
| `api/metrics.rs` | 2 | 1 | **Weak — the Prometheus body has no Rust test.** Only label escaping + `rss_lookup`. | Whole `metrics` rendering; covered only by chaos scenario 7. |
| `api/providers.rs` | 1 | 4 | **Weakest surface.** One DTO serialization test. | `providers`, `quotas`, `requests`, `events` handlers; `/api/events` SSE framing. |
| `api/config_mgmt.rs` | **0** | 3 | **No unit tests.** | `get_config`/`put_config`/`reload` (§B-7). |
| `api/mod.rs` | 3 | 4 | Masking helpers. | `validate_name`, `validate_secret_len` only indirect. |
| `logging.rs` | 1 | — | Minimal. | JSON log format escaping of user-controlled fields. |
| `lib.rs` | 9 | 3 | Reload/apply-order, shutdown-with-open-stream, body deadline, combo spelling. | **`handle_cli`**, `spawn_background_tasks`, the **half-sent request head** (§B-2). |
| `main.rs` | 0 | — | 24 lines, `run()` wrapper. | — |
| `distributed/mod.rs` | 0 | — | Re-exports only. | — |
| **`tests/fuzz_parsers.rs`** | 18 | — | Deterministic fuzz harness, 8 targets + 10 regressions. | See §B-3: the allocation invariant is weakened by `cargo test` parallelism. |
| **doctests** | **0 run / 3 ignored** | — | `src/tls.rs:10,18,301` are ```` ```ignore ````. | Nothing is compiled or checked. |

**Summary of the weak quadrants:** the *parsing/data-plane* (`ws`, `sse`, `scan`,
`redis`, `responses`, `media`, `realtime`, `pool`) is genuinely well tested — much
better than most projects of this size. The *admin control-plane*
(`api/providers`, `api/config_mgmt`, `api/provider_keys` mutations, `api/combos`,
`api/metrics`) and the *transport edge* (request head deadline, TLS handshake
timeout, the `cors` middleware, the `/api/config` secret exposure) are where the
untested code is.

---

## B. Findings

Every finding names the file and line, the evidence, and a concrete test.

---

### B-1 · HIGH · `src/lib.rs:818-915`, `Cargo.toml:18-26` — the build can be red and nothing says so

**Evidence.** During this audit `src/lib.rs` gained `serve_connections`
(hyper-util + tower) and stopped compiling:

```
$ cargo test --locked --offline
error[E0599]: no method named `into_service` found ... --> src/lib.rs:898:21
error[E0277]: ... `<L as axum::serve::Listener>::Io: hyper::rt::Read` ... --> src/lib.rs:913:67
```

Nothing caught it before it was committed: `test/audit.sh:35-53` does run
`cargo clippy --all-targets`, but nobody runs `audit.sh` on every edit, and its
first two gates (`fmt`, `clippy`) both go through the same compiler. There is no
`cargo check` in a `.git/hooks/pre-commit`-equivalent, and no `--keep-going`
matrix of `cargo check --all-targets --no-default-features`.

**Test to add.** `scripts/quick-gate.sh` — `cargo fmt --all -- --check && cargo
check --locked --all-targets && cargo check --locked --no-default-features`,
with the exit status propagated (no `|| true`). Assert in CI that a deliberately
broken `cfg` symbol fails it. This is a process test, not a unit test, but it is
the highest-leverage single change: every other gate in this document is
downstream of "the tree compiles".

---

### B-2 · HIGH · `src/lib.rs:818-850` (`HEADER_READ_TIMEOUT`) — the new slowloris guard has no test at all

**Evidence.** The new const documents the motivating measurement in its own
comment — *"Measured before this bound existed: twenty such sockets were all
still open after 45 s"* — and no test exercises it. The nearest neighbours do not
cover it:

* `src/lib.rs:1581` `a_stalled_request_body_fails_instead_of_hanging` covers the
  **body**, via `body_with_idle_timeout`;
* `test/chaos_test.py:1237-1250` check `2.10` covers an **oversized** body
  (2 MiB → 413), not a head that never finishes;
* `test/chaos_test.py:1226` check `2.9` sends an abandoned half-sent body.

A socket that sends `GET /healthz HTTP/1.1\r\n` and stops is handled by hyper's
`header_read_timeout`, which only exists if the connection builder has a timer
installed — that is the entire point of the change, and it is exactly the
behaviour that can silently regress when someone replaces the builder.

**Test to add.** `src/lib.rs::tests::a_half_sent_request_head_is_closed_by_the_deadline`
— bind `127.0.0.1:0`, start `serve_connections`, open a raw `TcpStream`, write
only `b"GET /healthz HTTP/1.1\r\nHost: x\r\n"`, then `tokio::time::timeout(2 *
HEADER_READ_TIMEOUT, read_to_end)`; assert it returns (EOF) and not a timeout,
and repeat 20 times to prove the fd count does not grow (read
`/proc/self/fd` length before/after).

---

### B-3 · HIGH · `tests/fuzz_parsers.rs:64-107` — the allocation invariant is weakened by `cargo test` parallelism

**Evidence.** The memory bound is the harness's headline claim
(`docs/FUZZING.md` §"Invariants asserted on every iteration", item 2: *"A
`#[global_allocator]` wrapper counts bytes allocated on the fuzzing thread … Caps:
8 MiB per iteration"*). The counter is thread-local:

```rust
thread_local! {
    static MEASURED: Cell<usize> = const { Cell::new(0) };
    static MEASURING: Cell<bool>  = const { Cell::new(false) };
}
```

`MEASURING` is set inside `measure()` (`tests/fuzz_parsers.rs:125-128`), which is
only sound if **every** allocation that should be charged happens on the thread
that flipped the flag. `cargo test` runs the 18 integration tests on a
libtest thread pool; each `fuzz_*` test *also* spawns its own worker
(`run_target`, line 425) — so charges are correct *for that worker's thread*.
The real hole is the opposite one: any allocation that a target's parser makes
**on another runtime thread** (e.g. a `tokio` worker, or `block_on` offloading)
is silently invisible to the meter, and the per-test parallelism means a
regression that allocates in a helper thread would never be charged. There is no
test that pre-loads the meter with a known cross-thread allocation and asserts
it is *not* counted (the existing
`the_allocation_meter_counts_inside_the_window_only` only proves the flag gates
same-thread counting).

**Test to add.** `the_meter_ignores_allocations_from_other_threads` — flip
`MEASURING`, `std::thread::spawn(|| vec![0u8; 1 MiB])`, join, assert
`MEASURED == 0`, then allocate 1 MiB on the current thread and assert it is
charged. This turns an implicit assumption into an asserted contract, and
documents why every fuzz target must parse *inline*.

---

### B-4 · HIGH · `src/middleware.rs:660-719` — the CORS middleware has no test; only its pure helper does

**Evidence.** `cors()` is 60 lines of security-relevant logic — it short-circuits
a preflight (never forwards `OPTIONS`), inserts `Vary: origin`, and adds
`Access-Control-Allow-*` only for an allowed origin. The only CORS test is
`json_error_tests::only_listed_origins_are_allowed` (`src/middleware.rs:786`),
which calls `cors_allow(&list, origin)` — **a pure function that is not the
middleware**. Nothing asserts:

* a preflight against a listed origin returns `204` and *does not reach the
  inner service*;
* an unlisted origin gets **no** `Access-Control-Allow-Origin` **and** no
  `Access-Control-Allow-Credentials` ever;
* `Vary: origin` is present on a real (non-preflight) response;
* CORS headers are present on a **401/500** response, not only 200s (the layer
  order in `build_router` claims this).

`test/run_all.sh:163-180` does assert several of these end-to-end — which is why
this is HIGH rather than CRITICAL — but a Rust-level test would catch it in 1 s
instead of requiring the full e2e suite.

**Test to add.** `src/middleware.rs::cors_tests::a_preflight_is_answered_before_the_router`
— build the small `router()`/`serve()` harness already used by
`a_client_keys_concurrency_cap_holds_until_the_request_ends`, wrap it in
`middleware::cors`, and assert (a) `OPTIONS` with a listed `Origin` +
`Access-Control-Request-Method` is `204` with the echo origin, methods, headers,
`max-age`, and `Vary: origin`; (b) inner handler never ran (counter == 0);
(c) `https://evil.example` preflight has no `allow-origin`; (d) a 401 response
still carries the headers.

---

### B-5 · HIGH · `src/middleware.rs:403-431` — the `MAX_FAIL_ENTRIES` eviction added last round is untested

**Evidence.** `docs/TEST-COVERAGE.md` §7 row 2 says *"`AuthFailures` pruned only
expired entries … Fix: Hard cap with oldest-quarter eviction"*. The code is
there (`src/middleware.rs:397-425`, `MAX_FAIL_ENTRIES = 10_000`), but the only
`AuthFailures` tests are `retry_after_reports_the_rest_of_the_window` and
`a_lapsed_window_starts_a_fresh_budget` (`src/middleware.rs:818, 1073`). Grep of
the test list confirms: no test references `MAX_FAIL_ENTRIES`.

**Test to add.** `auth_failures_never_exceed_the_hard_cap` — insert
`MAX_FAIL_ENTRIES + 1_000` distinct IPs inside one window with a long window,
then assert `fails.seen.len() <= MAX_FAIL_ENTRIES`, that the **newest** entry
survived, and that the eviction removed roughly a quarter (i.e. the size dropped
to ~7 500 rather than thrashing on every insert). Assert also that
`retry_after_secs` for a freshly inserted IP still works after eviction.

---

### B-6 · MEDIUM · `src/tls.rs:259-281` — the handshake timeout and failed-handshake drop are untested

**Evidence.** `spawn_handshake` runs `acceptor.accept(stream)` under
`HANDSHAKE_TIMEOUT`, logs `"tls handshake timed out; connection dropped"` on
`Err(_)` and `"tls handshake failed; connection dropped"` on `Ok(Err(..))`. The
only TLS test that touches a socket is `serves_a_request_over_tls`
(`src/tls.rs:783-828`), which is the happy path. Nothing asserts that a client
that opens a TCP connection and never sends a `ClientHello` is dropped rather
than leaking a task/`pending` slot forever — the same class of bug as §B-2.

**Test to add.** `src/tls.rs::tests::a_client_that_never_speaks_tls_is_dropped` —
after the existing `serves_a_request_over_tls` setup, `TcpStream::connect(addr)`
and send nothing; assert the connection is closed (EOF) within
`1.5 * HANDSHAKE_TIMEOUT`, and that a *subsequent* legitimate TLS handshake on a
new connection still succeeds (proving `pending` did not corrupt the ready queue).

---

### B-7 · MEDIUM · `src/api/config_mgmt.rs:17-27` — `GET /api/config` returns provider keys and OAuth tokens verbatim

**Evidence.** `get_config` is `std::fs::read_to_string(&state.config_path)` →
`text/plain`. The file it reads holds `keys = ["sk-or-…"]` for every provider and
`refresh_token = "1//…"` for every OAuth account (`anyhop.example.toml:34, 56-62`).
`api/server.rs` masks the same data for `/api/server`
(`proxy: s.proxy.as_deref().map(super::mask_proxy)` at line 155) and
`api/client_keys.rs` masks keys — so `/api/config` is the one endpoint that
breaks the project's own "secrets are write-only" rule. `README.md:451` documents
it as *"raw TOML (validated before it is written)"* without noting the exposure.

This is a **product** finding surfaced by the test audit (there is no test, so no
one noticed the asymmetry). It is arguably intended — the raw editor needs the
text to round-trip — but then it must be **tested as an invariant** so nobody
"fixes" the editor into redaction and silently breaks saves.

**Test to add.** `api::config_mgmt::tests::the_raw_editor_round_trips_a_masked_secret_as_write_only`
— `GET /api/config` → assert the body is byte-identical to the file on disk
(pins the current contract); then `PUT` a document whose `keys` are unchanged
and assert the file is byte-identical. If the intent is instead to redact, the
test asserts the *inverse* (no `sk-` in the GET body). Either way the decision
becomes executable.

---

### B-8 · MEDIUM · `src/api/provider_keys.rs:—`, `src/api/combos.rs:—` — key and combo mutation handlers have no tests

**Evidence.** `api::provider_keys::tests` covers `provider_add`/`update`/`delete`
only (`adding_a_provider_installs_it_and_keeps_the_config_loadable`,
`a_rejected_provider_add_leaves_the_file_untouched`,
`deleting_a_provider_also_drops_the_combos_that_used_it`). The four handlers that
rewrite the **credential list** — `key_add`, `key_delete`, `key_enable`,
`key_disable` — have no test, and `api::combos::tests` has only the four name
validators, no handler. `docs/TEST-COVERAGE.md` §5.3 lists exactly these as
*"the next tests I would write, in order"* and they were never written.

The risk is concrete: `key_delete` on a provider whose TOML has one key plus one
runtime-added key must not produce `keys = []` (which `Config::validate` rejects
— see `a_key_provider_with_accounts_but_no_keys_is_rejected`, `config.rs`), and
the "restore the extras list when the write is refused" rollback has no coverage.

**Test to add.** `api::provider_keys::edit_tests::deleting_the_last_key_is_refused_and_leaves_a_loadable_file`
— seed a config with one provider and one key, `POST /api/keys/delete`, assert
`400`; then assert `Config::load(path)` still succeeds and `keys.len() == 1`.
Plus `key_add_then_delete_restores_the_original_credentials` (byte-identical file
modulo ordering).

---

### B-9 · MEDIUM · `src/proxy/chat/stream.rs:439-449` — the relay allowlist is tested as a predicate, never end-to-end

**Evidence.** `only_safe_upstream_headers_are_relayed` asserts
`forward_header(&HeaderName::from_static("set-cookie")) == false` and the same
for `authorization`, `content-length`, `transfer-encoding`, `connection`. But
`forward_header` is only *called* at `src/proxy/chat/stream.rs:90` and `:507`;
nothing asserts that a real `reqwest::Response` carrying `Set-Cookie` produces an
`axum` response without it. A refactor that stops calling `forward_header` (or
calls `.headers()` instead of `.filter()` on line 90) would leave the test green.

**Test to add.** `a_set_cookie_from_the_upstream_never_reaches_the_client` —
build a `reqwest::Response` from a loopback fixture (the pattern already exists in
`proxy/chat/retry.rs::response_with` and
`proxy/chat/stream.rs::endless_stream`) that returns `Set-Cookie: a=b` and
`Authorization: x` alongside `Content-Type: application/json`; run the stream
through the relay and assert the resulting `axum::Response` headers contain
neither, and do contain `x-request-id`.

---

### B-10 · MEDIUM · `tests/fuzz_parsers.rs:299` — CI never runs the campaign the docs cite as evidence

**Evidence.** `DEFAULT_ITERS = 2_000`. `.github/workflows/ci.yml:35` is
`cargo test --locked` with **no** `ANYHOP_FUZZ_ITERS`, so CI performs 2 000 × 8 =
16 000 inputs. `docs/FUZZING.md` reports **200 000 per target = 1.6 M inputs** as
the evidence that nothing was found, and frames *that* number as the campaign.
`test/audit.sh:158` runs `ANYHOP_FUZZ_ITERS=20000` — a tenth of the documented
campaign — and `audit.sh` is not a CI job at all (`docs/AUDIT-2026-10-24.md:229`
describes it as a local "one command" gate). Net: **the documented campaign is
never executed by any automation.**

**Test to add (CI gate).** A `fuzz` job in `ci.yml` on `schedule` + `push` to the
default branch: `ANYHOP_FUZZ_ITERS=200000 cargo test --locked --test fuzz_parsers
-- --nocapture`, `timeout-minutes: 20`, publishing `/tmp/suite.log` on failure
via the existing `publish-ci-logs.sh`. Assert in the job that the printed
iteration count equals 200 000 (a guard against the env var being dropped).

---

### B-11 · MEDIUM · `src/distributed/limiter.rs:33-73` + `test/mock_redis.py` — the shipped Lua is verified against a *re-implementation*

**Evidence.** `TOKEN_BUCKET_LUA` contains the carefully-clamped clock-skew logic
(*"A caller clock that jumped backwards must not hand out extra credit, and one
that jumped forwards must not mint a full bucket out of thin air"*). The Rust
tests run it against `distributed::redis::fake::FakeRedis`, which **does not
execute Lua** — `test/mock_redis.py` header says it *"emulates the token-bucket
Lua script"*, and the Rust fake keys on a `-- anyhop:token-bucket` marker
(`src/distributed/limiter.rs:44`). So a bug in the clamp is invisible to
`cargo test`. The only real-server verification is `test/redis_lua_test.py`
(docker + `redis:7-alpine`), which `run_all.sh:285-298` treats as a **skip** when
docker is absent — and CI's `integration` job never installs a docker daemon
setup for it, so on a runner without docker it silently `warn`s.

**Test to add.** Extend `test/redis_lua_test.py` with
`backwards_clock_gives_no_credit` and `forward_clock_jump_caps_at_one_bucket`:
`EVAL` the shipped script with `now_ms` = `T`, then `T - 60_000`, and assert the
second call does not return `allowed=1`; then `T + 86_400_000` and assert only
one bucket's worth passes. Make CI run this job unconditionally (docker is
available on `ubuntu-latest`) so the skip never fires.

---

### B-12 · MEDIUM · `.github/workflows/ci.yml` — missing gates

**Evidence (each verified against the file):**

| gate | present? | note |
|---|---|---|
| fmt / clippy `-D warnings` | ✅ `ci.yml:28-31` | — |
| unit + integration tests | ✅ `ci.yml:35` | single run, no `--all-features` |
| `--no-default-features` build | ✅ `ci.yml:50-51` | build only, **tests not run** under that feature set |
| **`cargo audit` / `cargo deny`** | ❌ | the only dependency-vulnerability check is `test/audit.sh:120-135`, which is **not a CI job**. `.gitignore`/CI have no `deny.toml`, no license policy. |
| **Miri / ASAN** | ❌ | `docs/FUZZING.md` §"Known limits" admits *"Miri/ASAN are unavailable (nightly)"* — correct, but there is also no nightly job that *tries*. |
| **doctests** | ⚠️ | `cargo test --locked` runs them, but all 3 are ```` ```ignore ````, so 0 doctests execute. |
| **MSRV check** | ❌ | `Cargo.toml:5` declares `rust-version = "1.88"`; CI only has `dtolnay/rust-toolchain@stable`. Nothing verifies 1.88 still builds. |
| **feature-combination matrix** | ❌ | only `default` and `--no-default-features`; `alloc-mimalloc` × `dashboard` (4 combos) never built together. |
| **bench regression gate** | ❌ | `cargo build --locked --benches` (`ci.yml:47`) compiles them; nothing compares numbers. |
| **job timeouts** | ❌ | no `timeout-minutes` anywhere in `ci.yml` → GitHub's 360 min default; a hung `run_all.sh` burns 6 h. |
| **concurrency / cancel-in-progress** | ❌ in `ci.yml` | present in `docker.yml:30-32` but not in CI, so every push to a PR queues a full e2e run. |
| **action pinning** | ⚠️ | all actions are major-tag pinned (`@v4`, `@v2`) — acceptable, but `dtolnay/rust-toolchain@stable` floats the **compiler** itself, which is the least reproducible pin in the file. |

**Test to add (CI gates).**
1. `audit` job: `taiki-e/install-action@cargo-audit` + `cargo audit --deny warnings`;
   a `deny.toml` with a license allow-list.
2. `msrv` job: toolchain `1.88` + `cargo check --locked --all-targets`.
3. `features` job: matrix over `--features alloc-mimalloc` / `--no-default-features`
   running `cargo test --no-run`, not just `build`.
4. `timeout-minutes` on every job (`test: 20`, `integration: 30`, `ui: 20`).

---

### B-13 · MEDIUM · `test/audit.sh:150-190` — the gate's own fuzz block runs under a different toolchain rule and is indented as if it were outside the `if`

**Evidence.** Lines 150-153 open `if [ "$QUICK" = "0" ]; then` / `echo "== fuzz =="`,
but the `if ANYHOP_FUZZ_ITERS=20000 cargo test --offline …` on line 158, the
`echo "== integration =="` on line 165, and the entire integration block are
**not indented** (they only *look* like siblings of the `QUICK` guard). They are
inside it by brace matching, so `--quick` skips them — correct — but the
mis-indentation means a future edit that adds a line at column 0 will land
*outside* the guard without any visible signal. Separately, line 158 is the only
`cargo` invocation in the file that passes `--offline` while every other one
relies on `CARGO_HOME=/tmp/ch` (line 14); on a machine with no vendored registry
this is a hard fail the rest of the gate cannot explain.

**Test to add.** `bash -n` already passes; add `shellcheck -S warning test/audit.sh`
and `test/run_all.sh` to a CI step, and re-indent the block. No behaviour change.

---

### B-14 · MEDIUM · `test/run_all.sh:1-30` — the suite is `set -u` only and its `trap` cannot clean up a mock that fails to start

**Evidence.** `set -u` with no `-e` (line 3) means a failing `python3 test/mock_x.py &`
(line 31-39) leaves `$!` in `MOCKS` and the script continues. More importantly the
`trap cleanup EXIT` (line 27) kills pids, but a mock that exits immediately (bad
port, syntax error) is silently replaced by the *stale* one from a previous run —
this is precisely the failure the port-probe loop at lines 42-56 was added to
mitigate, and it still cannot distinguish "my mock answered" from "an older mock
from run N-1 answered". Ports **9100–9105 and 6399 are hardcoded**
(`test/anyhop.test.toml:11,20,25,44,56,…`), so two concurrent suites collide; the
gateway port is configurable (`ANYHOP_TEST_PORT`) but the mocks are not.

Secondary: `SETTLE` sleeps exist (`sleep 1` after SIGHUP at line 304); the
`expect()` helper (line 104) greps a *substring* of the response, so a 500 error
envelope that happens to contain the needle passes — mitigated for the antigravity
check (comment at line 110) but not systematically.

**Test to add.** Give every mock its own `--port 0`-style ephemeral port, write
the chosen ports into the generated config, and add a `mock_upstream` `/healthz`
that returns a **run-id** (a UUID generated by `run_all.sh` and passed via env);
assert the run-id matches before the first real check. This makes "stale mock"
impossible rather than unlikely.

---

### B-15 · MEDIUM · `test/*.py` — no test asserts an *upstream request count* for the retry path outside chaos

**Evidence.** `test/mock_upstream.py` (196 lines) has **no hit counter** — it
serves `bad-429`, `bad-500`, `bad-401` by inspecting the bearer token and nothing
records how many times each model was called. `test/chaos_test.py` *does* have
`MOCK.state.hits` / `key_hits` (lines 314-333) and asserts
`anyhop_key_requests_total == attempts` (check 7.3) — good — but chaos is not in
CI and is not run by `run_all.sh`. So in the CI e2e path, nothing proves that a
`429 → retry` does not perform a *retry storm* (e.g. `max_retries` ignored and 10
attempts per request). Chaos covers it; CI does not.

**Test to add.** Add a `hits` counter + `/__hits` endpoint to
`test/mock_upstream.py`, then in `run_all.sh` after the `err500` exhaustion check
(lines 186-193): read the counter before and after one request with
`max_retries = 4` and assert the delta is **exactly** `max_retries` (5 attempts),
not more and not fewer.

---

### B-16 · MEDIUM · `src/api/metrics.rs` — 2 tests for a 248-line Prometheus renderer

**Evidence.** `cargo test --lib -- --list` for `api::metrics` yields exactly
`label_values_are_escaped` and `rss_lookup_does_not_panic`. The `metrics` handler
itself (the exposition body: series names, `# HELP`/`# TYPE` headers, `anyhop_up`,
per-key series) is asserted only by `test/run_all.sh:182-186` (three `grep`s) and
chaos scenario 7. A malformed exposition (`promtool check metrics`) fails silently
in CI.

**Test to add.** `api::metrics::tests::the_exposition_is_well_formed` — build a
minimal `AppState` (the `test_state` helper in `src/lib.rs` tests already
exists), call `metrics(state)`, collect the body, and assert: every `# TYPE` is
followed by a sample with that name; no sample line has a space inside the
metric name; labels are sorted; `anyhop_up 1` present. Add `promtool check
metrics` to the `integration` job as a one-liner.

---

### B-17 · LOW · `src/ratelimit.rs:155-165` — a timing tolerance is asserted with a hard 900 ms/59 s window

**Evidence.** `allows_a_burst_then_limits` asserts
`retry >= Duration::from_millis(900) && retry <= Duration::from_secs(1)`, and
`exhausted_key_reports_a_sane_retry_after` asserts `59 s ≤ retry ≤ 60 s`. Both
use the *injected* `try_take_at(now)` — good — but the bound is derived from a
floating `rate_per_sec` and a `Duration::from_secs_f64`, so the test is exact
arithmetic, not timing; it cannot flake. **The real flake is elsewhere:**
`src/distributed/limiter.rs:375` does `tokio::time::sleep(Duration::from_millis(1_100))`
and then asserts *"one token refilled"* — a real wall-clock sleep in a test that
runs on a loaded CI box; under heavy load the 1 100 ms can elapse but the refill
maths uses the fake's clock, so this is safe *today* only because the fake is
driven by `SET`/`GET` and not by `Instant`. Fragile by construction.

**Test to add.** Give `RedisLimiter::try_acquire` an injectable `now_ms` (it
already sends `ARGV[3] = now_ms`), and change the test to pass `t0 + 1_100`
explicitly. Remove the sleep.

---

### B-18 · LOW · `src/antigravity.rs:1195-1205` — an `unsafe set_var` in a test body races with any concurrent test reading the environment

**Evidence.** The comment says *"this is a single-threaded test body"*, but
libtest runs test **functions** on N threads; `unsafe { std::env::set_var(...) }`
in `each_flow_gets_an_unpredictable_state` mutates the process environment while
`run_all.sh` (and any test that reads `ANYHOP_*`) may read it. The justification
"single-threaded test body" is true only within the function, not within the test
binary. This is precisely the Rust-test anti-pattern the crate itself avoids
elsewhere (config is passed by value into `start_auth_with`).

**Test to add (refactor + guard).** Change `start_auth_with` to take the client
id/secret as parameters (it already takes `Option<…>` for the callback), delete
both `set_var` calls, and add a test asserting the parameters flow into the URL.

---

### B-19 · LOW · `src/tls.rs:452-514` — tests silently `return` (pass) when openssl is missing

**Evidence.** `certs_or_skip()` returns `false` when `scripts/gen-test-certs.sh`
fails, and every caller then does `eprintln!("skipping: openssl is unavailable"); return;`
— a **passing** test that ran nothing. `test/certs/` is git-ignored
(`.gitignore` line for `/test/certs`), so a fresh CI checkout *depends* on
`openssl` being installed on `ubuntu-latest` (it is), but a slim container or a
contributor without openssl gets 5 silently-green TLS tests.

**Test to add.** Replace the silent skip with `#[ignore = "needs openssl"]` plus
`if !certs_or_skip() { panic!("run scripts/gen-test-certs.sh (openssl is a build requirement)") }`,
or — better — check the generated pair into the repo as a *fixture* (it is a
public test certificate; only the `.key` needs to be excluded and regenerated).
At minimum add a CI step that fails if `test/certs/localhost.crt` is absent after
the test run.

---

### B-20 · LOW · `tests/` holds exactly one file — no shared harness

**Evidence.** `ls tests/` → `fuzz_parsers.rs` only. Every other integration-style
test is either a `#[cfg(test)] mod` inside `src/` (fine) or Python. There is no
`tests/common/` for the "spin up a real router over a socket" fixture, so
`src/middleware.rs:1145-1195` re-implements it (`router()`, `serve()`,
`wait_until()`, `state_with_key()`) and `src/proxy/realtime.rs:2970`, `:3063`,
`:3193` and `src/proxy/media.rs:1684` each build their own `axum::Router`. That
duplication is the reason §B-4's CORS middleware test was never written: there is
no one place to add it.

**Test to add.** `tests/common/mod.rs` exposing
`fn app_with(cfg: &str) -> (SocketAddr, JoinHandle)` built from
`build_router` (which is currently `fn build_router` — **private**,
`src/lib.rs:614`; make it `pub(crate)` or `#[doc(hidden)] pub` so an integration
test can reach it). This is the single infrastructure change that unblocks most
of §C.

---

### B-21 · NIT · `src/middleware.rs:698-700` — the `Access-Control-Allow-Headers` literal contains a 22-space run

**Evidence.**

```rust
"authorization, content-type, x-api-key, anthropic-version,                      openai-organization, openai-beta",
```

A doubled space is harmless to browsers, but it is a copy-paste artifact and an
exact-string test would have to encode it. Trim it, and pin the value with a test
in §B-4.

---

## C. Top 15 highest-value tests to add, ranked

Ranked by `(production risk exposed) × (probability the guard silently regresses)
÷ (implementation cost)`. Each is described so it can be written directly.

| # | Test | File | Asserts | Why this rank |
|---:|---|---|---|---|
| **1** | `a_half_sent_request_head_is_closed_by_the_deadline` | `src/lib.rs::tests` (with §B-2's `serve_connections`) | 20 sockets that send only a request line are closed within `2 × HEADER_READ_TIMEOUT`; `/proc/self/fd` count returns to baseline | The new slowloris fix is the single highest-severity *unverified* behaviour in the tree; the bug it fixes was measured (20 sockets, 45 s) and reproduceable. |
| **2** | `cors_tests::{a_preflight_is_answered_before_the_router, an_unlisted_origin_gets_no_headers, cors_headers_survive_a_401}` | `src/middleware.rs::tests` (needs §B-20 harness) | `204` + full header set for a listed origin; **inner handler never invoked** for a preflight; no `Access-Control-Allow-Origin` for `https://evil.example`; headers present on 401; `Access-Control-Allow-Credentials` never sent | The CORS middleware is 60 lines of internet-facing security logic and has **zero** Rust tests (only its pure helper). |
| **3** | `auth_failures_never_exceed_the_hard_cap` | `src/middleware.rs::auth_tests` | `MAX_FAIL_ENTRIES + 1_000` distinct IPs in one window → `seen.len() <= MAX_FAIL_ENTRIES`; newest entry survives; `retry_after_secs` still works after eviction | A documented, "closed" DoS fix with no regression guard at all. |
| **4** | `a_client_that_never_speaks_tls_is_dropped` | `src/tls.rs::tests` | A raw TCP connect with no `ClientHello` is dropped within `1.5 × HANDSHAKE_TIMEOUT`; a subsequent legitimate handshake still succeeds | `spawn_handshake`'s timeout is the same leak class as #1 and is untested. |
| **5** | `a_set_cookie_from_the_upstream_never_reaches_the_client` | `src/proxy/chat/stream.rs::tests` | A real `reqwest::Response` carrying `Set-Cookie` + `Authorization` yields an `axum` response with neither, and still carries `x-request-id` | Header-injection defence tested as a predicate only; the call site is one line away from silently bypassing it. |
| **6** | `deleting_the_last_key_is_refused_and_leaves_a_loadable_file` | `src/api/provider_keys.rs::edit_tests` | `POST /api/keys/delete` on the only key → `400`; `Config::load` still succeeds; `keys.len() == 1` | The credential-rewriting handlers have no tests; a bad write bricks the next start (this exact class already bit the project once, `provider_add`). |
| **7** | `edit_tests::combo_add_update_delete_keep_the_file_loadable` | `src/api/combos.rs::tests` | add → present in `/api/combos` and in the rewritten TOML; update changes the chain; delete removes it; each step leaves a file `Config::load` accepts | Cheapest remaining admin-surface gap; same write path as #6. |
| **8** | `the_exposition_is_well_formed` (+ `promtool check metrics` in CI) | `src/api/metrics.rs::tests` | Every `# TYPE name` has a `name` sample; no spaces in metric names; sorted labels; `anyhop_up 1` | 2 tests for a 248-line renderer whose only verification is three `grep`s in an e2e script. |
| **9** | `redis_lua_test.py::{backwards_clock_gives_no_credit, forward_clock_jump_caps_at_one_bucket}` | `test/redis_lua_test.py` (real `redis:7-alpine`) | `EVAL` with `now_ms = T-60_000` does not grant a token; `T+86_400_000` grants at most one bucket | The Lua's clock-skew clamp is the subtle security-relevant part and is only ever run against a Python/Rust *re-implementation*. |
| **10** | `the_meter_ignores_allocations_from_other_threads` | `tests/fuzz_parsers.rs` | `MEASURED == 0` after a 1 MiB spawn-thread allocation inside the window; a same-thread 1 MiB allocation *is* charged | Makes the fuzzer's headline invariant's assumption explicit, so it cannot be invalidated by a future `block_on`/offload refactor. |
| **11** | `a_low_remaining_budget_never_produces_more_than_max_retries_upstream_calls` | `test/run_all.sh` + a `/__hits` endpoint in `test/mock_upstream.py` | one request against `err500` produces **exactly** `max_retries + 1` upstream hits | CI currently cannot see a retry storm; the counter infrastructure already exists in `chaos_test.py` and just is not wired into `run_all.sh`. |
| **12** | `only_the_allowlisted_model_is_reachable_through_every_surface` | `tests/` (needs §B-20) | A key allowed only `gemini/test-gemini` gets `403 model_not_allowed` from `/v1/chat/completions`, `/v1/embeddings`, `/v1/fim/completions`, `/v1/images/generations`, `/v1/realtime` (WS handshake refused) | The allowlist is the authorization boundary; it is unit-tested per handler (`proxy/access.rs`, `media.rs`, `realtime.rs`) but never verified **across** all five surfaces in one test, which is how a new endpoint gets added without the check. |
| **13** | `a_config_that_fails_to_build_never_reaches_the_disk` — extend to **every** writer | `src/api/*::tests` (table test) | For each of `provider_add`, `provider_update`, `provider_delete`, `key_add`, `key_delete`, `client_key_add/update/delete`, `combo_*`, `model_enable/disable`, `put_config`: an unbuildable payload leaves the file byte-identical and the live router unchanged | `commit_config_text` is tested once (`api::persist::tests::a_rejected_document_never_reaches_the_disk`); the property it guarantees is needed by ~12 handlers and only one is pinned. |
| **14** | `the_raw_editor_round_trips_secrets_as_write_only` | `src/api/config_mgmt.rs::tests` | Documents and pins the `/api/config` decision: body == file on disk, and a `PUT` with unchanged keys is byte-idempotent (or, if intended: no `sk-`/`1//` in the GET body) | Turns an undocumented secret-exposure choice into an asserted contract (§B-7). |
| **15** | `msrv_builds` + `all_feature_combinations_build` (CI, not Rust) | `.github/workflows/ci.yml` | toolchain `1.88` + `cargo check --locked --all-targets`; matrix over `dashboard` × `alloc-mimalloc` running `cargo test --no-run` | `rust-version = "1.88"` is declared and unverified; `--no-default-features` is compiled but its **tests** are never built. |

---

## D. Answers to the specific questions in the brief

**1. Coverage gaps.** See §A. Security-critical modules are, with two exceptions,
well covered: `middleware` (auth) 16 tests, `ws` 36, `sse` 9, `ratelimit` 8,
`tls` 14, `distributed/{redis,limiter}` 49, `scan` 19, `proxy/access` 4,
`proxy/realtime` 39. The exceptions are the **`cors` middleware** (§B-4), the
**`AuthFailures` cap** (§B-5), and the **transport edge** — request-head deadline
(§B-2) and TLS handshake timeout (§B-6) — which have no tests. Error paths are
generally covered (`proxy/chat/errors.rs` 12 tests, `api/errors.rs` 7,
`api/histograms.rs` 12 including cardinality folding); the notable error-path
gaps are the *write* handlers (§B-8) and `api/config_mgmt` (§B-7).

**2. Test quality.** Weak asserts: 30 occurrences of bare `assert!(x.is_ok())`,
but almost all are in `ratelimit.rs`/`distributed/limiter.rs` where the value is
exactly a pass/fail token grant — acceptable. The genuinely weak ones are
`src/proxy/responses.rs:2796` (`serde_json::from_slice::<Value>(b"[[1]]").is_ok()`
— asserts the JSON crate works), `src/ws.rs:1080`
(`std::str::from_utf8(...).is_ok()` with no content check), and
`src/api/auth.rs:874` (`rx.try_recv().is_ok()`). Timing: `ratelimit.rs` correctly
injects the clock; the only real wall-clock sleep is
`distributed/limiter.rs:375` (1 100 ms, §B-17) plus 300 ms `sleep`s in
`distributed/redis.rs:1840,2040` used to keep a fake server's socket open
(benign). Global state: one `unsafe set_var` in `antigravity.rs:1199` (§B-18) —
the only env mutation in `src/`. Fixed ports: none in Rust tests (22 uses of
`127.0.0.1:0`); **all six mocks plus the RESP double use hardcoded ports**
(§B-14).

**3. e2e suite.** `run_all.sh` is 348 lines and does real assertions, not smoke:
401-without-key, CORS preflight/allow/deny, `Vary: origin`, traversal 404,
security headers on 401, CSP script hashes, `?key=` GET-only, per-key rate limit
with `Retry-After`, duplicate-model-key routing integrity, `store:false` chain
refusal, FIM native pass-through, SIGHUP survival, `SKIP` reported separately
from `PASS`. `hardening_test.py` and `client_keys_and_models_test.py` assert
lockout semantics, per-key concurrency, TLS handshake, and that a listing never
carries a secret. Weaknesses: no upstream *call-count* assertion in CI (§B-15),
hardcoded mock ports (§B-14), `set -u` without `-e` (§B-14), and `expect()`
substring matching. Python anti-patterns: `soak.py` was fixed to fail on
no-samples; `redis_lua_test.py` correctly returns exit 2 for "skip" and
`run_all.sh:289` correctly captures `$?` inside `else` (verified in bash:
`if f; then :; else R=$?; fi` gives the *function's* status, not 1);
`chaos_test.py` uses `free_port()` everywhere, per-instance temp dirs and
redb files, and `run()` wraps each scenario so one crash cannot take the harness
down. Timeouts: `soak.py` (30 s connect, `timeout 300` in the caller), `canary.py`
(60 s), `chaos_test.py` (`--short`), `redis_lua_test.py` (120 s docker run,
600 s pull) — all bounded.

**4. CI.** See §B-12. Strong points: fmt and clippy are hard gates; the
no-dashboard build is checked; the e2e job receives the real `ui/dist` artifact
(a real bug fixed earlier); failure logs are published to a `ci-logs` branch from
every job. Missing: `cargo audit`/`cargo deny`, MSRV, feature matrix, doctests
(3 ignored), bench regression gate, job timeouts, `concurrency` on the CI
workflow, and a scheduled long fuzz campaign.

**5. Missing infrastructure.** No `proptest`/`quickcheck` (zero hits for
`proptest|quickcheck|arbitrary`). **No `fuzz/` directory** (`ls fuzz` →
`No such file or directory`); `docs/FUZZING.md` is honest about this — it
documents a hand-rolled deterministic harness in `tests/fuzz_parsers.rs` and says
`cargo-fuzz` "needs nightly". That is a defensible trade-off, but it means there
are no libFuzzer targets, no corpus directory, and no coverage feedback. Mutation
testing exists only as a *one-off, manually documented* exercise in
`docs/TEST-COVERAGE.md` §3 (14 mutations, each recorded with the failing test) —
valuable evidence, zero automation. Benchmarks (`benches/hot_paths.rs`,
`benches/load.rs`) are hand-rolled best-of-5 and only *compiled* in CI.

**6. `scripts/`.** Two files, both working (`bash -n` clean).
`scripts/gen-test-certs.sh` generates the git-ignored `test/certs/localhost.{crt,key}`
with `openssl` and is referenced from `src/tls.rs:470` and
`test/hardening_test.py:208`. `scripts/run.sh` sources `~/.config/anyhop/env` and
`exec`s the release binary; it is referenced **only** from
`docs/AUDIT-2026-10-24.md:177`, not from `README.md` — a reader of the README
never learns it exists. Neither script is exercised by CI.