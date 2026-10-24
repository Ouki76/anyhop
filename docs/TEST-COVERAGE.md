# Test coverage of the anyhop gateway

Audit date: 2026-10-22. Baseline commit `c19e6ef` (479 library tests). Three
commits from a parallel agent landed while the audit ran — `ae418d8` (PKCE),
`3a0f5cc` (wire/fuzz fixes) and `512ae88` — and this audit's tests are part of
`3a0f5cc`/`512ae88`. All numbers below measure the tree at `512ae88` plus this
document.

## Why this is measured by analysis + execution

`cargo-llvm-cov` cannot run in this toolchain — there is no `llvm-profdata`
matching `rustc` — so no line/branch counters exist. Coverage was therefore
established in three steps:

1. **Surface map (analysis).** Every `pub` / `pub(crate)` item under `src/` was
   extracted (visibility, file, line), the `#[cfg(test)]` regions were located,
   and each item was matched against call sites inside test code across the
   whole crate. That gives the *directly exercised* set.
2. **Behavioural reading.** For every module the tests were read, not just
   counted: a function can be reached through a handler, a router or another
   module's tests, and — the opposite failure — a test can mention a name without
   asserting anything about it. Modules listed as "indirect" below were checked
   by hand.
3. **Mutation proof (execution).** 14 behaviours were broken on purpose in a
   scratch copy (`/tmp/gapcheck`, never in this repository), the new test was run
   against the broken code, and the failure was recorded. A test that still
   passes against broken code proves nothing, so the two that did not bite were
   rewritten (see "A test that did not bite" in §3).

Commands used:

```bash
CARGO_HOME=/tmp/ch cargo test --offline            # 576 + 18 tests
CARGO_HOME=/tmp/ch cargo clippy --offline --all-targets
CARGO_HOME=/tmp/ch cargo fmt --all -- --check
ANYHOP_TEST_PORT=18161 ./test/run_all.sh ./target/release/anyhop   # alone
```

## 1. Per-module map

`items` = public + crate-visible functions defined in non-test code (methods of
`impl` blocks included). `exercised` = reached from a `#[cfg(test)]` block of
this crate, directly or through a router/handler test (marked `~` when only
indirect). `NOT exercised` lists items that no test executes at all.

| module | items | exercised | NOT exercised |
|---|---|---|---|
| `anthropic.rs` | 4 | 3 | `translate_sse_stream_from` |
| `antigravity.rs` | 26 | 8 ~ | `pool_secret`, `label`, `client`, `ensure_access_token`, `ensure_project_id`, `fetch_available_models`, `start_auth`, `complete_auth`, `wait_for_callback`, `complete_with_code`, `run_auth_flow`, `exchange_code`, `fetch_email`, `build_auth_url`, `urlencoded`, `percent_decode`, `loopback_redirect_uri`, `random_oauth_state` |
| `api/auth.rs` | 5 | 2 | `auth_start`, `auth_status`, `auth_cancel` (the OAuth flow handlers) |
| `api/client_keys.rs` | 6 | 5 | `client_keys_list` (covered by the Python suite) |
| `api/combos.rs` | 4 | 0 ~ | `combos`, `combo_add`, `combo_update`, `combo_delete` — helpers tested, handlers only e2e |
| `api/config_mgmt.rs` | 3 | 0 ~ | `get_config`, `put_config`, `reload` — the shared write path is tested via `commit_config_text` |
| `api/errors.rs` | 12 | 12 | — |
| `api/histograms.rs` | 3 | 3 | — |
| `api/metrics.rs` | 1 | 0 ~ | `metrics` (Prometheus body; Python suite asserts the series) |
| `api/mod.rs` | 4 | 2 ~ | `validate_name`, `validate_secret_len` (used indirectly by the handlers) |
| `api/models.rs` | 8 | 5 | `models_refresh`, `refresh_all_providers` (network), `model_enable` |
| `api/persist.rs` | 6 | 3 ~ | `persist_client_keys`, `persist_disabled_models` (via handler tests), `write_validated` (via `provider_update`) |
| `api/provider_keys.rs` | 7 | 3 | `key_add`, `key_delete`, `key_enable`, `key_disable` |
| `api/providers.rs` | 4 | 0 | `providers`, `quotas`, `requests`, `events` (DTO/SSE surface) |
| `api/server.rs` | 3 | 2 | `write_config_checked` |
| `codex.rs` | 14 | 3 | `translate_sse_stream`, `collect_non_stream`, `pool_secret`, `label`, `client`, `ensure_access_token`, `start_auth`, `complete_auth`, `wait_for_callback`, `complete_with_code`, `run_auth_flow` |
| `config.rs` | 20 | 3 ~ | the 17 `Tuning` accessors are used indirectly; `Config::load` is exercised through every reload test |
| `dashboard.rs` | 3 | 3 | — |
| `distributed/limiter.rs` | 6 | 6 | — |
| `distributed/redis.rs` | 24 | 21 | `digest` (called from production only), `reply_from_slice` (test-only helper), `timeout` (accessor) |
| `events.rs` | 9 | 7 | `with_capacity`/`emit` are reached through `new`/`emit_simple` |
| `fim.rs` | 1 | 0 | `fim_completions` (prefix-trimming helpers are tested; the handler is e2e only) |
| `gemini.rs` | 6 | 4 | `translate_sse_stream_from`, `usage_pair` |
| `lib.rs` | 3 | 2 | `run` (process entry point) |
| `middleware.rs` | 13 | 6 ~ | `require_admin_key`, `record_metrics`, `json_errors` (router-level, Python suite), `require_api_key`/`security_headers` now driven by router tests |
| `pool/key.rs` | 7 | 2 ~ | `is_available`, `try_acquire`, `set_cooldown`, `health`, `restore_health` — exercised through the pool |
| `pool/mod.rs` | 20 | 16 | `persist_stats`, `is_empty`, `secret_by_id`, `set_label` (each used by production and by the reload/e2e paths) |
| `pool/sticky.rs` | 6 | 6 | — |
| `providers.rs` | 11 | 2 ~ | `has_capability` (media/realtime tests), `effective_models` (models tests), `build_http_client*`, `ag_account`, `codex_account`, `fetch_upstream_models`, `refresh_models`, `quotas` |
| `proxy/access.rs` | 3 | 3 | — |
| `proxy/chat/errors.rs` | 6 | 4 | `internal_body_error`, `exhausted_response` (only on unreachable/raced paths) |
| `proxy/chat/mod.rs` | 2 | 0 ~ | `chat_completions`, `run_target_pub` — every branch below them is tested; the handlers are e2e |
| `proxy/chat/retry.rs` | 1 | 1 | — |
| `proxy/chat/session.rs` | 2 | 2 | — |
| `proxy/chat/stream.rs` | 5 | 4 ~ | `content_type_of` (via `accept_2xx` tests) |
| `proxy/embeddings.rs` | 1 | 0 ~ | `embeddings` (translation helpers tested, handler e2e) |
| `proxy/media.rs` | 6 | 1 ~ | the five pass-through handlers (routing/multipart/header logic is tested by 31 tests on the helpers) |
| `proxy/mod.rs` | 9 | 7 | `invalidate_catalog`, `tuning` (accessors) |
| `proxy/models.rs` | 2 | 2 | — |
| `proxy/realtime.rs` | 1 | 0 ~ | `realtime` (39 tests including a real hyper upgrade round-trip) |
| `proxy/responses.rs` | 3 | 2 ~ | `responses` handler (37 tests on the translation/replay core) |
| `ratelimit.rs` | 6 | 6 | — |
| `scan.rs` | 2 | 2 | — |
| `sse.rs` | 6 | 5 | `frame` (called from production and every stream test) |
| `storage.rs` | 2 | 1 ~ | `secret_hash` (called by the pool/models ids everywhere) |
| `tls.rs` | 5 | 5 | — |
| `ws.rs` | 23 | 22 | `into_inner` (accessor) |

Reading of the table: the hot-path/large modules (`ws`, `sse`, `scan`, `storage`,
`distributed`, `ratelimit`, `realtime`, `responses`, `media`, `tls`, `pool`,
`dashboard`) are well covered. The weak spots were the **admin API surface**, the
**Codex/antigravity translation of requests and SSE events**, **`events`**,
**`proxy/access`**, and the **auth middleware's request-level guarantees**.

## 2. Unexercised behaviours, ranked by risk

Risk = blast radius × probability of a silent regression.

| # | behaviour | where | risk | status |
|---|---|---|---|---|
| 1 | Per-key in-flight cap and when the slot is released (including the websocket handoff) | `middleware::require_api_key` | **high** — a leaked permit 429s a tenant forever; a missing cap lets one key eat the gateway | **tested** (§3 P3/P4) |
| 2 | Constant-time credential comparison semantics | `middleware::token_eq` | **high** — every credential check goes through it | **tested** (§3 P1) |
| 3 | Which credential sources are accepted (`?key=` on GET only, percent decoding) | `middleware::{query_key,bearer_ok}` | **high** — a POST query key leaks into logs; a wrong decode locks out custom keys | **tested** (§3 P2) |
| 4 | Proactive drain from `x-ratelimit-*` headers (threshold, reset, fallback) | `proxy/chat/retry.rs` | **high** — decides when a key is benched before a 429; an inverted comparison silently disables the feature | **tested** (§3 P6) |
| 5 | `pool.drain` itself: cooldown length, clamp, persistence | `pool/mod.rs` | **high** — the same benching, plus the reload round-trip | **tested** (§3 P5) |
| 6 | Client-key allowlist matching, esp. no bypass through another provider | `proxy/access.rs` | **high** — authorization boundary | **tested** (§3 P8) |
| 7 | Codex request translation (system→instructions, tool flattening, images) | `codex::translate_request` | **high** — the Codex provider is unusable if the shape is wrong; errors are remote 400s | **tested** (§3 P9) |
| 8 | Codex SSE mapping (text/reasoning/tool deltas, finish reasons, failure frame) | `codex::translate_event` | **high** — a wrong tool index corrupts every agent loop | **tested** (§3 P10) |
| 9 | Antigravity quota-reset parsing (later signal wins, RFC3339 offsets) | `antigravity::parse_quota_reset_ms` | **high** — a short parse benches the model for the wrong window | **tested** (§3 P10) |
| 10 | Config write ordering (build before write) for the editor and every mutation | `lib::apply_config` via `api::persist::commit_config_text` | **high** — a bad save bricks the next start | **tested** (§3 P11) |
| 11 | Failed-auth window lapses / lockout accounting | `middleware::AuthFailures` | medium — a window that never lapses bans an address forever | **tested** (§3 P13) |
| 12 | Event ring keeps the *newest* entries and honours the cap | `events::EventBus` | medium — the dashboard shows the wrong history | **tested** (§3 P12) |
| 13 | `mask_key` never reveals a usable secret | `api/client_keys.rs` | medium — a leaked key in a screenshot/log | **tested** (§3 P14) |
| 14 | Provider add/delete config rewrites (valid document, combos cleaned up) | `api/provider_keys.rs` | **high** — writes credentials and the provider list | **tested** (§4) |
| 15 | Key add / delete / enable / disable | `api/provider_keys.rs` | **high** — an empty `keys = []` is an invalid config | **not tested** (see §5.3) |
| 16 | Combo add/update/delete handlers | `api/combos.rs` | medium — same write pattern, validated before write | **not tested** (see §5.3) |
| 17 | OAuth flow handlers (`auth_start/status/cancel`) and the account append/refresh path | `api/auth.rs`, `codex.rs`, `antigravity.rs` | medium — needs a browser + upstream identity provider | **not tested** (see §5.2) |
| 18 | `GET /v1/models` catalogue cache + allowlist filtering | `proxy/models.rs` | medium — stale cache advertises disabled models | **tested** (§4) |
| 19 | `EventBus` broadcast to live SSE subscribers | `events::subscribe` | low — subscriber lag is handled by `Lagged` | **tested** |
| 20 | `dashboard::asset` traversal guard | `dashboard.rs` | medium — static-file route is internet-facing | **tested** (§4) |
| 21 | `Tuning` range validation (22 knobs) | `config.rs` | medium — a zero disables a guard | **tested** (§4) |
| 22 | `?key=` / bearer helpers, client IP precedence | `middleware.rs` | medium | **tested** (§3 P2, §4) |
| 23 | Model enable/disable spelling consistency (`m` vs `provider/m` vs `combo/m`) | `api/models.rs` | medium — a toggle that never re-enables | **tested** (§4) |
| 24 | Request feed ring (`log_request`) and `client_key_label` | `proxy/mod.rs` | low | **tested** (§4) |
| 25 | `storage::secret_hash`, `pool::{is_empty, set_label, secret_by_id}` | misc | low — thin accessors, used by everything | not tested, accepted |
| 26 | `Fim` / `embeddings` / `media` / `realtime` / `responses` handler wrappers | `proxy/*` | low — their logic lives in tested helpers; e2e by the Python suite | not tested, accepted |
| 27 | `Llm`-side metadata (`fetch_upstream_models`, `refresh_models`, `quotas`) | `providers.rs`, `antigravity.rs` | low — requires a live upstream; cache TTL behaviour is tested | not tested, accepted |

## 3. The behaviours proved with tests

Each row was proved by mutation: the production line was broken in a scratch copy
(`/tmp/gapcheck/repo`, a copy of `src/`), the new test was run against it, and the
test failed. The file was then restored. The "observed" column quotes the panic
location reported by the broken build.

| # | behaviour | test | mutation applied | observed |
|---|---|---|---|---|
| P1 | A credential is compared exactly; a prefix/one-byte/length difference is rejected | `middleware::auth_tests::credentials_compare_exactly` | `token_eq` returns `true` unconditionally | panic at `middleware.rs:810` (prefix matched) |
| P2 | `?key=` authenticates GET only; percent escapes decode; malformed escapes survive | `middleware::auth_tests::a_query_key_only_authenticates_get_requests` | drop the method check in `query_key` | panic at `middleware.rs:838` (POST accepted) |
| P3 | Per-key in-flight cap: second concurrent request 429s, `saturated` counted, slot released with the request | `middleware::auth_tests::a_client_keys_concurrency_cap_holds_until_the_request_ends` | `if cur >= limit` → `if false && …` | panic at `middleware.rs:1066` (second request 200) |
| P4 | A websocket upgrade receives its slot in the *request* extensions (not on the response) | `middleware::auth_tests::a_websocket_upgrade_receives_its_slot_in_the_request` | never insert the guard for `Upgrade::WebSocket` | panic at `middleware.rs:1119` (handler did not see the guard) |
| P5 | `pool.drain` benches exactly that key for the advertised reset and leaves the pool serving | `pool::tests::a_proactive_drain_benches_only_the_advertised_key` | `drain` no longer calls `set_cooldown` | panic at `pool/mod.rs:1162` (status stayed `active`) |
| P6 | Drain on `x-ratelimit-*`: strictly-below threshold drains, at/above does not, missing/garbage reset uses the fallback | `proxy::chat::retry::tests::a_low_remaining_budget_drains_the_key_for_the_advertised_reset` | invert `>=` to `<=` | panic at `proxy/chat/retry.rs:121` (key not benched) |
| P7 | A qualified allowlist entry cannot be satisfied by another provider's same model name | `proxy::access::tests::a_qualified_allowlist_entry_cannot_be_bypassed_through_another_provider` | compare the entry's bare model name (`ends_with(upstream)`) | panic at `proxy/access.rs:83` (azure/gpt-4 allowed) |
| P8 | Codex tools are flattened (`function.parameters` → `parameters`), choices mapped, no-nested form left | `codex::translate_tests::tool_definitions_are_flattened_and_choices_are_mapped` | emit the schema under `arguments_schema` | panic at `codex.rs:1137` |
| P9 | Codex SSE: one stable index per streamed tool call, argument deltas land on it, unknown ids ignored | `codex::translate_tests::streamed_tool_calls_keep_one_index_per_item` | `let idx = st.item_tool.len()` → `0` | panic at `codex.rs:1304` (second call index 0) |
| P10 | Antigravity quota reset: the *later* of `retryDelay` and `quotaResetTimeStamp` wins | `antigravity::quota_reset_tests::the_later_of_two_signals_wins` | `u.max(candidate)` → `u.min(candidate)` | panic at `antigravity.rs:1328` |
| P11 | A config that cannot be built never reaches the disk (file byte-identical, router unchanged) | `api::persist::tests::a_rejected_document_never_reaches_the_disk` | write the file before `prepare_config` | panic at `api/persist.rs:316` (file was rewritten) |
| P12 | The event ring drops the *oldest* entry and keeps the cap | `events::tests::the_buffer_keeps_the_newest_events_up_to_the_cap` | `pop_front()` → `pop_back()` | panic at `events.rs:138` |
| P13 | A lapsed failed-auth window starts a fresh budget | `middleware::auth_tests::a_lapsed_window_starts_a_fresh_budget` | never reset the window (`if false`) | panic at `middleware.rs:902` |
| P14 | `mask_key` never exposes the middle of a key (and fully hides short keys) | `api::client_keys::secret_tests::a_mask_never_reveals_the_middle_of_a_key` | return the key itself | panic at `api/client_keys.rs:506` |

The first ten are the highest-risk set; the last four are extra proofs from the
same campaign.

### A test that did not bite

The first version of the qualified-allowlist mutation (`a == canonical` →
`a == upstream`) still passed, because the allow entry (`openai/gpt-4`) is never
equal to a bare upstream name — the mutation changed nothing observable. The
proof above uses a realistic slip (`ends_with(upstream)`). This is the main value
of the exercise: a green test is not evidence until it has been seen to fail.

The first version of the middleware probe helper also held the gate mutex across
an `await`; with the cap disabled the second request then blocked instead of
returning 200. The helper was fixed to take the receiver out under a short lock,
so a regression fails fast instead of hanging the suite.

## 4. What was added (Phase 3)

68 tests, all inside `#[cfg(test)]` blocks, offline and deterministic (no
outbound network: the middleware and drain-header tests bind a loopback socket on
`127.0.0.1:0`, everything else is pure or file-based):

| file | new tests | covers |
|---|---|---|
| `src/middleware.rs` | 8 | token comparison, credential sources, IP precedence, lockout window, per-key cap, upgrade handoff, hardening headers/HSTS |
| `src/pool/mod.rs` | 3 | `drain`: length, clamp, persistence across a rebuild |
| `src/proxy/chat/retry.rs` | 5 | header-driven drain: threshold boundary, fallback, overflow, disabled knob |
| `src/proxy/access.rs` | 4 | allowlist and disabled-set matching, provider isolation |
| `src/codex.rs` | 9 | request translation (roles, tools, knobs, local rejects), SSE events (text, tools, terminal, failure) |
| `src/antigravity.rs` | 6 | quota-reset parsing (relative/absolute/offsets/garbage), v1internal envelope, endpoints |
| `src/events.rs` | 6 | ring cap/order, `set_cap`, restore, live subscribers, JSON round-trip |
| `src/api/persist.rs` | 3 | build-before-write for the editor, write failure, disabled-models round-trip |
| `src/api/client_keys.rs` | 5 | masking, key generation, limit normalisation, add/delete config round-trip, pre-write validation |
| `src/api/models.rs` | 5 | disabled-set spelling consistency, toggle idempotence, disable-all/enable-all |
| `src/api/provider_keys.rs` | 3 | provider add/delete rewrites, rejected adds, combo cleanup |
| `src/proxy/models.rs` | 3 | catalogue listing, epoch cache invalidation, allowlist filtering |
| `src/proxy/mod.rs` | 3 | `client_key_label`, request-feed ring, error envelope |
| `src/proxy/chat/session.rs` | 2 | configurable session prefix |
| `src/dashboard.rs` | 2 | asset traversal guard, index policy |
| `src/config.rs` | 1 | every `[tuning]` range, by name |

No production code was changed. `unwrap()`/`expect()` appear only inside test
blocks, where the crate's lint config allows them.

## 5. Gaps that remain, and the verdict on each

### 5.1 Not acceptable — production findings (reported, not fixed here)

1. **`provider_add` writes before it builds** (`src/api/provider_keys.rs`).
   `provider_add` calls `config::write_atomic` and only then `reload_config`.
   A request that is schema-valid but unbuildable — most easily `{"kind":
   "openai_compat", "base_url": "…"}` *without* a `key`, which
   `Config::validate` rejects as "no keys configured" — is written to disk and
   the handler answers 400 "saved but reload failed". The file is now invalid,
   so the **next start fails**, and the raw editor and every other mutation read
   the broken document. Every other write path in the crate uses
   `commit_config_text`/`write_validated`, which build first. Suggested fix: use
   `commit_config_text` (or validate/build into the document before the write).
   Verified in the scratch copy: `provider_add` with no `key` returns an error,
   the file then contains the new provider, and `Config::load` on it fails with
   "provider 'openai_compat': no keys configured". Not asserted in a test because
   the current behaviour is the bug.

2. **The failed-auth map is not actually bounded** (`src/middleware.rs`,
   `AuthFailures::note`). The comment says the map is pruned so a spray of
   spoofed addresses cannot grow it, but the prune only *retains entries newer
   than the window* — i.e. it removes nothing while the spray is in progress
   (all entries are fresh). With `X-Forwarded-For` honoured and a proxy that
   appends, one attacker can add unbounded entries for up to a window
   (`auth_fail_window_secs`, default 60 s) and again every window. Suggested
   fix: hard-cap the map (e.g. at 10 000) and evict the oldest entry on insert.
   Not tested: the test would have to assert the buggy growth.

3. **`disabled_models` spelling mismatch for combos** (`src/proxy/models.rs` vs
   `src/api/models.rs` vs `src/proxy/chat/mod.rs`). `api::models` treats
   `"combo/x"` and `"x"` as the same model, and the chat path blocks a request
   for `"combo/x"`. But the catalogue stores combos by their bare name and only
   compares `c.name`/`bare`, so a hand-written `disabled_models = ["combo/x"]`
   leaves the combo listed by `GET /v1/models` and `GET /v1/models/{id}` while a
   bare-name request still serves it. The admin API normalises the prefix away,
   which is why this only bites hand-edited configs. Suggested fix: normalise
   `disabled_models` when the config is loaded.

4. **`GET /v1/models/{id}` ignores the client-key allowlist**
   (`src/proxy/models.rs::get_model`). `list_models` filters by
   `KeyPermissions::allowed_models`; `get_model` has no permission extractor, so
   a restricted key can confirm the existence (and owner) of any model. Model
   *use* is still blocked by the chat/media paths, so this is information
   disclosure only.

5. **Minor: `antigravity::parse_rfc3339_ms` does not range-check date parts.**
   `"2026-13-45T00:00:00Z"` parses to a finite, plausible timestamp (~2027-02)
   instead of `None`, so a malformed `quotaResetTimeStamp` yields a wrong
   (clamped) cooldown for that model rather than the 60 s fallback. The pool
   clamps to `max_cooldown`, so the impact is bounded. Suggested fix: reject
   month > 12, day > 31, hour > 23, minute/second > 59.

### 5.2 Acceptable, with the reason

- **OAuth flows** (`run_auth_flow`, `wait_for_callback`, `exchange_code`,
  `complete_auth`, `refresh`, `fetch_email`, `ensure_project_id`). They need a
  browser, a human consent click and Google/OpenAI endpoints. What *is*
  deterministic is tested: state generation (unpredictable, not the clock), PKCE
  (RFC 7636 vector), state single-use/expiry/foreign-state rejection, callback
  URL parsing, HTML escaping, and the TOML account append (preserves
  permissions, never writes an unloadable document). The remaining risk is the
  happy path against the real IdP, which a unit test cannot model honestly.
- **Assembling streamers** (`codex::translate_sse_stream`,
  `collect_non_stream`, `anthropic/gemini::translate_sse_stream_from`). They wrap
  a `reqwest::Response`; every event mapping they rely on is now unit-tested
  (`translate_event`), and the assembled stream is exercised end-to-end by the
  Python mock providers (`codex/gpt-codex-test` in `run_all.sh`). What is not
  unit-tested is the framing loop itself (role chunk first, `[DONE]` at EOF,
  token counters).
- **Handler wrappers with no logic of their own** (`chat_completions`,
  `embeddings`, the five media handlers, `realtime`, `responses`, `fim`,
  `metrics`). Their decisions were factored into helpers that are tested
  (routing, capability gating, multipart/JSON field location, header allowlists,
  retry loop, capacity admission, budget release), and the HTTP contract is
  covered by the Python suite (38 checks) plus dedicated router tests for
  realtime (a real hyper upgrade over a socket).
- **Network metadata** (`fetch_upstream_models`, `refresh_models`,
  `Provider::quotas`). These call the upstream; the cache TTL and the
  `effective_models` fallback they feed are tested with a configured model list.
- **Thin accessors** (`is_empty`, `secret_by_id`, `set_label`, `Tuning` getters,
  `redis::digest/timeout`, `ws::into_inner`). They are single-expression
  wrappers used on every request; a test would restate the code.
- **`api::client_keys::client_keys_list`, `api::providers::*`,
  `api::config_mgmt::*`**. DTO/serialisation surface; the Python suite asserts
  the shapes, and the write path they share is unit-tested
  (`commit_config_text`, `save_client_keys_to_toml`).

### 5.3 The next tests I would write, in order

1. `provider_keys::{key_add, key_delete, key_enable, key_disable}` — highest
   remaining risk: they rewrite the credential list. In particular
   `key_delete` on the last TOML key plus a runtime key, and the "restore the
   extras list when the write is refused" rollback.
2. `api::combos` handlers — same pattern as the provider tests added here;
   cheap now that the helpers exist.
3. `api::auth::{auth_start, auth_status, auth_cancel}` — the single-flow state
   machine, the abort of the callback task, and the "switch provider" path.
4. Assembly tests for the stream translators, using the loopback
   `reqwest::Response` fixture introduced in `proxy/chat/retry.rs`.

## 6. Final counts

| metric | before | after |
|---|---|---|
| `cargo test` (library) | 479 | **579** (2026-10-24 audit) |
| `cargo test` (integration, `tests/`) | 0 | 18 (added by a parallel agent) |
| doctests | 3 ignored | 3 ignored |
| tests added by this audit | — | **68** |
| `cargo clippy --all-targets` | 0 lines | **0 lines** |
| `cargo fmt --all -- --check` | clean | **clean** |
| `test/run_all.sh` (port 18161, alone) | — | **PASS=38 FAIL=0** |

The 29 library tests and 18 integration tests that arrived during the audit came
from the concurrent agent (PKCE, gemini/scan/pool::key additions, the `tests/`
harness), not from this work; they are included in the totals because they are in
the tree the suite measures.

Run discipline: the first attempt at the acceptance command failed with
`PASS=3 FAIL=35`. The pattern was diagnostic rather than a product failure: every
shell-level check against the suite's shared gateway got `connection refused`
while the hardening stage — which starts its own gateway instances — passed 13/13
and the shared gateway's log showed it being started and shut down by another
process within five seconds. That is a second suite holding the same port, the
exact collision the "run it alone" rule exists for. The reported `PASS=38 FAIL=0`
comes from a re-run with no other gateway, mock or suite alive.

## 7. Closed in this round (was: "reported, not fixed")

| # | Finding | Fix |
| --- | --- | --- |
| 1 | `provider_add` wrote the config before building it, so an unbuildable edit left a file that made the **next start exit**. Reproduced live: `POST /api/providers/add` without a key → `400 saved but reload failed`, `grep nokey` = 1 hit, next start died with `provider 'nokey': no keys configured`. | Routed through `commit_config_text` (build → write → swap). The same request now answers `400 invalid config: …` with the file untouched, and the gateway starts. |
| 2 | `AuthFailures` pruned only *expired* entries, so a spray of fresh spoofed IPs inside one window grew the map without limit. | Hard cap with oldest-quarter eviction; the expiry sweep still runs first. |
| 3 | `disabled_models = ["combo/x"]` meant two different things (request path vs catalogue). | Both spellings loaded; `disabled_entry()` derives the bare form. Test: `a_qualified_combo_is_reduced_to_its_bare_name`. |
| 4 | `GET /v1/models/{id}` ignored the client-key allowlist. | Same `model_allowed`/`combo_allowed` check as the list endpoint → `403 model_not_allowed`. |
| 5 | `parse_rfc3339_ms` accepted month 13 / day 45 / hour 25 from an upstream 429 body. | Range-checked before the arithmetic. Tests: `an_out_of_range_timestamp_is_rejected`, `a_valid_timestamp_still_parses`. |

### Still untested, and why that is acceptable

* **OAuth flows** — need a browser and a real IdP; the state/PKCE logic is unit-tested and the authorize URL was verified against Google live.
* **Stream assembly loops** — the event mapping is unit-tested; framing is covered end-to-end by the mocks and the fuzz harness.
* **Anthropic and Codex wire formats** — no credentials in this environment. The translators are covered by contract tests built from the documented event shapes; `docs/WIRE-VERIFICATION.md` marks them `[NOT TESTABLE HERE]` rather than pretending.
