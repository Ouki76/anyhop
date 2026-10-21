# Security audit log

Every finding below came from a review of this repository, was reproduced, and was
fixed with a test that fails without the fix. The list is kept so a later reader can
see *why* a piece of code looks the way it does, and so the same mistake is not
re-introduced.

Severity follows the usual ladder: **C**ritical = remote outage / auth bypass /
secret leak; **H**igh = cheap DoS, data exposure, broken promise; **M**edium =
hardening gap or resource limit; **L**ow = hygiene.

## Round 2 (multi-instance, media, realtime, response store)

| # | Sev | Where | What was wrong | Fix |
| --- | --- | --- | --- | --- |
| 1 | C | `src/tls.rs` | `TlsListener::accept()` awaited the TLS handshake inline. `axum::serve` accepts sequentially, so **one silent TCP connection stopped the listener**: no further connection was ever accepted. One socket, zero bytes, no credentials. | Handshakes run in their own task and land in a `ready` queue (`MAX_HANDSHAKES = 1024`, `HANDSHAKE_TIMEOUT = 10 s`); the accept loop `select!`s between "a handshake finished" and "a new connection". Proven: with five silent sockets held open, a real TLS request still answers in 30 ms. |
| 2 | H | `src/distributed/limiter.rs` | The **client's bearer token** was used verbatim as the Redis key name, so it travelled over plaintext `redis://` and persisted in KEYS/MONITOR/RDB/replicas. | The bucket name is `sha256(key)[..16]`, the same treatment the Redis password already got. |
| 3 | H | `src/distributed/redis.rs` | `parse_reply` bounded each field but not the total: `*1000000` + large bulks ≈ unbounded memory from a hostile/buggy Redis. | A cumulative `MAX_REPLY_BYTES` budget threaded through the recursion, `MAX_ARRAY` lowered to what a bucket reply needs. |
| 4 | H | `src/middleware.rs` | The auth lockout was a **pre-filter**: a locked-out address got 429 even with a valid key. Behind a reverse proxy every client shares the proxy address, so ten bad keys per minute from anyone locked out all of `/v1` and `/api` — a free, renewable self-DoS. | The lockout is now a *response to a failed credential*: the key is compared first, and only a failure counts towards the budget and can answer 429. `AuthFailures::blocked` (the pre-filter helper) was deleted so the mistake cannot come back. |
| 5 | H | `src/middleware.rs` + `src/proxy/realtime.rs` | The per-client-key concurrency slot was a **response** extension, so it was released the moment the `101` was written: `client_key_max_concurrent` did not bound websocket sessions at all. | For upgrades the guard travels in the *request* extensions and is moved into the session by the handler, so it lives until the socket closes. |
| 6 | H | `src/proxy/realtime.rs` | Relay writes sat inside `select!` arm bodies: with a zero receive window `write_all` pended and the idle timer could never fire, pinning the task, both sockets and a provider key slot forever. | Every write has a deadline; expiry ends the session. |
| 7 | H | `src/storage.rs`, `src/proxy/responses.rs` | The response store was capped by **count** (1000) not bytes — up to ~8 GiB of redb growth from an authenticated caller. | Records above a size cap are not stored (the reply is still served), and the in-memory mirror is capped by count and bytes. |
| 8 | H | `src/proxy/responses.rs` | `previous_response_id` was not bound to the calling key: any leaked id let another tenant replay and read that conversation. | `StoredResponse.owner` is set on persist and checked on replay; a mismatch answers the same "unknown or expired" 400. |
| 9 | M | `src/api/metrics.rs`, `src/middleware.rs` | For a key without a name, the **raw secret** became a Prometheus label value and was written into the persisted request feed. | One helper, `proxy::client_key_label`, returns the name or `key-<digest8>`; both sites use it. |
| 10 | M | `src/proxy/media.rs` | The multipart `model` scan was quadratic: a 156 KB body quoting `name="model"` 12 000 times burned **171 s** of CPU. | Rewritten as one linear line-wise pass (the same scan is also only run on the first 8 KiB of a part header). |
| 11 | M | `src/api/histograms.rs` | The new endpoints (`/v1/realtime`, images, audio) collapsed into `route="other"`, so the new surface had no latency data. | Added to the static route table. |
| 12 | M | `src/middleware.rs`, `src/proxy/mod.rs` | `security_headers` cloned the whole `RtConfig` — including `api_key`/`redis_url` strings — on **every request** just to read one bool. | `AppState::tls_enabled_flag` (`AtomicBool`), refreshed on reload. |
| 13 | M | `src/ws.rs` | 16 MiB frame/message caps are three orders of magnitude above real realtime traffic, and a single big frame left a 16 MiB buffer allocated for the session's life; no session cap, no maximum lifetime (pings refreshed the idle timer). | Caps lowered to 1 MiB, buffers shrink when drained, per-process session budget and a hard session lifetime. |
| 14 | M | `src/distributed/redis.rs`, `limiter.rs` | A hostile reply was `Debug`-printed into a log line — an 8 MiB bulk became a ~32 MB log entry. | `Resp::summary()` prints the tag and length; server text is truncated before logging. |
| 15 | L | `src/proxy/realtime.rs` | The upstream `101` was validated only by `Sec-WebSocket-Accept`; a 101 declaring a body would have its body replayed as frames. | Both upgrade tokens required, `Content-Length != 0` / `Transfer-Encoding` rejected. |

### Parser hardening (found by adversarial tests, all fixed)

| Where | Bug | Trigger |
| --- | --- | --- |
| `src/ws.rs` | Close frames were not validated: 1-byte payloads and reserved codes (1005/1006/0/999/…) were relayed. | `88 81 <mask> 03` |
| `src/distributed/redis.rs` | A line truncated by EOF was accepted as a complete reply (`+OK` with no CRLF). | Server closes mid-line |
| `src/distributed/redis.rs` | `read_until` grew the buffer *before* the `MAX_LINE` check. | 1 MiB line with no `\n` |
| `src/proxy/responses.rs` | `prompt_tokens + completion_tokens` overflowed on upstream-supplied `u64::MAX`. | Hostile provider `usage` |
| `src/proxy/responses.rs` | No bound on input amplification (10 MiB string, `["","",…]`). | Large `input` |
| `src/proxy/responses.rs` | `max_output_tokens: u64::MAX` forwarded verbatim. | Large knob value |
| `src/anthropic.rs` | `max_tokens = budget_tokens + 1` overflowed for `i64::MAX`. | `thinking.budget_tokens` |

### Verified sound (worth not breaking)

* Frame lengths are validated **from the header, before allocating**, including the
  2^63 MSB check; the read buffer only grows with bytes actually received.
* The RESP client encodes commands as length-prefixed bulk strings, so no protocol
  injection is possible even with attacker-chosen key names; negative lengths other
  than the two nil forms are rejected; one deadline covers write+flush+parse.
* Secrets are compared in constant time and never appear in labels, logs or the
  persisted request feed; the Redis password is digested before it is used as a
  pool identity.
* Media responses relay an **allowlist** of headers and stream the body (a 20 MiB
  image is never buffered), with the key slot held until the client has it.
* `previous_response_id` replay is a one-level flatten with no pointer walk, so a
  chain cannot cycle.