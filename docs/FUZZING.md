# Fuzzing the untrusted-input parsers

`tests/fuzz_parsers.rs` is a deterministic, self-contained fuzzer for every place
in the gateway that parses bytes a client or an upstream controls. It is an
integration test, not a separate binary, so `cargo test` always runs it.

The file lives in `tests/` (not `test/`) because that is the directory Cargo
compiles as integration tests; `test/` holds the Python end-to-end fixtures and is
not touched.

`cargo-fuzz`/libFuzzer is not an option here: it needs nightly, and this project
builds on stable (`rust-version = "1.88"`, currently 1.99). The harness therefore
brings its own generator (a seeded xorshift), its own corpus, its own allocation
meter and its own panic containment.

## Running it

```bash
# The default run: every corpus entry and every mutator, small and quick.
cargo test --test fuzz_parsers

# The full campaign reported below: 200 000 generated inputs per target.
ANYHOP_FUZZ_ITERS=200000 cargo test --test fuzz_parsers -- --nocapture

# One target only.
ANYHOP_FUZZ_ITERS=200000 cargo test --test fuzz_parsers fuzz_anthropic -- --nocapture
```

`--nocapture` prints one line per target (iterations, wall time, rate, peak
single-iteration allocation). A failure prints the offending input in hex.

The generator is seeded: target *N* always sees the same sequence of inputs, so a
finding is reproducible byte for byte from the reported hex — no corpus directory
to keep, no "it only fails sometimes".

## What is fuzzed

| Target | Entry point driven | Bytes that reach it in production |
|---|---|---|
| `src/ws.rs` | `FrameReader::with_limits` → `next_message`/`next_frame` (masking required **and** forbidden), `FrameReader::prepend`+drain, `write_frame`/`write_frame_masked` → decode | every WebSocket frame of `GET /v1/realtime`, both directions |
| `src/distributed/redis.rs` | `reply_from_slice` (the real `parse_reply`/`parse_bounded`/`read_line` chain), `encode_command` | every RESP reply from the Redis that enforces shared rate limits |
| `src/sse.rs` | `SseParser::feed_checked`/`feed`/`finish`/`buffered_len` | upstream `text/event-stream` bodies for every translating provider |
| `src/proxy/media.rs` | `multipart_field_span` | `POST /v1/images/*`, `/v1/audio/*` multipart bodies |
| `src/scan.rs` | `peek_request`, `string_field_span` | every chat/embeddings/FIM request body (32 MiB cap upstream of it) |
| `src/proxy/responses.rs` | `to_chat_request`, `replay_history` | `POST /v1/responses` JSON, and stored history replayed into a follow-up |
| `src/gemini.rs`, `src/anthropic.rs` | `translate_sse_stream_from` (whole stream state machine), `translate_response` | `data:` payloads of upstream SSE streams and non-streamed bodies |

`reply_from_slice` is a three-line `#[doc(hidden)] pub` wrapper added for this
harness (it is `parse_reply` over a `&[u8]`, so the caps, the reply budget and the
error types are exactly the ones the pool sees). `SseParser::buffered_len` and
`MAX_EVENT_BYTES` were made `pub` for the same reason, and `multipart_field_span`,
`to_chat_request` and `replay_history` are now `#[doc(hidden)] pub`. No behaviour
changed in any of those edits.

## Invariants asserted on **every** iteration

1. **No panic.** Each parser call runs under `catch_unwind`; a panic is recorded
   with the input hex and fails the test. (All targets are also self-contained:
   `reply_from_slice` never touches a socket, the translators are driven from an
   in-memory stream, the WS reader reads from a `&[u8]`.)
2. **No unbounded allocation.** A `#[global_allocator]` wrapper counts bytes
   allocated *on the fuzzing thread* during one iteration (per-thread `Cell`s, so
   targets running in parallel cannot bill each other). Caps: **8 MiB** per
   iteration for ws/sse/media/scan/responses/gemini/anthropic, and **33 MiB** for
   Redis, whose documented whole-reply budget is 32 MiB and whose largest legal
   frame is an 8 MiB bulk.
3. **Bounded work / bounded state**, per target:
   * ws: message payload ≤ 8 KiB (`with_limits(4 KiB, 8 KiB)`), ≤ 4096 delivered
     messages, `next_message` never yields an unfinished frame, and every frame is
     ≤ `MAX_FRAME_BYTES` on the write side;
   * redis: nils, negative and `u64::MAX` lengths, over-cap arrays and nesting past
     the depth cap are errors, never partial successes;
   * sse: `buffered_len() <= MAX_EVENT_BYTES` after every feed, every event ≤ the
     cap, an overflow releases the buffer and is sticky;
   * media/scan: every returned span is inside the input (`bytes[span]` is the
     check — the handler slices exactly that way) and a decoded model is at most
     4× the input (lossy UTF-8 expansion);
   * responses: a translated request always has a model and a non-empty message
     list, every message has a role and content, replay prepends exactly the
     stored turn plus one assistant message and appends the new turn unchanged;
   * translators: every emitted frame is UTF-8, SSE-terminated, ≤ 4096 frames and
     ≤ 4 MiB in total, **re-parses through `SseParser` as exactly one event per
     frame**, and every event except `[DONE]` is JSON.
4. **Cross-checks between two implementations** (the oracles that find real bugs):
   * ws: `write_frame`/`write_frame_masked` → `FrameReader` returns the same
     payload (masked and unmasked), so encoder and decoder must agree;
   * redis: `encode_command`'s output is a RESP2 array, so it is parsed back by
     the reply decoder and compared argument by argument;
   * sse: the same bytes fed whole and fed in pseudo-random chunks yield exactly
     the same events (chunk-boundary independence);
   * translators: the emitted stream is fed back through the shared SSE parser.
5. **Bounded input.** Each target caps the generated input (8–64 KiB) so a single
   iteration cannot be blamed on a 32 MiB body; the large fixed shapes get their
   own deterministic tests (64 KiB `data:` block, 8 MiB RESP bulk, 8 MiB+1
   `responses` input).

## Input generation

A seeded xorshift64 plus a corpus per target. Every input is a corpus entry that
is then mutated 1–4 times:

| Edit | Why |
|---|---|
| single bit flip | classic |
| byte stomp | classic |
| truncation at a random offset | every "partial frame/line/event" path |
| byte insertion / deletion | shifts every length and offset in the input |
| slice duplication | doubles a declared length without growing the body |
| run of `0xFF` / run of NULs | high-bit length prefixes, C-string truncation |
| corpus splice | recombines structures from different fixtures |
| **hostile length prefix** | replaces a run of decimal digits with `18446744073709551615` or `999999999999`, for the WS 64-bit length, the RESP `$`/`*` counts and the JSON array indices |

Stream parsers additionally receive their input split at pseudo-random offsets
(derived from the input via FNV-1a, so it stays deterministic): 1–4 chunks, with
empty chunks possible. This is what puts a chunk boundary in the middle of a CRLF
pair, in the middle of a `data:` line, and between a WebSocket header and its
payload.

### Fixtures (hand-written nasty cases)

Each corpus starts with *valid* inputs (so mutation explores the success path) and
then adds:

* **ws** — every opcode in both directions; fragmented messages; 300 one-byte
  continuations; reserved bits set; unknown opcode `0xF`; fragmented and oversized
  control frames; `126`/`127` length prefixes with 0 bytes behind them; a 64-bit
  length with the MSB set; `u64::MAX`; 65536 declared; mask bit without a key; key
  without a payload; invalid UTF-8 text; one-byte and reserved-code close frames;
  continuation without a start; a new message mid-fragment; valid frame + garbage.
* **redis** — all five RESP2 types, both nils, RESP3 types (`_`, `%`, `~`, `,`,
  `#`), empty/absent lines, unknown tags, non-UTF-8 lines, `$-2`, `*-2`,
  `i64::MIN-1`, `u64::MAX` lengths, `*1024` with and without elements, `*1025`,
  12- and 40-deep nesting, `$8388608` with no body, valid prefix + garbage.
* **sse** — LF, CRLF, lone CR, `\n\n`, `\r\n\r\n`, `\n\r\n`, empty `data:`,
  multi-line `data:`, comments/`event:`/`id:` lines, missing blank line, NULs,
  invalid UTF-8, 64 KiB of `data:` lines with the blank line only at the end, a
  single 64 KiB event, 200 events in one chunk, `[DONE]`, and a chunk-split
  between the `\r` and `\n` of a CRLF.
* **media** — a real multipart body; lower-cased header; `filename="model"`,
  `xname="model"`, `name="models"`, unquoted `name=model`; a *prompt* that quotes
  `content-disposition: … name="model"`; truncation after every part of the
  header; LF-only framing; no boundary at all; NULs and invalid UTF-8 in the
  value; a 4 KiB model value; repeated fields; 1000 quoted field names.
* **scan** — valid bodies, whitespace around the colon, escaped model values,
  `\u0000` escapes, `model_id`/`stream_options` lookalikes, a model name inside a
  message string, nested objects, a 200-deep array, unterminated strings, invalid
  UTF-8 in the value, `trueXXX` bools, 4096 `{` and 4096 `"`.
* **responses** — valid Responses requests; `tools`/`tool_choice`/`reasoning`/
  `text.format` shapes; missing/blank/non-string model; non-object and mixed
  input items; unknown roles; content parts we cannot translate; `stream:"yes"`;
  `max_output_tokens` at 0, −1, `u64::MAX`, `1e400`; `previous_response_id`;
  `null`/`[]`/`{}`; 200-item arrays; 60- and 200-deep nesting.
* **gemini / anthropic** — every event type each translator knows (text,
  function calls, thought parts, thinking + signature, redacted thinking, tool
  JSON deltas, blocked prompts, `message_stop`, error events), `usageMetadata`
  and `usage` at `u64::MAX`, block `index` at `u64::MAX` and 1e9, unknown events,
  non-object payloads (`[]`, `null`, `"str"`, `123`), non-JSON `data:`, `[DONE]`,
  CRLF framing, invalid UTF-8.

## Iterations and timing

`ALLOC_CAP` = 8 MiB; Redis = 33 MiB. Debug profile (the default `cargo test`
profile), 1.6 M generated inputs total:

| Target | Iterations | Time | Rate | Peak alloc / iteration |
|---|---:|---:|---:|---:|
| ws | 200 000 | 2.88 s | 69 473/s | 192 KiB |
| redis | 200 000 | 4.04 s | 49 463/s | 8 218 KiB |
| gemini | 200 000 | 4.20 s | 47 572/s | 101 KiB |
| responses | 200 000 | 4.81 s | 41 590/s | 2 033 KiB |
| anthropic | 200 000 | 4.84 s | 41 289/s | 97 KiB |
| scan | 200 000 | 14.91 s | 13 418/s | 162 KiB |
| media | 200 000 | 28.41 s | 7 041/s | 0.0 KiB |
| sse | 200 000 | 43.55 s | 4 593/s | 472 KiB |

1 600 000 inputs, **43.6 s** of test time (the targets run on parallel test
threads, so the wall clock is the slowest target — `sse` — plus build). The Redis
peak is the `$8388608\r\n` header case discussed below; nothing ever came near its
33 MiB cap. Debug profile, so these rates are roughly a tenth of release.

**What it costs the default `cargo test`:** 0.45 s for the 18 tests in this file
(8 fuzz targets, 10 deterministic regression/invariant tests). The library's own
unit tests (579 at the 2026-10-24 audit) take ~4 s, so this file adds roughly **+0.4 s (+25 % of test
time)**. Default iterations are 2 000 per target; `ANYHOP_FUZZ_ITERS` raises them.

## Findings

### 1. FIXED — `u64` overflow on upstream usage counters (`src/anthropic.rs`)

Both the non-streamed translation and the streamed usage chunk computed the total
with a plain `+`:

```rust
"total_tokens": input_tokens + output_tokens        // translate_response
"total_tokens": self.prompt_tokens + self.completion_tokens  // SseState::usage_chunk
```

Both operands come straight out of the upstream JSON (`as_u64`), so a hostile or
broken provider chooses them. In a debug build (`cargo test`, and the debug
profile an operator might run) the sum panics:

```
[panic] attempt to add with overflow
```

In a release build it wraps, reporting `total_tokens: 0` for a usage report that
should be enormous — silently wrong accounting rather than a crash.

Minimal trigger, non-streamed (`translate_response`, 65 bytes):

```
7b227573616765223a7b22696e7075745f746f6b656e73223a31383434363734343037333730393535313631352c226f75747075745f746f6b656e73223a317d7d
```

```json
{"usage":{"input_tokens":18446744073709551615,"output_tokens":1}}
```

Minimal trigger, streamed (181 bytes):

```
646174613a207b2274797065223a226d6573736167655f7374617274222c226d657373616765223a7b227573616765223a7b22696e7075745f746f6b656e73223a31383434363734343037333730393535313631357d7d7d0a0a646174613a207b2274797065223a226d6573736167655f64656c7461222c227573616765223a7b226f75747075745f746f6b656e73223a317d7d0a0a646174613a207b2274797065223a226d6573736167655f73746f70227d0a0a
```

```text
data: {"type":"message_start","message":{"usage":{"input_tokens":18446744073709551615}}}

data: {"type":"message_delta","usage":{"output_tokens":1}}

data: {"type":"message_stop"}

```

(the streaming panic fires when `message_stop` emits the usage chunk).

**Fix:** `saturating_add` at both sites, with the reasoning written down where the
next reader will see it. `src/proxy/responses.rs` already did exactly this
(`saturating_add` in three places) — this was the one translation layer that had
not been hardened. Regression tests: `hostile_usage_totals_saturate_instead_of_overflowing`
in `tests/fuzz_parsers.rs`, plus `src/anthropic.rs`'s own
`hostile_usage_counters_saturate_instead_of_overflowing` (covers both paths).

**Same bug in the sibling translator — FIXED:** `src/codex.rs` had an identical
`prompt_tokens + completion_tokens` in its per-chunk usage object; it now uses
`saturating_add` as well.

### 2. FOUND HERE, FIXED IN PARALLEL — the scanner and the upstream disagreed about `model`

This one is not a panic; it is a *semantic* mismatch between two parsers, which is
exactly what a two-implementation oracle is for. I did not fix it (the fix changes
hot-path semantics for ambiguous bodies — a design decision, not a bounds check),
and while this harness was being finished the owner of `src/scan.rs` fixed it in
two steps (duplicate keys first, then escaped spellings). Both triggers are kept
below because they are the regression cases.

`scan.rs` used to stop at the **first** top-level `model` key: `peek_request`
returned it (routing, `disabled_models`, client-key `allowed_models`) and
`string_field_span` returned its span, which `splice_model` rewrote in place. The
body is then forwarded to an OpenAI-compatible provider **verbatim**. A JSON
object, however, keeps the **last** value for a duplicated key — in `serde_json`
and in every upstream parser the gateway talks to. So:

```
input: {"model":"allowed","messages":[],"model":"disabled"}     (52 bytes)
hex:   7b226d6f64656c223a22616c6c6f776564222c226d65737361676573223a5b5d2c226d6f64656c223a2264697361626c6564227d
```

* the gateway routed and authorized `allowed` and spliced over that first span;
* the provider parsed the body and used `disabled` — a model the client was not
  allowed to use, or one the operator had disabled.

No duplicate plain key is needed either, because the scanner compared raw key
bytes while JSON decodes escapes before deduplicating:

```
input: {"model":"allowed","mod\u0065l":"disabled"}              (43 bytes)
hex:   7b226d6f64656c223a22616c6c6f776564222c226d6f645c75303036356c223a2264697361626c6564227d
```

**Fixed (duplicate key).** `peek_request` and `string_field_span` now count
occurrences and return `None` when the key appears twice, so the caller falls back
to the existing `serde_json::Value` path and routes on the same value the upstream
will use. Guarded by `ambiguous_model_keys_fall_back_to_a_real_parse` here.

**Also fixed (escaped spelling).** The first version of that fix only covered
duplicate *plain* keys, so a body whose second key is written with an escape
(`"mod\u0065l"`, 43 bytes above) still routed as `allowed` while the provider
resolved `disabled`: an escaped spelling never matches a literal `key == b"model"`
comparison. `peek_request` now matches an escaped key by decoding it
(`decode_json_string` only allocates for a key that actually contains a
backslash, so the hot path is unchanged) and bails out — `None`, i.e. the
`serde_json` fallback — for any escaped occurrence as well as for duplicates.
Both spellings are covered by `ambiguous_model_keys_fall_back_to_a_real_parse`.

### 3. OBSERVED, WITHIN BOUND — an 11-byte RESP header allocates 8 MiB

```
input: $8388608\r\n            (10 bytes)
hex:   24383338383630380d0a
```

`parse_bounded` charges the length from the header and then does
`vec![0u8; len + 2]` before a single payload byte arrives, so a malicious Redis (or
a MITM in front of it) turns 10 bytes into an 8 MiB zeroed allocation
(`MAX_BULK`), and an array header into up to `MAX_ARRAY × size_of::<Resp>()`. It is
*intentional and bounded*: `MAX_BULK`/`MAX_ARRAY` and the 32 MiB whole-reply
budget all bite before the allocation, and the pool is capped at 4 sockets. The
fuzzer's 8 218 KiB peak is this case; it is why Redis gets a 33 MiB cap instead of
8 MiB. A header-triggered allocation is still an amplification an operator may
want to shave (reserve incrementally instead), so it is recorded here rather than
silently accepted.

### 4. Not a bug: the first replay invariant was too strong

The initial responses target asserted that every message produced by
`replay_history` carries a role. It fired immediately — correctly, but the harness
was wrong: `StoredResponse::input` is written by the gateway from an
already-translated request, so the builder replays it verbatim by design and a
corrupted store is not attacker-reachable. The target now asserts the real
contract (stored turn verbatim, one assistant turn, new turn appended unchanged).

## What was *not* found

1.6 M generated inputs (and 10 fixed adversarial tests) produced no further
panic and no over-allocation. That is a statement about coverage, not a proof: ws,
redis, sse and media already had dedicated hostile-input unit tests (see the
`// ----- hostile …` sections), and those are exactly the paths the corpus
re-seeds from. The two findings above both came from *cross-checks* (a
two-implementation oracle for `scan.rs`, and an upstream-numbered field for
`anthropic.rs`), which is where this harness earns its keep beyond the existing
unit tests.

## Known limits

* **No coverage feedback.** Mutations are blind; a corpus that misses a branch
  keeps missing it. The corpus is therefore hand-built per target and mutates
  *valid* inputs.
* **Debug profile.** No optimizations, so timings here are ~10× the release
  cost and say nothing about production throughput.
* **No sanitizers.** Miri/ASAN are unavailable (nightly); the harness catches
  panics and allocation growth, not UB that does not manifest as either.
* **Deterministic seed.** A different seed would explore different inputs; the
  long campaign's value is bounded by one seed sequence per target. Re-running
  with a different seed means editing the seed constant in the target's
  `drive(...)` call.
* **Single reply per Redis connection.** `reply_from_slice` parses one reply from
  one buffer; pipelining across replies is covered by the pool's own tests.