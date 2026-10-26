# Conformance audit — `anyhop` vs. the real OpenAI Chat Completions + Responses spec

Evidence base: `openai/openai-openapi` @ `master`, `info.version: 2.3.0` (`openapi.yaml`).
Line references into the spec below are from that file. All code references are
`file:line` in this repository at the time of audit.

Verification method: the six target files were read in full; every claim marked
**VERIFIED** was additionally reproduced by running code (probes executed against
the real translators, then removed — the tree is clean). Claims marked **READ** are
from close reading only.

---

## Area 1 — Request fields accepted / dropped

### 1a. Pass-through (`ProviderKind::OpenaiCompat`) — no field is inspected

`run_target` rewrites only the `model` value in the raw bytes and forwards the body
verbatim (`src/proxy/chat/mod.rs:491-519`, `:525` `body(bytes)`). Nothing else is
touched, so **all 26 fields survive byte-for-byte**. Fields the gateway cannot
implement (`audio`, `prediction`, `web_search_options`, `logprobs`) are passed to an
upstream that may silently ignore them — but that is the upstream's contract, not
the gateway's, and pass-through is the correct default.

| Field | Spec requirement | Code does | Verdict |
|---|---|---|---|
| `stream_options.include_usage` | honoured by the upstream | forwarded verbatim (`mod.rs:525`) | **MATCH** (relay-side caveats: Area 4) |

### 1b. Translating providers — the drop matrix

`gemini::translate_request` / `anthropic::translate_request` / `codex::translate_request`
rebuild the body from scratch, so **every field they do not name is discarded**. The
only knobs that get an explicit "I am ignoring this" log are `seed`,
`frequency_penalty`, `presence_penalty`, `logit_bias` and `logprobs` — and only in the
Anthropic translator (`src/anthropic.rs:384-390`). Everything else vanishes silently.

Legend: ✅ forwarded · ⚠️ forwarded with changed semantics · ❌ silently dropped · 🚫 rejected by name

| Field | Gemini | Anthropic | Codex | Does a silent drop change semantics? |
|---|---|---|---|---|
| `model` | ✅ `gemini.rs:243` | ✅ arg | ✅ arg | — |
| `messages` | ✅ | ✅ | ✅ | — |
| `temperature` | ✅ clamped 0–2 `gemini.rs:419-425`; **⚠️ dropped entirely when thinking on** (`gemini.rs:415`) | ✅ clamped 0–1 `anthropic.rs:394-396` | ⚠️ dropped for reasoning models, logged `codex.rs:380` | **⚠️ YES** — Gemini silently ignores a client temperature when `reasoning_effort` is set. Anthropic clamping 2.0→1.0 is a deliberate, documented rescue. |
| `top_p` | ✅ `gemini.rs:427-434` (also dropped when thinking) | ✅ `anthropic.rs:397-400`; `top_p: 0` **dropped** | ❌ | Minor: `top_p: 0` on Anthropic silently becomes default=1. |
| `n` | 🚫 `n>1` rejected `gemini.rs:232-238` | 🚫 `anthropic.rs:226-232` | 🚫 `codex.rs:239-245` | **Correct** — refusing beats truncating. |
| `stream` | ✅ via URL (`:streamGenerateContent`) | ✅ `mod.rs:542-544` | ✅ always SSE | — |
| `stream_options` | ❌ | ❌ | ❌ | **YES — see D1** (usage chunk emitted unconditionally) |
| `stop` | ✅ clipped to 5, control chars dropped `gemini.rs:449-476` | ✅ control chars dropped `anthropic.rs:402-418` | ❌ | Codex drop is cosmetic (provider has no equivalent). |
| `max_tokens` / `max_completion_tokens` | ✅ both, `max_completion_tokens` wins `gemini.rs:431-464` | ✅ same `anthropic.rs:349-367` | ❌ | Codex: model-dependent cap, cosmetic. |
| `presence_penalty` | ❌ | ❌ (logged `:386`) | ❌ | Cosmetic — no common provider equivalent. |
| `frequency_penalty` | ❌ | ❌ (logged) | ❌ | Cosmetic. |
| `logit_bias` | ❌ | ❌ (logged) | ❌ | Cosmetic. |
| `logprobs` / `top_logprobs` | ❌ | ❌ (logged) | ❌ | **Silent misbehaviour for the rare client that asked**: response simply has no `logprobs` (spec makes it required on a choice — see D4). |
| `user` | ❌ | ✅ → `metadata.user_id` `anthropic.rs:379-383` | ❌ | Cosmetic (abuse attribution). |
| `seed` | ❌ | ❌ (logged) | ❌ | **YES in principle** — a client believing it has determinism does not. Logged for Anthropic only. |
| `response_format` | ✅ full `json_schema`/`json_object` mapping `gemini.rs:512`, `:180-220` | ✅ `anthropic.rs:455` | ✅ → `text.format` `codex.rs:384+` | Good coverage. |
| `tools` | ✅ `gemini.rs` | ✅ `anthropic.rs:470-483` | ✅ | — |
| `tool_choice` | ✅ | ✅ `anthropic.rs:486` | ✅ | — |
| `parallel_tool_calls` | ❌ (only in test names, `gemini.rs:1095`, `:1265` — never read) | ❌ | ❌ | **YES** — a client sending `false` still gets parallel calls. See D7. |
| `service_tier` | ❌ | ❌ | ❌ | Cosmetic (pricing/priority hint). |
| `metadata` | ❌ | ❌ | ❌ | Cosmetic (OpenAI echoes it back). |
| `store` | ❌ | ❌ | ✅ hard-coded `false` `codex.rs:302` | Cosmetic — the gateway is stateless for chat. |
| `reasoning_effort` | ✅ → `thinkingConfig` `gemini.rs:253-275` | ✅ → thinking budget `anthropic.rs:242-256` | ✅ | — |
| `modalities` | ❌ | ❌ | ❌ | **YES** — `["text"]` is fine, audio out is not delivered. |
| `audio` | ❌ | ❌ | ❌ | **YES if requested** — response carries no `delta.audio`. |
| `prediction` | ❌ | ❌ | ❌ | Cosmetic (optimisation hint only). |
| `web_search_options` | ❌ | ❌ | ❌ | **YES if set** — a client asking for web grounding gets an ungrounded answer with no signal. |

---

## Area 2 — Response object (chat.completion / chunk)

Spec: `CreateChatCompletionResponse` requires `choices, created, id, model`
(`openapi.yaml:45696-45701`); `object` is an enum const `chat.completion`
(`:45681-45684`); `system_fingerprint` is optional and **deprecated** (`:45666-45674`).
`CreateChatCompletionStreamResponse` requires `choices, created, id, model, object`
(`:45889-45894`); each choice requires `delta` + `index` (`:45762-45764`).

| Field | Spec | Code | Verdict |
|---|---|---|---|
| `id` | required, string | Anthropic echoes upstream `v.id` or generates `anthropic.rs:707`; Gemini `gen_id()` `gemini.rs:764`; Codex `gen_id()` `codex.rs:504` | **MATCH** |
| `object` | exact `"chat.completion"` / `"chat.completion.chunk"` | literal at `anthropic.rs:708`, `:765`, `:776`; `gemini.rs:765`, `:839`; `codex.rs:505` | **MATCH** — verified literal in all six sites |
| `created` | required, unixtime | `now_secs()` `anthropic.rs:709`, `gemini.rs:766`; Gemini **captured once per stream** (`gemini.rs:955`, `:719` for non-stream) so all chunks share it ✅ | **MATCH** |
| `model` | required | resolved upstream model | **MATCH** |
| `choices[].index` | required, int | always `0`; translators cap `n` at 1 (Area 1) | **MATCH** |
| `choices[].message` | required | `"message": msg` `anthropic.rs:713` | **MATCH** |
| `choices[].finish_reason` | required (non-null in non-stream) | `map_stop()` `anthropic.rs:511`, `map_finish()` `gemini.rs:45` | **MATCH** (Area 5) |
| `choices[].logprobs` | **required** on a choice (may be `null`) | **never emitted** | **DEVIATION (D4)** — strict validators reject; the SDK types it optional-ish, so most clients tolerate it |
| `usage` | `CompletionUsage` | `anthropic.rs:721-725`; Gemini `gemini.rs:769` `usage_of(v)` | **MATCH** (Area 3) |
| `system_fingerprint` | optional + **deprecated** | **never emitted** anywhere | **MATCH** — absence is spec-legal and the field is deprecated; do **not** add it. |
| `object` on chunks — `usage` key | optional only with `include_usage` | see Area 4 | **DEVIATION (D1)** |

---

## Area 3 — `usage`

Spec: `CompletionUsage` requires exactly `prompt_tokens, completion_tokens,
total_tokens` (`openapi.yaml:44392-44396`). `prompt_tokens_details` /
`completion_tokens_details` are optional objects whose sub-fields all default to 0
(`:44333-44396`); `prompt_tokens_details.cached_tokens` and
`completion_tokens_details.reasoning_tokens` are the two you asked about.

| Item | Spec | Code | Verdict |
|---|---|---|---|
| three required counters | required | all emitted; `total_tokens` via `saturating_add` (`anthropic.rs:723`, `codex.rs:513`, `gemini.rs:767`) | **MATCH** — saturation is a genuine hardening win |
| `prompt_tokens_details.cached_tokens` | optional, default 0 | emitted by Anthropic with real cache buckets `anthropic.rs:724`; `prompt_usage()` sums the cache buckets so `prompt_tokens` is the full context (`anthropic.rs:171` doc, used `:704`, `:388`) | **MATCH and better than naive maps** |
| `completion_tokens_details.reasoning_tokens` | optional, default 0 | **never emitted** | **DEVIATION (D6)** — reasoning tokens are billed inside `completion_tokens` but not attributed. Clients that chart reasoning spend read 0. |
| `prompt_tokens_details` on Gemini/Codex | optional | absent | **MATCH** (optional) |
| streamed usage accounting | — | Gemini: last cumulative `usageMetadata` only (`gemini.rs:788`, `:993`); Anthropic: `input_tokens` from `message_start`, `output_tokens` from `message_delta` (`anthropic.rs:958-960`, `:1130-1132`) | **MATCH** |

---

## Area 4 — Streaming and `stream_options.include_usage`

Spec (`openapi.yaml:43846-43868` and `:45857-45870`): with
`stream_options: {"include_usage": true}`, **exactly one extra chunk** is streamed
**before** `data: [DONE]`, its `choices` is **always the empty array**, it carries the
usage for the whole request, and **all other chunks carry `usage: null`**.
Without `include_usage`, no usage-bearing chunk exists.

### 4a. Pass-through providers — **MATCH**

`src/proxy/chat/stream.rs:469-534` relays upstream frames by refcount, adds a
synthesised `[DONE]` only when the upstream omitted it (`:515-522`), and injects an
error frame + `[DONE]` on mid-body failure (`:495-510`). It never inserts, drops or
reorders a chunk, so an upstream that honours `include_usage` produces exactly the
spec sequence, and one that does not produces none.

> Caveat: the gateway never *checks* that the upstream honoured the flag. A
> non-conforming upstream yields no usage chunk and the gateway relays that faithfully.

### 4b. Translated providers — **DEVIATION (D1)**, VERIFIED by probe

`stream_options` is dropped by all three translators (Area 1), and no translator is
told whether the client asked. The usage chunk is emitted **unconditionally**:

- Anthropic `src/anthropic.rs:1032-1038` — `push_usage()` runs on every terminal path
  (`:1132`, `:1146`) whenever `prompt+completion > 0`
- Anthropic `usage_chunk()` `src/anthropic.rs:773-788` — `"choices": []` ✅ correct shape
- Gemini `src/gemini.rs:844-846` — attaches `usage` to the **terminal content chunk**
  (non-empty `choices`), not to a separate `choices: []` chunk

Measured output with **no** `include_usage` in the request:

```
--- anthropic (client sent NO include_usage) ---
  choices=1 usage_key=false finish=null obj="chat.completion.chunk"
  choices=1 usage_key=false finish=null obj="chat.completion.chunk"
  choices=1 usage_key=false finish="stop" obj="chat.completion.chunk"
  choices=0 usage_key=true  usage={"completion_tokens":7,"prompt_tokens":11,"total_tokens":18}
  [DONE]
--- gemini (client sent NO include_usage) ---
  choices=1 usage_key=false finish=null obj="chat.completion.chunk"
  choices=1 usage_key=true  usage={"completion_tokens":3,"prompt_tokens":5,"total_tokens":8} finish="stop"
  [DONE]
```

So Anthropic returns an unrequested `choices: []` usage chunk (usually harmless,
but not spec-conformant), and **Gemini returns a `choices[0]`-bearing chunk that
carries `usage` without `include_usage`** — a shape the spec never permits. Meanwhile
`prompt_tokens_details.cached_tokens` is lost on the streaming path even though the
non-streaming path emits it (`anthropic.rs:724` vs `:773-788`).

### 4c. Same question, Responses-side proxy

`src/proxy/responses.rs:613` sets `chat["stream_options"] = json!({"include_usage": true})`
whenever it streams — correct and necessary, since `response.completed.usage` is
sourced from that chunk.

---

## Area 5 — `finish_reason` enum

Spec enum: `stop, length, tool_calls, content_filter, function_call` (+ `null` on chunks)
— `openapi.yaml:45622-45627`, `:45811-45817`.

| Item | Code | Verdict |
|---|---|---|
| Anthropic map | `map_stop()` `anthropic.rs:511-524`: `max_tokens→length`, `tool_use→tool_calls`, `refusal→content_filter`, `compaction→length`, default `stop` | **MATCH** — only in-enum values |
| Gemini map | `map_finish()` `gemini.rs:45-66`: `MAX_TOKENS→length`, 9 safety reasons → `content_filter`, `OTHER`/`MALFORMED_FUNCTION_CALL`/… → `content_filter`, default `stop` | **MATCH** |
| Codex map | `codex.rs:573-597`: `incomplete→length`, calls→`tool_calls`, else `stop` | **MATCH** |
| Gemini "STOP but calls present" | upgraded to `tool_calls` `gemini.rs:739-742` | **MATCH** — spec-faithful |
| Stream ending with no `stop_reason` | Anthropic forces one `finish_if_missing()` `anthropic.rs:1022-1030` | **MATCH** — prevents a "looks truncated" stream |
| Any out-of-enum value | none found in any translator | **MATCH** |

**No deviation in Area 5.** All five legal values, never anything else.

---

## Area 6 — `/v1/models`

Spec `Model` requires `id, object, created, owned_by` (`openapi.yaml:57401-57405`);
`object` is the const `model`. `ListModelsResponse` requires `object:"list"` + `data`.

| Item | Spec | Code | Verdict |
|---|---|---|---|
| `{object:"list", data:[…]}` | required | `models.rs:77` literal `"object": "list"` | **MATCH** |
| `id` | required | `models.rs:170` | **MATCH** |
| `object: "model"` | required, const | `models.rs:171` | **MATCH** |
| `created` | **required**, unixtime | **never emitted** — `model_json()` (`models.rs:168-212`) builds only `id`/`object`/`owned_by` + limit fields | **DEVIATION (D2)** |
| `owned_by` | required | `models.rs:172` | **MATCH** |
| `GET /v1/models/{id}` | returns one `Model` | `get_model()` `models.rs:95-157` returns `model_json(...)`, 404 with `not_found_error` otherwise | **MATCH** (same shape, same missing `created`) |
| extra limit fields | `additionalProperties` allowed | `context_length`, `context_window`, `max_completion_tokens`, `limit{context,output}`, `top_provider{…}` `models.rs:178-208` | **MATCH** — additive, harmless |

---

## Area 7 — Embeddings

Spec: response requires `object, model, data, usage` (`openapi.yaml:46465-46469`);
`Embedding` requires `index, object, embedding` (`:50588-50591`); `usage` requires
`prompt_tokens` + `total_tokens` (`:46459-46463`).

| Item | Spec | Code | Verdict |
|---|---|---|---|
| `object: "list"` | required | `embeddings.rs:398` | **MATCH** |
| `data[].object: "embedding"` | required | `embeddings.rs:392` | **MATCH** |
| `data[].index` | required | `embeddings.rs:393` = enumeration index | **MATCH** |
| `data[].embedding` | required | `embeddings.rs:394` | **MATCH** |
| `model` | required | `embeddings.rs:400` (Gemini path); pass-through keeps upstream's | **MATCH** |
| `usage.prompt_tokens/total_tokens` | required | `embeddings.rs:403` hard-codes `0/0` for Gemini | **DEVIATION (D5)** — schema-valid, semantically a lie-by-omission; comment at `:401-402` documents the choice |
| pass-through | — | `embeddings.rs:228-232` relays provider JSON untouched | **MATCH** (but: a base64/`encoding_format` request reaches Gemini with the field dropped — `gemini_request()` `:376-391` only maps `input`) |

---

## Area 8 — Responses API events

Spec: every stream event carries `type` + `sequence_number`
(`openapi.yaml:71292-71300` for `response.completed`; `:74388-74418` for
`response.output_text.delta`, which also **requires** `item_id, output_index,
content_index, delta, logprobs`).

| Item | Spec | Code | Verdict |
|---|---|---|---|
| `response.created` | required: `type, response, sequence_number` | `responses.rs:1324-1327` | **MATCH** |
| `response.output_item.added` | required: `type, output_index, item, sequence_number` | `responses.rs:1306-1319`, `:1418-1433` | **MATCH** |
| `response.output_text.delta` | requires `logprobs` | emitted without `logprobs` `responses.rs:1371-1380` | **DEVIATION (D3)** |
| `response.output_text.done` | requires `text, item_id, output_index, content_index` | `responses.rs:1516-1524` | **MATCH** |
| `response.function_call_arguments.delta/done` | required fields | `responses.rs:1443-1451`, `:1526-1536` | **MATCH** |
| `response.output_item.done` | required `type, output_index, item, sequence_number` | `responses.rs:1537-1551` | **MATCH** |
| `response.completed` / `.incomplete` | required `type, response, sequence_number` | `responses.rs:1578-1583`; `incomplete_details.reason="max_output_tokens"` correctly derived from `finish_reason=="length"` `:1574-1582` | **MATCH** — the `length→incomplete` mapping is exactly right |
| `sequence_number` monotonic from 0 | integer | `emit()` stamps and increments `responses.rs:1275-1282` | **MATCH** — verified 0,1,2,… in probe |
| ordering: item added before its deltas | — | lazy `item_added_event()` before first text delta `responses.rs:1365-1368` | **MATCH** |
| **`output_index` stability** | one item ⇔ one index, throughout | **collides** — see probe | **DEVIATION (D8), real breakage** |
| SSE framing | `event:` + `data:` | `event_frame()` `responses.rs:1195-1205` | **MATCH** |
| `response.failed` | optional | `responses.rs:1590-1599` | **MATCH** |
| `[DONE]` on the Responses stream | *not* part of the Responses spec | emitted? — `StreamMapper` never pushes `DONE_FRAME`; stream ends at EOF after the terminal event (`responses.rs:1699-1708`) | **MATCH** — correct, Responses streams do not use `[DONE]` |

### D8 probe output (reproduced, then the probe was removed)

Upstream: one tool call, then a text delta, then `[DONE]`.

```
response.created                     seq=0
response.output_item.added      output_index=0  item.type=function_call  seq=1
response.function_call_arguments.delta output_index=0                   seq=2
response.output_item.added      output_index=0  item.type=message        seq=3
response.output_text.delta      output_index=0                          seq=4
response.output_text.done       output_index=0                          seq=5
response.function_call_arguments.done output_index=1                    seq=6
response.output_item.done       output_index=1  item.type=function_call seq=7
response.completed                                                      seq=8
```

Two distinct items claim `output_index: 0` (seq 1 and seq 3), and the
`function_call` item is **announced at 0 but closed at 1** (seq 6-7). A client that
keys items by `output_index` — which is what the field is for — mis-associates the
item and its completion. Root cause: `output_index()` (`responses.rs:1458-1465`) is
evaluated at *close* time against `self.item_added`, which flipped to `true` after
the tool item was announced.

---

## Area 9 — Error envelope

Spec `Error` requires `type, message, param, code`, with `code` and `param`
`string|null` (`openapi.yaml:50621-50625`). `ErrorResponse` wraps it in `error`.

`error_response()` `src/proxy/mod.rs:315-328` emits
`{"error":{message, type, code, param}}`; `param` is always `Value::Null`,
`code` is always a string via `error_code_for()` (`mod.rs:290-307`) which never
returns an integer and never returns null.

| Item | Spec | Code | Verdict |
|---|---|---|---|
| all four keys present | required | `mod.rs:316-326` | **MATCH** |
| `code` string-or-null | `anyOf [string, null]` | always a string; `_ => "api_error"` | **MATCH** — the old integer-code bug is gone (`:312-314` documents it) |
| `param` string-or-null | `anyOf [string, null]` | always `null` | **MATCH** |
| `type` realistic | string | `invalid_request_error`, `rate_limit_exceeded`, `provider_unavailable`, `upstream_error`, `model_not_found`, `model_not_allowed`, `api_error` | **⚠️ MINOR (D9)** — `upstream_error`/`provider_unavailable` are not OpenAI `type` vocabulary; gateway-specific types are unavoidable, but SDKs branching on `type == "rate_limit_error"` will miss `rate_limit_exceeded` (which OpenAI uses as a *code*, not a type) |
| status/type agreement | — | `busy_response` → 429 + `rate_limit_exceeded` (`errors.rs:84-106`); `exhausted_response` → 503 + `provider_unavailable` (`:109-125`) | **MATCH** in spirit |
| streaming error frame | not in `Error` spec | `{"error":{message,type}}` inside SSE — missing `code`/`param` (`stream.rs:496-501`, `gemini.rs:913-916`) | **⚠️ MINOR (D10)** — relaxed but tolerated by clients |

---

## Ranked deviations

### Real breakage (fix these)

**D8 — `output_index` collision and inconsistent close index (Responses stream).**
`responses.rs:1458-1465` vs `:1311` (message item), `:1424` (function_call item), `:1520` (output_text.done). Two items share index 0 and a
`function_call` item is announce-open at 0 / close at 1. Breaks `previous_response_id`
replay and any item-keyed client. **Verified by probe.**
*Fix:* assign `output_index` when an item is **created** and store it (e.g.
`item_index: u32` on the tool-call struct and `0` reserved for the message item), then
reuse the stored value in `output_item.done` and `function_call_arguments.done`.
Model it as "the message item takes index 0 if it exists, otherwise tool items start
at 0" decided once, at announce time.

**D1 — usage chunk emitted without `include_usage` (translated providers), and Gemini
attaches `usage` to a non-empty `choices` chunk.**
`anthropic.rs:1032-1038`, `:1132`, `:1146`; `gemini.rs:844-846`.
**Verified by probe.** Non-conformant shape; the Gemini case violates the "usage only
with `include_usage`" rule outright.
*Fix:* thread `include_usage: bool` (parsed once in `chat_completions`,
`mod.rs:54-132`, alongside `is_stream`) into `success_response` (`stream.rs:246`) and
on into both translators; gate `push_usage()` on it, and in Gemini emit a separate
`{"choices": [], "usage": …}` chunk before `[DONE]` instead of tagging a content chunk.

**D2 — `GET /v1/models[/{id}]` omits required `created`.**
`models.rs:168-172`. Strict schema validators and some SDKs (and every OpenAI-shaped
catalogue ingester) treat `created` as required.
*Fix:* add `"created": <unix ts>`. There is no per-model creation time to report —
`ProviderConfig` (`config.rs:1221`) carries none (the only `created_at` in config,
`config.rs:943`, is on `ClientKeyConfig`, unrelated). Two honest options: (a) add a
`[providers] created_at` the loader stamps on first sight, or (b) emit a fixed
catalogue-build constant. Do **not** emit `now()`, which would change per request and
break clients that diff the catalogue.

### Semantic drift worth a decision (cheap, high-value)

**D4 — `logprobs: null` missing from choices.** Required: `CreateChatCompletionResponse`
lists `logprobs` in the per-choice `required` set (`openapi.yaml:45598-45602`), though
the value may be `null`. One-line fix: `"logprobs": Value::Null` in
`anthropic.rs:711-715`, `gemini.rs:768`, `codex.rs:837`.

**D3 — `response.output_text.delta` omits required `logprobs`.** Same one-line fix at
`responses.rs:1371-1380` (`"logprobs": []` or `null`).

**D6 — `completion_tokens_details.reasoning_tokens` never emitted.** Reasoning-capable
providers (Gemini thinking, Anthropic *thinking* blocks, Codex reasoning) all bill
these into `completion_tokens`; clients charting reasoning spend read 0. Optional in
spec, so this is drift not breakage.

**D7 — `parallel_tool_calls: false` silently ignored on every translated provider**
(zero reads in `gemini.rs`/`anthropic.rs`/`codex.rs`). A client disabling parallel
tool calls still gets them. Either forward it (`Anthropic`: `tool_choice.disable_parallel_tool_use`)
or reject it by name like `n` is (`gemini.rs:232-238`).

**D5 — Gemini embeddings hard-code `usage: {0, 0}`** (`embeddings.rs:403`). Schema-valid,
but every consumer that sums embedding spend sees zero for that provider. `usageMetadata`
is usually absent there, so this is the honest choice — but it should be surfaced as a
provider capability flag rather than silent zeros.

### Cosmetic drift (document, don't fix)

- `seed`, `presence_penalty`, `frequency_penalty`, `logit_bias`, `service_tier`,
  `prediction`, `metadata`, `store`, `user` dropped on translated providers. The
  first four change semantics only for clients that *believe* they got what they asked;
  Anthropic logs them at debug (`anthropic.rs:384-390`), Gemini/Codex do not.
- `system_fingerprint` absent everywhere — **spec-legal and deprecated; correct to omit.**
- `object` is a correct literal in all six construction sites; `created` is stable per
  stream; `finish_reason` never leaves the enum. These three are the things that most
  commonly break in gateways and they are clean here.
- D9/D10 error-envelope vocabulary drift (`upstream_error`, `rate_limit_exceeded` as a
  *type*, stream frames missing `code`/`param`).

---

## The short version

The gateway is in much better shape than a typical translating proxy. `object`
literals, `finish_reason` mapping (including Anthropic's four non-obvious cases and
Gemini's `STOP`-with-calls correction), `sequence_number` monotonicity, cache-aware
`prompt_tokens`, the `length → response.incomplete` mapping, and the `Error` envelope's
`code`-as-string fix are all correct and, in several cases, more rigorous than the spec
demands.

Three things are genuinely broken, and only one of them is hard: **`output_index`**
collides and changes between announce and close (D8); **usage chunks ignore
`include_usage`** and Gemini puts `usage` on a content chunk (D1); and **`created` is
missing from every model object** (D2). D4 and D3 are one-line `null` fields. D7 and D6
are the two judgement calls I would put in front of a maintainer: they change
observable behaviour for clients that asked for something specific.