# Wire verification: Gemini translation vs. the live providers

Six open questions from the round-3 audit were carried as `[WIRE]` — claims about
upstream behaviour that only a real provider can settle. This document records what
the wire actually did on **2026-10-22**, against the two providers configured on
this machine (`antigravity` — Google OAuth, two accounts; `dashscope` —
OpenAI-compatible). Where a real-provider answer was impossible, a loopback
upstream was used to prove the *gateway's* half of the wire (the URL and the JSON it
emits) and is labelled as such.

Nothing here is a fix. Each FAIL below names the code that breaks and the exact
request that reproduces it.

## How it was run

* A **copy** of the live config at `/tmp/wire-check.toml` (`chmod 600`), with only
  two keys changed: `listen = "127.0.0.1:18991"` and
  `state_file = "/tmp/wire-check.redb"`. The real `anyhop.toml` and `anyhop.redb`
  were never opened for writing, and the gateway already serving `:8080` was left
  alone.
* A second instance on `:18993` with a mock-only config (no server-wide proxy) ran a
  loopback Gemini-shaped upstream on `:18992` that **logs the exact path and JSON
  body** the gateway produces. Requests that go through the real provider and the
  same request through the loopback together pin down "gateway bug" vs. "upstream
  quirk".
* Both test instances and the mock were terminated afterwards; only the original
  `:8080` gateway is still running.
* The test instance had no `api_key`, so the `curl` commands below carry no auth
  header. On a keyed instance every one of them needs
  `-H 'authorization: Bearer sk-…'`.
* **Redaction:** no key material, no OAuth token, no account e-mail and no
  `anyhop.toml` value appears in this file. Tool-call ids are shown as shapes
  (`call_<digits>`, `call_<created>_<n>`) rather than literal values; thought
  signatures are shown by length only.
* The binary under test was `cargo build --bin anyhop` from the working tree at
  `c19e6ef` plus the uncommitted changes that were already present (they touch
  `middleware.rs`, `pool/mod.rs`, `sse.rs`, `anthropic.rs`, `redis.rs`, `media.rs`,
  `responses.rs`). **Neither `src/gemini.rs` nor `src/antigravity.rs` is modified**,
  so every FAIL below is a property of the committed HEAD revision of those files.

## Summary

| # | Question | Verdict |
| --- | --- | --- |
| 1 | Gemini `functionCall` chunking → distinct `index`/`id`, `finish_reason: tool_calls` | **PASS** (per-call `index` and ids are distinct; the per-stream counter is also proven directly on the loopback path) |
| 2 | `usageMetadata` repeated per chunk → counters bump once | **PASS** (with one semantic caveat: `total_tokens` includes thinking tokens) |
| 3 | Thinking + tools round trip (replay the gateway's own output) | **CLOSED (2026-10-24)** — was FAIL; `thoughtSignature` now rides as a sibling of `functionCall` on replay (`src/gemini.rs`), covered by unit tests |
| 4 | `response_format` → `responseMimeType` / `responseJsonSchema` | **CLOSED (2026-10-24)** — was FAIL; `apply_response_format` maps all three OpenAI shapes and rejects unknown ones by name instead of dropping them |
| 5 | Model id spellings (`provider/model`, bare, `models/`-prefixed) | **PASS**, including the antigravity envelope (the `models/` prefix is stripped once); the embeddings path was fixed in the 2026-10-24 audit |
| 6 | Anthropic / Codex | **NOT TESTABLE HERE** — no such provider is configured |

---

## 1. Gemini `functionCall` chunking — **PASS**

**Assumed:** Gemini streams each parallel `functionCall` as its own part, and the
gateway's `SseState`/`PartSink` (per-stream monotonic counter) turns them into
distinct OpenAI `tool_calls[].index` and distinct `id`s, with a terminal
`finish_reason: "tool_calls"`.

**What the wire did** (`antigravity/gemini-2.5-flash`, streaming, two tool
declarations, prompt asking for both calls in one turn):

```text
HTTP/1.1 200 OK
content-type: text/event-stream

event#1 finish=None delta={"role":"assistant"}            usage={p:113,c:0,t:113}
event#2 finish=None delta={"tool_calls":[{"index":0,"id":"call_<digits>",
            "type":"function","function":{"name":"get_weather",
            "arguments":"{\"city\":\"Paris\"}","thought_signature":"<…>"}}]}
event#3 finish=None delta={"tool_calls":[{"index":1,"id":"call_<digits>",
            "type":"function","function":{"name":"get_time",
            "arguments":"{\"tz\":\"UTC\"}"}}]}
event#4 finish=tool_calls delta={}                        usage={p:113,c:32,t:145}
data: [DONE]
```

* **One `functionCall` part per SSE event** — two parts, two events, in order. The
  gateway never splits or re-batches parts, so this is also the upstream's
  chunking, not an artefact.
* **`index` values are distinct** (`0`, `1`). Gemini has no `index` concept, so
  these are entirely the gateway's: this is the live proof of the counter fix.
* **`id`s are distinct.** On this provider they were **upstream-supplied**
  (shape `call_<digits>`, no second underscore group) rather than counter-made, so
  the counter's synthetic format was not exercised here — see the loopback probe
  below, which does exercise it.
* **`finish_reason` is `tool_calls`** on the terminal event, although the upstream
  said `STOP` and that event carried no `tool_calls` itself. `saw_tool_call`
  (`src/gemini.rs:574`) is what makes this work.
* The non-streaming path agrees: one `candidate` with two parts yields
  `"index": 0` / `"index": 1`, `finish_reason: "tool_calls"`.

**Counter path, proven directly** (loopback upstream that sends two `functionCall`
parts **without ids** in two separate events):

```text
delta.tool_calls[0] = {"index":0,"id":"call_<created>_1","function":{"name":"get_weather",…}}
delta.tool_calls[1] = {"index":1,"id":"call_<created>_2","function":{"name":"get_time",…}}
finish=tool_calls
```

Distinct synthetic ids from one per-stream counter, exactly as `PartSink::call_id`
(`src/gemini.rs:437-440`) intends. A per-chunk allocator would have produced
`call_<created>_1` twice.

Reproduction:

```bash
curl -sS -N -H 'content-type: application/json' \
  -d '{"model":"antigravity/gemini-2.5-flash","stream":true,
       "messages":[{"role":"user","content":"Call BOTH tools now, in the same turn: get_weather for Paris and get_time for UTC. Do not reply with text."}],
       "tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}},
                {"type":"function","function":{"name":"get_time","parameters":{"type":"object","properties":{"tz":{"type":"string"}},"required":["tz"]}}}]}' \
  http://127.0.0.1:<port>/v1/chat/completions
```

---

## 2. `usageMetadata` semantics — **PASS, with a semantic caveat**

**Assumed:** Gemini repeats *cumulative* `usageMetadata` on every event, and the
gateway's counters increment once (from the last cumulative value), not once per
chunk.

**What the wire did.** The four events of the item-1 stream carried:

| event | `promptTokenCount` | `candidatesTokenCount` | `totalTokenCount` |
| --- | --- | --- | --- |
| 1 | 113 | 0 | 113 |
| 2 | 113 | 16 | 129 |
| 3 | 113 | 32 | 145 |
| 4 | 113 | 32 | 145 |

Cumulative, repeated on **every** event — the premise is correct.

After exactly that one request, `GET /api/providers` and `/metrics` reported:

```text
anyhop_key_tokens_total{provider="antigravity",key="<digest>",type="prompt"} 113
anyhop_key_tokens_total{provider="antigravity",key="<digest>",type="completion"} 32
```

113 / 32 — i.e. the last cumulative value, added **once**. A per-chunk bump would
have been 452 / 80. Confirmed independently on the loopback upstream: three
cumulative events (11/4, 11/9, 11/9) moved the counters by exactly 11/9.

The mechanism is `StreamState::add_usage_once` (`src/gemini.rs:672-681`) reading
`st.last_usage`, which is overwritten on every event (`src/gemini.rs:773-775`).

**Caveat (new finding, M):** when thinking is on, `usage_of` (`src/gemini.rs:405-413`)
maps `total_tokens` from upstream `totalTokenCount`, which **includes**
`thoughtsTokenCount`, while `completion_tokens` comes from `candidatesTokenCount`,
which does not. Observed with `reasoning_effort: "high"`:

```json
"usage": {"prompt_tokens": 59, "completion_tokens": 16, "total_tokens": 176}
```

59 + 16 = 75, not 176 (the 101-token gap is consistent with `thoughtsTokenCount`,
which the gateway does not map at all). Every OpenAI client that derives cost or
context-fill from `total_tokens` over-counts on a thinking model, and the invariant
`total = prompt + completion` is broken. The same request **without**
`reasoning_effort` reported `50 / 16 / 66` — consistent — so the mismatch appears
together with `includeThoughts`.

---

## 3. Thinking + tools round trip — **FAIL**

**Assumed:** a response taken verbatim from the gateway and replayed as
conversation history (assistant `tool_calls` + the `tool` result) is accepted by the
same gateway; `thought_signature` is present and survives the replay.

**What the wire did.** The signature **is** present on the response — and then the
gateway cannot take its own output back:

```text
POST /v1/chat/completions  (reasoning_effort: "high", one tool)
→ "finish_reason": "tool_calls",
  "message": {"content": null,
              "reasoning_content": "<thoughts>",
              "tool_calls": [{"index": 0, "id": "call_<digits>", "type": "function",
                              "function": {"name": "get_weather",
                                           "arguments": "{\"city\":\"Paris\"}",
                                           "thought_signature": "<652 chars, base64>"}}]}
```

Replaying that message plus `{"role":"tool","tool_call_id":"call_<digits>",…}`:

```text
HTTP 400
{"error":{"code":400,"type":"upstream_error","message":"{… \"message\":
  \"Invalid JSON payload received. Unknown name \\\"thoughtSignature\\\" at
   'request.contents[1].parts[0].function_call': Cannot find field.\" …}"}}
```

and with the signature **removed** from the replayed call:

```text
HTTP 400
{"error":{"code":400,"type":"upstream_error","message":"{… \"message\":
  \"Function call is missing a thought_signature in functionCall parts. This is
   required for tools to work correctly …\" …}"}}
```

So **both** ways fail: echoing it puts it where the upstream does not allow it,
dropping it is rejected as missing. The requirement is not a Gemini-3-only rule —
it fires on `gemini-2.5-flash`, and it fires **without** `reasoning_effort` too
(thinking is dynamic by default), so multi-turn tool use through `antigravity` is
broken for every request, not just for explicit thinking.

Control: a **text-only** two-turn replay (assistant `content`, no `tool_calls`)
returns 200 — the breakage is specific to `functionCall` parts.

**Where it breaks — `src/gemini.rs:190-199`.** The replayed call is built as

```rust
let mut fc = json!({"name": name, "args": args});
if let Some(sig) = tc.pointer("/function/thought_signature").and_then(|s| s.as_str()) {
    fc["thoughtSignature"] = json!(sig);          // <-- inside the functionCall object
}
parts.push(json!({"functionCall": fc}));          // <-- produces functionCall.thoughtSignature
```

Gemini's `Part` schema puts `thoughtSignature` **next to** `functionCall`, not inside
it. The response side already proves it — `extract_parts` reads it from
`part.thoughtSignature` / `part.functionCall.thoughtSignature`
(`src/gemini.rs:479-482`), i.e. the part — and the live 400 names the exact wrong
nesting (`at 'request.contents[1].parts[0].function_call'`). The fix belongs on the
replay side: emit `{"functionCall": {"name":…, "args":…}, "thoughtSignature": sig}`,
and keep the OpenAI-side carrier (`function.thought_signature`) as is.

The same body, captured verbatim from the gateway on the loopback upstream
(assistant `tool_calls` with `function.thought_signature` + one `tool` result):

```json
{"contents":[
   {"role":"user","parts":[{"text":"weather?"}]},
   {"role":"model","parts":[{"functionCall":{"name":"get_weather",
        "args":{"city":"Paris"},"thoughtSignature":"SIG-…"}}]},
   {"role":"user","parts":[{"functionResponse":{"name":"get_weather",
        "response":{"result":"{\"temp_c\":14}"}}},{"text":"and?"}]}],
 "tools":[{"function_declarations":[{"name":"get_weather","description":"",
           "parameters":{"type":"object","properties":{"city":{"type":"string"}}}}]}]}
```

`thoughtSignature` sits inside the `functionCall` object — one level too deep.

Reproduction (self-contained; first request, then replay):

```bash
# 1. obtain a tool call with a signature
curl -sS -H 'content-type: application/json' \
  -d '{"model":"antigravity/gemini-2.5-flash","reasoning_effort":"high","max_tokens":2048,
       "messages":[{"role":"user","content":"What is the weather in Paris right now? You must call get_weather."}],
       "tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}}]}' \
  http://127.0.0.1:<port>/v1/chat/completions > /tmp/r.json

# 2. replay the assistant message verbatim + the tool result  -> 400
python3 - <<'PY'
import json
m = json.load(open('/tmp/r.json'))['choices'][0]['message']
print(json.dumps({"model":"antigravity/gemini-2.5-flash","max_tokens":512,
  "messages":[{"role":"user","content":"weather?"}, m,
              {"role":"tool","tool_call_id":m["tool_calls"][0]["id"],"content":"{\"temp_c\":14}"},
              {"role":"user","content":"thanks"}],
  "tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}}]}))
PY
# pipe the emitted JSON body back to /v1/chat/completions -> HTTP 400, "Unknown name thoughtSignature"
```

---

## 4. Structured output — **FAIL**

**Assumed** (per the audit note): `response_format: {"type":"json_object"}` and
`{"type":"json_schema",…}` are forwarded as `generationConfig.responseMimeType` /
`generationConfig.responseJsonSchema`.

**What the wire did.** They are not forwarded at all. A loopback upstream that logs
the exact translated body shows the field's presence changes nothing:

| request `response_format` | body the upstream received |
| --- | --- |
| `{"type":"json_object"}` | `{"contents":[…]}` |
| `{"type":"json_schema","json_schema":{"name":"cat","strict":true,"schema":{…}}}` | `{"contents":[…]}` |
| absent (control) | `{"contents":[…]}` |

No `generationConfig` object is produced at all, let alone `responseMimeType` or
`responseJsonSchema` — identical bytes for all three. A grep for
`responseMimeType|responseJsonSchema|response_format` over `src/` returns **zero
hits**, so the mapping was not "added" in the sense the audit assumed.

Against the real provider the consequence is observable:

* `json_object` with *"Describe a cat in a JSON object with keys name and sound. No
  prose."* → `{"name":"Whiskers","sound":"Meow"}` — **valid JSON, but only because
  the prompt asked for it**; nothing enforced it.
* `json_schema` (schema `{name: string, legs: integer}`, `strict`, with
  `additionalProperties: false`) → a markdown bullet list of prose, no JSON at all,
  `finish_reason: "stop"`, HTTP 200. Total silent failure: the client asked for a
  schema and got text with no error to indicate the contract was dropped.

**Where it breaks:** `translate_request` (`src/gemini.rs:274-384`) builds
`generationConfig` from `temperature`, `top_p`, `max_tokens`/`max_completion_tokens`,
`stop` and `thinkingConfig` only, and then constructs the request from the fields it
knows (`req["contents"]`, `system_instruction`, `generationConfig`, `tools`,
`toolConfig`). Unknown OpenAI fields are dropped by construction, so
`response_format` disappears without a warning — which is worse than a 400, because
the caller believes the constraint was applied.

Reproduction:

```bash
curl -sS -H 'content-type: application/json' \
  -d '{"model":"antigravity/gemini-2.5-flash","max_tokens":300,
       "response_format":{"type":"json_schema","json_schema":{"name":"cat","strict":true,
         "schema":{"type":"object","properties":{"name":{"type":"string"},"legs":{"type":"integer"}},
                   "required":["name","legs"],"additionalProperties":false}}},
       "messages":[{"role":"user","content":"Describe a cat with the required fields."}]}' \
  http://127.0.0.1:<port>/v1/chat/completions
# → HTTP 200, content is prose ("Here is a description of a cat…"), not JSON
```

---

## 5. Model id spellings — **PASS for `gemini`, FAIL for `antigravity`**

**Assumed:** `provider/model`, a bare `model`, and a configured id that already
starts with `models/` all reach the upstream without doubling the `models/` path
segment.

**What the wire did**, loopback upstream, `type = "gemini"`, models list containing
both `gemini-2.5-flash` and `models/gemini-2.5-flash`:

| request `model` | path the upstream received |
| --- | --- |
| `mockgem/gemini-2.5-flash` | `/v1beta/models/gemini-2.5-flash:generateContent` |
| `mockgem/models/gemini-2.5-flash` | `/v1beta/models/gemini-2.5-flash:generateContent` |
| `models/gemini-2.5-flash` (bare, resolved from the configured list) | `/v1beta/models/gemini-2.5-flash:generateContent` |
| `gemini-2.5-flash` (bare) | `/v1beta/models/gemini-2.5-flash:generateContent` |
| streaming variant | `/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse` |

No `models/models/…` in any case: `endpoint()`'s
`strip_prefix("models/")` (`src/gemini.rs:22`) holds, and `provider/model` routing
works (`resolve_single`, `src/providers.rs:554-559`).

Against the real provider, the two spellings that matter:

| request `model` | result |
| --- | --- |
| `antigravity/gemini-2.5-flash` | **200**, `model` echoed as `gemini-2.5-flash` |
| `gemini-2.5-flash` (bare) | **200** (resolved via the provider's advertised list) |
| `antigravity/models/gemini-2.5-flash` | **404** from the upstream: `"Requested entity was not found."` |

**Why the antigravity case fails:** that provider does not use
`gemini::endpoint()` at all — it posts to
`{base}/v1internal:streamGenerateContent` and puts the model **in the envelope
body** (`antigravity::translate_request_envelope`, `src/antigravity.rs:426-451`,
`{"model": model, …}`), with no `strip_prefix("models/")`. The upstream therefore
receives `"model": "models/gemini-2.5-flash"`, which it does not resolve → 404. So
the audit's fix covers the `gemini` path construction but not the `antigravity`
envelope, which is the only Gemini-backed provider we actually have.

This is a live-able failure: Google's generativelanguage `ListModels` returns ids of
the form `models/gemini-…`, so a client that takes an id from a Gemini model list and
prefixes it with the provider name produces exactly this 404.

Reproduction:

```bash
curl -sS -H 'content-type: application/json' \
  -d '{"model":"antigravity/models/gemini-2.5-flash","max_tokens":30,
       "messages":[{"role":"user","content":"Say OK"}]}' \
  http://127.0.0.1:<port>/v1/chat/completions
# → HTTP 404 {"error":{"code":404,"type":"upstream_error","message":"… \"Requested entity was not found.\" …"}}
# the same request with "antigravity/gemini-2.5-flash" → 200
```

---

## 6. Anthropic / Codex — **NOT TESTABLE HERE**

The config on this machine declares exactly two providers, `antigravity`
(`type = "antigravity"`) and `dashscope` (`type = "openai_compat"`). There is no
`type = "anthropic"` and no `type = "codex"` provider, hence no Anthropic API key
and no ChatGPT OAuth account to drive them. `src/anthropic.rs` and `src/codex.rs`
were therefore not exercised against a real upstream at all; the audit's claim about
the Anthropic thinking/tools fix is **NOT TESTABLE HERE**. No inference was drawn
from the Gemini analogue beyond noting that it *is* broken (item 3) — the two
translation layers are separate code paths.

---

## Incidental observations (not part of the six)

* **`/api/providers` exposes full OAuth account e-mails.** `KeySnapshot.masked` is
  `KeyState::masked()`, which returns the key's label when one is set
  (`src/pool/key.rs:88-101`), and for OAuth providers the label is
  `Account::label()` = the configured **account e-mail** (`src/antigravity.rs:188-195`,
  set in `src/providers.rs:177-180`). Any caller that can read `/api/providers` (or
  the dashboard) sees the addresses verbatim. Round 2 finding #9 fixed the *secret*
  ending up in a label, but for OAuth accounts the label is PII, not a digest. Low
  severity, worth a decision either way.
* **`reasoning_content` is dropped on replay** (only `content` and `tool_calls` are
  translated back, `src/gemini.rs:167-206`). Harmless for Gemini — the upstream
  does not need it — but a client that expects to round-trip its own transcript will
  see the field vanish.
* **A replay of a tool result is merged into the following user turn**
  (`src/gemini.rs:246-267`). Gemini accepts it, and part order is preserved
  (`functionResponse` before the text), so this is fine — noting it because the
  translated body looks surprising.
* **The `usage` block is emitted on every chunk when the upstream sent one**
  (`src/gemini.rs:624-626`). That is legal for OpenAI clients that read the final
  usage, but it is not the `stream_options.include_usage` convention; clients that
  sum chunk usages will over-count by design of *their* loop, not ours.