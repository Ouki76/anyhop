//! Where a model's context window and token caps come from.
//!
//! Four sources, most specific first:
//!
//! 1. **override** — `[[model_limits]]` in the config (the dashboard's editor);
//! 2. **provider** — parsed from the provider's own model listing
//!    (Antigravity's `maxTokens`/`maxOutputTokens`, Gemini's
//!    `inputTokenLimit`/`outputTokenLimit`, OpenRouter-style `context_length`…);
//! 3. **builtin** — a small table of published numbers for well-known families,
//!    used only when the provider says nothing (DashScope's `/models`, for one,
//!    returns nothing but `id`);
//! 4. **unknown** — no number. We publish no field rather than invent one.
//!
//! The upstream payload is the source of truth whenever it exists: a provider that
//! states the numbers is never overridden by the table below.

use serde_json::Value;

/// Context window and caps, as numbers (0 = unknown).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Limits {
    pub context_window: u64,
    pub max_output_tokens: u64,
    pub max_input_tokens: u64,
}

impl Limits {
    pub fn is_empty(&self) -> bool {
        self.context_window == 0 && self.max_output_tokens == 0 && self.max_input_tokens == 0
    }
}

/// Which source a resolved value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Source {
    Override,
    Provider,
    Builtin,
    #[default]
    Unknown,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Override => "override",
            Source::Provider => "provider",
            Source::Builtin => "builtin",
            Source::Unknown => "unknown",
        }
    }
}

/// The limits that apply to a model, with the provenance of each field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Resolved {
    pub limits: Limits,
    pub sources: Sources,
}

/// Provenance of each of the three numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sources {
    pub context_window: Source,
    pub max_output_tokens: Source,
    pub max_input_tokens: Source,
}

impl Resolved {
    /// Merge the three layers, most specific last: a number set by the operator
    /// beats the provider's own figure, which beats the builtin table. A field
    /// nobody states stays at 0 / `unknown`.
    pub fn resolve(
        overrides: Option<Limits>,
        provider: Option<Limits>,
        builtin: Option<Limits>,
    ) -> Self {
        let layers = [
            (builtin, Source::Builtin),
            (provider, Source::Provider),
            (overrides, Source::Override),
        ];
        let pick = |field: fn(&Limits) -> u64| -> (u64, Source) {
            let mut out = (0, Source::Unknown);
            for (layer, source) in layers {
                if let Some(l) = layer
                    && field(&l) > 0
                {
                    out = (field(&l), source);
                }
            }
            out
        };
        let (ctx, s_ctx) = pick(|l| l.context_window);
        let (out, s_out) = pick(|l| l.max_output_tokens);
        let (inp, s_in) = pick(|l| l.max_input_tokens);
        Resolved {
            limits: Limits {
                context_window: ctx,
                max_output_tokens: out,
                max_input_tokens: inp,
            },
            sources: Sources {
                context_window: s_ctx,
                max_output_tokens: s_out,
                max_input_tokens: s_in,
            },
        }
    }

    /// The source of one field, as a string for the wire.
    pub fn source_of(&self, field: &str) -> &'static str {
        let s = match field {
            "context_window" => self.sources.context_window,
            "max_output_tokens" => self.sources.max_output_tokens,
            _ => self.sources.max_input_tokens,
        };
        s.as_str()
    }
}

// ---------- parsing a provider's model object ----------

/// Read the numbers a provider publishes for one model.
///
/// Every provider spells them differently, and the same provider may change the
/// spelling between APIs, so this looks at all the names in use instead of
/// branching on the kind: `context_length` (OpenRouter), `max_model_len` (vLLM),
/// `max_context_length`, `n_ctx` (llama.cpp), `maxTokens` (Antigravity),
/// `inputTokenLimit` (Gemini), `max_completion_tokens` / `max_output_tokens`…
pub fn from_json(v: &Value) -> Limits {
    let look = |names: &[&str]| -> u64 {
        for name in names {
            if let Some(n) = find_number(v, name) {
                return n;
            }
        }
        0
    };
    let context = look(&[
        "maxTokens",
        "context_length",
        "context_window",
        "max_context_length",
        "max_context_tokens",
        "max_model_len",
        "max_sequence_length",
        "inputTokenLimit",
        "n_ctx",
        "num_ctx",
    ]);
    let output = look(&[
        "maxOutputTokens",
        "max_completion_tokens",
        "max_output_tokens",
        "outputTokenLimit",
        "max_tokens",
    ]);
    let input = look(&[
        "max_input_tokens",
        "inputTokenLimit",
        "max_input",
        "input_token_limit",
    ]);
    Limits {
        context_window: context,
        max_output_tokens: output,
        max_input_tokens: input,
    }
}

/// Find a number under `key` anywhere in the object: top level, inside
/// `top_provider`/`limits`/`meta`/`model_spec`, and case/`_`-insensitively.
fn find_number(v: &Value, key: &str) -> Option<u64> {
    let want = normalize(key);
    let obj = v.as_object()?;
    for (k, val) in obj {
        if normalize(k) != want {
            continue;
        }
        if let Some(n) = as_u64(val) {
            return Some(n);
        }
    }
    // One level of nesting covers every payload seen in the wild
    // (`top_provider`, `meta`, `model_spec`, `limits`, `architecture`…).
    for (_, val) in obj {
        let Some(inner) = val.as_object() else {
            continue;
        };
        for (k, deep) in inner {
            if normalize(k) == want
                && let Some(n) = as_u64(deep)
            {
                return Some(n);
            }
        }
    }
    None
}

fn normalize(k: &str) -> String {
    k.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn as_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
        .or_else(|| v.as_f64().filter(|f| *f > 0.0).map(|f| f as u64))
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
        .filter(|n| *n > 0)
}

// ---------- the builtin table ----------

/// Published limits for model families whose numbers are stable and documented.
///
/// Deliberately small: a wrong number here is worse than no number, because the
/// dashboard presents it as a fact. Anything not listed resolves to "unknown" (and
/// publishes no field) unless the provider states it or the operator overrides it.
/// Values are matched on the model id after stripping the provider prefix.
pub fn builtin(model: &str) -> Option<Limits> {
    let id = model.to_ascii_lowercase();
    let id = id.rsplit('/').next().unwrap_or(&id);
    let has = |needle: &str| id.contains(needle);
    let pair = |ctx: u64, out: u64| {
        Some(Limits {
            context_window: ctx,
            max_output_tokens: out,
            max_input_tokens: 0,
        })
    };

    // Google Gemini (the provider publishes these itself; this covers models it
    // does not list, e.g. the Antigravity codenames).
    if has("gemini-3") || has("gemini-2.5") || has("gemini-2.0") {
        return pair(1_048_576, 65_536);
    }
    if has("gemini-1.5-pro") {
        return pair(2_097_152, 8_192);
    }
    if has("gemini-1.5-flash") {
        return pair(1_048_576, 8_192);
    }

    // Anthropic Claude: 200k window for every current model.
    if has("claude") {
        if has("haiku") {
            return pair(200_000, 8_192);
        }
        if has("opus") {
            return pair(200_000, 32_000);
        }
        if has("sonnet") {
            return pair(200_000, 64_000);
        }
        return pair(200_000, 8_192);
    }

    // OpenAI.
    if has("gpt-4.1") {
        return pair(1_047_576, 32_768);
    }
    if has("gpt-4o") {
        return pair(128_000, 16_384);
    }
    if has("gpt-4-turbo") {
        return pair(128_000, 4_096);
    }
    if has("gpt-3.5") {
        return pair(16_385, 4_096);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn antigravity_and_gemini_payloads_are_understood() {
        // Verbatim shapes from the live endpoints.
        let ag = json!({
            "displayName": "Gemini 2.5 Pro",
            "maxTokens": 1048576,
            "maxOutputTokens": 65535,
            "quotaInfo": {"remainingFraction": 1}
        });
        assert_eq!(
            from_json(&ag),
            Limits {
                context_window: 1_048_576,
                max_output_tokens: 65_535,
                max_input_tokens: 0
            }
        );

        let gemini = json!({
            "name": "models/gemini-2.5-flash",
            "inputTokenLimit": 1048576,
            "outputTokenLimit": 65536
        });
        assert_eq!(
            from_json(&gemini),
            Limits {
                context_window: 1_048_576,
                max_output_tokens: 65_536,
                max_input_tokens: 1_048_576
            }
        );
    }

    #[test]
    fn openrouter_and_vllm_shapes_are_understood() {
        let openrouter = json!({
            "id": "anthropic/claude-3.5-sonnet",
            "context_length": 200000,
            "top_provider": {"context_length": 200000, "max_completion_tokens": 8192}
        });
        let l = from_json(&openrouter);
        assert_eq!(l.context_window, 200_000);
        assert_eq!(l.max_output_tokens, 8_192);

        let vllm = json!({"id": "qwen3-32b", "max_model_len": 32768, "meta": {"n_ctx": 32768}});
        assert_eq!(from_json(&vllm).context_window, 32_768);

        // Numbers written as strings are still numbers.
        let strings = json!({"context_length": "131072", "max_completion_tokens": "4096"});
        let l = from_json(&strings);
        assert_eq!((l.context_window, l.max_output_tokens), (131_072, 4_096));

        // A payload with nothing useful stays empty (DashScope's /models).
        assert!(from_json(&json!({"id": "qwen-max", "object": "model"})).is_empty());
    }

    #[test]
    fn resolution_prefers_override_then_provider_then_builtin() {
        let provider = Limits {
            context_window: 262_144,
            max_output_tokens: 8_192,
            max_input_tokens: 0,
        };
        let builtin = Limits {
            context_window: 1_048_576,
            max_output_tokens: 65_536,
            max_input_tokens: 0,
        };
        let over = Limits {
            context_window: 0,
            max_output_tokens: 4_096,
            max_input_tokens: 100_000,
        };

        let r = Resolved::resolve(Some(over), Some(provider), Some(builtin));
        // The provider's window wins over the table; the override wins over both —
        // field by field, and a field nobody set stays empty.
        assert_eq!(r.limits.context_window, 262_144);
        assert_eq!(r.source_of("context_window"), "provider");
        assert_eq!(r.limits.max_output_tokens, 4_096);
        assert_eq!(r.source_of("max_output_tokens"), "override");
        assert_eq!(r.limits.max_input_tokens, 100_000);
        assert_eq!(r.source_of("max_input_tokens"), "override");

        let r = Resolved::resolve(None, None, Some(builtin));
        assert_eq!(r.source_of("context_window"), "builtin");
        assert_eq!(r.limits.context_window, 1_048_576);

        let r = Resolved::resolve(None, None, None);
        assert!(r.limits.is_empty());
        assert_eq!(r.source_of("context_window"), "unknown");
    }

    #[test]
    fn the_builtin_table_covers_the_families_it_claims_and_nothing_else() {
        let expect = |id: &str, ctx: u64, out: u64| {
            let l = builtin(id).unwrap_or_else(|| panic!("{id} must be known"));
            assert_eq!((l.context_window, l.max_output_tokens), (ctx, out), "{id}");
        };
        expect("dashscope/gemini-2.5-pro", 1_048_576, 65_536);
        expect("antigravity/claude-sonnet-4-6", 200_000, 64_000);
        expect("antigravity/claude-opus-4-6-thinking", 200_000, 32_000);
        expect("openai/gpt-4o-mini", 128_000, 16_384);
        // Unknown families must stay unknown — a guess would be shown as a fact.
        assert!(builtin("dashscope/qwen3.8-max").is_none());
        assert!(builtin("dashscope/deepseek-v4-pro").is_none());
        assert!(builtin("mock/test-model").is_none());
    }
}
