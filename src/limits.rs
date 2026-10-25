//! Where a model's context window and token caps come from.
//!
//! Two sources, most specific first:
//!
//! 1. **override** — `[[model_limits]]` in the config (the dashboard's editor);
//! 2. **provider** — parsed from a catalogue the provider itself serves
//!    (Antigravity's `maxTokens`/`maxOutputTokens`, Gemini's
//!    `inputTokenLimit`/`outputTokenLimit`, OpenRouter-style `context_length`,
//!    DashScope's native `model_info`…).
//!
//! Anything nobody states is **unknown**: the field is not published at all. There
//! is deliberately no table of model families in this repository — model
//! catalogues change faster than a release, and a stale number presented as a fact
//! is worse than no number. A provider that serves no metadata is covered by
//! `limits_url` on the provider, or by an operator override.

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
    #[default]
    Unknown,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Override => "override",
            Source::Provider => "provider",
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
    /// Merge the layers, most specific last: a number set by the operator beats the
    /// provider's own figure. A field nobody states stays at 0 / `unknown`.
    pub fn resolve(overrides: Option<Limits>, provider: Option<Limits>) -> Self {
        let layers = [(provider, Source::Provider), (overrides, Source::Override)];
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

    /// DashScope's native catalogue nests everything under `model_info` (the
    /// OpenAI-compatible `/models` has no numbers at all).
    #[test]
    fn dashscope_model_info_is_understood() {
        let native = json!({
            "model": "qwen3.8-max",
            "name": "Qwen3.8-Max",
            "model_info": {
                "context_window": 1000000,
                "max_input_tokens": 991808,
                "max_output_tokens": 131072,
                "max_reasoning_tokens": 262144
            },
            "features": ["cache", "function-calling"],
            "prices": []
        });
        let l = from_json(&native);
        assert_eq!(l.context_window, 1_000_000);
        assert_eq!(l.max_input_tokens, 991_808);
        assert_eq!(l.max_output_tokens, 131_072);
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
    fn resolution_prefers_the_operator_and_never_invents_a_number() {
        let provider = Limits {
            context_window: 262_144,
            max_output_tokens: 8_192,
            max_input_tokens: 0,
        };
        let over = Limits {
            context_window: 0,
            max_output_tokens: 4_096,
            max_input_tokens: 100_000,
        };

        let r = Resolved::resolve(Some(over), Some(provider));
        // Field by field: the override wins where it is set, the provider's figure
        // fills the rest, and a field nobody states stays empty.
        assert_eq!(r.limits.context_window, 262_144);
        assert_eq!(r.source_of("context_window"), "provider");
        assert_eq!(r.limits.max_output_tokens, 4_096);
        assert_eq!(r.source_of("max_output_tokens"), "override");
        assert_eq!(r.limits.max_input_tokens, 100_000);
        assert_eq!(r.source_of("max_input_tokens"), "override");

        let r = Resolved::resolve(None, Some(provider));
        assert_eq!(r.source_of("context_window"), "provider");
        assert_eq!(r.limits.context_window, 262_144);

        let r = Resolved::resolve(None, None);
        assert!(r.limits.is_empty());
        assert_eq!(r.source_of("context_window"), "unknown");
    }
}
