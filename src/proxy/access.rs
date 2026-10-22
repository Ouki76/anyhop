/// Client key allowlist matching.
/// An entry with '/' only matches the full "provider/model" id (no bypass through
/// another provider with the same upstream name). A bare entry matches the
/// upstream model name or the requested name.
pub fn model_allowed(allowed: &[String], requested: &str, canonical: &str, upstream: &str) -> bool {
    allowed.iter().any(|a| {
        if a.contains('/') {
            a == canonical || a == requested
        } else {
            a == upstream || a == requested
        }
    })
}

/// Allowlist matching for combos: "combo/flash" and "flash" are equivalent.
pub fn combo_allowed(allowed: &[String], requested: &str) -> bool {
    let bare = requested.strip_prefix("combo/").unwrap_or(requested);
    allowed
        .iter()
        .any(|a| a.strip_prefix("combo/").unwrap_or(a) == bare)
}

pub fn model_disabled(
    disabled: &std::collections::HashSet<String>,
    requested: &str,
    canonical: &str,
    upstream: &str,
) -> bool {
    disabled.contains(requested) || disabled.contains(canonical) || disabled.contains(upstream)
}

/// These three functions are the whole authorization boundary for model access:
/// a client key's allowlist, and the admin's disabled set. They are pure, so the
/// rules can be pinned exactly — including the one that is easy to get wrong and
/// is a real escalation: a *qualified* allowlist entry must not be satisfied by
/// another provider that happens to serve a model with the same upstream name.
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn list(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    // ----- client-key allowlists -----

    #[test]
    fn a_bare_allowlist_entry_matches_the_upstream_or_the_requested_name() {
        let allowed = list(&["gpt-4"]);
        // Routed as "mock/gpt-4"; the upstream name is "gpt-4".
        assert!(model_allowed(&allowed, "mock/gpt-4", "mock/gpt-4", "gpt-4"));
        // A bare request name also matches.
        assert!(model_allowed(&allowed, "gpt-4", "mock/gpt-4", "gpt-4"));
        assert!(!model_allowed(
            &allowed,
            "mock/gpt-5",
            "mock/gpt-5",
            "gpt-5"
        ));
        // A bare entry is not a wildcard.
        assert!(!model_allowed(
            &list(&[]),
            "mock/gpt-4",
            "mock/gpt-4",
            "gpt-4"
        ));
    }

    /// `"openai/gpt-4"` must mean *that* provider's gpt-4 only. If the qualified
    /// form were compared against the bare upstream name, a key limited to
    /// openai/gpt-4 could spend tokens on any other provider serving "gpt-4".
    #[test]
    fn a_qualified_allowlist_entry_cannot_be_bypassed_through_another_provider() {
        let allowed = list(&["openai/gpt-4"]);
        assert!(model_allowed(
            &allowed,
            "openai/gpt-4",
            "openai/gpt-4",
            "gpt-4"
        ));
        // Same upstream model, different provider: NOT allowed.
        assert!(!model_allowed(
            &allowed,
            "azure/gpt-4",
            "azure/gpt-4",
            "gpt-4"
        ));
        // The bare name is not enough to satisfy a qualified entry.
        assert!(!model_allowed(&allowed, "gpt-4", "azure/gpt-4", "gpt-4"));
        // A sibling model on the right provider is still not covered.
        assert!(!model_allowed(
            &allowed,
            "openai/gpt-4o",
            "openai/gpt-4o",
            "gpt-4o"
        ));
    }

    /// `combo/flash` and `flash` name the same combo, because the request path
    /// accepts both spellings. Anything else is a different model.
    #[test]
    fn combo_allowlists_treat_the_prefix_as_optional() {
        assert!(combo_allowed(&list(&["combo/flash"]), "flash"));
        assert!(combo_allowed(&list(&["combo/flash"]), "combo/flash"));
        assert!(combo_allowed(&list(&["flash"]), "combo/flash"));
        assert!(!combo_allowed(&list(&["flash"]), "flash-lite"));
        assert!(!combo_allowed(&list(&["combo/flash"]), "combo/flash-lite"));
        assert!(!combo_allowed(&list(&["other"]), "flash"));
    }

    // ----- the admin's disabled set -----

    /// Disabling is deliberately broader than allowing: any spelling the request
    /// path may use has to disable the model, or a disabled model stays reachable
    /// through the spelling nobody thought of.
    #[test]
    fn a_disabled_model_is_blocked_under_every_spelling() {
        let bare: HashSet<String> = ["gpt-4".to_string()].into_iter().collect();
        assert!(model_disabled(&bare, "mock/gpt-4", "mock/gpt-4", "gpt-4"));
        assert!(model_disabled(&bare, "gpt-4", "mock/gpt-4", "gpt-4"));
        // A different model is not affected, even on the same provider.
        assert!(!model_disabled(&bare, "mock/gpt-5", "mock/gpt-5", "gpt-5"));

        let qualified: HashSet<String> = ["mock/gpt-4".to_string()].into_iter().collect();
        assert!(model_disabled(
            &qualified,
            "mock/gpt-4",
            "mock/gpt-4",
            "gpt-4"
        ));
        // Other providers' identically named model is a different model id.
        assert!(!model_disabled(
            &qualified,
            "other/gpt-4",
            "other/gpt-4",
            "gpt-4"
        ));

        // An empty set disables nothing.
        assert!(!model_disabled(
            &HashSet::new(),
            "mock/gpt-4",
            "mock/gpt-4",
            "gpt-4"
        ));
    }
}
