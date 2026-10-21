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
