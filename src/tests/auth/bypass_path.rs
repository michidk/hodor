use crate::auth::{BypassPath, is_bypass_path};

fn paths(patterns: &[&str]) -> Vec<BypassPath> {
    patterns
        .iter()
        .map(|pattern| BypassPath::parse(pattern).expect("valid pattern"))
        .collect()
}

#[test]
fn exact_pattern_matches_only_itself() {
    let configured = paths(&["/api/mcp"]);
    assert!(is_bypass_path("/api/mcp", &configured));
    assert!(!is_bypass_path("/api/mcp/", &configured));
    assert!(!is_bypass_path("/api/mcp/tools", &configured));
    assert!(!is_bypass_path("/api", &configured));
}

#[test]
fn exact_pattern_does_not_match_sibling_with_shared_prefix() {
    let configured = paths(&["/api"]);
    assert!(!is_bypass_path("/api-secret", &configured));
    assert!(!is_bypass_path("/apiary", &configured));
}

#[test]
fn wildcard_pattern_matches_subtree_but_not_the_bare_prefix() {
    let configured = paths(&["/static/*"]);
    assert!(is_bypass_path("/static/app.css", &configured));
    assert!(is_bypass_path("/static/nested/deep.js", &configured));
    assert!(is_bypass_path("/static/", &configured));
    assert!(!is_bypass_path("/static", &configured));
    assert!(!is_bypass_path("/static-private/app.css", &configured));
}

#[test]
fn root_wildcard_matches_everything() {
    let configured = paths(&["/*"]);
    assert!(is_bypass_path("/", &configured));
    assert!(is_bypass_path("/anything/at/all", &configured));
}

#[test]
fn empty_configuration_never_matches() {
    assert!(!is_bypass_path("/api/mcp", &[]));
}

#[test]
fn traversal_fails_closed_even_when_the_prefix_matches() {
    let configured = paths(&["/static/*", "/api/mcp"]);
    assert!(!is_bypass_path("/static/../secret", &configured));
    assert!(!is_bypass_path("/static/./app.css", &configured));
    assert!(!is_bypass_path("/static//app.css", &configured));
    assert!(!is_bypass_path("/api/mcp/../../secret", &configured));
}

#[test]
fn encoded_separators_fail_closed() {
    let configured = paths(&["/static/*"]);
    assert!(!is_bypass_path("/static/%2e%2e/secret", &configured));
    assert!(!is_bypass_path("/static/%2E%2E/secret", &configured));
    assert!(!is_bypass_path("/static/a%2fb", &configured));
    assert!(!is_bypass_path("/static/%252e%252e/secret", &configured));
}

#[test]
fn unrelated_encoding_still_matches() {
    let configured = paths(&["/static/*"]);
    assert!(is_bypass_path("/static/my%20file.css", &configured));
}

#[test]
fn parse_requires_a_leading_slash() {
    assert!(BypassPath::parse("api/mcp").is_err());
    assert!(BypassPath::parse("").is_err());
}

#[test]
fn parse_rejects_wildcards_outside_a_trailing_segment() {
    assert!(BypassPath::parse("/a*b").is_err());
    assert!(BypassPath::parse("/*/b").is_err());
    assert!(BypassPath::parse("/a/*/b").is_err());
    assert!(BypassPath::parse("/api/*x").is_err());
}

#[test]
fn parse_accepts_exact_and_wildcard_forms() {
    assert_eq!(
        BypassPath::parse("/api/mcp"),
        Ok(BypassPath::Exact("/api/mcp".to_string()))
    );
    assert_eq!(
        BypassPath::parse("/static/*"),
        Ok(BypassPath::Prefix("/static/".to_string()))
    );
}
