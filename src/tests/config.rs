use std::net::IpAddr;

use crate::config::{load_config_with_env, parse_listen_addr};

#[test]
fn parse_listen_addr_port_only() {
    let addr = parse_listen_addr(":9090");
    assert_eq!(addr.port(), 9090);
    assert_eq!(addr.ip(), IpAddr::from([0, 0, 0, 0]));
}

#[test]
fn parse_listen_addr_full() {
    let addr = parse_listen_addr("127.0.0.1:8080");
    assert_eq!(addr.port(), 8080);
    assert_eq!(addr.ip(), IpAddr::from([127, 0, 0, 1]));
}

#[test]
fn load_config_with_env_preserves_numeric_password_text() {
    let config = load_config_with_env([("PASSWORD", "123"), ("UPSTREAM", "http://localhost:3000")])
        .expect("numeric PASSWORD from env should deserialize as a string");

    assert_eq!(config.password, "123");
}

#[test]
fn load_config_with_env_preserves_decimal_password_text() {
    let config = load_config_with_env([("PASSWORD", "1.0"), ("UPSTREAM", "http://localhost:3000")])
        .expect("decimal PASSWORD from env should preserve its text");

    assert_eq!(config.password, "1.0");
}

#[test]
fn load_config_with_env_still_parses_typed_overrides() {
    let config = load_config_with_env([
        ("PASSWORD", "123"),
        ("UPSTREAM", "http://localhost:3000"),
        ("SESSION_TTL", "42"),
        ("DISABLE_DEFAULT_CSS", "true"),
        ("SECURE_COOKIE", "true"),
        ("TRUST_PROXY", "true"),
        ("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 192.168.0.0/16"),
        ("BYPASS_CIDRS", "100.64.0.0/10, fd7a:115c:a1e0::/48"),
        ("PRESERVE_HOST", "true"),
        ("COOKIE_DOMAIN", ".preview.example.com"),
    ])
    .expect("typed env overrides should still parse after string-preserving password fix");

    assert_eq!(config.password, "123");
    assert_eq!(config.session_ttl, 42);
    assert!(config.disable_default_css);
    assert!(config.secure_cookie);
    assert!(config.trust_proxy);
    assert_eq!(config.trusted_proxy_cidrs, ["10.0.0.0/8", "192.168.0.0/16"]);
    assert_eq!(
        config.bypass_cidrs,
        ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]
    );
    assert!(config.preserve_host);
    assert_eq!(
        config.cookie_domain.as_deref(),
        Some(".preview.example.com")
    );
}

#[test]
fn load_config_with_env_rejects_missing_password() {
    let error = load_config_with_env([("UPSTREAM", "http://localhost:3000")])
        .expect_err("missing PASSWORD should be rejected");

    assert_eq!(error, "PASSWORD is required and cannot be empty");
}

#[test]
fn load_config_with_env_rejects_missing_upstream() {
    let error = load_config_with_env([("PASSWORD", "hunter2")])
        .expect_err("missing UPSTREAM should be rejected");

    assert_eq!(error, "UPSTREAM is required and cannot be empty");
}

#[test]
fn load_config_with_env_rejects_empty_secret() {
    let error = load_config_with_env([
        ("PASSWORD", "hunter2"),
        ("UPSTREAM", "http://localhost:3000"),
        ("SECRET", ""),
    ])
    .expect_err("empty SECRET should be rejected");

    assert_eq!(error, "SECRET cannot be empty when configured");
}

#[test]
fn load_config_with_env_rejects_zero_session_ttl() {
    let error = load_config_with_env([
        ("PASSWORD", "hunter2"),
        ("UPSTREAM", "http://localhost:3000"),
        ("SESSION_TTL", "0"),
    ])
    .expect_err("zero SESSION_TTL should be rejected");

    assert_eq!(error, "SESSION_TTL must be greater than zero");
}

#[test]
fn load_config_with_env_rejects_invalid_cidr() {
    let error = load_config_with_env([
        ("PASSWORD", "hunter2"),
        ("UPSTREAM", "http://localhost:3000"),
        ("BYPASS_CIDRS", "not-a-network"),
    ])
    .expect_err("invalid bypass CIDR should be rejected");

    assert!(error.starts_with("BYPASS_CIDRS contains invalid CIDR"));
}

#[test]
fn load_config_with_env_requires_trust_proxy_for_proxy_cidrs() {
    let error = load_config_with_env([
        ("PASSWORD", "hunter2"),
        ("UPSTREAM", "http://localhost:3000"),
        ("TRUSTED_PROXY_CIDRS", "10.0.0.0/8"),
    ])
    .expect_err("trusted proxy CIDRs without proxy trust should be rejected");

    assert_eq!(
        error,
        "TRUST_PROXY must be true when TRUSTED_PROXY_CIDRS is configured"
    );
}

#[test]
fn load_config_with_env_rejects_invalid_cookie_domain() {
    let error = load_config_with_env([
        ("PASSWORD", "hunter2"),
        ("UPSTREAM", "http://localhost:3000"),
        ("COOKIE_DOMAIN", "preview example.com"),
    ])
    .expect_err("invalid cookie domain should be rejected");

    assert_eq!(error, "COOKIE_DOMAIN must be a valid DNS domain");
}

#[test]
fn load_config_with_env_parses_bypass_paths() {
    let config = load_config_with_env([
        ("PASSWORD", "hunter2"),
        ("UPSTREAM", "http://localhost:3000"),
        ("BYPASS_PATHS", "/api/mcp, /oauth/token, /static/*"),
    ])
    .expect("valid bypass paths should parse");

    assert_eq!(
        config.bypass_paths,
        ["/api/mcp", "/oauth/token", "/static/*"]
    );
}

#[test]
fn load_config_with_env_defaults_bypass_paths_to_empty() {
    let config = load_config_with_env([
        ("PASSWORD", "hunter2"),
        ("UPSTREAM", "http://localhost:3000"),
    ])
    .expect("config without bypass paths should parse");

    assert!(config.bypass_paths.is_empty());
}

#[test]
fn load_config_with_env_rejects_relative_bypass_path() {
    let error = load_config_with_env([
        ("PASSWORD", "hunter2"),
        ("UPSTREAM", "http://localhost:3000"),
        ("BYPASS_PATHS", "api/mcp"),
    ])
    .expect_err("bypass path without a leading slash should be rejected");

    assert!(error.starts_with("BYPASS_PATHS"), "{error}");
}

#[test]
fn load_config_with_env_rejects_interior_wildcard() {
    let error = load_config_with_env([
        ("PASSWORD", "hunter2"),
        ("UPSTREAM", "http://localhost:3000"),
        ("BYPASS_PATHS", "/a/*/b"),
    ])
    .expect_err("interior wildcard should be rejected");

    assert!(error.starts_with("BYPASS_PATHS"), "{error}");
}
