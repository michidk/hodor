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
    ])
    .expect("typed env overrides should still parse after string-preserving password fix");

    assert_eq!(config.password, "123");
    assert_eq!(config.session_ttl, 42);
    assert!(config.disable_default_css);
    assert!(config.secure_cookie);
    assert!(config.trust_proxy);
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
