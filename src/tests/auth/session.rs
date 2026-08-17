use axum::http::HeaderMap;
use axum::http::header::{COOKIE, HeaderValue};

use super::super::{test_secret, test_state};
use crate::auth::{
    clear_cookie, cookie_value, is_authenticated, now_unix, session_cookie, sign_token,
    validate_token,
};

#[test]
fn sign_and_validate_token_roundtrip() {
    let secret = test_secret();
    let expiry = now_unix() + 3600;
    let token = sign_token(&secret, expiry);
    assert!(validate_token(&secret, &token));
}

#[test]
fn validate_token_rejects_expired() {
    let secret = test_secret();
    let token = sign_token(&secret, 0);
    assert!(!validate_token(&secret, &token));
}

#[test]
fn validate_token_rejects_tampered_signature() {
    let secret = test_secret();
    let expiry = now_unix() + 3600;
    let token = sign_token(&secret, expiry);
    let tampered = format!("{expiry}|deadbeef");
    assert!(!validate_token(&secret, &tampered));
    assert!(validate_token(&secret, &token));
}

#[test]
fn validate_token_rejects_wrong_secret() {
    let secret = test_secret();
    let expiry = now_unix() + 3600;
    let token = sign_token(&secret, expiry);
    assert!(!validate_token(b"wrong-secret", &token));
}

#[test]
fn validate_token_rejects_malformed() {
    let secret = test_secret();
    assert!(!validate_token(&secret, "no-pipe-separator"));
    assert!(!validate_token(&secret, "notanumber|abcdef"));
    assert!(!validate_token(&secret, "|"));
    assert!(!validate_token(&secret, ""));
    assert!(!validate_token(&secret, "123|not-hex!@#"));
}

#[test]
fn cookie_value_finds_named_cookie() {
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, HeaderValue::from_static("hodor=abc123; other=xyz"));
    assert_eq!(cookie_value(&headers, "hodor"), Some("abc123"));
    assert_eq!(cookie_value(&headers, "other"), Some("xyz"));
}

#[test]
fn cookie_value_returns_none_when_missing() {
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, HeaderValue::from_static("other=xyz"));
    assert_eq!(cookie_value(&headers, "hodor"), None);
}

#[test]
fn cookie_value_returns_none_without_cookie_header() {
    let headers = HeaderMap::new();
    assert_eq!(cookie_value(&headers, "hodor"), None);
}

#[test]
fn session_cookie_contains_expected_parts() {
    let state = test_state(false);
    let cookie = session_cookie(&state, "token123");
    assert!(cookie.contains("hodor=token123"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Max-Age=3600"));
    assert!(!cookie.contains("Secure"));
}

#[test]
fn session_cookie_includes_secure_flag() {
    let state = test_state(true);
    let cookie = session_cookie(&state, "token123");
    assert!(cookie.contains("Secure"));
}

#[test]
fn clear_cookie_sets_max_age_zero() {
    let state = test_state(false);
    let cookie = clear_cookie(&state);
    assert!(cookie.contains("hodor="));
    assert!(cookie.contains("Max-Age=0"));
}

#[test]
fn clear_cookie_includes_secure_flag() {
    let state = test_state(true);
    let cookie = clear_cookie(&state);
    assert!(cookie.contains("Secure"));
}

#[test]
fn session_and_clear_cookies_include_configured_domain() {
    let mut state = test_state(true);
    state.cookie_domain = Some(".preview.example.com".to_string());

    assert!(session_cookie(&state, "token123").contains("Domain=.preview.example.com"));
    assert!(clear_cookie(&state).contains("Domain=.preview.example.com"));
}

#[test]
fn is_authenticated_with_valid_cookie() {
    let secret = test_secret();
    let expiry = now_unix() + 3600;
    let token = sign_token(&secret, expiry);
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&format!("hodor={token}")).unwrap(),
    );
    assert!(is_authenticated(&headers, &secret));
}

#[test]
fn is_authenticated_rejects_no_cookie() {
    let secret = test_secret();
    let headers = HeaderMap::new();
    assert!(!is_authenticated(&headers, &secret));
}

#[test]
fn is_authenticated_rejects_expired_cookie() {
    let secret = test_secret();
    let token = sign_token(&secret, 0);
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&format!("hodor={token}")).unwrap(),
    );
    assert!(!is_authenticated(&headers, &secret));
}
