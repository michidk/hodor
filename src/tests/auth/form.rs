use axum::body::Body;
use axum::http::StatusCode;
use hyper::body::Bytes;

use crate::auth::{
    MAX_LOGIN_BODY_SIZE, collect_body, decode_form_component, form_value, parse_form_body,
    sanitize_redirect,
};

#[test]
fn sanitize_redirect_allows_relative_paths() {
    assert_eq!(sanitize_redirect("/"), "/");
    assert_eq!(sanitize_redirect("/dashboard"), "/dashboard");
    assert_eq!(sanitize_redirect("/a/b?q=1"), "/a/b?q=1");
}

#[test]
fn sanitize_redirect_blocks_open_redirects() {
    assert_eq!(sanitize_redirect("//evil.com"), "/");
    assert_eq!(sanitize_redirect("https://evil.com"), "/");
    assert_eq!(sanitize_redirect("javascript:alert(1)"), "/");
    assert_eq!(sanitize_redirect(""), "/");
    assert_eq!(sanitize_redirect("relative"), "/");
}

#[test]
fn parse_form_body_basic() {
    let body = Bytes::from("password=hunter2&redirect=%2Fdashboard");
    let form = parse_form_body(&body);
    assert_eq!(form_value(&form, "password"), Some("hunter2"));
    assert_eq!(form_value(&form, "redirect"), Some("/dashboard"));
}

#[test]
fn parse_form_body_empty() {
    let body = Bytes::from("");
    let form = parse_form_body(&body);
    assert!(form.is_empty());
}

#[tokio::test]
async fn collect_body_rejects_oversized_login_form() {
    let body = Body::from(vec![b'x'; MAX_LOGIN_BODY_SIZE + 1]);

    let response = collect_body(body)
        .await
        .expect_err("oversized login form should be rejected");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn collect_body_accepts_login_form_at_limit() {
    let body = Body::from(vec![b'x'; MAX_LOGIN_BODY_SIZE]);

    let collected = collect_body(body)
        .await
        .expect("login form at size limit should be accepted");

    assert_eq!(collected.len(), MAX_LOGIN_BODY_SIZE);
}

#[test]
fn form_value_missing_key() {
    let body = Bytes::from("a=1");
    let form = parse_form_body(&body);
    assert_eq!(form_value(&form, "b"), None);
}

#[test]
fn decode_form_component_plain() {
    assert_eq!(decode_form_component("hello"), "hello");
}

#[test]
fn decode_form_component_plus_to_space() {
    assert_eq!(decode_form_component("hello+world"), "hello world");
}

#[test]
fn decode_form_component_percent_encoding() {
    assert_eq!(decode_form_component("%2Fdashboard"), "/dashboard");
    assert_eq!(decode_form_component("100%25"), "100%");
}

#[test]
fn decode_form_component_mixed() {
    assert_eq!(decode_form_component("a+b%3Dc"), "a b=c");
}

#[test]
fn decode_form_component_incomplete_percent() {
    assert_eq!(decode_form_component("100%"), "100%");
    assert_eq!(decode_form_component("100%2"), "100%2");
}
