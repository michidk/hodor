use axum::http::HeaderMap;
use axum::http::header::{CONNECTION, HeaderName, HeaderValue, UPGRADE};
use std::net::IpAddr;

use super::test_state;
use crate::auth::X_FORWARDED_FOR_HEADER;
use crate::proxy::{
    ForwardedProto, X_FORWARDED_PROTO_HEADER, append_forwarded_headers, build_upstream_uri,
    is_hop_by_hop_header, is_websocket_upgrade, join_paths, resolve_forwarded_proto,
};

#[test]
fn join_paths_empty_base() {
    assert_eq!(join_paths("", "/foo"), "/foo");
}

#[test]
fn join_paths_root_base() {
    assert_eq!(join_paths("/", "/foo"), "/foo");
}

#[test]
fn join_paths_base_with_root_path() {
    assert_eq!(join_paths("/api", "/"), "/api");
}

#[test]
fn join_paths_base_with_subpath() {
    assert_eq!(join_paths("/api", "/users"), "/api/users");
    assert_eq!(join_paths("/api/", "/users"), "/api/users");
    assert_eq!(join_paths("/api", "users"), "/api/users");
}

#[test]
fn is_hop_by_hop_header_detects_correctly() {
    let headers = HeaderMap::new();
    assert!(is_hop_by_hop_header(
        &headers,
        &HeaderName::from_static("connection")
    ));
    assert!(is_hop_by_hop_header(
        &headers,
        &HeaderName::from_static("transfer-encoding")
    ));
    assert!(is_hop_by_hop_header(
        &headers,
        &HeaderName::from_static("upgrade")
    ));
    assert!(!is_hop_by_hop_header(
        &headers,
        &HeaderName::from_static("content-type")
    ));
    assert!(!is_hop_by_hop_header(
        &headers,
        &HeaderName::from_static("authorization")
    ));
}

#[test]
fn is_hop_by_hop_header_detects_connection_nominated_headers() {
    let mut headers = HeaderMap::new();
    headers.append(
        CONNECTION,
        HeaderValue::from_static("keep-alive, X-Custom-Hop"),
    );
    headers.append(CONNECTION, HeaderValue::from_static("X-Second-Hop"));

    assert!(is_hop_by_hop_header(
        &headers,
        &HeaderName::from_static("x-custom-hop")
    ));
    assert!(is_hop_by_hop_header(
        &headers,
        &HeaderName::from_static("x-second-hop")
    ));
    assert!(!is_hop_by_hop_header(
        &headers,
        &HeaderName::from_static("content-type")
    ));
}

#[test]
fn is_websocket_upgrade_detects_correctly() {
    let mut headers = HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    assert!(is_websocket_upgrade(&headers));
}

#[test]
fn is_websocket_upgrade_rejects_missing_upgrade_header() {
    let mut headers = HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    assert!(!is_websocket_upgrade(&headers));
}

#[test]
fn is_websocket_upgrade_rejects_missing_connection_header() {
    let mut headers = HeaderMap::new();
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    assert!(!is_websocket_upgrade(&headers));
}

#[test]
fn is_websocket_upgrade_rejects_non_websocket() {
    let mut headers = HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static("h2c"));
    assert!(!is_websocket_upgrade(&headers));
}

#[test]
fn build_upstream_uri_basic() {
    let state = test_state(false);
    let uri = build_upstream_uri(&state, "/foo", None);
    assert_eq!(uri.to_string(), "http://localhost:3000/foo");
}

#[test]
fn build_upstream_uri_with_query() {
    let state = test_state(false);
    let uri = build_upstream_uri(&state, "/foo", Some("bar=1"));
    assert_eq!(uri.to_string(), "http://localhost:3000/foo?bar=1");
}

#[test]
fn append_forwarded_headers_sets_headers() {
    let mut headers = HeaderMap::new();
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    append_forwarded_headers(&mut headers, ip, ForwardedProto::Http);
    assert_eq!(
        headers
            .get(X_FORWARDED_FOR_HEADER)
            .unwrap()
            .to_str()
            .unwrap(),
        "192.168.1.1"
    );
    assert_eq!(
        headers
            .get(X_FORWARDED_PROTO_HEADER)
            .unwrap()
            .to_str()
            .unwrap(),
        "http"
    );
}

#[test]
fn append_forwarded_headers_appends_to_existing() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(X_FORWARDED_FOR_HEADER),
        HeaderValue::from_static("10.0.0.1"),
    );
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    append_forwarded_headers(&mut headers, ip, ForwardedProto::Http);
    assert_eq!(
        headers
            .get(X_FORWARDED_FOR_HEADER)
            .unwrap()
            .to_str()
            .unwrap(),
        "10.0.0.1, 192.168.1.1"
    );
}

#[test]
fn append_forwarded_headers_preserves_proto_from_trusted_proxy() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(X_FORWARDED_PROTO_HEADER),
        HeaderValue::from_static("https"),
    );
    let ip: IpAddr = "192.168.1.1".parse().unwrap();

    append_forwarded_headers(&mut headers, ip, ForwardedProto::Https);

    assert_eq!(headers.get(X_FORWARDED_PROTO_HEADER).unwrap(), "https");
}

#[test]
fn append_forwarded_headers_rejects_proto_from_untrusted_client() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(X_FORWARDED_PROTO_HEADER),
        HeaderValue::from_static("https"),
    );
    let ip: IpAddr = "192.168.1.1".parse().unwrap();

    append_forwarded_headers(&mut headers, ip, ForwardedProto::Http);

    assert_eq!(headers.get(X_FORWARDED_PROTO_HEADER).unwrap(), "http");
}

#[test]
fn resolve_forwarded_proto_reads_connection_nominated_source_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONNECTION,
        HeaderValue::from_static(X_FORWARDED_PROTO_HEADER),
    );
    headers.insert(
        HeaderName::from_static(X_FORWARDED_PROTO_HEADER),
        HeaderValue::from_static("https"),
    );

    assert_eq!(
        resolve_forwarded_proto(&headers, true),
        ForwardedProto::Https
    );
}

#[test]
fn resolve_forwarded_proto_uses_rightmost_trusted_value() {
    let mut headers = HeaderMap::new();
    headers.append(
        HeaderName::from_static(X_FORWARDED_PROTO_HEADER),
        HeaderValue::from_static("http, https"),
    );

    assert_eq!(
        resolve_forwarded_proto(&headers, true),
        ForwardedProto::Https
    );
}

#[test]
fn resolve_forwarded_proto_uses_rightmost_header_instance() {
    let mut headers = HeaderMap::new();
    headers.append(
        HeaderName::from_static(X_FORWARDED_PROTO_HEADER),
        HeaderValue::from_static("http"),
    );
    headers.append(
        HeaderName::from_static(X_FORWARDED_PROTO_HEADER),
        HeaderValue::from_static("https"),
    );

    assert_eq!(
        resolve_forwarded_proto(&headers, true),
        ForwardedProto::Https
    );
}

#[test]
fn resolve_forwarded_proto_rejects_unrecognized_rightmost_value() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(X_FORWARDED_PROTO_HEADER),
        HeaderValue::from_static("https, ftp"),
    );

    assert_eq!(
        resolve_forwarded_proto(&headers, true),
        ForwardedProto::Http
    );
}

#[test]
fn resolve_forwarded_proto_ignores_untrusted_value() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(X_FORWARDED_PROTO_HEADER),
        HeaderValue::from_static("https"),
    );

    assert_eq!(
        resolve_forwarded_proto(&headers, false),
        ForwardedProto::Http
    );
}
