use axum::Router;
use axum::http::HeaderMap;
use axum::http::header::{CONNECTION, HeaderName, HeaderValue, UPGRADE};
use axum::routing::get;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::test_state;
use crate::auth::X_FORWARDED_FOR_HEADER;
use crate::proxy::{
    ForwardedProto, X_FORWARDED_PROTO_HEADER, append_forwarded_headers, build_upstream_uri,
    is_hop_by_hop_header, is_websocket_upgrade, join_paths, proxy_or_login,
    resolve_forwarded_proto,
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

#[tokio::test]
async fn proxy_preserves_host_and_tunnels_websocket_bytes() {
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let headers = read_http_headers(&mut stream).await;
        assert!(headers.contains("host: preview.example.com"));
        assert!(headers.contains("connection: upgrade"));
        assert!(headers.contains("upgrade: websocket"));

        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });

    let mut state = test_state(false);
    state.upstream = format!("http://{upstream_addr}").parse().unwrap();
    state.upstream_authority = upstream_addr.to_string();
    state.preserve_host = true;
    state.bypass_cidrs = vec!["127.0.0.0/8".parse().unwrap()];

    let app = Router::new()
        .route("/_gate/health", get(|| async { "ok" }))
        .fallback(proxy_or_login)
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let exchange = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                b"GET /socket HTTP/1.1\r\nHost: preview.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_http_headers(&mut client).await;
        assert!(response.starts_with("http/1.1 101 switching protocols"));

        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    })
    .await;

    proxy.abort();
    exchange.expect("WebSocket exchange should complete");
    upstream.await.unwrap();
}

async fn read_http_headers(stream: &mut tokio::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).unwrap().to_ascii_lowercase()
}
