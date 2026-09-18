use axum::body::Body;
use axum::http::header::{COOKIE, LOCATION, RETRY_AFTER, SET_COOKIE};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

use super::super::test_state;
use crate::auth::{MAX_LOGIN_BODY_SIZE, RATE_LIMIT_ATTEMPTS, check_login_attempt};
use crate::state::AppState;

struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

async fn spawn_gate(state: AppState) -> (SocketAddr, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            crate::app(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (addr, server)
}

async fn request(
    addr: SocketAddr,
    method: Method,
    path: &str,
    body: impl Into<Body>,
    cookie: Option<&str>,
) -> TestResponse {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"));
    if let Some(cookie) = cookie {
        builder = builder.header(COOKIE, cookie);
    }
    let request = builder.body(body.into()).unwrap();
    let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let response = client.request(request).await.unwrap();
    let (parts, body) = response.into_parts();
    TestResponse {
        status: parts.status,
        headers: parts.headers,
        body: body.collect().await.unwrap().to_bytes(),
    }
}

#[tokio::test]
async fn login_get_redirects_and_health_reports_ok() {
    let (addr, server) = spawn_gate(test_state(false)).await;

    let login = request(addr, Method::GET, "/_gate/login", Body::empty(), None).await;
    assert_eq!(login.status, StatusCode::SEE_OTHER);
    assert_eq!(login.headers.get(LOCATION).unwrap(), "/");

    let health = request(addr, Method::GET, "/_gate/health", Body::empty(), None).await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.body, "ok");
    server.abort();
}

#[tokio::test]
async fn successful_login_issues_a_usable_cookie_and_redirects() {
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });

    let mut state = test_state(false);
    state.upstream = format!("http://{upstream_addr}").parse().unwrap();
    state.upstream_authority = upstream_addr.to_string();
    let (addr, server) = spawn_gate(state).await;

    let login = request(
        addr,
        Method::POST,
        "/_gate/login",
        "password=hunter2&redirect=%2Fprivate%3Ftab%3D1",
        None,
    )
    .await;
    assert_eq!(login.status, StatusCode::SEE_OTHER);
    assert_eq!(login.headers.get(LOCATION).unwrap(), "/private?tab=1");
    let set_cookie = login.headers.get(SET_COOKIE).unwrap().to_str().unwrap();
    assert!(set_cookie.contains("hodor="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    let cookie = set_cookie.split(';').next().unwrap();

    let protected = request(addr, Method::GET, "/private", Body::empty(), Some(cookie)).await;
    assert_eq!(protected.status, StatusCode::NO_CONTENT);
    tokio::time::timeout(Duration::from_secs(1), upstream)
        .await
        .expect("authenticated request should reach upstream")
        .unwrap();
    server.abort();
}

#[tokio::test]
async fn login_sanitizes_external_redirects() {
    let (addr, server) = spawn_gate(test_state(false)).await;
    let response = request(
        addr,
        Method::POST,
        "/_gate/login",
        "password=hunter2&redirect=https%3A%2F%2Fevil.example",
        None,
    )
    .await;

    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(response.headers.get(LOCATION).unwrap(), "/");
    server.abort();
}

#[tokio::test]
async fn wrong_and_missing_passwords_render_the_error_state() {
    let (addr, server) = spawn_gate(test_state(false)).await;

    for body in ["password=wrong", "redirect=%2Fprivate"] {
        let response = request(addr, Method::POST, "/_gate/login", body, None).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert!(String::from_utf8_lossy(&response.body).contains("Wrong password."));
    }
    server.abort();
}

#[tokio::test]
async fn oversized_login_body_is_rejected() {
    let (addr, server) = spawn_gate(test_state(false)).await;
    let response = request(
        addr,
        Method::POST,
        "/_gate/login",
        vec![b'a'; MAX_LOGIN_BODY_SIZE + 1],
        None,
    )
    .await;

    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    server.abort();
}

#[tokio::test]
async fn route_enforces_the_login_rate_limit() {
    let state = test_state(false);
    let client_ip = "127.0.0.1".parse().unwrap();
    for _ in 0..RATE_LIMIT_ATTEMPTS {
        assert!(check_login_attempt(&state, client_ip).is_none());
    }
    let (addr, server) = spawn_gate(state).await;
    let response = request(addr, Method::POST, "/_gate/login", "password=hunter2", None).await;

    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers.contains_key(RETRY_AFTER));
    server.abort();
}

#[tokio::test]
async fn logout_clears_the_session_cookie() {
    let (addr, server) = spawn_gate(test_state(true)).await;
    let response = request(addr, Method::GET, "/_gate/logout", Body::empty(), None).await;

    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(response.headers.get(LOCATION).unwrap(), "/");
    let cookie = response.headers.get(SET_COOKIE).unwrap().to_str().unwrap();
    assert!(cookie.contains("hodor="));
    assert!(cookie.contains("Max-Age=0"));
    assert!(cookie.contains("Secure"));
    server.abort();
}

#[tokio::test]
async fn unauthenticated_request_renders_login_without_contacting_upstream() {
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let mut state = test_state(false);
    state.upstream = format!("http://{upstream_addr}").parse().unwrap();
    state.upstream_authority = upstream_addr.to_string();
    let (addr, server) = spawn_gate(state).await;

    let response = request(addr, Method::GET, "/private", Body::empty(), None).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(String::from_utf8_lossy(&response.body).contains("action=\"/_gate/login\""));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream_listener.accept())
            .await
            .is_err(),
        "unauthenticated request must not reach upstream"
    );
    server.abort();
}
