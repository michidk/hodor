use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{CONNECTION, HOST, HeaderName, HeaderValue, UPGRADE};
use axum::http::{HeaderMap, Request, Response, Uri};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use tracing::{debug, info, warn};

use crate::auth::{
    X_FORWARDED_FOR_HEADER, is_authenticated, is_bypass_ip, is_bypass_path, is_trusted_proxy,
    resolve_client_ip,
};
use crate::state::AppState;
use crate::templates::{bad_gateway, login_page_response};

pub(crate) const X_FORWARDED_PROTO_HEADER: &str = "x-forwarded-proto";
pub(crate) const X_HODOR_AUTH_HEADER: &str = "x-hodor-auth";
const HODOR_HEADER_PREFIX: &str = "x-hodor-";

// How the request cleared the gate, reported to the upstream so it does not have
// to reimplement hodor's session format to answer the same question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthMethod {
    Password,
    Bypass,
    Public,
}

impl AuthMethod {
    const fn as_header_value(self) -> HeaderValue {
        match self {
            Self::Password => HeaderValue::from_static("password"),
            Self::Bypass => HeaderValue::from_static("bypass"),
            Self::Public => HeaderValue::from_static("public"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForwardedProto {
    Http,
    Https,
}

impl ForwardedProto {
    const fn as_header_value(self) -> HeaderValue {
        match self {
            Self::Http => HeaderValue::from_static("http"),
            Self::Https => HeaderValue::from_static("https"),
        }
    }
}

pub(crate) async fn proxy_or_login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let trusted_proxy = is_trusted_proxy(addr.ip(), state.trust_proxy, &state.trusted_proxy_cidrs);
    let client_ip = resolve_client_ip(
        request.headers(),
        addr.ip(),
        state.trust_proxy,
        &state.trusted_proxy_cidrs,
    );
    let Some(auth_method) = resolve_auth_method(&state, client_ip, &request) else {
        return login_page_response(&state, false);
    };

    proxy_request(state, addr, trusted_proxy, auth_method, request).await
}

fn resolve_auth_method(
    state: &AppState,
    client_ip: IpAddr,
    request: &Request<Body>,
) -> Option<AuthMethod> {
    if is_bypass_path(request.uri().path(), &state.bypass_paths) {
        return Some(AuthMethod::Public);
    }
    if is_authenticated(request.headers(), &state.secret) {
        return Some(AuthMethod::Password);
    }
    if is_bypass_ip(client_ip, &state.bypass_cidrs) {
        return Some(AuthMethod::Bypass);
    }
    None
}

async fn proxy_request(
    state: AppState,
    addr: SocketAddr,
    trusted_proxy: bool,
    auth_method: AuthMethod,
    mut request: Request<Body>,
) -> Response<Body> {
    let started_at = Instant::now();
    let request_method = request.method().clone();
    let request_path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    let websocket = is_websocket_upgrade(request.headers());
    let downstream_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();

    let path = join_paths(&state.upstream_base_path, parts.uri.path());
    let uri = build_upstream_uri(&state, &path, parts.uri.query());
    let forwarded_proto = resolve_forwarded_proto(&parts.headers, trusted_proxy);

    let mut proxied = match Request::builder().method(parts.method).uri(uri).body(body) {
        Ok(request) => request,
        Err(_) => return bad_gateway(&state),
    };

    *proxied.version_mut() = parts.version;

    copy_end_to_end_headers(&parts.headers, proxied.headers_mut(), !state.preserve_host);
    if websocket {
        copy_upgrade_headers(&parts.headers, proxied.headers_mut());
    }
    overwrite_auth_headers(proxied.headers_mut(), auth_method);

    if !state.preserve_host {
        match HeaderValue::from_str(&state.upstream_authority) {
            Ok(host) => {
                proxied.headers_mut().insert(HOST, host);
            }
            Err(_) => return bad_gateway(&state),
        }
    }

    append_forwarded_headers(proxied.headers_mut(), addr.ip(), forwarded_proto);

    let mut response = match state.client.request(proxied).await {
        Ok(response) => response,
        Err(_) => return bad_gateway(&state),
    };

    let status = response.status();
    if websocket && status == http::StatusCode::SWITCHING_PROTOCOLS {
        if let Some(downstream_upgrade) = downstream_upgrade {
            let upstream_upgrade = hyper::upgrade::on(&mut response);
            tokio::spawn(tunnel_websocket(downstream_upgrade, upstream_upgrade));
        }
    }
    match build_downstream_response(response, websocket) {
        Ok(response) => {
            info!(
                method = %request_method,
                path = %request_path,
                status = status.as_u16(),
                duration_ms = started_at.elapsed().as_millis(),
                "proxied request"
            );
            response
        }
        Err(_) => bad_gateway(&state),
    }
}

fn copy_end_to_end_headers(source: &HeaderMap, target: &mut HeaderMap, skip_host: bool) {
    for (name, value) in source {
        if (!skip_host || name != HOST) && !is_hop_by_hop_header(source, name) {
            target.append(name, value.clone());
        }
    }
}

fn build_downstream_response(
    response: hyper::Response<hyper::body::Incoming>,
    websocket: bool,
) -> Result<Response<Body>, http::Error> {
    let (parts, body) = response.into_parts();
    let mut builder = Response::builder().status(parts.status);
    if let Some(headers) = builder.headers_mut() {
        copy_end_to_end_headers(&parts.headers, headers, false);
        if websocket {
            copy_upgrade_headers(&parts.headers, headers);
        }
    }
    builder.body(Body::new(body))
}

// Drops any client-supplied X-Hodor-* header before setting hodor's own, so a
// request to a public path cannot forge the authentication method upstream.
fn overwrite_auth_headers(headers: &mut HeaderMap, auth_method: AuthMethod) {
    let forged: Vec<HeaderName> = headers
        .keys()
        .filter(|name| name.as_str().starts_with(HODOR_HEADER_PREFIX))
        .cloned()
        .collect();
    for name in forged {
        headers.remove(&name);
    }
    headers.insert(
        HeaderName::from_static(X_HODOR_AUTH_HEADER),
        auth_method.as_header_value(),
    );
}

fn copy_upgrade_headers(source: &HeaderMap, target: &mut HeaderMap) {
    for name in [CONNECTION, UPGRADE] {
        for value in source.get_all(&name) {
            target.append(name.clone(), value.clone());
        }
    }
}

async fn tunnel_websocket(downstream: OnUpgrade, upstream: OnUpgrade) {
    let (downstream, upstream) = match tokio::try_join!(downstream, upstream) {
        Ok(upgrades) => upgrades,
        Err(error) => {
            debug!(%error, "websocket upgrade failed");
            return;
        }
    };
    let mut downstream = TokioIo::new(downstream);
    let mut upstream = TokioIo::new(upstream);
    if let Err(error) = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await {
        warn!(%error, "websocket tunnel closed with an error");
    }
}

pub(crate) fn resolve_forwarded_proto(headers: &HeaderMap, trust_proxy: bool) -> ForwardedProto {
    if !trust_proxy {
        return ForwardedProto::Http;
    }

    let mut rightmost = None;
    for value in headers.get_all(X_FORWARDED_PROTO_HEADER) {
        let Ok(value) = value.to_str() else {
            return ForwardedProto::Http;
        };
        for token in value.split(',') {
            rightmost = Some(token.trim());
        }
    }

    match rightmost {
        Some(value) if value.eq_ignore_ascii_case("https") => ForwardedProto::Https,
        Some(value) if value.eq_ignore_ascii_case("http") => ForwardedProto::Http,
        _ => ForwardedProto::Http,
    }
}

pub(crate) fn append_forwarded_headers(
    headers: &mut HeaderMap,
    client_ip: IpAddr,
    forwarded_proto: ForwardedProto,
) {
    let forwarded_for = match headers
        .get(HeaderName::from_static(X_FORWARDED_FOR_HEADER))
        .and_then(|value| value.to_str().ok())
    {
        Some(existing) if !existing.trim().is_empty() => format!("{existing}, {client_ip}"),
        _ => client_ip.to_string(),
    };

    if let Ok(value) = HeaderValue::from_str(&forwarded_for) {
        headers.insert(HeaderName::from_static(X_FORWARDED_FOR_HEADER), value);
    }
    headers.insert(
        HeaderName::from_static(X_FORWARDED_PROTO_HEADER),
        forwarded_proto.as_header_value(),
    );
}

pub(crate) fn build_upstream_uri(state: &AppState, path: &str, query: Option<&str>) -> Uri {
    let mut uri = format!(
        "{}://{}{}",
        state.upstream_scheme, state.upstream_authority, path
    );
    if let Some(query) = query {
        uri.push('?');
        uri.push_str(query);
    }
    uri.parse().unwrap_or_else(|_| state.upstream.clone())
}

pub(crate) fn join_paths(base: &str, path: &str) -> String {
    if base.is_empty() || base == "/" {
        return path.to_string();
    }

    if path == "/" {
        return base.to_string();
    }

    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

pub(crate) fn is_hop_by_hop_header(headers: &HeaderMap, name: &HeaderName) -> bool {
    if matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) {
        return true;
    }

    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(name.as_str()))
}

pub(crate) fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let has_upgrade_connection = headers
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    let is_websocket = headers
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    has_upgrade_connection && is_websocket
}
