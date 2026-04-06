use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{
    CONNECTION, COOKIE, HOST, HeaderMap, HeaderName, HeaderValue, SET_COOKIE, UPGRADE,
};
use axum::http::{Request, Response, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::get;
use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use minijinja::{Environment, context};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

type HmacSha256 = Hmac<Sha256>;

const COOKIE_NAME: &str = "hodor";
const BUILTIN_TEMPLATE: &str = include_str!("template.html");
const RATE_LIMIT_ATTEMPTS: usize = 5;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const TEMPLATE_NAME: &str = "login.html";
const X_FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
const X_FORWARDED_PROTO_HEADER: &str = "x-forwarded-proto";

#[derive(Clone)]
struct AppState {
    password: Vec<u8>,
    title: String,
    template_source: String,
    secret: Vec<u8>,
    upstream: Uri,
    upstream_scheme: String,
    upstream_authority: String,
    upstream_base_path: String,
    session_ttl: Duration,
    secure_cookie: bool,
    rate_limiter: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    client: Client<HttpConnector, Body>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Config {
    password: String,
    upstream: String,
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default = "default_title")]
    title: String,
    #[serde(default)]
    template: Option<String>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default = "default_session_ttl")]
    session_ttl: u64,
    #[serde(default)]
    secure_cookie: bool,
    #[serde(default = "default_log_format")]
    log_format: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            password: String::new(),
            upstream: String::new(),
            listen: default_listen(),
            title: default_title(),
            template: None,
            secret: None,
            session_ttl: default_session_ttl(),
            secure_cookie: false,
            log_format: default_log_format(),
        }
    }
}

#[tokio::main]
async fn main() {
    init_tracing(&std::env::var("LOG_FORMAT").unwrap_or_else(|_| default_log_format()));

    let config = load_config();
    let upstream: Uri = config
        .upstream
        .parse()
        .expect("UPSTREAM must be a valid URI");
    let upstream_scheme = upstream
        .scheme_str()
        .expect("UPSTREAM must include a scheme")
        .to_string();
    let upstream_authority = upstream
        .authority()
        .expect("UPSTREAM must include an authority")
        .to_string();
    let upstream_base_path = upstream.path().trim_end_matches('/').to_string();
    let listen_addr = parse_listen_addr(&config.listen);
    let template_source = load_template(config.template.as_deref());
    validate_template(&template_source, &config.title).expect("template must parse and render");
    let secret = load_secret(config.secret.as_deref());

    let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let state = AppState {
        password: config.password.into_bytes(),
        title: config.title,
        template_source,
        secret,
        upstream,
        upstream_scheme,
        upstream_authority,
        upstream_base_path,
        session_ttl: Duration::from_secs(config.session_ttl),
        secure_cookie: config.secure_cookie,
        rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        client,
    };

    info!(
        listen_addr = %listen_addr,
        upstream = %state.upstream,
        custom_template_loaded = config.template.is_some(),
        session_ttl_secs = state.session_ttl.as_secs(),
        secure_cookie = state.secure_cookie,
        log_format = %config.log_format,
        "starting hodor"
    );

    let app = Router::new()
        .route("/_gate/login", get(login_get).post(login_post))
        .route("/_gate/logout", get(logout))
        .route("/_gate/health", get(health))
        .fallback(proxy_or_login)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .expect("failed to bind listen address");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("server error");
}

async fn login_get() -> impl IntoResponse {
    Redirect::to("/")
}

async fn health() -> &'static str {
    "ok"
}

async fn logout(State(state): State<AppState>) -> Response<Body> {
    let mut response = Redirect::to("/").into_response();
    match HeaderValue::from_str(&clear_cookie(&state)) {
        Ok(value) => {
            response.headers_mut().insert(SET_COOKIE, value);
            response
        }
        Err(_) => internal_server_error(),
    }
}

async fn login_post(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let client_ip = addr.ip();

    if !allow_login_attempt(&state, client_ip) {
        info!(client_ip = %client_ip, success = false, rate_limited = true, "login attempt");
        return (StatusCode::TOO_MANY_REQUESTS, "too many login attempts").into_response();
    }

    let body = match collect_body(request.into_body()).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    let form = parse_form_body(&body);
    let redirect = sanitize_redirect(form_value(&form, "redirect").unwrap_or("/"));
    let password = form_value(&form, "password").unwrap_or("");

    if !bool::from(password.as_bytes().ct_eq(state.password.as_slice())) {
        info!(client_ip = %client_ip, success = false, rate_limited = false, "login attempt");
        return login_page_response(&state.template_source, &state.title, true);
    }

    let token = sign_token(&state.secret, now_unix() + state.session_ttl.as_secs());
    let cookie = session_cookie(&state, &token);

    let mut response = Redirect::to(&redirect).into_response();
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            info!(client_ip = %client_ip, success = true, rate_limited = false, "login attempt");
            response.headers_mut().insert(SET_COOKIE, value);
            response
        }
        Err(_) => internal_server_error(),
    }
}

async fn proxy_or_login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if !is_authenticated(request.headers(), &state.secret) {
        return login_page_response(&state.template_source, &state.title, false);
    }

    proxy_request(state, addr, request).await
}

async fn proxy_request(
    state: AppState,
    addr: SocketAddr,
    request: Request<Body>,
) -> Response<Body> {
    let started_at = Instant::now();
    let request_method = request.method().clone();
    let request_path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    let (parts, body) = request.into_parts();

    if is_websocket_upgrade(&parts.headers) {
        debug!(method = %request_method, path = %request_path, client_ip = %addr.ip(), "websocket upgrade requested but not supported");
        return websocket_not_supported();
    }

    let path = join_paths(&state.upstream_base_path, parts.uri.path());
    let uri = build_upstream_uri(&state, &path, parts.uri.query());

    let mut proxied = match Request::builder().method(parts.method).uri(uri).body(body) {
        Ok(request) => request,
        Err(_) => return bad_gateway(),
    };

    *proxied.version_mut() = parts.version;

    for (name, value) in &parts.headers {
        if name != HOST && !is_hop_by_hop_header(name) {
            proxied.headers_mut().append(name, value.clone());
        }
    }

    match HeaderValue::from_str(&state.upstream_authority) {
        Ok(host) => {
            proxied.headers_mut().insert(HOST, host);
        }
        Err(_) => return bad_gateway(),
    }

    append_forwarded_headers(proxied.headers_mut(), addr.ip());

    let response = match state.client.request(proxied).await {
        Ok(response) => response,
        Err(_) => return bad_gateway(),
    };

    let (parts, body) = response.into_parts();
    let status = parts.status;

    let mut builder = Response::builder().status(status);
    if let Some(headers) = builder.headers_mut() {
        for (name, value) in &parts.headers {
            if !is_hop_by_hop_header(name) {
                headers.append(name, value.clone());
            }
        }
    } else {
        return bad_gateway();
    }

    match builder.body(Body::new(body)) {
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
        Err(_) => bad_gateway(),
    }
}

fn load_config() -> Config {
    Figment::new()
        .merge(Serialized::defaults(Config::default()))
        .merge(Toml::file("hodor.toml"))
        .merge(Env::raw())
        .extract()
        .expect("failed to load configuration from defaults, hodor.toml, and environment")
}

fn load_template(template_path: Option<&str>) -> String {
    match template_path {
        Some(path) => std::fs::read_to_string(path)
            .expect("failed to read custom template from TEMPLATE path"),
        None => BUILTIN_TEMPLATE.to_string(),
    }
}

fn validate_template(template_source: &str, title: &str) -> Result<(), minijinja::Error> {
    render_login_page(template_source, title, false).map(|_| ())
}

fn render_login_page(
    template_source: &str,
    title: &str,
    show_error: bool,
) -> Result<String, minijinja::Error> {
    let mut env = Environment::new();
    env.add_template(TEMPLATE_NAME, template_source)?;
    env.get_template(TEMPLATE_NAME)?
        .render(context!(title => title, show_error => show_error))
}

fn login_page_response(template_source: &str, title: &str, show_error: bool) -> Response<Body> {
    match render_login_page(template_source, title, show_error) {
        Ok(page) => (StatusCode::UNAUTHORIZED, Html(page)).into_response(),
        Err(error) => {
            warn!(%error, "failed to render login page");
            internal_server_error()
        }
    }
}

fn is_authenticated(headers: &HeaderMap, secret: &[u8]) -> bool {
    let Some(cookie) = cookie_value(headers, COOKIE_NAME) else {
        return false;
    };

    validate_token(secret, cookie)
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookie = headers.get(COOKIE)?.to_str().ok()?;
    for pair in cookie.split(';') {
        let pair = pair.trim();
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if key == name {
            return Some(value);
        }
    }
    None
}

fn allow_login_attempt(state: &AppState, ip: IpAddr) -> bool {
    let now = Instant::now();
    let cutoff = now.checked_sub(RATE_LIMIT_WINDOW).unwrap_or(now);
    let mut limiter = state
        .rate_limiter
        .lock()
        .expect("rate limiter lock poisoned");

    limiter.retain(|_, attempts| {
        attempts.retain(|attempt| *attempt >= cutoff);
        !attempts.is_empty()
    });

    let attempts = limiter.entry(ip).or_default();
    if attempts.len() >= RATE_LIMIT_ATTEMPTS {
        return false;
    }

    attempts.push(now);
    true
}

fn session_cookie(state: &AppState, token: &str) -> String {
    let mut cookie = format!(
        "{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        state.session_ttl.as_secs()
    );
    if state.secure_cookie {
        cookie.push_str("; Secure");
    }
    cookie
}

fn clear_cookie(state: &AppState) -> String {
    let mut cookie = format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if state.secure_cookie {
        cookie.push_str("; Secure");
    }
    cookie
}

fn append_forwarded_headers(headers: &mut HeaderMap, client_ip: IpAddr) {
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
        HeaderValue::from_static("http"),
    );
}

// Token format: `<unix_expiry>|<hex_hmac_sha256(expiry)>` so expiry stays inspectable while integrity remains signed.
fn sign_token(secret: &[u8], expiry: u64) -> String {
    let expiry = expiry.to_string();
    let mut mac = HmacSha256::new_from_slice(secret).expect("valid HMAC key");
    mac.update(expiry.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    format!("{expiry}|{signature}")
}

fn validate_token(secret: &[u8], token: &str) -> bool {
    let Some((expiry, signature)) = token.split_once('|') else {
        return false;
    };

    let Ok(expiry) = expiry.parse::<u64>() else {
        return false;
    };

    if expiry < now_unix() {
        return false;
    }

    let Ok(signature) = hex::decode(signature) else {
        return false;
    };

    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(expiry.to_string().as_bytes());
    mac.verify_slice(&signature).is_ok()
}

fn load_secret(configured_secret: Option<&str>) -> Vec<u8> {
    match configured_secret {
        Some(secret) => secret.as_bytes().to_vec(),
        None => {
            let mut secret = [0_u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            warn!("SECRET not set, generated ephemeral signing key");
            secret.to_vec()
        }
    }
}

fn parse_listen_addr(listen: &str) -> SocketAddr {
    let listen = if let Some(port) = listen.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else {
        listen.to_string()
    };
    listen
        .parse()
        .expect("LISTEN must be a valid socket address")
}

fn build_upstream_uri(state: &AppState, path: &str, query: Option<&str>) -> Uri {
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

fn join_paths(base: &str, path: &str) -> String {
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

fn parse_form_body(body: &Bytes) -> Vec<(String, String)> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode_form_component(key), decode_form_component(value))
        })
        .collect()
}

fn form_value<'a>(form: &'a [(String, String)], key: &str) -> Option<&'a str> {
    form.iter()
        .find_map(|(form_key, form_value)| (form_key == key).then_some(form_value.as_str()))
}

fn decode_form_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    decoded.push(byte);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&decoded).into_owned()
}

fn sanitize_redirect(redirect: &str) -> String {
    if redirect.starts_with('/') && !redirect.starts_with("//") {
        redirect.to_string()
    } else {
        "/".to_string()
    }
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn collect_body(body: Body) -> Result<Bytes, Response<Body>> {
    match body.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(_) => Err((StatusCode::BAD_REQUEST, "invalid request body").into_response()),
    }
}

fn init_tracing(format: &str) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if format.eq_ignore_ascii_case("json") {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .compact()
            .init();
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl-c");
    };

    let terminate = async {
        signal(SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");
}

fn default_listen() -> String {
    ":8080".to_string()
}

fn default_title() -> String {
    "Password Required".to_string()
}

fn default_session_ttl() -> u64 {
    86_400
}

fn default_log_format() -> String {
    "compact".to_string()
}

fn internal_server_error() -> Response<Body> {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
}

fn bad_gateway() -> Response<Body> {
    (StatusCode::BAD_GATEWAY, "bad gateway").into_response()
}

fn websocket_not_supported() -> Response<Body> {
    (
        StatusCode::NOT_IMPLEMENTED,
        "websocket proxying is not supported yet",
    )
        .into_response()
}
