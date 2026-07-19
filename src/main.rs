use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{
    CONNECTION, COOKIE, HOST, HeaderMap, HeaderName, HeaderValue, RETRY_AFTER, SET_COOKIE, UPGRADE,
};
use axum::http::{Request, Response, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::get;
use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use minijinja::{Environment, context};
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
const BUILTIN_ERROR_TEMPLATE: &str = include_str!("error_template.html");
const RATE_LIMIT_ATTEMPTS: usize = 5;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const LOCKOUT_THRESHOLD: u32 = 10;
const LOCKOUT_BASE: Duration = Duration::from_secs(60);
const LOCKOUT_MAX: Duration = Duration::from_secs(3600);
const FAILED_LOGIN_DELAY: Duration = Duration::from_millis(500);
const MAX_TRACKED_IPS: usize = 10_000;
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);
const ERROR_TEMPLATE_NAME: &str = "error.html";
const TEMPLATE_NAME: &str = "login.html";
const X_FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
const X_FORWARDED_PROTO_HEADER: &str = "x-forwarded-proto";

#[derive(Clone)]
struct AppState {
    password: Vec<u8>,
    title: String,
    custom_css: String,
    disable_default_css: bool,
    template_source: String,
    error_template_source: String,
    secret: Vec<u8>,
    upstream: Uri,
    upstream_scheme: String,
    upstream_authority: String,
    upstream_base_path: String,
    session_ttl: Duration,
    secure_cookie: bool,
    trust_proxy: bool,
    login_guard: Arc<Mutex<LoginGuard>>,
    client: Client<HttpConnector, Body>,
}

// Brute-force tracker shared across handlers. `last_pruned` throttles the
// full-map cleanup so it runs at most once per PRUNE_INTERVAL rather than on
// every login attempt.
#[derive(Debug)]
struct LoginGuard {
    records: HashMap<IpAddr, LoginRecord>,
    last_pruned: Instant,
}

impl LoginGuard {
    fn new(now: Instant) -> Self {
        Self {
            records: HashMap::new(),
            last_pruned: now,
        }
    }
}

// Brute-force protection state per client IP. A sliding window throttles
// bursts; consecutive failures past LOCKOUT_THRESHOLD trigger lockouts that
// double per failure (capped at LOCKOUT_MAX). A successful login clears the
// record.
#[derive(Debug, Clone)]
struct LoginRecord {
    attempts: Vec<Instant>,
    consecutive_failures: u32,
    locked_until: Option<Instant>,
    last_seen: Instant,
}

impl LoginRecord {
    fn new(now: Instant) -> Self {
        Self {
            attempts: Vec::new(),
            consecutive_failures: 0,
            locked_until: None,
            last_seen: now,
        }
    }
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
    custom_css: Option<String>,
    #[serde(default)]
    disable_default_css: bool,
    #[serde(default)]
    template: Option<String>,
    #[serde(default)]
    error_template: Option<String>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default = "default_session_ttl")]
    session_ttl: u64,
    #[serde(default)]
    secure_cookie: bool,
    #[serde(default)]
    trust_proxy: bool,
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
            custom_css: None,
            disable_default_css: false,
            template: None,
            error_template: None,
            secret: None,
            session_ttl: default_session_ttl(),
            secure_cookie: false,
            trust_proxy: false,
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
    let custom_css = config.custom_css.unwrap_or_default();
    let template_source = load_template(config.template.as_deref());
    validate_template(
        &template_source,
        &config.title,
        &custom_css,
        config.disable_default_css,
    )
    .expect("template must parse and render");
    let error_template_source = load_error_template(config.error_template.as_deref());
    validate_error_template(
        &error_template_source,
        &config.title,
        &custom_css,
        config.disable_default_css,
    )
    .expect("error template must parse and render");
    let secret = load_secret(config.secret.as_deref());

    let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let state = AppState {
        password: config.password.into_bytes(),
        title: config.title,
        custom_css,
        disable_default_css: config.disable_default_css,
        template_source,
        error_template_source,
        secret,
        upstream,
        upstream_scheme,
        upstream_authority,
        upstream_base_path,
        session_ttl: Duration::from_secs(config.session_ttl),
        secure_cookie: config.secure_cookie,
        trust_proxy: config.trust_proxy,
        login_guard: Arc::new(Mutex::new(LoginGuard::new(Instant::now()))),
        client,
    };

    info!(
        listen_addr = %listen_addr,
        upstream = %state.upstream,
        custom_template_loaded = config.template.is_some(),
        custom_error_template_loaded = config.error_template.is_some(),
        custom_css_set = !state.custom_css.is_empty(),
        disable_default_css = state.disable_default_css,
        session_ttl_secs = state.session_ttl.as_secs(),
        secure_cookie = state.secure_cookie,
        trust_proxy = state.trust_proxy,
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
        Err(_) => internal_server_error(&state),
    }
}

async fn login_post(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let client_ip = resolve_client_ip(request.headers(), addr.ip(), state.trust_proxy);

    if let Some(retry_after) = check_login_attempt(&state, client_ip) {
        info!(client_ip = %client_ip, success = false, rate_limited = true, "login attempt");
        return too_many_requests(retry_after);
    }

    let body = match collect_body(request.into_body()).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    let form = parse_form_body(&body);
    let redirect = sanitize_redirect(form_value(&form, "redirect").unwrap_or("/"));
    let password = form_value(&form, "password").unwrap_or("");

    if !bool::from(password.as_bytes().ct_eq(state.password.as_slice())) {
        if let Some(lockout) = record_login_failure(&state, client_ip) {
            warn!(client_ip = %client_ip, lockout_secs = lockout.as_secs(), "locking out ip after repeated failed logins");
        }
        info!(client_ip = %client_ip, success = false, rate_limited = false, "login attempt");
        tokio::time::sleep(FAILED_LOGIN_DELAY).await;
        return login_page_response(&state, true);
    }

    record_login_success(&state, client_ip);

    let token = sign_token(&state.secret, now_unix() + state.session_ttl.as_secs());
    let cookie = session_cookie(&state, &token);

    let mut response = Redirect::to(&redirect).into_response();
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            info!(client_ip = %client_ip, success = true, rate_limited = false, "login attempt");
            response.headers_mut().insert(SET_COOKIE, value);
            response
        }
        Err(_) => internal_server_error(&state),
    }
}

async fn proxy_or_login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    if !is_authenticated(request.headers(), &state.secret) {
        return login_page_response(&state, false);
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
        return websocket_not_supported(&state);
    }

    let path = join_paths(&state.upstream_base_path, parts.uri.path());
    let uri = build_upstream_uri(&state, &path, parts.uri.query());

    let mut proxied = match Request::builder().method(parts.method).uri(uri).body(body) {
        Ok(request) => request,
        Err(_) => return bad_gateway(&state),
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
        Err(_) => return bad_gateway(&state),
    }

    append_forwarded_headers(proxied.headers_mut(), addr.ip());

    let response = match state.client.request(proxied).await {
        Ok(response) => response,
        Err(_) => return bad_gateway(&state),
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
        return bad_gateway(&state);
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
        Err(_) => bad_gateway(&state),
    }
}

fn load_config() -> Config {
    let env_pairs: Vec<(String, String)> = Env::raw()
        .iter()
        .map(|(key, value)| (key.as_str().to_string(), value))
        .collect();

    load_config_with_env(env_pairs).unwrap_or_else(|error| {
        panic!("failed to load configuration from defaults, hodor.toml, and environment: {error}")
    })
}

fn load_config_with_env<I, K, V>(pairs: I) -> Result<Config, String>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    let mut config: Config = Figment::new()
        .merge(Serialized::defaults(Config::default()))
        .merge(Toml::file("hodor.toml"))
        .extract()
        .map_err(|error| error.to_string())?;

    apply_env_overrides(&mut config, pairs)?;
    Ok(config)
}

fn apply_env_overrides<I, K, V>(config: &mut Config, pairs: I) -> Result<(), String>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    for (key, value) in pairs {
        let key = key.into().trim().to_ascii_uppercase();
        let value = value.into();

        match key.as_str() {
            "PASSWORD" => config.password = value,
            "UPSTREAM" => config.upstream = value,
            "LISTEN" => config.listen = value,
            "TITLE" => config.title = value,
            "CUSTOM_CSS" => config.custom_css = Some(value),
            "TEMPLATE" => config.template = Some(value),
            "ERROR_TEMPLATE" => config.error_template = Some(value),
            "SECRET" => config.secret = Some(value),
            "LOG_FORMAT" => config.log_format = value,
            "SESSION_TTL" => {
                config.session_ttl = value
                    .parse::<u64>()
                    .map_err(|error| format!("SESSION_TTL must be a valid integer: {error}"))?;
            }
            "SECURE_COOKIE" => {
                config.secure_cookie = value
                    .parse::<bool>()
                    .map_err(|error| format!("SECURE_COOKIE must be true or false: {error}"))?;
            }
            "TRUST_PROXY" => {
                config.trust_proxy = value
                    .parse::<bool>()
                    .map_err(|error| format!("TRUST_PROXY must be true or false: {error}"))?;
            }
            _ => {}
        }
    }

    Ok(())
}

fn load_template(template_path: Option<&str>) -> String {
    match template_path {
        Some(path) => std::fs::read_to_string(path)
            .expect("failed to read custom template from TEMPLATE path"),
        None => BUILTIN_TEMPLATE.to_string(),
    }
}

fn load_error_template(template_path: Option<&str>) -> String {
    match template_path {
        Some(path) => std::fs::read_to_string(path)
            .expect("failed to read custom error template from ERROR_TEMPLATE path"),
        None => BUILTIN_ERROR_TEMPLATE.to_string(),
    }
}

fn validate_template(
    template_source: &str,
    title: &str,
    custom_css: &str,
    disable_default_css: bool,
) -> Result<(), minijinja::Error> {
    render_login_page(
        template_source,
        title,
        custom_css,
        disable_default_css,
        false,
    )
    .map(|_| ())
}

fn validate_error_template(
    template_source: &str,
    title: &str,
    custom_css: &str,
    disable_default_css: bool,
) -> Result<(), minijinja::Error> {
    render_error_page(
        template_source,
        title,
        custom_css,
        disable_default_css,
        StatusCode::BAD_GATEWAY,
        "Bad Gateway",
        "The upstream service could not be reached.",
    )
    .map(|_| ())
}

fn render_login_page(
    template_source: &str,
    title: &str,
    custom_css: &str,
    disable_default_css: bool,
    show_error: bool,
) -> Result<String, minijinja::Error> {
    let mut env = Environment::new();
    env.add_template(TEMPLATE_NAME, template_source)?;
    env.get_template(TEMPLATE_NAME)?.render(context!(
        title => title,
        custom_css => custom_css,
        disable_default_css => disable_default_css,
        show_error => show_error,
    ))
}

fn render_error_page(
    template_source: &str,
    title: &str,
    custom_css: &str,
    disable_default_css: bool,
    status: StatusCode,
    heading: &str,
    message: &str,
) -> Result<String, minijinja::Error> {
    let mut env = Environment::new();
    env.add_template(ERROR_TEMPLATE_NAME, template_source)?;
    env.get_template(ERROR_TEMPLATE_NAME)?.render(context!(
        title => title,
        custom_css => custom_css,
        disable_default_css => disable_default_css,
        status_code => status.as_u16(),
        heading => heading,
        message => message,
    ))
}

fn login_page_response(state: &AppState, show_error: bool) -> Response<Body> {
    match render_login_page(
        &state.template_source,
        &state.title,
        &state.custom_css,
        state.disable_default_css,
        show_error,
    ) {
        Ok(page) => (StatusCode::UNAUTHORIZED, Html(page)).into_response(),
        Err(error) => {
            warn!(%error, "failed to render login page");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

fn error_page_response(
    state: &AppState,
    status: StatusCode,
    heading: &str,
    message: &str,
) -> Response<Body> {
    match render_error_page(
        &state.error_template_source,
        &state.title,
        &state.custom_css,
        state.disable_default_css,
        status,
        heading,
        message,
    ) {
        Ok(page) => (status, Html(page)).into_response(),
        Err(error) => {
            warn!(%error, "failed to render error page");
            (status, message.to_string()).into_response()
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

// With trust_proxy enabled, the rightmost X-Forwarded-For entry is the client
// address as recorded by the trusted proxy directly in front of hodor (e.g. a
// Kubernetes ingress). Left of that the header is client-controlled, so only
// the rightmost entry is trusted. Falls back to the TCP peer address when the
// header is missing or unparseable.
fn resolve_client_ip(headers: &HeaderMap, peer: IpAddr, trust_proxy: bool) -> IpAddr {
    if !trust_proxy {
        return peer;
    }
    headers
        .get(HeaderName::from_static(X_FORWARDED_FOR_HEADER))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(peer)
}

// Returns None when the attempt may proceed, or Some(retry_after) when the
// IP is currently locked out or has exhausted its rate-limit window.
fn check_login_attempt(state: &AppState, ip: IpAddr) -> Option<Duration> {
    let now = Instant::now();
    let mut guard = state.login_guard.lock().expect("login guard lock poisoned");

    if now.saturating_duration_since(guard.last_pruned) >= PRUNE_INTERVAL {
        prune_login_records(&mut guard.records, now);
        guard.last_pruned = now;
    }
    if !guard.records.contains_key(&ip) && guard.records.len() >= MAX_TRACKED_IPS {
        evict_oldest_record(&mut guard.records);
    }

    let record = guard
        .records
        .entry(ip)
        .or_insert_with(|| LoginRecord::new(now));
    record.last_seen = now;

    if let Some(locked_until) = record.locked_until {
        if locked_until > now {
            return Some(locked_until - now);
        }
        record.locked_until = None;
    }

    let cutoff = now.checked_sub(RATE_LIMIT_WINDOW).unwrap_or(now);
    record.attempts.retain(|attempt| *attempt >= cutoff);
    if record.attempts.len() >= RATE_LIMIT_ATTEMPTS {
        let oldest = record.attempts.iter().min().copied().unwrap_or(now);
        let retry_after = (oldest + RATE_LIMIT_WINDOW).saturating_duration_since(now);
        return Some(retry_after.max(Duration::from_secs(1)));
    }

    record.attempts.push(now);
    None
}

// Returns the lockout duration when this failure pushes the IP past
// LOCKOUT_THRESHOLD consecutive failures.
fn record_login_failure(state: &AppState, ip: IpAddr) -> Option<Duration> {
    let now = Instant::now();
    let mut guard = state.login_guard.lock().expect("login guard lock poisoned");

    let record = guard
        .records
        .entry(ip)
        .or_insert_with(|| LoginRecord::new(now));
    record.last_seen = now;
    record.consecutive_failures = record.consecutive_failures.saturating_add(1);

    if record.consecutive_failures < LOCKOUT_THRESHOLD {
        return None;
    }

    let lockout = lockout_duration(record.consecutive_failures - LOCKOUT_THRESHOLD);
    record.locked_until = Some(now + lockout);
    Some(lockout)
}

fn record_login_success(state: &AppState, ip: IpAddr) {
    let mut guard = state.login_guard.lock().expect("login guard lock poisoned");
    guard.records.remove(&ip);
}

fn lockout_duration(exponent: u32) -> Duration {
    let multiplier = 1_u32.checked_shl(exponent).unwrap_or(u32::MAX);
    LOCKOUT_BASE.saturating_mul(multiplier).min(LOCKOUT_MAX)
}

fn prune_login_records(records: &mut HashMap<IpAddr, LoginRecord>, now: Instant) {
    records.retain(|_, record| {
        let locked = record.locked_until.is_some_and(|until| until > now);
        locked || now.saturating_duration_since(record.last_seen) < LOCKOUT_MAX
    });
}

fn evict_oldest_record(records: &mut HashMap<IpAddr, LoginRecord>) {
    let oldest = records
        .iter()
        .min_by_key(|(_, record)| record.last_seen)
        .map(|(ip, _)| *ip);
    if let Some(ip) = oldest {
        records.remove(&ip);
    }
}

fn too_many_requests(retry_after: Duration) -> Response<Body> {
    let mut response = (StatusCode::TOO_MANY_REQUESTS, "too many login attempts").into_response();
    let rounded_up = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
    let seconds = rounded_up.max(1);
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
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
            rand::fill(&mut secret);
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

fn internal_server_error(state: &AppState) -> Response<Body> {
    error_page_response(
        state,
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal Server Error",
        "Something went wrong while processing this request.",
    )
}

fn bad_gateway(state: &AppState) -> Response<Body> {
    error_page_response(
        state,
        StatusCode::BAD_GATEWAY,
        "Upstream Unavailable",
        "Hodor is running, but the downstream service could not be reached.",
    )
}

fn websocket_not_supported(state: &AppState) -> Response<Body> {
    error_page_response(
        state,
        StatusCode::NOT_IMPLEMENTED,
        "WebSockets Not Supported",
        "This hodor instance does not support WebSocket proxying yet.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_secret() -> Vec<u8> {
        b"test-secret-key-for-unit-tests".to_vec()
    }

    fn test_state(secure_cookie: bool) -> AppState {
        AppState {
            password: b"hunter2".to_vec(),
            title: "Test".to_string(),
            custom_css: String::new(),
            disable_default_css: false,
            template_source: BUILTIN_TEMPLATE.to_string(),
            error_template_source: BUILTIN_ERROR_TEMPLATE.to_string(),
            secret: test_secret(),
            upstream: "http://localhost:3000".parse().unwrap(),
            upstream_scheme: "http".to_string(),
            upstream_authority: "localhost:3000".to_string(),
            upstream_base_path: String::new(),
            session_ttl: Duration::from_secs(3600),
            secure_cookie,
            trust_proxy: false,
            login_guard: Arc::new(Mutex::new(LoginGuard::new(Instant::now()))),
            client: Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
        }
    }

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
    fn is_hop_by_hop_header_detects_correctly() {
        assert!(is_hop_by_hop_header(&HeaderName::from_static("connection")));
        assert!(is_hop_by_hop_header(&HeaderName::from_static(
            "transfer-encoding"
        )));
        assert!(is_hop_by_hop_header(&HeaderName::from_static("upgrade")));
        assert!(!is_hop_by_hop_header(&HeaderName::from_static(
            "content-type"
        )));
        assert!(!is_hop_by_hop_header(&HeaderName::from_static(
            "authorization"
        )));
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
    fn check_login_attempt_permits_first_attempts() {
        let state = test_state(false);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..RATE_LIMIT_ATTEMPTS {
            assert!(check_login_attempt(&state, ip).is_none());
        }
    }

    #[test]
    fn check_login_attempt_blocks_after_limit_with_retry_after() {
        let state = test_state(false);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..RATE_LIMIT_ATTEMPTS {
            check_login_attempt(&state, ip);
        }
        let retry_after = check_login_attempt(&state, ip).expect("should be rate limited");
        assert!(retry_after <= RATE_LIMIT_WINDOW);
        assert!(retry_after >= Duration::from_secs(1));
    }

    #[test]
    fn check_login_attempt_isolates_ips() {
        let state = test_state(false);
        let ip1: IpAddr = "10.0.0.3".parse().unwrap();
        let ip2: IpAddr = "10.0.0.4".parse().unwrap();
        for _ in 0..RATE_LIMIT_ATTEMPTS {
            check_login_attempt(&state, ip1);
        }
        assert!(check_login_attempt(&state, ip1).is_some());
        assert!(check_login_attempt(&state, ip2).is_none());
    }

    #[test]
    fn record_login_failure_locks_out_after_threshold() {
        let state = test_state(false);
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        for _ in 0..LOCKOUT_THRESHOLD - 1 {
            assert!(record_login_failure(&state, ip).is_none());
        }
        let lockout = record_login_failure(&state, ip).expect("should trigger lockout");
        assert_eq!(lockout, LOCKOUT_BASE);
        let retry_after = check_login_attempt(&state, ip).expect("should be locked out");
        assert!(retry_after <= LOCKOUT_BASE);
    }

    #[test]
    fn record_login_failure_escalates_lockouts() {
        let state = test_state(false);
        let ip: IpAddr = "10.0.0.6".parse().unwrap();
        for _ in 0..LOCKOUT_THRESHOLD {
            record_login_failure(&state, ip);
        }
        let second = record_login_failure(&state, ip).expect("should stay locked out");
        assert_eq!(second, LOCKOUT_BASE * 2);
        let third = record_login_failure(&state, ip).expect("should stay locked out");
        assert_eq!(third, LOCKOUT_BASE * 4);
    }

    #[test]
    fn record_login_success_clears_record() {
        let state = test_state(false);
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        for _ in 0..RATE_LIMIT_ATTEMPTS {
            check_login_attempt(&state, ip);
        }
        for _ in 0..LOCKOUT_THRESHOLD {
            record_login_failure(&state, ip);
        }
        assert!(check_login_attempt(&state, ip).is_some());
        record_login_success(&state, ip);
        assert!(check_login_attempt(&state, ip).is_none());
    }

    #[test]
    fn lockout_duration_caps_at_max() {
        assert_eq!(lockout_duration(0), LOCKOUT_BASE);
        assert_eq!(lockout_duration(1), LOCKOUT_BASE * 2);
        assert_eq!(lockout_duration(10), LOCKOUT_MAX);
        assert_eq!(lockout_duration(u32::MAX), LOCKOUT_MAX);
    }

    #[test]
    fn login_guard_evicts_oldest_when_full() {
        let state = test_state(false);
        for index in 0..MAX_TRACKED_IPS {
            let ip = IpAddr::from(u32::try_from(index).unwrap().to_be_bytes());
            check_login_attempt(&state, ip);
        }
        {
            let guard = state.login_guard.lock().unwrap();
            assert_eq!(guard.records.len(), MAX_TRACKED_IPS);
        }
        let newcomer: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(check_login_attempt(&state, newcomer).is_none());
        let guard = state.login_guard.lock().unwrap();
        assert_eq!(guard.records.len(), MAX_TRACKED_IPS);
        assert!(guard.records.contains_key(&newcomer));
    }

    #[test]
    fn prune_login_records_keeps_locked_and_recent() {
        let now = Instant::now();
        let mut records: HashMap<IpAddr, LoginRecord> = HashMap::new();

        let locked_ip: IpAddr = "10.1.0.1".parse().unwrap();
        let mut locked = LoginRecord::new(now);
        locked.locked_until = Some(now + Duration::from_secs(30));
        records.insert(locked_ip, locked);

        let recent_ip: IpAddr = "10.1.0.2".parse().unwrap();
        records.insert(recent_ip, LoginRecord::new(now));

        prune_login_records(&mut records, now + LOCKOUT_MAX + Duration::from_secs(1));
        assert!(!records.contains_key(&locked_ip));
        assert!(!records.contains_key(&recent_ip));

        records.insert(recent_ip, LoginRecord::new(now));
        prune_login_records(&mut records, now + Duration::from_secs(1));
        assert!(records.contains_key(&recent_ip));
    }

    #[test]
    fn resolve_client_ip_uses_peer_when_proxy_not_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(X_FORWARDED_FOR_HEADER),
            HeaderValue::from_static("203.0.113.7"),
        );
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(resolve_client_ip(&headers, peer, false), peer);
    }

    #[test]
    fn resolve_client_ip_uses_rightmost_forwarded_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(X_FORWARDED_FOR_HEADER),
            HeaderValue::from_static("198.51.100.9, 203.0.113.7"),
        );
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let expected: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(resolve_client_ip(&headers, peer, true), expected);
    }

    #[test]
    fn resolve_client_ip_falls_back_to_peer() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(resolve_client_ip(&HeaderMap::new(), peer, true), peer);

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(X_FORWARDED_FOR_HEADER),
            HeaderValue::from_static("not-an-ip"),
        );
        assert_eq!(resolve_client_ip(&headers, peer, true), peer);
    }

    #[test]
    fn too_many_requests_sets_retry_after_header() {
        let response = too_many_requests(Duration::from_secs(42));
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(RETRY_AFTER)
                .unwrap()
                .to_str()
                .unwrap(),
            "42"
        );

        let response = too_many_requests(Duration::from_millis(10));
        assert_eq!(
            response
                .headers()
                .get(RETRY_AFTER)
                .unwrap()
                .to_str()
                .unwrap(),
            "1"
        );

        // Sub-second remainders round up so clients don't retry too early.
        let response = too_many_requests(Duration::from_millis(1900));
        assert_eq!(
            response
                .headers()
                .get(RETRY_AFTER)
                .unwrap()
                .to_str()
                .unwrap(),
            "2"
        );
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

    #[test]
    fn append_forwarded_headers_sets_headers() {
        let mut headers = HeaderMap::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        append_forwarded_headers(&mut headers, ip);
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
        append_forwarded_headers(&mut headers, ip);
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
    fn validate_template_accepts_builtin() {
        assert!(validate_template(BUILTIN_TEMPLATE, "Test", "", false).is_ok());
    }

    #[test]
    fn validate_template_rejects_invalid_syntax() {
        assert!(validate_template("{% invalid %}", "Test", "", false).is_err());
    }

    #[test]
    fn validate_error_template_accepts_builtin() {
        assert!(validate_error_template(BUILTIN_ERROR_TEMPLATE, "Test", "", false).is_ok());
    }

    #[test]
    fn validate_error_template_rejects_invalid_syntax() {
        assert!(validate_error_template("{% invalid %}", "Test", "", false).is_err());
    }

    #[test]
    fn render_login_page_includes_title() {
        let html = render_login_page(BUILTIN_TEMPLATE, "My Gate", "", false, false).unwrap();
        assert!(html.contains("My Gate"));
    }

    #[test]
    fn render_login_page_escapes_title() {
        let html =
            render_login_page(BUILTIN_TEMPLATE, "<script>xss</script>", "", false, false).unwrap();
        assert!(!html.contains("<script>xss</script>"));
    }

    #[test]
    fn render_login_page_includes_custom_css_verbatim() {
        let css = ".card > button { background: \"hotpink\"; }";
        let html = render_login_page(BUILTIN_TEMPLATE, "My Gate", css, false, false).unwrap();
        assert!(html.contains(css));
    }

    #[test]
    fn render_login_page_omits_custom_css_block_when_unset() {
        let html = render_login_page(BUILTIN_TEMPLATE, "My Gate", "", false, false).unwrap();
        assert_eq!(html.matches("<style>").count(), 1);
    }

    #[test]
    fn render_login_page_disable_default_css_removes_builtin_styles() {
        let css = "body { background: hotpink; }";
        let html = render_login_page(BUILTIN_TEMPLATE, "My Gate", css, true, false).unwrap();
        assert!(!html.contains("box-sizing"));
        assert!(html.contains(css));
        assert_eq!(html.matches("<style>").count(), 1);
    }

    #[test]
    fn render_login_page_keeps_builtin_styles_by_default() {
        let html = render_login_page(BUILTIN_TEMPLATE, "My Gate", "", false, false).unwrap();
        assert!(html.contains("box-sizing"));
    }

    #[test]
    fn render_error_page_disable_default_css_removes_builtin_styles() {
        let css = "body { background: hotpink; }";
        let html = render_error_page(
            BUILTIN_ERROR_TEMPLATE,
            "My Gate",
            css,
            true,
            StatusCode::BAD_GATEWAY,
            "Bad Gateway",
            "Oops",
        )
        .unwrap();
        assert!(!html.contains("box-sizing"));
        assert!(html.contains(css));
        assert_eq!(html.matches("<style>").count(), 1);
    }

    #[test]
    fn render_error_page_includes_custom_css_verbatim() {
        let css = "body { background: #1e3a5f; }";
        let html = render_error_page(
            BUILTIN_ERROR_TEMPLATE,
            "My Gate",
            css,
            false,
            StatusCode::BAD_GATEWAY,
            "Bad Gateway",
            "Oops",
        )
        .unwrap();
        assert!(html.contains(css));
    }

    #[test]
    fn render_error_page_omits_custom_css_block_when_unset() {
        let html = render_error_page(
            BUILTIN_ERROR_TEMPLATE,
            "My Gate",
            "",
            false,
            StatusCode::BAD_GATEWAY,
            "Bad Gateway",
            "Oops",
        )
        .unwrap();
        assert_eq!(html.matches("<style>").count(), 1);
    }

    #[test]
    fn render_error_page_includes_fields() {
        let html = render_error_page(
            BUILTIN_ERROR_TEMPLATE,
            "My Gate",
            "",
            false,
            StatusCode::BAD_GATEWAY,
            "Upstream Unavailable",
            "The downstream service could not be reached.",
        )
        .unwrap();
        assert!(html.contains("My Gate"));
        assert!(html.contains("502"));
        assert!(html.contains("Upstream Unavailable"));
        assert!(html.contains("The downstream service could not be reached."));
    }

    #[test]
    fn render_error_page_escapes_title() {
        let html = render_error_page(
            BUILTIN_ERROR_TEMPLATE,
            "<script>xss</script>",
            "",
            false,
            StatusCode::BAD_GATEWAY,
            "Bad Gateway",
            "Oops",
        )
        .unwrap();
        assert!(!html.contains("<script>xss</script>"));
    }

    #[test]
    fn load_config_with_env_preserves_numeric_password_text() {
        let config =
            load_config_with_env([("PASSWORD", "123"), ("UPSTREAM", "http://localhost:3000")])
                .expect("numeric PASSWORD from env should deserialize as a string");

        assert_eq!(config.password, "123");
    }

    #[test]
    fn load_config_with_env_preserves_decimal_password_text() {
        let config =
            load_config_with_env([("PASSWORD", "1.0"), ("UPSTREAM", "http://localhost:3000")])
                .expect("decimal PASSWORD from env should preserve its text");

        assert_eq!(config.password, "1.0");
    }

    #[test]
    fn load_config_with_env_still_parses_typed_overrides() {
        let config = load_config_with_env([
            ("PASSWORD", "123"),
            ("UPSTREAM", "http://localhost:3000"),
            ("SESSION_TTL", "42"),
            ("SECURE_COOKIE", "true"),
            ("TRUST_PROXY", "true"),
        ])
        .expect("typed env overrides should still parse after string-preserving password fix");

        assert_eq!(config.password, "123");
        assert_eq!(config.session_ttl, 42);
        assert!(config.secure_cookie);
        assert!(config.trust_proxy);
    }
}
