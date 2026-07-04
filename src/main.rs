use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{
    CONNECTION, COOKIE, HOST, HeaderMap, HeaderName, HeaderValue, SET_COOKIE, UPGRADE,
};
use axum::http::{Request, Response, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
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
use webauthn_rs::prelude::{
    CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Uuid, Webauthn, WebauthnBuilder,
};

type HmacSha256 = Hmac<Sha256>;

const COOKIE_NAME: &str = "hodor";
const BUILTIN_TEMPLATE: &str = include_str!("template.html");
const BUILTIN_ERROR_TEMPLATE: &str = include_str!("error_template.html");
const BUILTIN_PASSKEYS_TEMPLATE: &str = include_str!("passkeys_template.html");
const RATE_LIMIT_ATTEMPTS: usize = 5;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const ERROR_TEMPLATE_NAME: &str = "error.html";
const TEMPLATE_NAME: &str = "login.html";
const PASSKEYS_TEMPLATE_NAME: &str = "passkeys.html";
const CHALLENGE_TTL: Duration = Duration::from_secs(300);
const MAX_PENDING_CHALLENGES: usize = 256;
const PASSKEY_NAME_MAX_CHARS: usize = 64;
// Hodor has a single shared identity, so every passkey is registered under one fixed user handle.
const PASSKEY_USER_ID: Uuid = Uuid::from_bytes(*b"hodor-shared-usr");
const X_FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
const X_FORWARDED_PROTO_HEADER: &str = "x-forwarded-proto";

#[derive(Clone)]
struct AppState {
    password: Vec<u8>,
    title: String,
    template_source: String,
    error_template_source: String,
    secret: Vec<u8>,
    upstream: Uri,
    upstream_scheme: String,
    upstream_authority: String,
    upstream_base_path: String,
    session_ttl: Duration,
    secure_cookie: bool,
    rate_limiter: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    client: Client<HttpConnector, Body>,
    webauthn: Option<Arc<Webauthn>>,
    passkeys: Arc<Mutex<Vec<PasskeyRecord>>>,
    passkeys_file: String,
    reg_challenges: Arc<Mutex<HashMap<String, (Instant, PasskeyRegistration)>>>,
    auth_challenges: Arc<Mutex<HashMap<String, (Instant, PasskeyAuthentication)>>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PasskeyRecord {
    name: String,
    added_at: u64,
    passkey: Passkey,
}

#[derive(Serialize)]
struct PasskeyView {
    id: String,
    name: String,
    added_at: u64,
}

impl PasskeyView {
    fn from_record(record: &PasskeyRecord) -> Self {
        Self {
            id: hex::encode(record.passkey.cred_id().as_ref()),
            name: record.name.clone(),
            added_at: record.added_at,
        }
    }
}

#[derive(Deserialize)]
struct PasskeyRegisterFinishRequest {
    id: String,
    #[serde(default)]
    name: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
struct PasskeyLoginFinishRequest {
    id: String,
    #[serde(default)]
    redirect: Option<String>,
    credential: PublicKeyCredential,
}

#[derive(Deserialize)]
struct PasskeyDeleteRequest {
    id: String,
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
    error_template: Option<String>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default = "default_session_ttl")]
    session_ttl: u64,
    #[serde(default)]
    secure_cookie: bool,
    #[serde(default = "default_log_format")]
    log_format: String,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    rp_id: Option<String>,
    #[serde(default = "default_passkeys_file")]
    passkeys_file: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            password: String::new(),
            upstream: String::new(),
            listen: default_listen(),
            title: default_title(),
            template: None,
            error_template: None,
            secret: None,
            session_ttl: default_session_ttl(),
            secure_cookie: false,
            log_format: default_log_format(),
            origin: None,
            rp_id: None,
            passkeys_file: default_passkeys_file(),
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
    let error_template_source = load_error_template(config.error_template.as_deref());
    validate_error_template(&error_template_source, &config.title)
        .expect("error template must parse and render");
    let secret = load_secret(config.secret.as_deref());
    let webauthn = build_webauthn(config.origin.as_deref(), config.rp_id.as_deref());
    let passkeys = if webauthn.is_some() {
        validate_passkeys_template(BUILTIN_PASSKEYS_TEMPLATE, &config.title)
            .expect("passkeys template must parse and render");
        load_passkeys(&config.passkeys_file).expect("failed to load passkeys file")
    } else {
        Vec::new()
    };
    let passkey_count = passkeys.len();

    let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let state = AppState {
        password: config.password.into_bytes(),
        title: config.title,
        template_source,
        error_template_source,
        secret,
        upstream,
        upstream_scheme,
        upstream_authority,
        upstream_base_path,
        session_ttl: Duration::from_secs(config.session_ttl),
        secure_cookie: config.secure_cookie,
        rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        client,
        webauthn,
        passkeys: Arc::new(Mutex::new(passkeys)),
        passkeys_file: config.passkeys_file,
        reg_challenges: Arc::new(Mutex::new(HashMap::new())),
        auth_challenges: Arc::new(Mutex::new(HashMap::new())),
    };

    info!(
        listen_addr = %listen_addr,
        upstream = %state.upstream,
        custom_template_loaded = config.template.is_some(),
        custom_error_template_loaded = config.error_template.is_some(),
        session_ttl_secs = state.session_ttl.as_secs(),
        secure_cookie = state.secure_cookie,
        passkeys_enabled = state.webauthn.is_some(),
        passkeys_registered = passkey_count,
        log_format = %config.log_format,
        "starting hodor"
    );

    let app = Router::new()
        .route("/_gate/login", get(login_get).post(login_post))
        .route("/_gate/logout", get(logout))
        .route("/_gate/health", get(health))
        .route("/_gate/passkeys", get(passkeys_page))
        .route(
            "/_gate/passkey/register/start",
            post(passkey_register_start),
        )
        .route(
            "/_gate/passkey/register/finish",
            post(passkey_register_finish),
        )
        .route("/_gate/passkey/login/start", post(passkey_login_start))
        .route("/_gate/passkey/login/finish", post(passkey_login_finish))
        .route("/_gate/passkey/delete", post(passkey_delete))
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
        return login_page_response(&state, true);
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
        Err(_) => internal_server_error(&state),
    }
}

async fn passkeys_page(State(state): State<AppState>, headers: HeaderMap) -> Response<Body> {
    if state.webauthn.is_none() {
        return error_page_response(
            &state,
            StatusCode::NOT_FOUND,
            "Passkeys Not Enabled",
            "Set ORIGIN to the public URL of this instance to enable passkeys.",
        );
    }

    if !is_authenticated(&headers, &state.secret) {
        return login_page_response(&state, false);
    }

    let passkeys: Vec<PasskeyView> = {
        let records = state.passkeys.lock().expect("passkey store lock poisoned");
        records.iter().map(PasskeyView::from_record).collect()
    };

    match render_passkeys_page(BUILTIN_PASSKEYS_TEMPLATE, &state.title, &passkeys) {
        Ok(page) => Html(page).into_response(),
        Err(error) => {
            warn!(%error, "failed to render passkeys page");
            internal_server_error(&state)
        }
    }
}

async fn passkey_register_start(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response<Body> {
    let Some(webauthn) = state.webauthn.as_ref() else {
        return (StatusCode::NOT_FOUND, "passkeys not enabled").into_response();
    };
    if !is_authenticated(&headers, &state.secret) {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    }

    let exclude: Vec<CredentialID> = {
        let records = state.passkeys.lock().expect("passkey store lock poisoned");
        records
            .iter()
            .map(|record| record.passkey.cred_id().clone())
            .collect()
    };
    let exclude = (!exclude.is_empty()).then_some(exclude);

    let (challenge, registration) =
        match webauthn.start_passkey_registration(PASSKEY_USER_ID, "hodor", "hodor", exclude) {
            Ok(result) => result,
            Err(error) => {
                warn!(%error, "failed to start passkey registration");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to start passkey registration",
                )
                    .into_response();
            }
        };

    let Some(id) = challenge_insert(&state.reg_challenges, registration) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many pending passkey challenges",
        )
            .into_response();
    };

    Json(serde_json::json!({ "id": id, "challenge": challenge })).into_response()
}

async fn passkey_register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PasskeyRegisterFinishRequest>,
) -> Response<Body> {
    let Some(webauthn) = state.webauthn.as_ref() else {
        return (StatusCode::NOT_FOUND, "passkeys not enabled").into_response();
    };
    if !is_authenticated(&headers, &state.secret) {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    }

    let Some(registration) = challenge_take(&state.reg_challenges, &request.id) else {
        return (
            StatusCode::BAD_REQUEST,
            "unknown or expired passkey challenge",
        )
            .into_response();
    };

    let passkey = match webauthn.finish_passkey_registration(&request.credential, &registration) {
        Ok(passkey) => passkey,
        Err(error) => {
            warn!(%error, "passkey registration failed");
            return (StatusCode::BAD_REQUEST, "passkey registration failed").into_response();
        }
    };

    let mut records = state.passkeys.lock().expect("passkey store lock poisoned");
    records.push(PasskeyRecord {
        name: sanitize_passkey_name(&request.name),
        added_at: now_unix(),
        passkey,
    });
    if let Err(error) = save_passkeys(&state.passkeys_file, &records) {
        records.pop();
        warn!(%error, "failed to persist passkeys");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist passkey",
        )
            .into_response();
    }

    info!(passkeys = records.len(), "passkey registered");
    StatusCode::NO_CONTENT.into_response()
}

async fn passkey_login_start(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response<Body> {
    let Some(webauthn) = state.webauthn.as_ref() else {
        return (StatusCode::NOT_FOUND, "passkeys not enabled").into_response();
    };

    let client_ip = addr.ip();
    if !allow_login_attempt(&state, client_ip) {
        info!(client_ip = %client_ip, success = false, rate_limited = true, method = "passkey", "login attempt");
        return (StatusCode::TOO_MANY_REQUESTS, "too many login attempts").into_response();
    }

    let credentials: Vec<Passkey> = {
        let records = state.passkeys.lock().expect("passkey store lock poisoned");
        records
            .iter()
            .map(|record| record.passkey.clone())
            .collect()
    };
    if credentials.is_empty() {
        return (StatusCode::BAD_REQUEST, "no passkeys registered").into_response();
    }

    let (challenge, authentication) = match webauthn.start_passkey_authentication(&credentials) {
        Ok(result) => result,
        Err(error) => {
            warn!(%error, "failed to start passkey authentication");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to start passkey authentication",
            )
                .into_response();
        }
    };

    let Some(id) = challenge_insert(&state.auth_challenges, authentication) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many pending passkey challenges",
        )
            .into_response();
    };

    Json(serde_json::json!({ "id": id, "challenge": challenge })).into_response()
}

async fn passkey_login_finish(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<PasskeyLoginFinishRequest>,
) -> Response<Body> {
    let Some(webauthn) = state.webauthn.as_ref() else {
        return (StatusCode::NOT_FOUND, "passkeys not enabled").into_response();
    };

    let client_ip = addr.ip();
    let Some(authentication) = challenge_take(&state.auth_challenges, &request.id) else {
        return (
            StatusCode::BAD_REQUEST,
            "unknown or expired passkey challenge",
        )
            .into_response();
    };

    let result = match webauthn.finish_passkey_authentication(&request.credential, &authentication)
    {
        Ok(result) => result,
        Err(error) => {
            info!(client_ip = %client_ip, success = false, rate_limited = false, method = "passkey", "login attempt");
            debug!(%error, "passkey authentication failed");
            return (StatusCode::UNAUTHORIZED, "passkey authentication failed").into_response();
        }
    };

    {
        let mut records = state.passkeys.lock().expect("passkey store lock poisoned");
        let mut changed = false;
        for record in records.iter_mut() {
            if record.passkey.update_credential(&result) == Some(true) {
                changed = true;
            }
        }
        if changed {
            if let Err(error) = save_passkeys(&state.passkeys_file, &records) {
                warn!(%error, "failed to persist passkey counter update");
            }
        }
    }

    let redirect = sanitize_redirect(request.redirect.as_deref().unwrap_or("/"));
    let token = sign_token(&state.secret, now_unix() + state.session_ttl.as_secs());
    let cookie = session_cookie(&state, &token);

    let mut response = Json(serde_json::json!({ "redirect": redirect })).into_response();
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            info!(client_ip = %client_ip, success = true, rate_limited = false, method = "passkey", "login attempt");
            response.headers_mut().insert(SET_COOKIE, value);
            response
        }
        Err(_) => internal_server_error(&state),
    }
}

async fn passkey_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PasskeyDeleteRequest>,
) -> Response<Body> {
    if state.webauthn.is_none() {
        return (StatusCode::NOT_FOUND, "passkeys not enabled").into_response();
    }
    if !is_authenticated(&headers, &state.secret) {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    }

    let mut records = state.passkeys.lock().expect("passkey store lock poisoned");
    let before = records.len();
    records.retain(|record| hex::encode(record.passkey.cred_id().as_ref()) != request.id);
    if records.len() == before {
        return (StatusCode::NOT_FOUND, "unknown passkey").into_response();
    }
    if let Err(error) = save_passkeys(&state.passkeys_file, &records) {
        warn!(%error, "failed to persist passkeys");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist passkey removal",
        )
            .into_response();
    }

    info!(passkeys = records.len(), "passkey removed");
    StatusCode::NO_CONTENT.into_response()
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

fn load_error_template(template_path: Option<&str>) -> String {
    match template_path {
        Some(path) => std::fs::read_to_string(path)
            .expect("failed to read custom error template from ERROR_TEMPLATE path"),
        None => BUILTIN_ERROR_TEMPLATE.to_string(),
    }
}

fn validate_template(template_source: &str, title: &str) -> Result<(), minijinja::Error> {
    render_login_page(template_source, title, false, true).map(|_| ())
}

fn validate_passkeys_template(template_source: &str, title: &str) -> Result<(), minijinja::Error> {
    render_passkeys_page(template_source, title, &[]).map(|_| ())
}

fn validate_error_template(template_source: &str, title: &str) -> Result<(), minijinja::Error> {
    render_error_page(
        template_source,
        title,
        StatusCode::BAD_GATEWAY,
        "Bad Gateway",
        "The upstream service could not be reached.",
    )
    .map(|_| ())
}

fn render_login_page(
    template_source: &str,
    title: &str,
    show_error: bool,
    passkeys_enabled: bool,
) -> Result<String, minijinja::Error> {
    let mut env = Environment::new();
    env.add_template(TEMPLATE_NAME, template_source)?;
    env.get_template(TEMPLATE_NAME)?.render(context!(
        title => title,
        show_error => show_error,
        passkeys_enabled => passkeys_enabled,
    ))
}

fn render_passkeys_page(
    template_source: &str,
    title: &str,
    passkeys: &[PasskeyView],
) -> Result<String, minijinja::Error> {
    let mut env = Environment::new();
    env.add_template(PASSKEYS_TEMPLATE_NAME, template_source)?;
    env.get_template(PASSKEYS_TEMPLATE_NAME)?
        .render(context!(title => title, passkeys => passkeys))
}

fn render_error_page(
    template_source: &str,
    title: &str,
    status: StatusCode,
    heading: &str,
    message: &str,
) -> Result<String, minijinja::Error> {
    let mut env = Environment::new();
    env.add_template(ERROR_TEMPLATE_NAME, template_source)?;
    env.get_template(ERROR_TEMPLATE_NAME)?.render(context!(
        title => title,
        status_code => status.as_u16(),
        heading => heading,
        message => message,
    ))
}

fn login_page_response(state: &AppState, show_error: bool) -> Response<Body> {
    match render_login_page(
        &state.template_source,
        &state.title,
        show_error,
        state.webauthn.is_some(),
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

fn build_webauthn(origin: Option<&str>, rp_id: Option<&str>) -> Option<Arc<Webauthn>> {
    let origin = origin?;
    let url = Url::parse(origin).expect("ORIGIN must be a valid URL");
    let rp_id = match rp_id {
        Some(rp_id) => rp_id.to_string(),
        None => url
            .host_str()
            .expect("ORIGIN must include a host")
            .to_string(),
    };
    let webauthn = WebauthnBuilder::new(&rp_id, &url)
        .expect("RP_ID must be a registrable suffix of the ORIGIN domain")
        .build()
        .expect("failed to initialise WebAuthn");
    Some(Arc::new(webauthn))
}

fn load_passkeys(path: &str) -> std::io::Result<Vec<PasskeyRecord>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(std::io::Error::other),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

// Written via a temp file + rename so a crash mid-write cannot corrupt the store.
fn save_passkeys(path: &str, records: &[PasskeyRecord]) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(records).map_err(std::io::Error::other)?;
    let tmp_path = format!("{path}.tmp");
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, path)
}

fn sanitize_passkey_name(name: &str) -> String {
    let name = name.trim();
    if name.is_empty() {
        return "passkey".to_string();
    }
    name.chars().take(PASSKEY_NAME_MAX_CHARS).collect()
}

fn challenge_insert<T>(store: &Mutex<HashMap<String, (Instant, T)>>, value: T) -> Option<String> {
    let mut store = store.lock().expect("challenge store lock poisoned");
    store.retain(|_, (created_at, _)| created_at.elapsed() < CHALLENGE_TTL);
    if store.len() >= MAX_PENDING_CHALLENGES {
        return None;
    }

    let mut id = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    let id = hex::encode(id);
    store.insert(id.clone(), (Instant::now(), value));
    Some(id)
}

fn challenge_take<T>(store: &Mutex<HashMap<String, (Instant, T)>>, id: &str) -> Option<T> {
    let mut store = store.lock().expect("challenge store lock poisoned");
    store.retain(|_, (created_at, _)| created_at.elapsed() < CHALLENGE_TTL);
    store.remove(id).map(|(_, value)| value)
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

fn default_passkeys_file() -> String {
    "passkeys.json".to_string()
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
            template_source: BUILTIN_TEMPLATE.to_string(),
            error_template_source: BUILTIN_ERROR_TEMPLATE.to_string(),
            secret: test_secret(),
            upstream: "http://localhost:3000".parse().unwrap(),
            upstream_scheme: "http".to_string(),
            upstream_authority: "localhost:3000".to_string(),
            upstream_base_path: String::new(),
            session_ttl: Duration::from_secs(3600),
            secure_cookie,
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            client: Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
            webauthn: None,
            passkeys: Arc::new(Mutex::new(Vec::new())),
            passkeys_file: "passkeys.json".to_string(),
            reg_challenges: Arc::new(Mutex::new(HashMap::new())),
            auth_challenges: Arc::new(Mutex::new(HashMap::new())),
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
    fn allow_login_attempt_permits_first_attempts() {
        let state = test_state(false);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..RATE_LIMIT_ATTEMPTS {
            assert!(allow_login_attempt(&state, ip));
        }
    }

    #[test]
    fn allow_login_attempt_blocks_after_limit() {
        let state = test_state(false);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..RATE_LIMIT_ATTEMPTS {
            allow_login_attempt(&state, ip);
        }
        assert!(!allow_login_attempt(&state, ip));
    }

    #[test]
    fn allow_login_attempt_isolates_ips() {
        let state = test_state(false);
        let ip1: IpAddr = "10.0.0.3".parse().unwrap();
        let ip2: IpAddr = "10.0.0.4".parse().unwrap();
        for _ in 0..RATE_LIMIT_ATTEMPTS {
            allow_login_attempt(&state, ip1);
        }
        assert!(!allow_login_attempt(&state, ip1));
        assert!(allow_login_attempt(&state, ip2));
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
        assert!(validate_template(BUILTIN_TEMPLATE, "Test").is_ok());
    }

    #[test]
    fn validate_template_rejects_invalid_syntax() {
        assert!(validate_template("{% invalid %}", "Test").is_err());
    }

    #[test]
    fn validate_error_template_accepts_builtin() {
        assert!(validate_error_template(BUILTIN_ERROR_TEMPLATE, "Test").is_ok());
    }

    #[test]
    fn validate_error_template_rejects_invalid_syntax() {
        assert!(validate_error_template("{% invalid %}", "Test").is_err());
    }

    #[test]
    fn render_login_page_includes_title() {
        let html = render_login_page(BUILTIN_TEMPLATE, "My Gate", false, false).unwrap();
        assert!(html.contains("My Gate"));
    }

    #[test]
    fn render_login_page_escapes_title() {
        let html =
            render_login_page(BUILTIN_TEMPLATE, "<script>xss</script>", false, false).unwrap();
        assert!(!html.contains("<script>xss</script>"));
    }

    #[test]
    fn render_login_page_shows_passkey_button_when_enabled() {
        let html = render_login_page(BUILTIN_TEMPLATE, "Test", false, true).unwrap();
        assert!(html.contains("passkey-button"));
    }

    #[test]
    fn render_login_page_hides_passkey_button_when_disabled() {
        let html = render_login_page(BUILTIN_TEMPLATE, "Test", false, false).unwrap();
        assert!(!html.contains("passkey-button"));
    }

    #[test]
    fn render_passkeys_page_lists_passkeys() {
        let passkeys = vec![PasskeyView {
            id: "abc123".to_string(),
            name: "laptop".to_string(),
            added_at: 1_700_000_000,
        }];
        let html = render_passkeys_page(BUILTIN_PASSKEYS_TEMPLATE, "Test", &passkeys).unwrap();
        assert!(html.contains("laptop"));
        assert!(html.contains("abc123"));
        assert!(!html.contains("No passkeys registered yet."));
    }

    #[test]
    fn render_passkeys_page_escapes_names() {
        let passkeys = vec![PasskeyView {
            id: "abc123".to_string(),
            name: "<script>xss</script>".to_string(),
            added_at: 0,
        }];
        let html = render_passkeys_page(BUILTIN_PASSKEYS_TEMPLATE, "Test", &passkeys).unwrap();
        assert!(!html.contains("<script>xss</script>"));
    }

    #[test]
    fn render_passkeys_page_empty_state() {
        let html = render_passkeys_page(BUILTIN_PASSKEYS_TEMPLATE, "Test", &[]).unwrap();
        assert!(html.contains("No passkeys registered yet."));
    }

    #[test]
    fn validate_passkeys_template_accepts_builtin() {
        assert!(validate_passkeys_template(BUILTIN_PASSKEYS_TEMPLATE, "Test").is_ok());
    }

    #[test]
    fn sanitize_passkey_name_defaults_when_empty() {
        assert_eq!(sanitize_passkey_name(""), "passkey");
        assert_eq!(sanitize_passkey_name("   "), "passkey");
    }

    #[test]
    fn sanitize_passkey_name_trims_and_caps_length() {
        assert_eq!(sanitize_passkey_name("  laptop  "), "laptop");
        let long = "x".repeat(200);
        assert_eq!(sanitize_passkey_name(&long).chars().count(), 64);
    }

    #[test]
    fn challenge_store_roundtrip() {
        let store = Mutex::new(HashMap::new());
        let id = challenge_insert(&store, 42_u32).unwrap();
        assert_eq!(challenge_take(&store, &id), Some(42));
        assert_eq!(challenge_take(&store, &id), None);
    }

    #[test]
    fn challenge_store_unknown_id() {
        let store: Mutex<HashMap<String, (Instant, u32)>> = Mutex::new(HashMap::new());
        assert_eq!(challenge_take(&store, "missing"), None);
    }

    #[test]
    fn challenge_store_enforces_cap() {
        let store = Mutex::new(HashMap::new());
        for value in 0..MAX_PENDING_CHALLENGES {
            assert!(challenge_insert(&store, value).is_some());
        }
        assert!(challenge_insert(&store, 0).is_none());
    }

    #[test]
    fn load_passkeys_missing_file_is_empty() {
        let records = load_passkeys("/nonexistent/passkeys.json").unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn load_passkeys_rejects_invalid_json() {
        let path = std::env::temp_dir().join("hodor-test-invalid-passkeys.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(load_passkeys(path.to_str().unwrap()).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn save_and_load_passkeys_roundtrip() {
        let path = std::env::temp_dir().join("hodor-test-passkeys.json");
        let path = path.to_str().unwrap();
        save_passkeys(path, &[]).unwrap();
        assert!(load_passkeys(path).unwrap().is_empty());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn render_error_page_includes_fields() {
        let html = render_error_page(
            BUILTIN_ERROR_TEMPLATE,
            "My Gate",
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
            StatusCode::BAD_GATEWAY,
            "Bad Gateway",
            "Oops",
        )
        .unwrap();
        assert!(!html.contains("<script>xss</script>"));
    }
}
