use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{COOKIE, HOST, HeaderMap, HeaderName, HeaderValue, SET_COOKIE};
use axum::http::{Request, Response, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::get;
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rand::RngCore;
use sha2::Sha256;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const COOKIE_NAME: &str = "hodor";
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const LOGIN_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>__TITLE__</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      background: #0f0f0f;
      color: #f5f5f5;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .card {
      width: 100%;
      max-width: 400px;
      background: #1a1a1a;
      border: 1px solid #2a2a2a;
      border-radius: 16px;
      padding: 28px;
      box-shadow: 0 24px 64px rgba(0, 0, 0, 0.35);
    }
    h1 {
      margin: 0 0 20px;
      font-size: 1.5rem;
      font-weight: 700;
    }
    label {
      display: block;
      margin-bottom: 8px;
      font-size: 0.95rem;
      color: #d4d4d4;
    }
    input[type="password"] {
      width: 100%;
      padding: 12px 14px;
      border: 1px solid #2a2a2a;
      border-radius: 12px;
      background: #111111;
      color: #f5f5f5;
      font: inherit;
      margin-bottom: 16px;
    }
    button {
      width: 100%;
      padding: 12px 14px;
      border: 1px solid #2a2a2a;
      border-radius: 12px;
      background: #ffffff;
      color: #000000;
      font: inherit;
      font-weight: 600;
      cursor: pointer;
    }
    .error {
      display:none;
      margin-bottom: 16px;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid rgba(248, 113, 113, 0.25);
      background: rgba(127, 29, 29, 0.35);
      color: #f87171;
    }
  </style>
</head>
<body>
  <main class="card">
    <h1>__TITLE__</h1>
    <div class="error">Wrong password.</div>
    <form method="post" action="/_gate/login">
      <input type="hidden" name="redirect" value="/">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
      <button type="submit">Continue</button>
    </form>
  </main>
  <script>
    const redirect = document.querySelector('input[name="redirect"]');
    if (redirect) {
      redirect.value = `${window.location.pathname}${window.location.search}${window.location.hash}` || '/';
    }
  </script>
</body>
</html>
"#;

#[derive(Clone)]
struct AppState {
    password: String,
    title: String,
    secret: Vec<u8>,
    upstream: Uri,
    upstream_scheme: String,
    upstream_authority: String,
    upstream_base_path: String,
    client: Client<HttpConnector, Body>,
}

#[tokio::main]
async fn main() {
    let password = std::env::var("PASSWORD").unwrap();
    let upstream = std::env::var("UPSTREAM").unwrap();
    let listen = std::env::var("LISTEN").unwrap_or_else(|_| ":8080".to_string());
    let title = std::env::var("TITLE").unwrap_or_else(|_| "Password Required".to_string());

    let upstream: Uri = upstream.parse().unwrap();
    let upstream_scheme = upstream.scheme_str().unwrap().to_string();
    let upstream_authority = upstream.authority().unwrap().to_string();
    let upstream_base_path = upstream.path().trim_end_matches('/').to_string();
    let secret = load_secret();
    let listen_addr = parse_listen_addr(&listen);

    let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let state = AppState {
        password,
        title,
        secret,
        upstream,
        upstream_scheme,
        upstream_authority,
        upstream_base_path,
        client,
    };

    let app = Router::new()
        .route("/_gate/login", get(login_get).post(login_post))
        .route("/_gate/logout", get(logout))
        .fallback(proxy_or_login)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn login_get() -> impl IntoResponse {
    Redirect::to("/")
}

async fn logout() -> Response<Body> {
    let mut response = Redirect::to("/").into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static("hodor=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"),
    );
    response
}

async fn login_post(State(state): State<AppState>, request: Request<Body>) -> Response<Body> {
    let body = match collect_body(request.into_body()).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    let form = parse_form_body(&body);
    let redirect = sanitize_redirect(form_value(&form, "redirect").unwrap_or("/"));
    let password = form_value(&form, "password").unwrap_or("");

    if password != state.password {
        return login_page_response(&state.title, true);
    }

    let token = sign_token(&state.secret, now_unix() + SESSION_TTL.as_secs());
    let cookie = format!(
        "{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        SESSION_TTL.as_secs()
    );

    let mut response = Redirect::to(&redirect).into_response();
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            response.headers_mut().insert(SET_COOKIE, value);
            response
        }
        Err(_) => internal_server_error(),
    }
}

async fn proxy_or_login(State(state): State<AppState>, request: Request<Body>) -> Response<Body> {
    if !is_authenticated(request.headers(), &state.secret) {
        return login_page_response(&state.title, false);
    }

    proxy_request(state, request).await
}

async fn proxy_request(state: AppState, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body = match collect_body(body).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    let path = join_paths(&state.upstream_base_path, parts.uri.path());
    let uri = build_upstream_uri(&state, &path, parts.uri.query());

    let mut proxied = match Request::builder()
        .method(parts.method)
        .uri(uri)
        .body(Body::from(body))
    {
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

    let response = match state.client.request(proxied).await {
        Ok(response) => response,
        Err(_) => return bad_gateway(),
    };

    let (parts, body) = response.into_parts();
    let body = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return bad_gateway(),
    };

    let mut builder = Response::builder().status(parts.status);
    if let Some(headers) = builder.headers_mut() {
        for (name, value) in &parts.headers {
            if !is_hop_by_hop_header(name) {
                headers.append(name, value.clone());
            }
        }
    } else {
        return bad_gateway();
    }

    match builder.body(Body::from(body)) {
        Ok(response) => response,
        Err(_) => bad_gateway(),
    }
}

fn login_page_response(title: &str, show_error: bool) -> Response<Body> {
    (
        StatusCode::UNAUTHORIZED,
        Html(render_login_page(title, show_error)),
    )
        .into_response()
}

fn render_login_page(title: &str, show_error: bool) -> String {
    let page = LOGIN_PAGE.replace("__TITLE__", &escape_html(title));
    if show_error {
        page.replacen("display:none;", "display:block;", 1)
    } else {
        page
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

fn load_secret() -> Vec<u8> {
    match std::env::var("SECRET") {
        Ok(secret) => secret.into_bytes(),
        Err(_) => {
            let mut secret = [0_u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            eprintln!("warning: SECRET not set, generated ephemeral signing key");
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
    listen.parse().unwrap()
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

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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

fn internal_server_error() -> Response<Body> {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
}

fn bad_gateway() -> Response<Body> {
    (StatusCode::BAD_GATEWAY, "bad gateway").into_response()
}
