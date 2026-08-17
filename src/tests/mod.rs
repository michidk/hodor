mod auth;
mod config;
mod proxy;
mod templates;

use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::auth::LoginGuard;
use crate::state::AppState;
use crate::templates::{BUILTIN_ERROR_TEMPLATE, BUILTIN_TEMPLATE};

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
        trusted_proxy_cidrs: Vec::new(),
        bypass_cidrs: Vec::new(),
        preserve_host: false,
        cookie_domain: None,
        login_guard: Arc::new(Mutex::new(LoginGuard::new(Instant::now()))),
        client: Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
    }
}
