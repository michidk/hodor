mod auth;
mod config;
mod proxy;
mod state;
mod templates;

use axum::Router;
use axum::routing::get;
use std::net::SocketAddr;
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;
use tracing_subscriber::EnvFilter;

use auth::{health, login_get, login_post, logout};
use config::{default_log_format, load_config, parse_listen_addr};
use proxy::proxy_or_login;
use state::build_app_state;

#[tokio::main]
async fn main() {
    init_tracing(&std::env::var("LOG_FORMAT").unwrap_or_else(|_| default_log_format()));

    let config = load_config();
    let listen_addr = parse_listen_addr(&config.listen);
    let custom_template_loaded = config.template.is_some();
    let custom_error_template_loaded = config.error_template.is_some();
    let log_format = config.log_format.clone();
    let state = build_app_state(config);

    info!(
        listen_addr = %listen_addr,
        upstream = %state.upstream,
        custom_template_loaded,
        custom_error_template_loaded,
        custom_css_set = !state.custom_css.is_empty(),
        disable_default_css = state.disable_default_css,
        session_ttl_secs = state.session_ttl.as_secs(),
        secure_cookie = state.secure_cookie,
        trust_proxy = state.trust_proxy,
        trusted_proxy_cidrs = state.trusted_proxy_cidrs.len(),
        bypass_cidrs = state.bypass_cidrs.len(),
        bypass_paths = state.bypass_paths.len(),
        preserve_host = state.preserve_host,
        cookie_domain_set = state.cookie_domain.is_some(),
        log_format,
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

#[cfg(test)]
mod tests;
