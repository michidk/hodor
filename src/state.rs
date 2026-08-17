use axum::body::Body;
use axum::http::Uri;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use ipnet::IpNet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::auth::{LoginGuard, load_secret};
use crate::config::Config;
use crate::templates::{
    load_error_template, load_template, validate_error_template, validate_template,
};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) password: Vec<u8>,
    pub(crate) title: String,
    pub(crate) custom_css: String,
    pub(crate) disable_default_css: bool,
    pub(crate) template_source: String,
    pub(crate) error_template_source: String,
    pub(crate) secret: Vec<u8>,
    pub(crate) upstream: Uri,
    pub(crate) upstream_scheme: String,
    pub(crate) upstream_authority: String,
    pub(crate) upstream_base_path: String,
    pub(crate) session_ttl: Duration,
    pub(crate) secure_cookie: bool,
    pub(crate) trust_proxy: bool,
    pub(crate) trusted_proxy_cidrs: Vec<IpNet>,
    pub(crate) bypass_cidrs: Vec<IpNet>,
    pub(crate) preserve_host: bool,
    pub(crate) cookie_domain: Option<String>,
    pub(crate) login_guard: Arc<Mutex<LoginGuard>>,
    pub(crate) client: Client<HttpConnector, Body>,
}

pub(crate) fn build_app_state(config: Config) -> AppState {
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
    AppState {
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
        trusted_proxy_cidrs: parse_cidrs(config.trusted_proxy_cidrs),
        bypass_cidrs: parse_cidrs(config.bypass_cidrs),
        preserve_host: config.preserve_host,
        cookie_domain: config.cookie_domain,
        login_guard: Arc::new(Mutex::new(LoginGuard::new(Instant::now()))),
        client,
    }
}

fn parse_cidrs(cidrs: Vec<String>) -> Vec<IpNet> {
    cidrs
        .into_iter()
        .map(|cidr| {
            cidr.parse()
                .expect("CIDRs must be validated during config loading")
        })
        .collect()
}
