use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Config {
    pub(crate) password: String,
    pub(crate) upstream: String,
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    #[serde(default = "default_title")]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) custom_css: Option<String>,
    #[serde(default)]
    pub(crate) disable_default_css: bool,
    #[serde(default)]
    pub(crate) template: Option<String>,
    #[serde(default)]
    pub(crate) error_template: Option<String>,
    #[serde(default)]
    pub(crate) secret: Option<String>,
    #[serde(default = "default_session_ttl")]
    pub(crate) session_ttl: u64,
    #[serde(default)]
    pub(crate) secure_cookie: bool,
    #[serde(default)]
    pub(crate) trust_proxy: bool,
    #[serde(default = "default_log_format")]
    pub(crate) log_format: String,
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

pub(crate) fn load_config() -> Config {
    let env_pairs: Vec<(String, String)> = Env::raw()
        .iter()
        .map(|(key, value)| (key.as_str().to_string(), value))
        .collect();

    load_config_with_env(env_pairs).unwrap_or_else(|error| {
        panic!("failed to load configuration from defaults, hodor.toml, and environment: {error}")
    })
}

pub(crate) fn load_config_with_env<I, K, V>(pairs: I) -> Result<Config, String>
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
    validate_config(&config)?;
    Ok(config)
}

fn validate_config(config: &Config) -> Result<(), String> {
    if config.password.is_empty() {
        return Err("PASSWORD is required and cannot be empty".to_string());
    }
    if config.upstream.is_empty() {
        return Err("UPSTREAM is required and cannot be empty".to_string());
    }
    if config.secret.as_deref().is_some_and(str::is_empty) {
        return Err("SECRET cannot be empty when configured".to_string());
    }
    if config.session_ttl == 0 {
        return Err("SESSION_TTL must be greater than zero".to_string());
    }

    Ok(())
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
            "DISABLE_DEFAULT_CSS" => {
                config.disable_default_css = value.parse::<bool>().map_err(|error| {
                    format!("DISABLE_DEFAULT_CSS must be true or false: {error}")
                })?;
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

pub(crate) fn parse_listen_addr(listen: &str) -> SocketAddr {
    let listen = if let Some(port) = listen.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else {
        listen.to_string()
    };
    listen
        .parse()
        .expect("LISTEN must be a valid socket address")
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

pub(crate) fn default_log_format() -> String {
    "compact".to_string()
}
