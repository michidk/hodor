use axum::http::HeaderMap;
use axum::http::header::COOKIE;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

const COOKIE_NAME: &str = "hodor";

pub(crate) fn is_authenticated(headers: &HeaderMap, secret: &[u8]) -> bool {
    let Some(cookie) = cookie_value(headers, COOKIE_NAME) else {
        return false;
    };

    validate_token(secret, cookie)
}

pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
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

pub(crate) fn session_cookie(state: &AppState, token: &str) -> String {
    let mut cookie = format!(
        "{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        state.session_ttl.as_secs()
    );
    if state.secure_cookie {
        cookie.push_str("; Secure");
    }
    cookie
}

pub(crate) fn clear_cookie(state: &AppState) -> String {
    let mut cookie = format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if state.secure_cookie {
        cookie.push_str("; Secure");
    }
    cookie
}

// Token format: `<unix_expiry>|<hex_hmac_sha256(expiry)>` keeps expiry
// inspectable while making any modification detectable.
pub(crate) fn sign_token(secret: &[u8], expiry: u64) -> String {
    let expiry = expiry.to_string();
    let mut mac = HmacSha256::new_from_slice(secret).expect("valid HMAC key");
    mac.update(expiry.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    format!("{expiry}|{signature}")
}

pub(crate) fn validate_token(secret: &[u8], token: &str) -> bool {
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

pub(crate) fn load_secret(configured_secret: Option<&str>) -> Vec<u8> {
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

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
