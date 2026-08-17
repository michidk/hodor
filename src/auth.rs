mod form;
mod rate_limit;
mod session;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{HeaderValue, SET_COOKIE};
use axum::http::{Request, Response};
use axum::response::{IntoResponse, Redirect};
use std::net::SocketAddr;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tracing::{info, warn};

use crate::state::AppState;
use crate::templates::{internal_server_error, login_page_response};
pub(crate) use form::{collect_body, form_value, parse_form_body, sanitize_redirect};
pub(crate) use rate_limit::{
    check_login_attempt, is_bypass_ip, is_trusted_proxy, record_login_failure,
    record_login_success, resolve_client_ip, too_many_requests,
};
pub(crate) use session::{clear_cookie, now_unix, session_cookie, sign_token};

pub(crate) use rate_limit::{LoginGuard, X_FORWARDED_FOR_HEADER};
pub(crate) use session::{is_authenticated, load_secret};

const FAILED_LOGIN_DELAY: Duration = Duration::from_millis(500);

pub(crate) async fn login_get() -> impl IntoResponse {
    Redirect::to("/")
}

pub(crate) async fn health() -> &'static str {
    "ok"
}

pub(crate) async fn logout(State(state): State<AppState>) -> Response<Body> {
    let mut response = Redirect::to("/").into_response();
    match HeaderValue::from_str(&clear_cookie(&state)) {
        Ok(value) => {
            response.headers_mut().insert(SET_COOKIE, value);
            response
        }
        Err(_) => internal_server_error(&state),
    }
}

pub(crate) async fn login_post(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let client_ip = resolve_client_ip(
        request.headers(),
        addr.ip(),
        state.trust_proxy,
        &state.trusted_proxy_cidrs,
    );

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

#[cfg(test)]
pub(crate) use form::{MAX_LOGIN_BODY_SIZE, decode_form_component};
#[cfg(test)]
pub(crate) use rate_limit::{
    LOCKOUT_BASE, LOCKOUT_MAX, LOCKOUT_THRESHOLD, LoginRecord, MAX_TRACKED_IPS,
    RATE_LIMIT_ATTEMPTS, RATE_LIMIT_WINDOW, lockout_duration, prune_login_records,
};
#[cfg(test)]
pub(crate) use session::{cookie_value, validate_token};
