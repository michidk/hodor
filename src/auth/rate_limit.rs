use axum::body::Body;
use axum::http::header::{HeaderName, HeaderValue, RETRY_AFTER};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tracing::warn;

use crate::state::AppState;

pub(crate) const RATE_LIMIT_ATTEMPTS: usize = 5;
pub(crate) const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const LOCKOUT_THRESHOLD: u32 = 10;
pub(crate) const LOCKOUT_BASE: Duration = Duration::from_secs(60);
pub(crate) const LOCKOUT_MAX: Duration = Duration::from_secs(3600);
pub(crate) const MAX_TRACKED_IPS: usize = 10_000;
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);
pub(crate) const X_FORWARDED_FOR_HEADER: &str = "x-forwarded-for";

#[derive(Debug)]
pub(crate) struct LoginGuard {
    pub(crate) records: HashMap<IpAddr, LoginRecord>,
    last_pruned: Instant,
}

impl LoginGuard {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            records: HashMap::new(),
            last_pruned: now,
        }
    }
}

fn lock_login_guard(login_guard: &Mutex<LoginGuard>) -> MutexGuard<'_, LoginGuard> {
    match login_guard.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("login guard lock was poisoned; recovering state");
            let guard = poisoned.into_inner();
            login_guard.clear_poison();
            guard
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LoginRecord {
    attempts: Vec<Instant>,
    consecutive_failures: u32,
    pub(crate) locked_until: Option<Instant>,
    last_seen: Instant,
}

impl LoginRecord {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            attempts: Vec::new(),
            consecutive_failures: 0,
            locked_until: None,
            last_seen: now,
        }
    }
}

// Only the rightmost X-Forwarded-For entry was written by the directly trusted
// proxy; entries to its left remain client-controlled.
pub(crate) fn resolve_client_ip(headers: &HeaderMap, peer: IpAddr, trust_proxy: bool) -> IpAddr {
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

pub(crate) fn check_login_attempt(state: &AppState, ip: IpAddr) -> Option<Duration> {
    let now = Instant::now();
    let mut guard = lock_login_guard(&state.login_guard);

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

pub(crate) fn record_login_failure(state: &AppState, ip: IpAddr) -> Option<Duration> {
    let now = Instant::now();
    let mut guard = lock_login_guard(&state.login_guard);

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

pub(crate) fn record_login_success(state: &AppState, ip: IpAddr) {
    let mut guard = lock_login_guard(&state.login_guard);
    guard.records.remove(&ip);
}

pub(crate) fn lockout_duration(exponent: u32) -> Duration {
    let multiplier = 1_u32.checked_shl(exponent).unwrap_or(u32::MAX);
    LOCKOUT_BASE.saturating_mul(multiplier).min(LOCKOUT_MAX)
}

pub(crate) fn prune_login_records(records: &mut HashMap<IpAddr, LoginRecord>, now: Instant) {
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

pub(crate) fn too_many_requests(retry_after: Duration) -> Response<Body> {
    let mut response = (StatusCode::TOO_MANY_REQUESTS, "too many login attempts").into_response();
    let rounded_up = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
    let seconds = rounded_up.max(1);
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}
