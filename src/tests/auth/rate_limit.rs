use axum::http::header::{HeaderName, HeaderValue, RETRY_AFTER};
use axum::http::{HeaderMap, StatusCode};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::test_state;
use crate::auth::{
    LOCKOUT_BASE, LOCKOUT_MAX, LOCKOUT_THRESHOLD, LoginRecord, MAX_TRACKED_IPS,
    RATE_LIMIT_ATTEMPTS, RATE_LIMIT_WINDOW, X_FORWARDED_FOR_HEADER, check_login_attempt,
    lockout_duration, prune_login_records, record_login_failure, record_login_success,
    resolve_client_ip, too_many_requests,
};

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
fn check_login_attempt_recovers_from_poisoned_guard() {
    let state = test_state(false);
    let login_guard = Arc::clone(&state.login_guard);
    let poisoned = std::panic::catch_unwind(move || {
        let _guard = login_guard.lock().unwrap();
        panic!("poison login guard for test");
    });
    assert!(poisoned.is_err());
    let ip: IpAddr = "10.0.0.8".parse().unwrap();

    assert!(check_login_attempt(&state, ip).is_none());
    assert!(!state.login_guard.is_poisoned());
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
