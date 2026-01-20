//! Test utilities and shared configuration.
//!
//! This module provides common helpers for unit and integration tests,
//! reducing duplication across the codebase.

#[cfg(any(test, feature = "testing"))]
use crate::config::{CaptchaStyle, Config, FeatureFlags, WafMode};
#[cfg(any(test, feature = "testing"))]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(any(test, feature = "testing"))]
use std::sync::Arc;

/// Creates a standard configuration for testing purposes.
///
/// This configuration has:
/// - Default ports (8080/8081)
/// - Normal WAF mode
/// - CAPTCHA enabled
/// - Standard rate limits
#[cfg(any(test, feature = "testing"))]
#[must_use]
pub fn create_test_config() -> Arc<Config> {
    Arc::new(Config {
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
        internal_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
        backend_url: "http://localhost:8080".to_string(),
        waf_mode: WafMode::Normal,
        rate_limit_rps: 100,
        rate_limit_burst: 100,
        features: FeatureFlags {
            captcha_enabled: true,
            webhook_enabled: false,
            waf_body_scan_enabled: false,
            coep_enabled: false,
        },
        captcha_secret: "secret".to_string(),
        captcha_ttl: 300,
        captcha_difficulty: "medium".to_string(),
        captcha_style: CaptchaStyle::Simple,
        session_secret: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        session_expiry_secs: 3600,
        tor_circuit_prefix: "fc00".to_string(),
        tor_control_addr: None,
        tor_control_password: None,
        torrc_path: None,
        defense_error_rate_threshold: 0.5,
        defense_circuit_flood_threshold: 10,
        defense_cooldown_secs: 300,
        webhook_url: None,
        max_captcha_failures: 3,
        captcha_gen_limit: 5,
        ssrf_allowed_hosts: vec![],
        waf_body_scan_max_size: 1024,
        rate_limit_session_rps: 10,
        rate_limit_session_burst: 20,
        app_name: "TestApp".to_string(),
        favicon_base64: "data:image/x-icon;base64,".to_string(),
        meta_title: "Test".to_string(),
        meta_description: "Test".to_string(),
        meta_keywords: "Test".to_string(),
        log_format: "pretty".to_string(),
        csp_extra_sources: String::new(),
        coop_policy: "same-origin-allow-popups".to_string(),
        honeypot_paths: std::collections::HashSet::new(),
        karma_threshold: 50,
        webhook_token: None,
        attack_churn_threshold: 30,
        attack_rps_threshold: 30,
        attack_rpc_threshold: 5,
        attack_defense_score: 2.0,
        attack_pow_score: 4.0,
        attack_pow_effort: 5,
        attack_recovery_secs: 300,
        concurrency_limit: 1024,
    })
}
