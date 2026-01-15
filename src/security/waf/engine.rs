//! WAF inspection engine.
//!
//! Implements the primary request scanning logic using rule-based and algorithmic detection.

use super::rules::RuleEngine;
pub use crate::features::webhook::{EventType, WebhookNotifier, WebhookPayload};
use percent_encoding::percent_decode_str;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

const BLOCK_SCORE: u8 = 100;
const SEVERITY_CRITICAL: u8 = 5;
const SEVERITY_HIGH: u8 = 4;

#[derive(Debug, Clone)]
pub struct WafResult {
    /// Whether the request was blocked.
    pub blocked: bool,
    /// The reason for blocking (if any).
    pub reason: Option<String>,
    /// Security score assigned (higher means more dangerous).
    pub score: u8,
}

impl WafResult {
    /// Creates a safe result (allowed).
    #[must_use]
    pub const fn safe() -> Self {
        Self {
            blocked: false,
            reason: None,
            score: 0,
        }
    }

    /// Creates a blocked result with a reason and score.
    #[must_use]
    pub const fn blocked(reason: String, score: u8) -> Self {
        Self {
            blocked: true,
            reason: Some(reason),
            score,
        }
    }
}

#[derive(Clone)]
pub struct WafEngine {
    webhook: Arc<WebhookNotifier>,
    allowed_hosts: Vec<String>,
    rule_engine: RuleEngine,
}

impl WafEngine {
    /// Creates a new `WafEngine`.
    #[must_use]
    pub fn new(webhook: Arc<WebhookNotifier>, allowed_hosts: Vec<String>) -> Self {
        Self {
            webhook,
            allowed_hosts,
            rule_engine: RuleEngine::new(),
        }
    }

    /// Scans the input string for malicious patterns.
    pub fn scan(&self, input: &str, location: &str) -> WafResult {
        let (uri_path, uri_query) = input.split_once('?').unwrap_or((input, ""));
        let eval = self.rule_engine.evaluate(uri_path, uri_query, "", "");
        if eval.blocked {
            warn!(
                location = %location,
                rules = ?eval.matched_rules,
                action = "BLOCK",
                "Rule triggered"
            );
            let reason = format!("Rule triggered: {:?}", eval.matched_rules);
            self.notify_block("RuleEngine", &reason, SEVERITY_CRITICAL);
            return WafResult::blocked(reason, BLOCK_SCORE);
        }

        if Self::detect_path_traversal(input) {
            warn!(location = %location, action = "BLOCK", "Path traversal detected");
            let reason = format!("Path Traversal in {location}");
            self.notify_block("Path Traversal", &reason, SEVERITY_CRITICAL);
            return WafResult::blocked(reason, BLOCK_SCORE);
        }

        if self.detect_ssrf(input) {
            warn!(location = %location, action = "BLOCK", "SSRF/LFI detected");
            let reason = format!("SSRF/LFI in {location}");
            self.notify_block("SSRF/LFI", &reason, SEVERITY_CRITICAL);
            return WafResult::blocked(reason, BLOCK_SCORE);
        }

        let decoded_input = percent_decode_str(input).decode_utf8_lossy();
        let double_decoded = percent_decode_str(&decoded_input).decode_utf8_lossy();

        let mut inputs_to_scan = vec![input];
        if decoded_input != input {
            inputs_to_scan.push(decoded_input.as_ref());
        }
        if double_decoded != decoded_input && double_decoded != input {
            inputs_to_scan.push(double_decoded.as_ref());
        }

        let plus_decoded = decoded_input.replace('+', " ");
        if plus_decoded != decoded_input {
            inputs_to_scan.push(plus_decoded.as_ref());
        }

        for check_input in inputs_to_scan {
            let sqli_res = libinjectionrs::detect_sqli(check_input.as_bytes());
            if sqli_res.is_injection() {
                let fingerprint = sqli_res
                    .fingerprint
                    .map_or_else(|| "unknown".to_string(), |f| f.to_string());
                warn!(
                    location = %location,
                    fingerprint = %fingerprint,
                    action = "BLOCK",
                    "SQL injection detected"
                );
                let reason = format!("SQLi in {location}: {fingerprint}");
                self.notify_block("SQL Injection", &reason, SEVERITY_CRITICAL);
                return WafResult::blocked(reason, BLOCK_SCORE);
            }

            let xss_res = libinjectionrs::detect_xss(check_input.as_bytes());
            if xss_res.is_injection() {
                warn!(location = %location, action = "BLOCK", "XSS detected");
                let reason = format!("XSS in {location}");
                self.notify_block("XSS", &reason, SEVERITY_HIGH);
                return WafResult::blocked(reason, BLOCK_SCORE);
            }
        }

        WafResult::safe()
    }

    fn detect_path_traversal(input: &str) -> bool {
        let decoded = percent_decode_str(input).decode_utf8_lossy();
        let double_decoded = percent_decode_str(&decoded).decode_utf8_lossy();

        for check_input in [decoded.as_ref(), double_decoded.as_ref()] {
            if check_input.contains('\0') {
                return true;
            }

            let path = std::path::Path::new(check_input);
            let cleaned = path_clean::clean(path);
            let cleaned_str = cleaned.to_string_lossy();

            if cleaned_str.starts_with("..") {
                return true;
            }

            if cleaned_str.starts_with("/etc/")
                || cleaned_str.starts_with("/proc/")
                || cleaned_str.starts_with("/sys/")
            {
                return true;
            }

            if check_input.contains("../") || check_input.contains("..\\") {
                return true;
            }
        }

        false
    }

    fn detect_ssrf(&self, input: &str) -> bool {
        let decoded = percent_decode_str(input).decode_utf8_lossy();

        if self.is_dangerous_url(&decoded) {
            return true;
        }

        let parse_base = if decoded.starts_with('/') {
            format!("http://dummy{decoded}")
        } else {
            decoded.to_string()
        };

        if let Ok(parsed) = url::Url::parse(&parse_base) {
            for (_, value) in parsed.query_pairs() {
                let decoded_value = percent_decode_str(&value).decode_utf8_lossy();
                if self.is_dangerous_url(&decoded_value) {
                    return true;
                }
            }
        }

        let lower = decoded.to_lowercase();
        if lower.contains("c:\\windows\\") {
            return true;
        }

        false
    }

    fn is_dangerous_url(&self, input: &str) -> bool {
        let Ok(parsed_url) = url::Url::parse(input) else {
            return false;
        };

        let scheme = parsed_url.scheme();
        if scheme == "file" || scheme == "gopher" || scheme == "dict" || scheme == "ftp" {
            return true;
        }

        if scheme != "http" && scheme != "https" {
            return true;
        }

        let Some(host_str) = parsed_url.host_str() else {
            return false;
        };

        if !self.allowed_hosts.is_empty() {
            return !self.allowed_hosts.iter().any(|h| h == host_str);
        }

        if host_str == "localhost"
            || host_str == "127.0.0.1"
            || host_str == "::1"
            || host_str == "[::1]"
        {
            return true;
        }

        if let Ok(ip) = host_str.parse::<std::net::IpAddr>() {
            if ip.is_loopback() {
                return true;
            }

            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    if ipv4.is_private() || ipv4.is_link_local() || ipv4.is_unspecified() {
                        return true;
                    }
                    let octets = ipv4.octets();
                    if octets[0] == 169 && octets[1] == 254 {
                        return true;
                    }
                }
                std::net::IpAddr::V6(ipv6) => {
                    if (ipv6.segments()[0] & 0xfe00) == 0xfc00 {
                        return true;
                    }
                    if (ipv6.segments()[0] & 0xffc0) == 0xfe80 {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn notify_block(&self, attack_type: &str, reason: &str, severity: u8) {
        let full_message = format!("[{attack_type}] {reason}");
        self.webhook.notify(WebhookPayload {
            event_type: EventType::WafBlock,
            timestamp: i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )
            .unwrap_or(0),
            circuit_id: None,
            severity,
            message: full_message,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::webhook::WebhookNotifier;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    fn create_test_config() -> crate::config::Config {
        crate::config::Config {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            internal_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
            backend_url: "http://localhost:8080".to_string(),
            waf_mode: crate::config::WafMode::Normal,
            rate_limit_rps: 100,
            rate_limit_burst: 100,
            features: crate::config::FeatureFlags {
                captcha_enabled: true,
                webhook_enabled: false,
                waf_body_scan_enabled: false,
                coep_enabled: false,
            },
            captcha_secret: "secret".to_string(),
            captcha_ttl: 300,
            captcha_difficulty: "medium".to_string(),
            captcha_style: crate::config::CaptchaStyle::Simple,
            session_secret: "secret".to_string(),
            session_expiry_secs: 3600,
            tor_circuit_prefix: "fc00".to_string(),
            tor_control_addr: None,
            tor_control_password: None,
            torrc_path: None,
            defense_error_rate_threshold: 0.5,
            defense_circuit_flood_threshold: 10,
            defense_cooldown_secs: 5,
            webhook_url: None,
            max_captcha_failures: 3,
            captcha_gen_limit: 5,
            ssrf_allowed_hosts: vec![],
            waf_body_scan_max_size: 1024,
            rate_limit_session_rps: 10,
            rate_limit_session_burst: 20,
            app_name: "TestApp".to_string(),
            favicon_base64: String::new(),
            meta_title: "Test".to_string(),
            meta_description: "Test".to_string(),
            meta_keywords: "Test".to_string(),
            log_format: "json".to_string(),
            csp_extra_sources: String::new(),
            coop_policy: "same-origin-allow-popups".to_string(),
            honeypot_paths: std::collections::HashSet::new(),
            karma_threshold: 50,
            early_hints_links: Vec::new(),
        }
    }

    #[test]
    fn test_waf_scan_safe_input() {
        let config = Arc::new(create_test_config());
        let notifier = Arc::new(WebhookNotifier::new(&config));
        let engine = WafEngine::new(notifier, vec![]);

        let result = engine.scan("/safe/path?query=123", "test_loc");
        assert!(!result.blocked);
        assert_eq!(result.score, 0);
    }

    #[test]
    fn test_waf_scan_sql_injection() {
        let config = Arc::new(create_test_config());
        let notifier = Arc::new(WebhookNotifier::new(&config));
        let engine = WafEngine::new(notifier, vec![]);

        let result = engine.scan("/search?q=UNION SELECT 1", "test_loc");
        assert!(result.blocked);
        assert!(result.reason.unwrap().contains("Rule triggered"));
    }

    #[test]
    fn test_waf_scan_path_traversal() {
        let config = Arc::new(create_test_config());
        let notifier = Arc::new(WebhookNotifier::new(&config));
        let engine = WafEngine::new(notifier, vec![]);

        let result = engine.scan("/../../etc/passwd", "test_loc");
        assert!(result.blocked);
        let reason = result.reason.unwrap();
        assert!(reason.contains("Path Traversal") || reason.contains("Rule triggered"));
    }

    #[test]
    fn test_detect_path_traversal() {
        assert!(WafEngine::detect_path_traversal("../etc/passwd"));
        assert!(WafEngine::detect_path_traversal(
            "/var/log/../../etc/shadow"
        ));
        assert!(WafEngine::detect_path_traversal("%2e%2e/etc/passwd"));
        assert!(WafEngine::detect_path_traversal("/home/user/file\0.txt"));
        assert!(WafEngine::detect_path_traversal("..\\windows\\system32"));
        assert!(WafEngine::detect_path_traversal("/proc/self/environ"));
        assert!(!WafEngine::detect_path_traversal("/home/user/file.txt"));
    }

    #[test]
    fn test_detect_ssrf() {
        let config = Arc::new(create_test_config());
        let notifier = Arc::new(WebhookNotifier::new(&config));
        let engine = WafEngine::new(notifier, vec![]);

        assert!(engine.detect_ssrf("http://127.0.0.1/admin"));
        assert!(engine.detect_ssrf("file:///etc/passwd"));
        assert!(engine.detect_ssrf("gopher://localhost:6379"));
        assert!(engine.detect_ssrf("http://[::1]/"));
        assert!(engine.detect_ssrf("http://169.254.169.254/latest"));
        assert!(engine.detect_ssrf("c:\\windows\\system32\\drivers\\etc\\hosts"));
        assert!(engine.detect_ssrf("/?url=http://127.0.0.1"));
        assert!(!engine.detect_ssrf("https://example.com"));
        assert!(!engine.detect_ssrf("/search?q=rust"));
    }

    #[test]
    fn test_is_dangerous_url() {
        let config = Arc::new(create_test_config());
        let notifier = Arc::new(WebhookNotifier::new(&config));
        let engine = WafEngine::new(notifier, vec![]);

        assert!(engine.is_dangerous_url("file:///etc/passwd"));
        assert!(engine.is_dangerous_url("http://localhost"));
        assert!(engine.is_dangerous_url("http://127.0.0.1"));
        assert!(engine.is_dangerous_url("http://[::1]"));
        assert!(engine.is_dangerous_url("http://169.254.169.254/latest/meta-data/"));
        assert!(engine.is_dangerous_url("ftp://example.com"));
        assert!(engine.is_dangerous_url("dict://example.com"));
        assert!(engine.is_dangerous_url("http://0.0.0.0"));
        assert!(!engine.is_dangerous_url("https://example.com"));
    }

    #[test]
    fn test_libinjection_wrapper() {
        let config = Arc::new(create_test_config());
        let notifier = Arc::new(WebhookNotifier::new(&config));
        let engine = WafEngine::new(notifier, vec![]);

        let result = engine.scan("/login?user=' OR 1=1--", "test_loc");
        assert!(result.blocked);
    }

    #[test]
    fn test_waf_scan_sql_injection_plus_blocked() {
        let config = Arc::new(create_test_config());
        let notifier = Arc::new(WebhookNotifier::new(&config));
        let engine = WafEngine::new(notifier, vec![]);

        let result = engine.scan("/search?q=UNION+SELECT+1", "test_loc");

        assert!(result.blocked);
    }
}
