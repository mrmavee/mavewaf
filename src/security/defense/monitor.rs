//! Defense monitoring.
//!
//! Tracks error rates and circuit usage to trigger defensive countermeasures.

use crate::config::{Config, WafMode};
use papaya::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Monitors traffic patterns and triggers defense mode when thresholds are exceeded.
pub struct DefenseMonitor {
    config: Arc<Config>,
    error_count: AtomicU64,
    request_count: AtomicU64,
    circuit_counts: HashMap<String, AtomicU64>,
    circuit_karma: HashMap<String, AtomicU32>,
    last_reset: std::sync::Mutex<Instant>,
    last_reset_epoch: AtomicU64,
    current_mode: std::sync::atomic::AtomicU8,
    defense_activated_at: AtomicU64,
}

impl DefenseMonitor {
    /// Creates a new `DefenseMonitor`.
    #[must_use]
    pub fn new(config: Arc<Config>) -> Self {
        let initial_mode = match config.waf_mode {
            WafMode::Normal => 0,
            WafMode::Defense => 1,
        };
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let defense_activated_at = if initial_mode == 1 { now_epoch } else { 0 };

        Self {
            config,
            error_count: AtomicU64::new(0),
            request_count: AtomicU64::new(0),
            circuit_counts: HashMap::new(),
            circuit_karma: HashMap::new(),
            last_reset: std::sync::Mutex::new(Instant::now()),
            last_reset_epoch: AtomicU64::new(now_epoch),
            current_mode: std::sync::atomic::AtomicU8::new(initial_mode),
            defense_activated_at: AtomicU64::new(defense_activated_at),
        }
    }

    /// Records a request and updates statistics.
    pub fn record_request(&self, circuit_id: Option<&str>, is_error: bool) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        if is_error {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }

        if let Some(circuit) = circuit_id {
            let circuit_counts = self.circuit_counts.pin();
            if let Some(count) = circuit_counts.get(circuit) {
                count.fetch_add(1, Ordering::Relaxed);
            } else {
                circuit_counts.insert(circuit.to_string(), AtomicU64::new(1));
            }
        }

        self.check_thresholds();
    }

    fn check_thresholds(&self) {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last_check = self.last_reset_epoch.load(Ordering::Relaxed);
        if now_epoch.saturating_sub(last_check) < 60 {
            return;
        }

        let mut last_reset = self.last_reset.lock().unwrap();
        if last_reset.elapsed() < Duration::from_secs(60) {
            return;
        }

        let requests = self.request_count.load(Ordering::Relaxed);
        let errors = self.error_count.load(Ordering::Relaxed);
        let mut should_activate = false;

        if requests > 0 {
            let req_f64 = f64::from(u32::try_from(requests).unwrap_or(u32::MAX));
            let err_f64 = f64::from(u32::try_from(errors).unwrap_or(u32::MAX));
            let error_rate = err_f64 / req_f64;
            if error_rate > self.config.defense_error_rate_threshold {
                should_activate = true;
            }
        }

        let circuit_counts = self.circuit_counts.pin();
        for entry in &circuit_counts {
            let count = entry.1.load(Ordering::Relaxed);
            if count > u64::from(self.config.defense_circuit_flood_threshold) {
                should_activate = true;
                break;
            }
        }

        if should_activate {
            self.activate_defense(now_epoch);
        } else {
            self.try_deactivate(now_epoch);
        }

        self.error_count.store(0, Ordering::Relaxed);
        self.request_count.store(0, Ordering::Relaxed);
        self.circuit_counts.pin().clear();
        self.last_reset_epoch.store(now_epoch, Ordering::Relaxed);
        *last_reset = Instant::now();
    }

    fn activate_defense(&self, now: u64) {
        let was_normal = self.current_mode.swap(1, Ordering::Relaxed) == 0;
        if was_normal {
            self.defense_activated_at.store(now, Ordering::Relaxed);
            tracing::warn!(activated_at = now, "Defense mode activated");
        }
    }

    fn try_deactivate(&self, now: u64) {
        if self.config.waf_mode == WafMode::Defense {
            return;
        }

        let activated_at = self.defense_activated_at.load(Ordering::Relaxed);
        if activated_at == 0 {
            return;
        }

        let elapsed = now.saturating_sub(activated_at);
        if elapsed >= self.config.defense_cooldown_secs {
            self.current_mode.store(0, Ordering::Relaxed);
            self.defense_activated_at.store(0, Ordering::Relaxed);
            tracing::info!(cooldown_secs = elapsed, "Defense mode deactivated");
        }
    }

    /// Checks if a circuit has exceeded the flood threshold.
    pub fn check_circuit_flood(&self, circuit_id: &str) -> bool {
        let circuit_counts = self.circuit_counts.pin();
        if let Some(count) = circuit_counts.get(circuit_id) {
            let current = count.load(Ordering::Relaxed);
            if current > u64::from(self.config.defense_circuit_flood_threshold) {
                tracing::warn!(
                    circuit_id = circuit_id,
                    count = current,
                    threshold = self.config.defense_circuit_flood_threshold,
                    "Circuit flood threshold exceeded"
                );
                return true;
            }
        }
        false
    }

    /// Checks if defense mode is currently active.
    #[must_use]
    pub fn is_defense_mode(&self) -> bool {
        self.current_mode.load(Ordering::Relaxed) == 1
    }

    /// Returns the timestamp when defense mode was activated, or 0 if inactive.
    #[must_use]
    pub fn defense_started_at(&self) -> u64 {
        self.defense_activated_at.load(Ordering::Relaxed)
    }

    /// Returns the current operational WAF mode.
    #[must_use]
    pub fn current_mode(&self) -> WafMode {
        if self.current_mode.load(Ordering::Relaxed) == 1 {
            WafMode::Defense
        } else {
            WafMode::Normal
        }
    }

    pub fn add_karma(&self, circuit_id: &str, points: u32) -> u32 {
        let karma = self.circuit_karma.pin();
        karma.get(circuit_id).map_or_else(
            || {
                karma.insert(circuit_id.to_string(), AtomicU32::new(points));
                points
            },
            |score| score.fetch_add(points, Ordering::Relaxed) + points,
        )
    }

    #[must_use]
    pub fn get_karma(&self, circuit_id: &str) -> u32 {
        self.circuit_karma
            .pin()
            .get(circuit_id)
            .map_or(0, |v| v.load(Ordering::Relaxed))
    }

    #[must_use]
    pub fn check_karma_threshold(&self, circuit_id: &str) -> bool {
        let karma = self.get_karma(circuit_id);
        karma >= self.config.karma_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_test_config() -> Arc<Config> {
        Arc::new(Config {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            internal_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
            backend_url: "http://localhost:8080".to_string(),
            waf_mode: WafMode::Normal,
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
            log_format: "pretty".to_string(),
            csp_extra_sources: String::new(),
            coop_policy: "same-origin-allow-popups".to_string(),
            honeypot_paths: std::collections::HashSet::new(),
            karma_threshold: 50,
            early_hints_links: Vec::new(),
        })
    }

    #[test]
    fn test_initial_state() {
        let config = create_test_config();
        let monitor = DefenseMonitor::new(config);
        assert!(!monitor.is_defense_mode());
        assert_eq!(monitor.defense_started_at(), 0);
    }

    #[test]
    fn test_initial_defense_mode() {
        let mut config_inner = Arc::unwrap_or_clone(create_test_config());
        config_inner.waf_mode = WafMode::Defense;
        let config = Arc::new(config_inner);

        let monitor = DefenseMonitor::new(config);
        assert!(monitor.is_defense_mode());
        assert!(monitor.defense_started_at() > 0);
    }

    #[test]
    fn test_circuit_flood_detection() {
        let config = create_test_config();
        let monitor = DefenseMonitor::new(config);
        let circuit_id = "circuit_123";

        for _ in 0..10 {
            monitor.record_request(Some(circuit_id), false);
        }
        assert!(!monitor.check_circuit_flood(circuit_id));

        monitor.record_request(Some(circuit_id), false);
        assert!(monitor.check_circuit_flood(circuit_id));
    }

    #[test]
    fn test_defense_activation_on_error_rate() {
        let config = create_test_config();
        let monitor = DefenseMonitor::new(config);

        for _ in 0..4 {
            monitor.record_request(None, false);
        }
        for _ in 0..6 {
            monitor.record_request(None, true);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        monitor.last_reset_epoch.store(now - 62, Ordering::Relaxed);
        *monitor.last_reset.lock().unwrap() =
            Instant::now().checked_sub(Duration::from_secs(62)).unwrap();

        monitor.record_request(None, false);

        assert!(monitor.is_defense_mode());
        assert!(monitor.defense_started_at() > 0);
    }

    #[test]
    fn test_auto_deactivation() {
        let config = create_test_config();
        let monitor = DefenseMonitor::new(config);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        monitor.activate_defense(now - 10);

        assert!(monitor.is_defense_mode());

        monitor.try_deactivate(now);

        assert!(!monitor.is_defense_mode());
        assert_eq!(monitor.defense_started_at(), 0);
    }

    #[test]
    fn test_karma_accumulation() {
        let config = create_test_config();
        let monitor = DefenseMonitor::new(config);

        assert_eq!(monitor.get_karma("circuit_1"), 0);

        let total = monitor.add_karma("circuit_1", 10);
        assert_eq!(total, 10);
        assert_eq!(monitor.get_karma("circuit_1"), 10);

        let total2 = monitor.add_karma("circuit_1", 25);
        assert_eq!(total2, 35);
        assert_eq!(monitor.get_karma("circuit_1"), 35);

        assert!(!monitor.check_karma_threshold("circuit_1"));

        monitor.add_karma("circuit_1", 20);
        assert!(monitor.check_karma_threshold("circuit_1"));
    }
}
