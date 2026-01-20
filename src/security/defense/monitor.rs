//! Defense monitoring.
//!
//! Tracks error rates and circuit usage to trigger defensive countermeasures.

use crate::config::{Config, WafMode};
use papaya::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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
    attack_kill_count: AtomicU64,
    attack_window_start: AtomicU64,
    attack_unverified_count: AtomicU64,
    attack_circuits: HashMap<String, ()>,
    attack_request_count: AtomicU64,
    pow_enabled: AtomicBool,
    pow_enabled_at: AtomicU64,
    last_score_check: AtomicU64,
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
            attack_kill_count: AtomicU64::new(0),
            attack_window_start: AtomicU64::new(now_epoch),
            attack_unverified_count: AtomicU64::new(0),
            attack_circuits: HashMap::new(),
            attack_request_count: AtomicU64::new(0),
            pow_enabled: AtomicBool::new(false),
            pow_enabled_at: AtomicU64::new(0),
            last_score_check: AtomicU64::new(0),
        }
    }

    /// Records a request and updates statistics.
    pub fn record_request(&self, circuit_id: Option<&str>, is_error: bool) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        self.attack_request_count.fetch_add(1, Ordering::Relaxed);
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
            self.attack_circuits.pin().insert(circuit.to_string(), ());
        }

        self.check_thresholds();
    }

    pub fn is_circuit_blocked(&self, circuit_id: &str) -> bool {
        let karma_map = self.circuit_karma.pin();
        if let Some(karma) = karma_map.get(circuit_id) {
            let score = karma.load(Ordering::Relaxed);
            return score >= self.config.karma_threshold;
        }
        false
    }

    /// Checks if defense thresholds have been exceeded.
    ///
    /// # Panics
    ///
    /// Panics if the `last_reset` mutex is poisoned.
    pub fn check_thresholds(&self) {
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
        self.circuit_karma.pin().clear();
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

    pub fn record_circuit_kill(&self) {
        self.attack_kill_count.fetch_add(1, Ordering::Relaxed);
        self.reset_attack_window_if_needed();
    }

    pub fn record_unverified_request(&self) {
        self.attack_unverified_count.fetch_add(1, Ordering::Relaxed);
    }

    fn reset_attack_window_if_needed(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_start = self.attack_window_start.load(Ordering::Relaxed);
        if now.saturating_sub(window_start) >= 60 {
            self.attack_kill_count.store(0, Ordering::Relaxed);
            self.attack_unverified_count.store(0, Ordering::Relaxed);
            self.attack_request_count.store(0, Ordering::Relaxed);
            self.attack_circuits.pin().clear();
            self.attack_window_start.store(now, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn calculate_attack_score(&self) -> f64 {
        self.reset_attack_window_if_needed();

        let raw_requests = self.attack_request_count.load(Ordering::Relaxed);
        let circuits_seen = u32::try_from(self.attack_circuits.pin().len()).unwrap_or(u32::MAX);
        let kills =
            u32::try_from(self.attack_kill_count.load(Ordering::Relaxed)).unwrap_or(u32::MAX);
        let unverified =
            u32::try_from(self.attack_unverified_count.load(Ordering::Relaxed)).unwrap_or(u32::MAX);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_start = self.attack_window_start.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(window_start);

        if elapsed < 10 || (raw_requests < 10 && kills == 0 && unverified == 0) {
            return 0.0;
        }

        let requests_u32 = u32::try_from(raw_requests.max(1)).unwrap_or(u32::MAX);
        let elapsed_secs = f64::from(u32::try_from(elapsed.max(1)).unwrap_or(u32::MAX));

        let churn_rate = (f64::from(circuits_seen) * 60.0) / elapsed_secs;
        let request_rate = f64::from(requests_u32) / elapsed_secs;
        let avg_requests_per_circuit = if circuits_seen > 0 {
            f64::from(requests_u32) / f64::from(circuits_seen)
        } else {
            100.0
        };
        let kills_per_min = (f64::from(kills) * 60.0) / elapsed_secs;
        let unverified_ratio = if requests_u32 > 0 {
            f64::from(unverified) / f64::from(requests_u32)
        } else {
            0.0
        };

        let churn_factor = (churn_rate / f64::from(self.config.attack_churn_threshold)).min(2.0);
        let request_rate_factor =
            (request_rate / f64::from(self.config.attack_rps_threshold)).min(2.0);
        let low_circuit_usage_factor = if circuits_seen >= 5
            && avg_requests_per_circuit < f64::from(self.config.attack_rpc_threshold)
        {
            ((f64::from(self.config.attack_rpc_threshold) - avg_requests_per_circuit)
                / f64::from(self.config.attack_rpc_threshold))
            .min(1.0)
        } else {
            0.0
        };
        let kill_factor =
            (kills_per_min / f64::from(self.config.defense_circuit_flood_threshold)).min(2.0);

        churn_factor.mul_add(1.5, request_rate_factor)
            + low_circuit_usage_factor * 2.0
            + kill_factor * 1.5
            + unverified_ratio * 0.5
    }

    #[must_use]
    pub fn should_enable_pow(&self) -> Option<u32> {
        if self.pow_enabled.load(Ordering::Relaxed) {
            return None;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last_check = self.last_score_check.load(Ordering::Relaxed);
        if now.saturating_sub(last_check) < 5 {
            return None;
        }
        self.last_score_check.store(now, Ordering::Relaxed);

        let score = self.calculate_attack_score();
        if score >= self.config.attack_pow_score {
            Some(self.config.attack_pow_effort)
        } else {
            None
        }
    }

    pub fn mark_pow_enabled(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.pow_enabled.store(true, Ordering::Relaxed);
        self.pow_enabled_at.store(now, Ordering::Relaxed);
        if !self.is_defense_mode() {
            self.activate_defense(now);
        }
        tracing::warn!(
            score = self.calculate_attack_score(),
            "Tor PoW enabled due to attack"
        );
    }

    #[must_use]
    pub fn should_disable_pow(&self) -> bool {
        if !self.pow_enabled.load(Ordering::Relaxed) {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last_check = self.last_score_check.load(Ordering::Relaxed);
        if now.saturating_sub(last_check) < 5 {
            return false;
        }
        self.last_score_check.store(now, Ordering::Relaxed);

        let enabled_at = self.pow_enabled_at.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(enabled_at);
        let score = self.calculate_attack_score();
        elapsed >= self.config.attack_recovery_secs && score < self.config.attack_defense_score
    }

    pub fn mark_pow_disabled(&self) {
        self.pow_enabled.store(false, Ordering::Relaxed);
        self.pow_enabled_at.store(0, Ordering::Relaxed);
        tracing::info!("Tor PoW disabled, attack subsided");
    }

    #[must_use]
    pub fn should_auto_defense(&self) -> bool {
        let score = self.calculate_attack_score();
        score >= self.config.attack_defense_score
    }

    pub fn enable_auto_defense(&self) -> bool {
        if self.is_defense_mode() {
            return false;
        }
        if self.should_auto_defense() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.activate_defense(now);
            return true;
        }
        false
    }

    #[must_use]
    pub fn is_pow_enabled(&self) -> bool {
        self.pow_enabled.load(Ordering::Relaxed)
    }
}

#[cfg(any(test, feature = "testing"))]
impl DefenseMonitor {
    pub fn simulate_elapsed_time(&self, seconds: u64) {
        let current = self.attack_window_start.load(Ordering::Relaxed);
        self.attack_window_start
            .store(current.saturating_sub(seconds), Ordering::Relaxed);
    }

    pub fn simulate_pow_elapsed(&self, seconds: u64) {
        let current = self.pow_enabled_at.load(Ordering::Relaxed);
        self.pow_enabled_at
            .store(current.saturating_sub(seconds), Ordering::Relaxed);
        let last_check = self.last_score_check.load(Ordering::Relaxed);
        self.last_score_check
            .store(last_check.saturating_sub(10), Ordering::Relaxed);
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
    #[test]
    fn test_karma_cleanup() {
        let config = create_test_config();
        let monitor = DefenseMonitor::new(config);

        monitor.add_karma("circuit_dirty", 100);
        assert_eq!(monitor.get_karma("circuit_dirty"), 100);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        monitor.last_reset_epoch.store(now - 65, Ordering::Relaxed);
        *monitor.last_reset.lock().unwrap() =
            Instant::now().checked_sub(Duration::from_secs(65)).unwrap();

        monitor.check_thresholds();

        assert_eq!(monitor.get_karma("circuit_dirty"), 0);
    }
}
