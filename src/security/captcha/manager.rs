//! CAPTCHA lifecycle management.
//!
//! Coordinates CAPTCHA generation, storage, and verification.

use crate::config::Config;
use crate::security::captcha::generator::{CaptchaGenerator, CharPosition, Difficulty};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

pub struct CachedCaptcha {
    pub passcode: String,
    pub img: String,
    pub pos: Vec<CharPosition>,
}

pub struct CaptchaManager {
    generator: Arc<CaptchaGenerator>,
    queue: Arc<Mutex<VecDeque<CachedCaptcha>>>,
    condvar: Arc<Condvar>,
}

impl CaptchaManager {
    /// Creates a new `CaptchaManager` with configuration.
    #[must_use]
    pub fn new(config: &Arc<Config>) -> Self {
        let difficulty: Difficulty = config
            .captcha_difficulty
            .parse()
            .unwrap_or(Difficulty::Medium);
        Self {
            generator: Arc::new(CaptchaGenerator::new(
                &config.captcha_secret,
                config.captcha_ttl,
                difficulty,
                config.captcha_style,
            )),
            queue: Arc::new(Mutex::new(VecDeque::with_capacity(50))),
            condvar: Arc::new(Condvar::new()),
        }
    }

    /// Starts the background worker to refill the captcha queue.
    ///
    /// # Panics
    ///
    /// Panics if the `queue` mutex is poisoned or if the condition variable fails.
    pub fn start_worker(&self) {
        let generator = self.generator.clone();
        let queue = self.queue.clone();
        let condvar = self.condvar.clone();

        thread::spawn(move || {
            loop {
                let mut lock = queue.lock().unwrap();
                if lock.len() >= 50 {
                    lock = condvar.wait(lock).unwrap();
                }
                drop(lock);

                if let Ok((passcode, img, pos)) = generator.generate() {
                    let cached = CachedCaptcha { passcode, img, pos };
                    let mut lock = queue.lock().unwrap();
                    lock.push_back(cached);
                }
            }
        });
    }

    /// Generates a new CAPTCHA challenge.
    ///
    /// Tries to retrieve a cached CAPTCHA from the queue. If the queue is empty,
    /// falls back to generating one on-demand.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying generator fails to create or encode the CAPTCHA image.
    ///
    /// # Panics
    ///
    /// Panics if the `queue` mutex is poisoned.
    pub fn generate(&self) -> Result<(String, String, Vec<CharPosition>), String> {
        let mut lock = self.queue.lock().unwrap();
        if let Some(cached) = lock.pop_front() {
            self.condvar.notify_one();
            let token = self.generator.create_token(&cached.passcode);
            return Ok((token, cached.img, cached.pos));
        }
        drop(lock);

        let (passcode, img, pos) = self.generator.generate()?;
        let token = self.generator.create_token(&passcode);
        Ok((token, img, pos))
    }

    /// Verifies a CAPTCHA solution against a token.
    #[must_use]
    pub fn verify(&self, token: &str, answer: &str) -> bool {
        self.generator.verify(token, answer)
    }

    /// Creates a token for a given input.
    #[must_use]
    pub fn create_token(&self, input: &str) -> String {
        self.generator.create_token(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CaptchaStyle, WafMode};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_config() -> Arc<Config> {
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
            captcha_style: CaptchaStyle::Simple,
            session_secret: "secret".to_string(),
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
        })
    }

    #[test]
    fn test_manager_access() {
        let config = create_config();
        let manager = CaptchaManager::new(&config);

        let token = manager.generator.create_token("ABCDEF");
        assert!(manager.verify(&token, "ABCDEF"));
    }

    #[test]
    fn test_manager_worker_init() {
        let config = create_config();
        let manager = CaptchaManager::new(&config);

        manager.start_worker();

        std::thread::sleep(std::time::Duration::from_millis(50));

        let res = manager.generate();
        assert!(res.is_ok());
    }
}
