//! Configuration settings.
//!
//! Defines the main `Config` struct and environment variable loading logic.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// WAF operational mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafMode {
    /// Normal operation with minimal filtering.
    Normal,
    /// Defense mode with aggressive filtering and CAPTCHA.
    Defense,
}

impl WafMode {
    fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "DEFENSE" => Self::Defense,
            _ => Self::Normal,
        }
    }
}

fn get_env(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("{key} must be set in environment"))
}

fn get_env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn get_env_bool(key: &str) -> bool {
    env::var(key)
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

fn get_env_u32(key: &str) -> u32 {
    get_env(key)
        .parse()
        .unwrap_or_else(|_| panic!("{key} must be a valid u32"))
}

fn get_env_f64(key: &str) -> f64 {
    get_env(key)
        .parse()
        .unwrap_or_else(|_| panic!("{key} must be a valid f64"))
}

fn get_env_u64_or(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn get_env_u32_or(key: &str, default: u32) -> u32 {
    env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn get_env_u8_or(key: &str, default: u8) -> u8 {
    env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn get_env_usize_or(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Feature toggles for optional functionality.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
pub struct FeatureFlags {
    /// Whether CAPTCHA is enabled.
    pub captcha_enabled: bool,
    /// Whether webhook notifications are enabled.
    pub webhook_enabled: bool,
    /// Whether to scan request bodies for WAF signatures.
    pub waf_body_scan_enabled: bool,
    /// Enable Cross-Origin-Embedder-Policy header.
    pub coep_enabled: bool,
}

/// CAPTCHA visual style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaStyle {
    Complex,
    Simple,
}

impl CaptchaStyle {
    fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "SIMPLE" => Self::Simple,
            _ => Self::Complex,
        }
    }
}

/// Application configuration loaded from environment.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to listen on (external, receives PROXY protocol).
    pub listen_addr: SocketAddr,
    /// Internal address for Pingora HTTP processing.
    pub internal_addr: SocketAddr,
    /// Backend URL to proxy requests to.
    pub backend_url: String,
    /// Current WAF mode.
    pub waf_mode: WafMode,
    /// Requests per second limit per circuit.
    pub rate_limit_rps: u32,
    /// Burst capacity for rate limiting.
    pub rate_limit_burst: u32,
    /// Feature flags for optional functionality.
    pub features: FeatureFlags,
    /// Secret key for CAPTCHA HMAC signing.
    pub captcha_secret: String,
    /// Captcha TTL in seconds.
    pub captcha_ttl: u64,
    /// Captcha difficulty level (easy/medium/hard).
    pub captcha_difficulty: String,
    /// Captcha visual style (complex/simple).
    pub captcha_style: CaptchaStyle,
    /// Secret key for session cookie signing.
    pub session_secret: String,
    /// Session cookie expiry in seconds.
    pub session_expiry_secs: u64,
    /// Tor circuit ID prefix for identification.
    pub tor_circuit_prefix: String,
    /// Tor control port address.
    pub tor_control_addr: Option<SocketAddr>,
    /// Tor control password.
    pub tor_control_password: Option<String>,
    /// Path to torrc configuration file.
    pub torrc_path: Option<PathBuf>,
    /// Error rate threshold to trigger defense mode.
    pub defense_error_rate_threshold: f64,
    /// Circuit flood threshold to trigger defense mode.
    pub defense_circuit_flood_threshold: u32,
    /// Seconds after which defense mode auto-deactivates if traffic normalizes.
    pub defense_cooldown_secs: u64,
    /// Webhook URL for security notifications.
    pub webhook_url: Option<String>,
    /// Maximum captcha failures before redirect to queue.
    pub max_captcha_failures: u8,
    /// Maximum captcha generations allowed per session (anti-spam).
    pub captcha_gen_limit: u8,
    /// List of allowed hosts for SSRF protection.
    pub ssrf_allowed_hosts: Vec<String>,
    /// Maximum body size to scan in bytes (default 32KB).
    pub waf_body_scan_max_size: usize,
    /// Requests per second limit per session.
    pub rate_limit_session_rps: u32,
    /// Burst capacity for session rate limiting.
    pub rate_limit_session_burst: u32,
    /// Application name for footer/branding.
    pub app_name: String,
    /// Base64 encoded favicon/logo (data URI).
    pub favicon_base64: String,
    /// Meta title for WAF pages (SEO).
    pub meta_title: String,
    /// Meta description for WAF pages (SEO).
    pub meta_description: String,
    /// Meta keywords for WAF pages (SEO, optional).
    pub meta_keywords: String,
    /// Logging format: "json" or "pretty".
    pub log_format: String,
    /// Extra CSP sources to allow (e.g., `https://cdn.example.com`).
    pub csp_extra_sources: String,
    /// Cross-Origin-Opener-Policy: "same-origin", "same-origin-allow-popups", or "unsafe-none".
    pub coop_policy: String,
}

impl Config {
    /// Loads configuration from environment variables.
    ///
    /// # Panics
    ///
    /// Panics if any of the following environment variables are missing or invalid:
    /// - `LISTEN_ADDR` (must be a valid socket address)
    /// - `INTERNAL_ADDR` (must be a valid socket address)
    /// - `BACKEND_URL` (must be set)
    /// - `CAPTCHA_SECRET` (must be set)
    /// - `SESSION_SECRET` (must be set)
    /// - `TOR_CIRCUIT_PREFIX` (must be set)
    /// - `RATE_LIMIT_RPS` or `RATE_LIMIT_BURST` (must be valid u32)
    /// - `DEFENSE_ERROR_RATE_THRESHOLD` (must be valid f64)
    /// - `DEFENSE_CIRCUIT_FLOOD_THRESHOLD` (must be valid u32)
    #[must_use]
    pub fn from_env() -> Arc<Self> {
        let listen_addr = get_env_or("LISTEN_ADDR", "0.0.0.0:8080")
            .parse()
            .expect("LISTEN_ADDR must be a valid socket address");
        let internal_addr = get_env_or("INTERNAL_ADDR", "127.0.0.1:8081")
            .parse()
            .expect("INTERNAL_ADDR must be a valid socket address");
        let backend_url = get_env("BACKEND_URL");
        let waf_mode = WafMode::from_str(&get_env_or("WAF_MODE", "NORMAL"));
        let rate_limit_rps = get_env_u32("RATE_LIMIT_RPS");
        let rate_limit_burst = get_env_u32("RATE_LIMIT_BURST");
        let captcha_secret = get_env("CAPTCHA_SECRET");
        let captcha_ttl = get_env("CAPTCHA_TTL").parse().unwrap_or(300);
        let captcha_difficulty = get_env_or("CAPTCHA_DIFFICULTY", "medium");
        let captcha_style = CaptchaStyle::from_str(&get_env_or("CAPTCHA_STYLE", "complex"));
        let session_secret = get_env("SESSION_SECRET");
        let session_expiry_secs = get_env_u64_or("SESSION_EXPIRY_SECS", 3600);
        let tor_circuit_prefix = get_env("TOR_CIRCUIT_PREFIX");
        let tor_control_addr = env::var("TOR_CONTROL_ADDR")
            .ok()
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse().ok());
        let tor_control_password = env::var("TOR_CONTROL_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty());
        let torrc_path = env::var("TORRC_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let defense_error_rate_threshold = get_env_f64("DEFENSE_ERROR_RATE_THRESHOLD");
        let defense_circuit_flood_threshold = get_env_u32("DEFENSE_CIRCUIT_FLOOD_THRESHOLD");
        let defense_cooldown_secs = get_env_u64_or("DEFENSE_COOLDOWN_SECS", 300);
        let features = FeatureFlags {
            captcha_enabled: get_env_bool("CAPTCHA_ENABLED"),
            webhook_enabled: get_env_bool("WEBHOOK_ENABLED"),
            waf_body_scan_enabled: get_env_bool("WAF_BODY_SCAN_ENABLED"),
            coep_enabled: get_env_bool("COEP_ENABLED"),
        };
        let webhook_url = env::var("WEBHOOK_URL").ok().filter(|s| !s.is_empty());
        let waf_body_scan_max_size = get_env_usize_or("WAF_BODY_SCAN_MAX_SIZE", 32768);
        let rate_limit_session_rps = get_env_u32_or("RATE_LIMIT_SESSION_RPS", 3);
        let rate_limit_session_burst = get_env_u32_or("RATE_LIMIT_SESSION_BURST", 5);
        let app_name = get_env_or("APP_NAME", "");
        let favicon_base64 = Self::load_logo();

        Arc::new(Self {
            listen_addr,
            internal_addr,
            backend_url,
            waf_mode,
            rate_limit_rps,
            rate_limit_burst,
            features,
            captcha_secret,
            captcha_ttl,
            captcha_difficulty,
            captcha_style,
            session_secret,
            session_expiry_secs,
            tor_circuit_prefix,
            tor_control_addr,
            tor_control_password,
            torrc_path,
            defense_error_rate_threshold,
            defense_circuit_flood_threshold,
            defense_cooldown_secs,
            webhook_url,
            max_captcha_failures: get_env_u8_or("MAX_CAPTCHA_FAILURES", 3),
            captcha_gen_limit: get_env_u8_or("CAPTCHA_GEN_LIMIT", 5),
            ssrf_allowed_hosts: get_env_or("SSRF_ALLOWED_HOSTS", "")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            waf_body_scan_max_size,
            rate_limit_session_rps,
            rate_limit_session_burst,
            app_name,
            favicon_base64,
            meta_title: get_env_or("META_TITLE", "Security Check"),
            meta_description: get_env_or("META_DESCRIPTION", "Protected by MaveWAF"),
            meta_keywords: get_env_or("META_KEYWORDS", ""),
            log_format: get_env_or("LOG_FORMAT", "json"),
            csp_extra_sources: get_env_or("CSP_EXTRA_SOURCES", ""),
            coop_policy: get_env_or("COOP_POLICY", "same-origin-allow-popups"),
        })
    }

    fn load_logo() -> String {
        use base64::prelude::*;
        env::var("LOGO_PATH").map_or_else(
            |_| {
                "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAABmJLR0QA/wD/AP+gvaeTAAAFBElEQVR4nO1aO2xcRRQ9d2bXBoIlikWJZKFQUaAoLlxAAcLaROaTNRKfLSLLEcgdNe7dRZS4QojOyMJV5MIr2tR0UGwTCVAoFu9GiAJkK7tzKfa99fvMfbtzs34ueKdJNKuZe+fM3HNm5hmoUKFChQoVKlSoUKFChRmwtsu1y85BwtpaeG4mtMPjPwYrr20Pvgjtd9HYunOyff3KYCW0XzABdQCGee/G5/1WaN+LwubGk3UA32j6BhMAAMSwzDi4ce/Pm5r+88Tm+09eN250SAxVaYYT8HTciYAlItNZuTdY1gSeBz774OSaMa5DjJcM68bQ7gAQAwZYJvDRza3eFV14Pdrtx88PDR4Q83UCQADqT8PHUWlAHJAYIGC1DvtDu802PLwOu7tsFv5d/N44vEkATLQgGgQTMCT3CnEU9Dx46/fFwX1dCuF49NPgK8P4eLIIUS5D5quhYwUTQGRfjANO/h3/f+eNzYu3x607J9vE/KXBpAzPc6nhhdDxVBqQCp5YAcO899bmxdljbHeTuEjpETQ1GEyAFDxqs3A4ePvu/O0xaXeULr9JLnYUPm74DhglgiNdClFCS4ZNp9menz1m7S5bfnGbBsEEWKRZT4khJu3LbPlofQ726LO75K5LEqKBagekygB+Qshh1Z0+mz1KducR4PI0ILkDTFYDOLNCQOtvp7dHye4yFlyuBlikBTClAcgTYgg7730abo+Fdgc/IRqoj8JxQsaTUI4Q5r2Nj2a3x2l2JxGigY4A5CecE8P0ClkABx9+Mt0eZ7E7LyFc4jkgV/soEMPz35esM512S7bHWe1OEkOUogFO9H8vIckVAmPZWT7aWs/bY4jdSYRooNcAwY6mEULA6ulzaXsMtTuf3pQugoUrlBXDbBujVTs7t8dQu8uJYdSm0YDgZ6QFFK9GkTtMJgQADjt3Nwa/1Zw7Q6DdSWKokADFO9rIs+WFhOPEFkbcGxqyBLycmpDjr+Hv3x8Z/GNHeNVHiHD8VtWB2gbFFc7WPgN1R39ZS+8Qo5fWDq557K5vrLs1JPQlu5MIKec2KASfJoaHDxpdOGoaoDduY1//vrHu1reda78AntpPjO8rv9LuAtPsLqfOkUUdHje6hqlJ4J6nf9+YzOQxRQwTuahWUkMAksEL7E46oe0fN7oE0yRE5RCtPMC348nHiUl2JzlOeQQIyfnsyqdL+8eNriPTJEaPgD6Bb3/349WffTGk5zefGJb6JDar3Unbc/+40TXgd32TBwB4xC5HSOZ3zaeh4D7SdbjIv8n5x/JOPI5TYHc+Qko9CUp2J58MwwvUN+FCMSzLBbwHoUIxZGi+2xXVviSGGqifxGbxf4q8XrU9XWZMyITE5VfOk9gou8ISIZw++ysSm+m1KfF7Ke8BgKcGs6vBnPs9FEV2lyMkilv6l6Gs3Ul2pUFKVzCFEJSoAfAklCaEc4RogqS0RRDYLCEa6EUwEzwleh53CEWR3UliWI4NQrY70R2Eg1ARZjn7X8plyPdlKGl3WXd4ltqU7O5yL0MZf07ZnbBCVrMDINudRIgG4XeB0TiqZHcpd0i0haLI7kQLLuOPpLLJzfKYqToHuOLLkO/4rYH+IOSxuyJCdDEyK+wT2AQhGgSXwKKpP3LurEtu3DleKRufxiIiLAPGjdsWHD8MjeOIH55aGscYAYYSV2QCOIrBNM6BABiiX0PjVKhQoUKF/zP+A5KXL3I9XEqCAAAAAElFTkSuQmCC".to_string()
            },
            |path| {
                let data = std::fs::read(&path)
                    .unwrap_or_else(|e| panic!("Failed to read LOGO_PATH '{path}': {e}"));

                assert!(
                    data.len() <= 10 * 1024 * 1024,
                    "LOGO_PATH file '{path}' exceeds 10MB limit"
                );

                let img = image::load_from_memory(&data).unwrap_or_else(|e| {
                    panic!("Failed to decode image at LOGO_PATH '{path}': {e}")
                });

                let final_data = if data.len() <= 100 * 1024
                    && img.width() <= 128
                    && img.height() <= 128
                {
                    let mut buf = std::io::Cursor::new(Vec::new());
                    img.write_to(&mut buf, image::ImageFormat::Png)
                        .expect("Failed to encode optimized logo");
                    buf.into_inner()
                } else {
                    let scaled = img.resize(128, 128, image::imageops::FilterType::Lanczos3);
                    let mut buf = std::io::Cursor::new(Vec::new());
                    scaled
                        .write_to(&mut buf, image::ImageFormat::Png)
                        .expect("Failed to encode optimized logo");
                    buf.into_inner()
                };

                let b64 = BASE64_STANDARD.encode(&final_data);
                format!("data:image/png;base64,{b64}")
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_waf_mode_parsing() {
        assert_eq!(WafMode::from_str("Defense"), WafMode::Defense);
        assert_eq!(WafMode::from_str("DEFENSE"), WafMode::Defense);
        assert_eq!(WafMode::from_str("normal"), WafMode::Normal);
        assert_eq!(WafMode::from_str("invalid"), WafMode::Normal);
    }

    #[test]
    fn test_captcha_style_parsing() {
        assert_eq!(CaptchaStyle::from_str("simple"), CaptchaStyle::Simple);
        assert_eq!(CaptchaStyle::from_str("SIMPLE"), CaptchaStyle::Simple);
        assert_eq!(CaptchaStyle::from_str("complex"), CaptchaStyle::Complex);
        assert_eq!(CaptchaStyle::from_str("other"), CaptchaStyle::Complex);
    }

    #[test]
    fn test_helpers_defaults() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe {
            env::remove_var("TEST_MISSING_VAR");
        }
        assert_eq!(get_env_or("TEST_MISSING_VAR", "default"), "default");
        assert_eq!(get_env_u64_or("TEST_MISSING_VAR", 100), 100);
        assert_eq!(get_env_u32_or("TEST_MISSING_VAR", 50), 50);
        assert_eq!(get_env_u8_or("TEST_MISSING_VAR", 10), 10);
        assert_eq!(get_env_usize_or("TEST_MISSING_VAR", 1), 1);
        assert!(!get_env_bool("TEST_MISSING_VAR"));
    }

    #[test]
    fn test_helpers_parsing() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe {
            env::set_var("TEST_P1", "123");
            assert_eq!(get_env_u32("TEST_P1"), 123);

            env::set_var("TEST_P2", "1.5");
            assert!((get_env_f64("TEST_P2") - 1.5).abs() < f64::EPSILON);

            env::set_var("TEST_P3", "true");
            assert!(get_env_bool("TEST_P3"));

            env::set_var("TEST_P3", "1");
            assert!(get_env_bool("TEST_P3"));
        }
    }

    #[test]
    #[should_panic(expected = "TEST_REQ must be set")]
    fn test_get_env_panic() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe {
            env::remove_var("TEST_REQ");
        }
        get_env("TEST_REQ");
    }

    #[test]
    fn test_config_from_env_defaults() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unsafe {
            env::remove_var("WAF_MODE");
            env::set_var("LISTEN_ADDR", "127.0.0.1:9090");
            env::set_var("INTERNAL_ADDR", "127.0.0.1:9091");
            env::set_var("BACKEND_URL", "http://backend");
            env::set_var("CAPTCHA_SECRET", "s");
            env::set_var("SESSION_SECRET", "s");
            env::set_var("TOR_CIRCUIT_PREFIX", "f");
            env::set_var("RATE_LIMIT_RPS", "10");
            env::set_var("RATE_LIMIT_BURST", "20");
            env::set_var("DEFENSE_ERROR_RATE_THRESHOLD", "0.5");
            env::set_var("DEFENSE_CIRCUIT_FLOOD_THRESHOLD", "5");
            env::set_var("CAPTCHA_TTL", "300");
        }

        let config = Config::from_env();
        assert_eq!(config.listen_addr.port(), 9090);
        assert_eq!(config.waf_mode, WafMode::Normal);
        assert_eq!(config.defense_cooldown_secs, 300);
    }

    #[test]
    fn test_config_with_logo_path() {
        use std::io::Write;
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let png_bytes: [u8; 70] = [
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78,
            0xda, 0x63, 0xfc, 0xcf, 0xc0, 0x50, 0x0f, 0x00, 0x04, 0x85, 0x01, 0x80, 0x84, 0xa9,
            0x8c, 0x21, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ];

        let temp_dir = std::env::temp_dir();
        let logo_path = temp_dir.join("mavewaf_test_logo.png");
        {
            let mut f = std::fs::File::create(&logo_path).unwrap();
            f.write_all(&png_bytes).unwrap();
        }

        unsafe {
            env::set_var("LOGO_PATH", logo_path.to_str().unwrap());
            env::remove_var("WAF_MODE");
            env::set_var("LISTEN_ADDR", "127.0.0.1:9095");
            env::set_var("INTERNAL_ADDR", "127.0.0.1:9096");
            env::set_var("BACKEND_URL", "http://localhost");
            env::set_var("CAPTCHA_SECRET", "test");
            env::set_var("SESSION_SECRET", "test");
            env::set_var("TOR_CIRCUIT_PREFIX", "test");
            env::set_var("RATE_LIMIT_RPS", "10");
            env::set_var("RATE_LIMIT_BURST", "10");
            env::set_var("DEFENSE_ERROR_RATE_THRESHOLD", "0.5");
            env::set_var("DEFENSE_CIRCUIT_FLOOD_THRESHOLD", "5");
            env::set_var("CAPTCHA_TTL", "100");
        }

        let config = Config::from_env();

        unsafe {
            env::remove_var("LOGO_PATH");
        }
        let _ = std::fs::remove_file(logo_path);

        assert!(config.favicon_base64.starts_with("data:image/png;base64,"));
    }
}
