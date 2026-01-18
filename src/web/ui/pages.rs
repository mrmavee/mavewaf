//! HTML page rendering.
//!
//! Provides functions to render specific UI pages using loaded templates.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::error;

use crate::config::{CaptchaStyle, Config};
use crate::security::captcha::CharPosition;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Arc, OnceLock};

const TEMPLATE_DIR: &str = "templates";
static TEMPLATES: OnceLock<HashMap<String, Arc<str>>> = OnceLock::new();

/// Pre-loads all templates into memory.
pub fn preload_templates() {
    let _ = get_template_map();
}

fn get_template_map() -> &'static HashMap<String, Arc<str>> {
    TEMPLATES.get_or_init(|| {
        let mut m = HashMap::new();
        for name in &["queue.html", "captcha.html", "error.html", "access.html"] {
            let path = Path::new(TEMPLATE_DIR).join(name);
            match fs::read_to_string(&path) {
                Ok(content) => {
                    m.insert(name.to_string(), Arc::from(content));
                }
                Err(e) => {
                    error!(file = name, error = %e, "CRITICAL: Failed to load UI template");
                }
            }
        }
        m
    })
}

fn load_template(filename: &str) -> Option<Arc<str>> {
    get_template_map().get(filename).cloned()
}

/// Renders the queue waiting page.
#[must_use]
pub fn get_queue_page(
    wait_time_secs: u64,
    request_id: &str,
    target_url: &str,
    config: &Config,
) -> String {
    let template = load_template("queue.html")
        .map_or_else(|| {
            format!("<html><head><meta http-equiv='refresh' content='{wait_time_secs}'></head><body><h1>Queue: {wait_time_secs}s</h1></body></html>")
        }, |t: Arc<str>| t.to_string());

    template
        .replace("{{WAIT_TIME}}", &wait_time_secs.to_string())
        .replace("{{TARGET_URL}}", target_url)
        .replace("{{REQUEST_ID}}", request_id)
        .replace("{{CIRCUIT_ID}}", request_id)
        .replace("{{APP_NAME}}", &config.app_name)
        .replace("{{FAVICON}}", &config.favicon_base64)
        .replace("{{META_TITLE}}", &config.meta_title)
        .replace("{{META_DESCRIPTION}}", &config.meta_description)
        .replace("{{META_KEYWORDS}}", &config.meta_keywords)
}

fn format_timestamp(ts: u64) -> String {
    let days = ts / 86400;
    let seconds = ts % 86400;
    let (year, month, day) = date_from_days(days);
    let hour = seconds / 3600;
    let minute = (seconds % 3600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

fn date_from_days(mut days: u64) -> (u64, u8, u8) {
    let mut year = 1970;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let year_days = if is_leap { 366 } else { 365 };
        if days < year_days {
            let mut month = 1;
            let days_in_month = [
                31,
                if is_leap { 29 } else { 28 },
                31,
                30,
                31,
                30,
                31,
                31,
                30,
                31,
                30,
                31,
            ];
            for &dim in &days_in_month {
                if days < dim {
                    return (year, month, u8::try_from(days + 1).unwrap_or(1));
                }
                days -= dim;
                month += 1;
            }
        }
        days -= year_days;
        year += 1;
    }
}

/// Renders the CAPTCHA challenge page.
#[must_use]
pub fn get_captcha_page(
    s: &str,
    img_b64: &str,
    ttl_secs: u64,
    show_error: bool,
    positions: &[CharPosition],
    style: CaptchaStyle,
    config: &Config,
) -> String {
    let template = load_template("captcha.html").map_or_else(
        || "<html><body><h1>Security Check Error</h1></body></html>".to_string(),
        |t: Arc<str>| t.to_string(),
    );

    let timestamp_val = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let timestamp = format_timestamp(timestamp_val);

    let ttl_display = if ttl_secs >= 60 {
        format!("{} minutes", ttl_secs / 60)
    } else {
        format!("{ttl_secs} seconds")
    };

    let error_html = if show_error {
        r#"<div class="err">Incorrect code. Please try again.</div>"#
    } else {
        ""
    };

    let (captcha_css, inputs_html) = match style {
        CaptchaStyle::Simple => {
            let css =
                "<style>.input-row { padding-top: 0 !important; flex-direction: column !important; gap: 20px !important; } .image { position: static !important; width: 100% !important; max-width: 400px !important; aspect-ratio: 400/150 !important; height: auto !important; margin: 0 auto !important; transform: none !important; order: -1 !important; border-radius: 8px !important; border: 2px solid #3b82f6 !important; background-size: contain !important; background-repeat: no-repeat !important; }</style>"
                    .to_string();
            let inputs = r#"
                <input class="ch" style="width: 100%; letter-spacing: 0.5rem; font-size: 1.5rem;" 
                       type="text" name="solution" maxlength="6" pattern="[A-Za-z0-9]{6}" 
                       autocomplete="off" placeholder="Enter code" autofocus>
            "#
            .to_string();
            (css, inputs)
        }
        CaptchaStyle::Complex => {
            let mut css = String::from("<style>\n");
            for (i, pos) in positions.iter().enumerate() {
                let css_x = 12.00 - pos.x;
                let css_y = 4.00 - pos.y;
                let _ = writeln!(
                    css,
                    "input[name=c{}]:focus ~ .image {{ background-position: {:.2}px {:.2}px; transform: rotate({:.2}deg) scale(6) !important; }}",
                    i + 1,
                    css_x,
                    css_y,
                    -pos.rotation
                );
            }
            css.push_str("</style>");

            let inputs = r#"
                <input class="ch" type="text" name="c1" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off" autofocus>
                <input class="ch" type="text" name="c2" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off">
                <input class="ch" type="text" name="c3" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off">
                <input class="ch" type="text" name="c4" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off">
                <input class="ch" type="text" name="c5" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off">
                <input class="ch" type="text" name="c6" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off">
            "#
            .to_string();

            (css, inputs)
        }
    };

    template
        .replace("{{STATE_TOKEN}}", s)
        .replace("{{CAPTCHA_IMAGE}}", img_b64)
        .replace("{{TIMESTAMP}}", &timestamp)
        .replace("{{TTL_DISPLAY}}", &ttl_display)
        .replace("{{TTL_DISPLAY}}", &ttl_display)
        .replace("{{ERROR_MESSAGE}}", error_html)
        .replace("{{CAPTCHA_INPUTS}}", &inputs_html)
        .replace("{{CAPTCHA_CSS}}", &captcha_css)
        .replace("{{APP_NAME}}", &config.app_name)
        .replace("{{FAVICON}}", &config.favicon_base64)
        .replace("{{META_TITLE}}", &config.meta_title)
        .replace("{{META_DESCRIPTION}}", &config.meta_description)
        .replace("{{META_KEYWORDS}}", &config.meta_keywords)
}

/// Renders a generic error page.
#[must_use]
pub fn get_error_page(
    title: &str,
    description: &str,
    details: Option<Vec<(&str, &str)>>,
    config: Option<&Config>,
) -> String {
    let timestamp_val = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let timestamp = format_timestamp(timestamp_val);

    let template = load_template("error.html").map_or_else(|| {
        format!(
            "<html><head><title>{title}</title></head><body><h1>{title}</h1><p>{description}</p></body></html>"
        )
    }, |t: Arc<str>| t.to_string());

    let mut details_html = String::new();
    if let Some(dets) = details {
        use std::fmt::Write;
        for (k, v) in dets {
            let _ = write!(
                details_html,
                "<div class=\"meta-row\"><span class=\"label\">{k}</span><span class=\"value\">{v}</span></div>"
            );
        }
    }

    template
        .replace("{{TITLE}}", title)
        .replace("{{DESCRIPTION}}", description)
        .replace("{{DETAILS}}", &details_html)
        .replace("{{TIMESTAMP}}", &timestamp)
        .replace("{{APP_NAME}}", config.map_or("", |c| c.app_name.as_str()))
        .replace(
            "{{FAVICON}}",
            config.map_or("", |c| c.favicon_base64.as_str()),
        )
        .replace(
            "{{META_TITLE}}",
            config.map_or("Error", |c| c.meta_title.as_str()),
        )
        .replace(
            "{{META_DESCRIPTION}}",
            config.map_or("", |c| c.meta_description.as_str()),
        )
        .replace(
            "{{META_KEYWORDS}}",
            config.map_or("", |c| c.meta_keywords.as_str()),
        )
}

/// Renders a block page with a reason.
#[must_use]
pub fn get_block_page(reason: &str, request_id: &str, config: &Config) -> String {
    let details = vec![("Reason", reason), ("Request ID", request_id)];
    get_error_page(
        "Access Denied",
        "Your request was blocked by the security firewall.",
        Some(details),
        Some(config),
    )
}

/// Renders the access page.
#[must_use]
pub fn get_access_page(s: &str, config: &Config) -> String {
    let template = load_template("access.html").map_or_else(
        || "<html><body><h1>Security Check</h1></body></html>".to_string(),
        |t: Arc<str>| t.to_string(),
    );

    template
        .replace("{{STATE_TOKEN}}", s)
        .replace("{{APP_NAME}}", &config.app_name)
        .replace("{{FAVICON}}", &config.favicon_base64)
        .replace("{{META_TITLE}}", &config.meta_title)
        .replace("{{META_DESCRIPTION}}", &config.meta_description)
        .replace("{{META_KEYWORDS}}", &config.meta_keywords)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CaptchaStyle, FeatureFlags, WafMode};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_dummy_config() -> Config {
        Config {
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
        }
    }

    #[test]
    fn test_render_queue_page() {
        let config = create_dummy_config();
        let html = get_queue_page(10, "req-123", "/target", &config);
        assert!(html.contains("Queue: 10s") || html.contains("10"));
    }

    #[test]
    fn test_render_error_page() {
        let config = create_dummy_config();
        let html = get_error_page("Title", "Desc", None, Some(&config));
        assert!(html.contains("Title"));
        assert!(html.contains("Desc"));
    }

    #[test]
    fn test_render_block_page() {
        let config = create_dummy_config();
        let html = get_block_page("Malicious", "req-123", &config);
        assert!(html.contains("Access Denied"));
        assert!(html.contains("Malicious"));
    }

    #[test]
    fn test_render_captcha_page() {
        let config = create_dummy_config();
        let html = get_captcha_page(
            "token",
            "img_b64",
            300,
            false,
            &[],
            CaptchaStyle::Simple,
            &config,
        );
        assert!(html.contains("Security Check") || html.contains("img_b64"));
    }

    #[test]
    fn test_render_access_page() {
        let config = create_dummy_config();
        let html = get_access_page("test_token", &config);
        assert!(html.contains("Security Check"));
        assert!(html.contains("test_token"));
        assert!(html.contains("Click to Enter"));
    }
}
