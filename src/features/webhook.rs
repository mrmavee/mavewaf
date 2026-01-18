//! Webhook notifications.
//!
//! Handles asynchronous dispatch of security alerts to external endpoints.

use crate::config::{Config, Result, WafError};
use reqwest::Client;
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, error};

/// Security event types for webhook notifications.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    DefenseModeActivated,
    DefenseModeDeactivated,
    RateLimitExceeded,
    CircuitBlocked,
    CircuitKilled,
    HighErrorRate,
    WafBlock,
}

/// Webhook payload for security events.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub event_type: EventType,
    pub timestamp: i64,
    pub circuit_id: Option<String>,
    pub severity: u8,
    pub message: String,
}

pub struct WebhookNotifier {
    client: Client,
    webhook_url: Option<String>,
    webhook_token: Option<String>,
}

impl WebhookNotifier {
    #[must_use]
    pub fn new(config: &Arc<Config>) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            webhook_url: config.webhook_url.clone(),
            webhook_token: config.webhook_token.clone(),
        }
    }

    pub fn notify(&self, payload: WebhookPayload) {
        let Some(url) = self.webhook_url.clone() else {
            return;
        };

        let client = self.client.clone();
        let token = self.webhook_token.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::send_notification(&client, &url, token.as_deref(), &payload).await
            {
                error!(error = %e, "Webhook notification failed");
            }
        });
    }

    async fn send_notification(
        client: &Client,
        url: &str,
        token: Option<&str>,
        payload: &WebhookPayload,
    ) -> Result<()> {
        let (tags, title) = match payload.event_type {
            EventType::DefenseModeActivated => ("shield,red_circle", "Defense Mode Activated"),
            EventType::DefenseModeDeactivated => {
                ("shield,green_circle", "Defense Mode Deactivated")
            }
            EventType::RateLimitExceeded => ("snail,warning", "Rate Limit Exceeded"),
            EventType::CircuitBlocked => ("no_entry_sign,tor", "Circuit Blocked"),
            EventType::CircuitKilled => ("skull,blade", "Circuit Killed"),
            EventType::HighErrorRate => ("chart_with_upwards_trend,fire", "High Error Rate"),
            EventType::WafBlock => ("shield,stop_sign", "WAF Block"),
        };

        let mut req = client
            .post(url)
            .header("Title", title)
            .header("Priority", payload.severity.to_string())
            .header("Tags", tags)
            .body(payload.message.clone());

        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }

        req.send()
            .await
            .map_err(|e| WafError::Webhook(e.to_string()))?;

        debug!(event_type = ?payload.event_type, "Webhook notification sent");
        Ok(())
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
            webhook_token: None,
        })
    }

    #[test]
    fn test_payload_serialization() {
        let payload = WebhookPayload {
            event_type: EventType::WafBlock,
            timestamp: 1_234_567_890,
            circuit_id: Some("circuit-1".into()),
            severity: 5,
            message: "Block msg".into(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("waf_block"));
        assert!(json.contains("circuit-1"));
        assert!(json.contains("1234567890"));
    }

    #[test]
    fn test_event_types() {
        let events = [
            EventType::DefenseModeActivated,
            EventType::DefenseModeDeactivated,
            EventType::RateLimitExceeded,
            EventType::CircuitBlocked,
            EventType::CircuitKilled,
            EventType::HighErrorRate,
            EventType::WafBlock,
        ];
        assert_eq!(events.len(), 7);
    }

    #[test]
    fn test_notifier_creation_no_url() {
        let config = create_test_config();
        let notifier = WebhookNotifier::new(&config);
        assert!(notifier.webhook_url.is_none());
    }

    #[test]
    fn test_notify_without_url_does_not_panic() {
        let config = create_test_config();
        let notifier = WebhookNotifier::new(&config);
        let payload = WebhookPayload {
            event_type: EventType::WafBlock,
            timestamp: 123,
            circuit_id: None,
            severity: 1,
            message: "test".into(),
        };
        notifier.notify(payload);
    }

    #[test]
    fn test_payload_without_circuit_id() {
        let payload = WebhookPayload {
            event_type: EventType::RateLimitExceeded,
            timestamp: 999,
            circuit_id: None,
            severity: 3,
            message: "Rate limited".into(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("rate_limit_exceeded"));
        assert!(json.contains("null"));
    }

    #[test]
    fn test_payload_clone() {
        let payload = WebhookPayload {
            event_type: EventType::CircuitKilled,
            timestamp: 555,
            circuit_id: Some("cid".into()),
            severity: 4,
            message: "killed".into(),
        };
        let cloned = payload;
        assert_eq!(cloned.timestamp, 555);
        assert_eq!(cloned.severity, 4);
    }
}
