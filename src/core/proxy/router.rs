//! Request routing and logic handling.
//!
//! Manages request flow between WAF, CAPTCHA, Queue, and Upstream logic.

use crate::security::captcha::CaptchaManager;

use crate::core::middleware::{SESSION_COOKIE_NAME, format_set_cookie};
use crate::core::proxy::challenge::ChallengeHandler;
use crate::core::proxy::headers::inject_security_headers;
use crate::core::proxy::service::RequestCtx;
use crate::features::tor::control::TorControl;
use pingora::Result;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::security::defense::DefenseMonitor;

/// Router for handling CAPTCHA and queue logic.
pub struct WafRouter {
    pub config: Arc<crate::config::Config>,
    pub captcha: Arc<CaptchaManager>,
    pub cookie_crypto: crate::security::crypto::CookieCrypto,
    pub tor_control: Option<TorControl>,
    pub defense_monitor: Arc<DefenseMonitor>,
    handler: ChallengeHandler,
}

impl WafRouter {
    /// Creates a new `WafRouter`.
    #[must_use]
    pub fn new(
        config: Arc<crate::config::Config>,
        captcha: Arc<CaptchaManager>,
        cookie_crypto: crate::security::crypto::CookieCrypto,
        tor_control: Option<TorControl>,
        defense_monitor: Arc<DefenseMonitor>,
    ) -> Self {
        let handler = ChallengeHandler::new(
            config.clone(),
            captcha.clone(),
            cookie_crypto.clone(),
            tor_control.clone(),
        );
        Self {
            config,
            captcha,
            cookie_crypto,
            tor_control,
            defense_monitor,
            handler,
        }
    }

    /// Handles an incoming HTTP request.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be served or forwarded.
    pub async fn handle_request(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<bool> {
        let is_defense = self.config.waf_mode == crate::config::WafMode::Defense
            || self.defense_monitor.is_defense_mode();

        if is_defense {
            return self.handle_defense_mode(session, ctx).await;
        }

        Ok(false)
    }

    async fn handle_defense_mode(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<bool> {
        let path = session.req_header().uri.path();
        let method = session.req_header().method.clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let session_state = &ctx.session_data;

        let is_exempt = session_state.as_ref().is_some_and(|s| s.verified);

        if is_exempt {
            if path == "/captcha" || path == "/queue" {
                let mut header = ResponseHeader::build(303, None)?;
                header.insert_header("Location", "/")?;
                header.insert_header(
                    "Cache-Control",
                    "no-store, no-cache, must-revalidate, max-age=0",
                )?;
                header.insert_header("Pragma", "no-cache")?;
                header.insert_header("Expires", "0")?;
                header.insert_header("Clear-Site-Data", "\"cache\"")?;

                inject_security_headers(&mut header, &self.config)?;

                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }

            return Ok(false);
        } else if path == "/"
            && method == pingora::http::Method::POST
            && let Ok(Some(body)) = session.read_request_body().await
        {
            if !self.config.features.captcha_enabled {
                return self
                    .handler
                    .handle_access_verify(session, ctx, &body, now)
                    .await;
            }

            let queue_ok = session_state.as_ref().is_some_and(|s| s.queue_completed);
            if !queue_ok {
                return self.handler.serve_queue_page(session, ctx, now).await;
            }

            return self
                .handler
                .handle_captcha_verify(session, ctx, &body, now)
                .await;
        } else if session_state.as_ref().is_some_and(|s| s.queue_completed) {
            let show_error = session_state
                .as_ref()
                .is_some_and(|s| s.captcha_failures > 0);
            return self
                .handler
                .serve_captcha_page(session, ctx, show_error)
                .await;
        } else if let Some(sess) = session_state
            && sess.queue_started_at > 0
        {
            let waited = now.saturating_sub(sess.queue_started_at);
            if waited >= 5 {
                if !self.config.features.captcha_enabled {
                    return self.handler.serve_access_page(session, ctx).await;
                }

                let mut new_session = sess.clone();
                new_session.queue_completed = true;
                new_session.captcha_gen_count = 1;
                let cookie_val = self.cookie_crypto.encrypt(&new_session.to_bytes());
                let cookie_header = format_set_cookie(SESSION_COOKIE_NAME, &cookie_val, 300);

                return self
                    .handler
                    .serve_captcha_page_with_cookie(session, ctx, false, &cookie_header)
                    .await;
            }
            let remaining = 5 - waited;
            return self
                .handler
                .serve_queue_page_with_time(session, ctx, remaining)
                .await;
        }

        self.handler.serve_queue_page(session, ctx, now).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, FeatureFlags, WafMode};
    use crate::core::middleware::EncryptedSession;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_test_config() -> Arc<Config> {
        Arc::new(Config {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            internal_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
            backend_url: "http://localhost:8080".to_string(),
            waf_mode: WafMode::Defense,
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
            captcha_style: crate::config::CaptchaStyle::Simple,
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
            favicon_base64: String::new(),
            meta_title: "Test".to_string(),
            meta_description: "Test".to_string(),
            meta_keywords: "Test".to_string(),
            log_format: "pretty".to_string(),
            csp_extra_sources: String::new(),
            coop_policy: "same-origin-allow-popups".to_string(),
        })
    }

    #[test]
    fn test_router_construction() {
        let config = create_test_config();
        let captcha = Arc::new(CaptchaManager::new(&config));
        let crypto = crate::security::crypto::CookieCrypto::new(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let monitor = Arc::new(DefenseMonitor::new(config.clone()));

        let router = WafRouter::new(config, captcha, crypto, None, monitor);
        assert!(router.tor_control.is_none());
    }

    #[test]
    fn test_exemption_logic_verified_user() {
        let _config = create_test_config();

        let session = EncryptedSession {
            session_id: "test".to_string(),
            verified: true,
            verified_at: 100,
            created_at: 90,
            ..Default::default()
        };

        let is_exempt = Some(session).as_ref().is_some_and(|s| s.verified);
        assert!(is_exempt);
    }

    #[test]
    fn test_exemption_logic_unverified_user() {
        let _config = create_test_config();

        let session = EncryptedSession {
            session_id: "test".to_string(),
            verified: false,
            verified_at: 0,
            created_at: 90,
            ..Default::default()
        };

        let is_exempt = Some(session).as_ref().is_some_and(|s| s.verified);
        assert!(!is_exempt);
    }
}
