//! Challenge handling logic.
//!
//! Manages CAPTCHA generation, validation, and queue page serving.

use crate::config::Config;
use crate::core::middleware::{
    EncryptedSession, SESSION_COOKIE_NAME, format_set_cookie, generate_session_id,
};
use crate::core::proxy::response::{parse_form_submission, serve_html, serve_redirect};
use crate::core::proxy::service::RequestCtx;
use crate::features::tor::control::TorControl;
use crate::security::captcha::CaptchaManager;
use crate::security::crypto::CookieCrypto;
use crate::web::ui;
use pingora::Result;
use pingora::proxy::Session;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

/// Handler for serving CAPTCHA and queue pages.
pub struct ChallengeHandler {
    pub config: Arc<Config>,
    pub captcha: Arc<CaptchaManager>,
    pub cookie_crypto: CookieCrypto,
    pub tor_control: Option<TorControl>,
}

impl ChallengeHandler {
    #[must_use]
    pub const fn new(
        config: Arc<Config>,
        captcha: Arc<CaptchaManager>,
        cookie_crypto: CookieCrypto,
        tor_control: Option<TorControl>,
    ) -> Self {
        Self {
            config,
            captcha,
            cookie_crypto,
            tor_control,
        }
    }

    async fn kill_circuit_if_possible(&self, circuit_id: Option<&str>) {
        if let (Some(tor), Some(cid)) = (&self.tor_control, circuit_id)
            && !cid.starts_with("i2p:")
            && let Err(e) = tor.kill_circuit(cid).await
        {
            warn!(circuit_id = %cid, error = %e, "Failed to kill circuit");
        }
    }

    fn create_session_cookie(&self, session: &EncryptedSession, max_age: u64) -> String {
        let cookie_val = self.cookie_crypto.encrypt(&session.to_bytes());
        let secure = !session
            .circuit_id
            .as_deref()
            .is_some_and(|cid| cid.starts_with("i2p:"));
        format_set_cookie(SESSION_COOKIE_NAME, &cookie_val, max_age, secure)
    }

    /// Serves the queue page.
    ///
    /// # Errors
    ///
    /// Returns an error if the response cannot be written.
    pub async fn serve_queue_page(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        target_url: &str,
        now: u64,
    ) -> Result<bool> {
        debug!(circuit_id = ?ctx.circuit_id, "Queue page served");
        let new_session = EncryptedSession {
            session_id: generate_session_id(),
            circuit_id: ctx.circuit_id.clone(),
            created_at: now,
            queue_started_at: now,
            queue_completed: false,
            captcha_failures: 0,
            captcha_gen_count: 0,
            verified: false,
            verified_at: 0,
            last_active_at: now,
        };
        let cookie_header = self.create_session_cookie(&new_session, 300);
        let html = ui::get_queue_page(5, &new_session.session_id, target_url, &self.config);
        serve_html(session, &self.config, 200, html, Some(&cookie_header)).await
    }

    /// Serves the queue page with remaining time.
    ///
    /// # Errors
    ///
    /// Returns an error if the response cannot be written.
    pub async fn serve_queue_page_with_time(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        target_url: &str,
        remaining: u64,
    ) -> Result<bool> {
        self.serve_queue_page_with_time_and_cookie(session, ctx, target_url, remaining, None)
            .await
    }

    /// Serves the queue page with remaining time and an optional cookie.
    ///
    /// # Errors
    ///
    /// Returns an error if the response cannot be written.
    pub async fn serve_queue_page_with_time_and_cookie(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        target_url: &str,
        remaining: u64,
        cookie_header: Option<&str>,
    ) -> Result<bool> {
        debug!(circuit_id = ?ctx.circuit_id, remaining_seconds = remaining, "Queue in progress");
        let session_id = ctx
            .session_data
            .as_ref()
            .map_or("unknown", |s| s.session_id.as_str());
        let html = ui::get_queue_page(remaining, session_id, target_url, &self.config);
        serve_html(session, &self.config, 200, html, cookie_header).await
    }

    /// Serves the CAPTCHA page.
    ///
    /// # Errors
    ///
    /// Returns an error if the response cannot be written or CAPTCHA generation fails.
    pub async fn serve_captcha_page(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        show_error: bool,
    ) -> Result<bool> {
        debug!(circuit_id = ?ctx.circuit_id, "CAPTCHA page served");

        let mut session_data = ctx.session_data.clone().unwrap_or_default();

        if let Some(remaining) = Self::check_queue_bypass(&session_data) {
            warn!(
                circuit_id = ?ctx.circuit_id,
                remaining = remaining,
                "Queue bypass attempt blocked"
            );
            return self
                .serve_queue_page_with_time(session, ctx, "/", remaining)
                .await;
        }

        session_data.captcha_gen_count += 1;

        if session_data.captcha_gen_count > self.config.captcha_gen_limit {
            return self.handle_captcha_gen_limit_exceeded(session, ctx).await;
        }

        let cookie_header = self.create_session_cookie(&session_data, 300);
        self.generate_and_serve_captcha(session, show_error, &cookie_header)
            .await
    }

    fn check_queue_bypass(session_data: &EncryptedSession) -> Option<u64> {
        const REQUIRED_WAIT: u64 = 5;

        if session_data.queue_started_at == 0 {
            return None;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now < session_data.queue_started_at + REQUIRED_WAIT {
            let remaining = (session_data.queue_started_at + REQUIRED_WAIT).saturating_sub(now);
            Some(remaining.max(1))
        } else {
            None
        }
    }

    async fn handle_captcha_gen_limit_exceeded(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
    ) -> Result<bool> {
        warn!(
            circuit_id = ?ctx.circuit_id,
            session_id = ?ctx.session_data.as_ref().map(|s| &s.session_id),
            "CAPTCHA generation limit exceeded"
        );
        self.kill_circuit_if_possible(ctx.circuit_id.as_deref())
            .await;
        let html = ui::get_error_page(
            "Too Many Requests",
            "You have refreshed the page too many times. Access blocked.",
            None,
            Some(&self.config),
        );
        serve_html(session, &self.config, 403, html, None).await
    }

    async fn generate_and_serve_captcha(
        &self,
        session: &mut Session,
        show_error: bool,
        cookie_header: &str,
    ) -> Result<bool> {
        let captcha = self.captcha.clone();
        let config = self.config.clone();
        let cookie = cookie_header.to_string();

        let res = tokio::task::spawn_blocking(move || captcha.generate()).await;

        match res {
            Ok(Ok((id, img, positions))) => {
                let html = ui::get_captcha_page(
                    &id,
                    &img,
                    config.captcha_ttl,
                    show_error,
                    &positions,
                    config.captcha_style,
                    &config,
                );
                serve_html(session, &self.config, 200, html, Some(&cookie)).await
            }
            Ok(Err(e)) => self.serve_captcha_error(session, &e).await,
            Err(e) => self.serve_captcha_panic(session, &e.to_string()).await,
        }
    }

    async fn serve_captcha_error(&self, session: &mut Session, error: &str) -> Result<bool> {
        let ref_id = generate_session_id();
        error!(ref_id = %ref_id, error = %error, "CAPTCHA generation failed");
        let html = ui::get_error_page(
            "Verification Error",
            "Unable to generate security challenge. Please reload the page.",
            Some(vec![("Error ID", &ref_id)]),
            Some(&self.config),
        );
        serve_html(session, &self.config, 500, html, None).await
    }

    async fn serve_captcha_panic(&self, session: &mut Session, error: &str) -> Result<bool> {
        let ref_id = generate_session_id();
        error!(ref_id = %ref_id, error = %error, "CAPTCHA task panicked");
        let html = ui::get_error_page(
            "System Error",
            "A temporary system error occurred.",
            Some(vec![("Error ID", &ref_id)]),
            Some(&self.config),
        );
        serve_html(session, &self.config, 500, html, None).await
    }

    /// Serves the CAPTCHA page with a cookie.
    ///
    /// # Errors
    ///
    /// Returns an error if the response cannot be written or CAPTCHA generation fails.
    pub async fn serve_captcha_page_with_cookie(
        &self,
        session: &mut Session,
        _ctx: &mut RequestCtx,
        show_error: bool,
        cookie_header: &str,
    ) -> Result<bool> {
        debug!("Queue complete, serving CAPTCHA");
        self.generate_and_serve_captcha(session, show_error, cookie_header)
            .await
    }

    /// Serves the access page.
    ///
    /// # Errors
    ///
    /// Returns an error if the response cannot be written.
    pub async fn serve_access_page(&self, session: &mut Session, ctx: &RequestCtx) -> Result<bool> {
        debug!(circuit_id = ?ctx.circuit_id, "Access page served");

        let session_data = ctx.session_data.clone().unwrap_or_default();
        let cookie_header = self.create_session_cookie(&session_data, 300);

        let token = self
            .captcha
            .create_token(&session_data.session_id.to_uppercase());

        let html = ui::get_access_page(&token, &self.config);
        serve_html(session, &self.config, 200, html, Some(&cookie_header)).await
    }

    /// Verifies the access token submission.
    ///
    /// # Errors
    ///
    /// Returns an error if the response cannot be written.
    pub async fn handle_access_verify(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        body: &[u8],
        now: u64,
    ) -> Result<bool> {
        let (token, _) = parse_form_submission(body);
        let session_id = ctx
            .session_data
            .as_ref()
            .map_or("unknown", |s| s.session_id.as_str());

        if self.captcha.verify(&token, session_id) {
            info!(
                circuit_id = ?ctx.circuit_id,
                session_id = ?session_id,
                "Access verified via click-to-enter"
            );
            let uri = session.req_header().uri.to_string();
            let new_session = Self::create_verified_session(ctx, now);
            let cookie_header = self.create_session_cookie(&new_session, 3600);
            serve_redirect(session, &self.config, &uri, Some(&cookie_header), true).await
        } else {
            warn!(
                circuit_id = ?ctx.circuit_id,
                session_id = ?session_id,
                "Access verification failed (invalid token)"
            );
            let uri = session.req_header().uri.to_string();
            serve_redirect(session, &self.config, &uri, None, true).await
        }
    }

    /// Verifies the CAPTCHA submission.
    ///
    /// # Errors
    ///
    /// Returns an error if the response cannot be written.
    pub async fn handle_captcha_verify(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        body: &[u8],
        now: u64,
    ) -> Result<bool> {
        let (token, answer) = parse_form_submission(body);

        if self.captcha.verify(&token, &answer) {
            info!(
                circuit_id = ?ctx.circuit_id,
                session_id = ?ctx.session_data.as_ref().map(|s| &s.session_id),
                "CAPTCHA verified"
            );
            let uri = session.req_header().uri.to_string();
            let new_session = Self::create_verified_session(ctx, now);
            let cookie_header = self.create_session_cookie(&new_session, 3600);
            serve_redirect(session, &self.config, &uri, Some(&cookie_header), true).await
        } else {
            self.handle_captcha_failure(session, ctx, now).await
        }
    }

    fn create_verified_session(ctx: &RequestCtx, now: u64) -> EncryptedSession {
        EncryptedSession {
            session_id: generate_session_id(),
            circuit_id: ctx.circuit_id.clone(),
            created_at: now,
            queue_started_at: 0,
            queue_completed: true,
            captcha_failures: 0,
            captcha_gen_count: 0,
            verified: true,
            verified_at: now,
            last_active_at: now,
        }
    }

    async fn handle_captcha_failure(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        now: u64,
    ) -> Result<bool> {
        let mut current_session = ctx.session_data.clone().unwrap_or_default();
        current_session.captcha_failures += 1;

        warn!(
            circuit_id = ?ctx.circuit_id,
            session_id = ?current_session.session_id,
            failures = current_session.captcha_failures,
            "CAPTCHA verification failed"
        );

        let uri = session.req_header().uri.to_string();

        if current_session.captcha_failures >= self.config.max_captcha_failures {
            info!(circuit_id = ?ctx.circuit_id, "CAPTCHA failures exceeded, session reset");
            let reset_session = EncryptedSession {
                session_id: generate_session_id(),
                circuit_id: ctx.circuit_id.clone(),
                created_at: now,
                queue_started_at: now,
                queue_completed: false,
                captcha_failures: 0,
                captcha_gen_count: 0,
                verified: false,
                verified_at: 0,
                last_active_at: now,
            };
            let cookie_header = self.create_session_cookie(&reset_session, 300);
            return serve_redirect(session, &self.config, &uri, Some(&cookie_header), true).await;
        }

        current_session.created_at = now;
        current_session.circuit_id.clone_from(&ctx.circuit_id);
        let cookie_header = self.create_session_cookie(&current_session, 300);
        serve_redirect(session, &self.config, &uri, Some(&cookie_header), true).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_queue_bypass_no_queue() {
        let session = EncryptedSession::default();
        assert!(ChallengeHandler::check_queue_bypass(&session).is_none());
    }

    #[test]
    fn test_check_queue_bypass_completed() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let session = EncryptedSession {
            queue_started_at: now - 10,
            verified: false,
            ..Default::default()
        };
        assert!(ChallengeHandler::check_queue_bypass(&session).is_none());
    }
}
