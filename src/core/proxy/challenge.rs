//! Challenge handling logic.
//!
//! Manages CAPTCHA generation, validation, and queue page serving.

use crate::config::Config;
use crate::core::middleware::{
    EncryptedSession, SESSION_COOKIE_NAME, format_set_cookie, generate_session_id,
};
use crate::core::proxy::headers::inject_security_headers;
use crate::core::proxy::service::RequestCtx;
use crate::features::tor::control::TorControl;
use crate::security::captcha::CaptchaManager;
use crate::security::crypto::CookieCrypto;
use crate::web::ui;
use pingora::Result;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::sync::Arc;
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

    async fn serve_html(
        &self,
        session: &mut Session,
        status: u16,
        html: String,
        set_cookie: Option<&str>,
    ) -> Result<bool> {
        let mut header = ResponseHeader::build(status, None)?;
        header.insert_header("Content-Type", "text/html; charset=utf-8")?;
        header.insert_header("Content-Length", html.len().to_string())?;
        header.insert_header(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, max-age=0",
        )?;
        header.insert_header("Pragma", "no-cache")?;
        header.insert_header("Expires", "0")?;

        if let Some(cookie) = set_cookie {
            header.insert_header("Set-Cookie", cookie)?;
        }

        inject_security_headers(&mut header, &self.config)?;

        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(bytes::Bytes::from(html)), true)
            .await?;
        Ok(true)
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
        };
        let cookie_val = self.cookie_crypto.encrypt(&new_session.to_bytes());
        let cookie_header = format_set_cookie(SESSION_COOKIE_NAME, &cookie_val, 300);
        let request_id = &new_session.session_id;
        let html = ui::get_queue_page(5, request_id, &self.config);
        self.serve_html(session, 200, html, Some(&cookie_header))
            .await
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
        remaining: u64,
    ) -> Result<bool> {
        debug!(circuit_id = ?ctx.circuit_id, remaining_seconds = remaining, "Queue in progress");
        let session_id = ctx
            .session_data
            .as_ref()
            .map_or("unknown", |s| s.session_id.as_str());
        let html = ui::get_queue_page(remaining, session_id, &self.config);
        self.serve_html(session, 200, html, None).await
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
        session_data.captcha_gen_count += 1;

        if session_data.captcha_gen_count > self.config.captcha_gen_limit {
            warn!(
                circuit_id = ?ctx.circuit_id,
                session_id = ?session_data.session_id,
                gen_count = session_data.captcha_gen_count,
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
            return self.serve_html(session, 403, html, None).await;
        }

        let cookie_val = self.cookie_crypto.encrypt(&session_data.to_bytes());
        let cookie_header = format_set_cookie(SESSION_COOKIE_NAME, &cookie_val, 300);

        let captcha = self.captcha.clone();
        let config_ttl = self.config.captcha_ttl;
        let config = self.config.clone();

        let res = tokio::task::spawn_blocking(move || captcha.generate()).await;

        match res {
            Ok(Ok((id, img, positions))) => {
                let html = ui::get_captcha_page(
                    &id,
                    &img,
                    config_ttl,
                    show_error,
                    &positions,
                    config.captcha_style,
                    &config,
                );
                self.serve_html(session, 200, html, Some(&cookie_header))
                    .await
            }
            Ok(Err(e)) => {
                let ref_id = generate_session_id();
                error!(ref_id = %ref_id, error = %e, "CAPTCHA generation failed");
                let html = ui::get_error_page(
                    "Verification Error",
                    "Unable to generate security challenge. Please reload the page.",
                    Some(vec![("Error ID", &ref_id)]),
                    Some(&config),
                );
                self.serve_html(session, 500, html, None).await
            }
            Err(e) => {
                let ref_id = generate_session_id();
                error!(ref_id = %ref_id, error = %e, "CAPTCHA task panicked");
                let html = ui::get_error_page(
                    "System Error",
                    "A temporary system error occurred.",
                    Some(vec![("Error ID", &ref_id)]),
                    Some(&config),
                );
                self.serve_html(session, 500, html, None).await
            }
        }
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
        let captcha = self.captcha.clone();
        let config_ttl = self.config.captcha_ttl;
        let cookie_header_val = cookie_header.to_string();
        let config = self.config.clone();

        let res = tokio::task::spawn_blocking(move || captcha.generate()).await;

        match res {
            Ok(Ok((id, img, positions))) => {
                let html = ui::get_captcha_page(
                    &id,
                    &img,
                    config_ttl,
                    show_error,
                    &positions,
                    config.captcha_style,
                    &config,
                );
                self.serve_html(session, 200, html, Some(&cookie_header_val))
                    .await
            }
            Ok(Err(e)) => {
                let ref_id = generate_session_id();
                error!(ref_id = %ref_id, error = %e, "CAPTCHA generation failed");
                let html = ui::get_error_page(
                    "Verification Error",
                    "Unable to generate security challenge. Please reload the page.",
                    Some(vec![("Error ID", &ref_id)]),
                    Some(&config),
                );
                self.serve_html(session, 500, html, None).await
            }
            Err(e) => {
                let ref_id = generate_session_id();
                error!(ref_id = %ref_id, error = %e, "CAPTCHA task panicked");
                let html = ui::get_error_page(
                    "System Error",
                    "A temporary system error occurred.",
                    Some(vec![("Error ID", &ref_id)]),
                    Some(&config),
                );
                self.serve_html(session, 500, html, None).await
            }
        }
    }

    /// Serves the access page.
    ///
    /// # Errors
    ///
    /// Returns an error if the response cannot be written.
    pub async fn serve_access_page(&self, session: &mut Session, ctx: &RequestCtx) -> Result<bool> {
        debug!(circuit_id = ?ctx.circuit_id, "Access page served");

        let session_data = ctx.session_data.clone().unwrap_or_default();
        let cookie_val = self.cookie_crypto.encrypt(&session_data.to_bytes());
        let cookie_header = format_set_cookie(SESSION_COOKIE_NAME, &cookie_val, 300);

        let token = self
            .captcha
            .create_token(&session_data.session_id.to_uppercase());

        let html = ui::get_access_page(&token, &self.config);
        self.serve_html(session, 200, html, Some(&cookie_header))
            .await
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
        let (token, _) = parse_captcha_submission(body);
        let session_id = ctx
            .session_data
            .as_ref()
            .map_or("unknown", |s| &s.session_id);

        if self.captcha.verify(&token, session_id) {
            info!(
                circuit_id = ?ctx.circuit_id,
                session_id = ?session_id,
                "Access verified via click-to-enter"
            );
            let new_session = EncryptedSession {
                session_id: generate_session_id(),
                circuit_id: ctx.circuit_id.clone(),
                created_at: now,
                queue_started_at: 0,
                queue_completed: true,
                captcha_failures: 0,
                captcha_gen_count: 0,
                verified: true,
                verified_at: now,
            };
            let cookie_val = self.cookie_crypto.encrypt(&new_session.to_bytes());
            let cookie_header = format_set_cookie(SESSION_COOKIE_NAME, &cookie_val, 3600);

            let mut header = ResponseHeader::build(303, None)?;
            header.insert_header("Location", "/")?;
            header.insert_header("Set-Cookie", cookie_header)?;
            header.insert_header("Clear-Site-Data", "\"cache\"")?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
        } else {
            warn!(
                circuit_id = ?ctx.circuit_id,
                session_id = ?session_id,
                "Access verification failed (invalid token)"
            );
            let uri = session.req_header().uri.to_string();
            let mut header = ResponseHeader::build(303, None)?;
            header.insert_header("Location", uri)?;
            header.insert_header("Clear-Site-Data", "\"cache\"")?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
        }
        Ok(true)
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
        let (token, answer) = parse_captcha_submission(body);

        let captcha_ok = self.captcha.verify(&token, &answer);

        if captcha_ok {
            info!(
                circuit_id = ?ctx.circuit_id,
                session_id = ?ctx.session_data.as_ref().map(|s| &s.session_id),
                "CAPTCHA verified"
            );
            let new_session = EncryptedSession {
                session_id: generate_session_id(),
                circuit_id: ctx.circuit_id.clone(),
                created_at: now,
                queue_started_at: 0,
                queue_completed: true,
                captcha_failures: 0,
                captcha_gen_count: 0,
                verified: true,
                verified_at: now,
            };
            let cookie_val = self.cookie_crypto.encrypt(&new_session.to_bytes());
            let cookie_header = format_set_cookie(SESSION_COOKIE_NAME, &cookie_val, 3600);

            let mut header = ResponseHeader::build(303, None)?;
            header.insert_header("Location", "/")?;
            header.insert_header("Set-Cookie", cookie_header)?;
            header.insert_header("Clear-Site-Data", "\"cache\"")?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
        } else {
            let mut current_session = ctx.session_data.clone().unwrap_or_default();
            current_session.captcha_failures += 1;
            warn!(
                circuit_id = ?ctx.circuit_id,
                session_id = ?current_session.session_id,
                failures = current_session.captcha_failures,
                "CAPTCHA verification failed"
            );

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
                };
                let cookie_val = self.cookie_crypto.encrypt(&reset_session.to_bytes());
                let cookie_header = format_set_cookie(SESSION_COOKIE_NAME, &cookie_val, 300);

                let uri = session.req_header().uri.to_string();
                let mut header = ResponseHeader::build(303, None)?;
                header.insert_header("Location", uri)?;
                header.insert_header("Set-Cookie", cookie_header)?;
                header.insert_header("Clear-Site-Data", "\"cache\"")?;

                inject_security_headers(&mut header, &self.config)?;

                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(true);
            }

            current_session.created_at = now;
            current_session.circuit_id.clone_from(&ctx.circuit_id);
            let cookie_val = self.cookie_crypto.encrypt(&current_session.to_bytes());
            let cookie_header = format_set_cookie(SESSION_COOKIE_NAME, &cookie_val, 300);

            let uri = session.req_header().uri.to_string();
            let mut header = ResponseHeader::build(303, None)?;
            header.insert_header("Location", uri)?;
            header.insert_header("Set-Cookie", cookie_header)?;
            header.insert_header("Clear-Site-Data", "\"cache\"")?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
        }
        Ok(true)
    }
}

fn urlencoding_decode(s: &str) -> String {
    let mut res = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            if let (Some(h1), Some(h2)) = (chars.next(), chars.next())
                && let Ok(byte) = u8::from_str_radix(&format!("{h1}{h2}"), 16)
            {
                res.push(byte as char);
                continue;
            }
            res.push('%');
        } else if c == '+' {
            res.push(' ');
        } else {
            res.push(c);
        }
    }
    res
}

fn parse_captcha_submission(body: &[u8]) -> (String, String) {
    let body_str = String::from_utf8_lossy(body);
    let mut token = String::new();
    let mut solution = String::new();
    let mut c_map = std::collections::HashMap::new();

    for pair in body_str.split('&') {
        let mut kv = pair.splitn(2, '=');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
            let dk = urlencoding_decode(k);
            let dv = urlencoding_decode(v);
            if dk == "s" {
                token = dv;
            } else if dk == "solution" {
                solution = dv;
            } else if dk.starts_with('c') && dk.len() == 2 {
                c_map.insert(dk, dv);
            }
        }
    }

    let answer = if solution.is_empty() {
        format!(
            "{}{}{}{}{}{}",
            c_map.get("c1").unwrap_or(&String::new()),
            c_map.get("c2").unwrap_or(&String::new()),
            c_map.get("c3").unwrap_or(&String::new()),
            c_map.get("c4").unwrap_or(&String::new()),
            c_map.get("c5").unwrap_or(&String::new()),
            c_map.get("c6").unwrap_or(&String::new())
        )
    } else {
        solution
    };

    (token, answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decoding() {
        assert_eq!(urlencoding_decode("%20"), " ");
        assert_eq!(urlencoding_decode("A+B"), "A B");
        assert_eq!(urlencoding_decode("%21"), "!");
        assert_eq!(urlencoding_decode("%"), "%");
        assert_eq!(urlencoding_decode("%2"), "%");
        assert_eq!(urlencoding_decode("Normal"), "Normal");
    }

    #[test]
    fn test_parse_captcha_submission() {
        let body = b"s=token_123&c1=A&c2=B&c3=C&c4=D&c5=E&c6=F";
        let (token, answer) = parse_captcha_submission(body);
        assert_eq!(token, "token_123");
        assert_eq!(answer, "ABCDEF");

        let body_solution = b"s=token_456&solution=XYZ";
        let (token_sol, answer_sol) = parse_captcha_submission(body_solution);
        assert_eq!(token_sol, "token_456");
        assert_eq!(answer_sol, "XYZ");

        let empty = b"";
        let (t, a) = parse_captcha_submission(empty);
        assert!(t.is_empty());
        assert!(a.is_empty());
    }

    #[test]
    fn test_url_decoding_complex() {
        assert_eq!(urlencoding_decode("%C3%A9"), "Ã©");
        assert_eq!(urlencoding_decode("a%20b"), "a b");
        assert_eq!(urlencoding_decode("%"), "%");
        assert_eq!(urlencoding_decode("%2"), "%");
        assert_eq!(urlencoding_decode("%2G"), "%");
        assert_eq!(urlencoding_decode("foo%00bar"), "foo\0bar");
    }

    #[test]
    fn test_parse_captcha_submission_edge_cases() {
        let body = b"s=1&solution=2&c10=A&c=B";
        let (t, a) = parse_captcha_submission(body);
        assert_eq!(t, "1");
        assert_eq!(a, "2");
    }
}
