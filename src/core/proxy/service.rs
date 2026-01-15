//! Proxy service logic.
//!
//! Handles the core proxy logic including request filtering, WAF integration,
//! and upstream forwarding.

use crate::config::Config;
use crate::core::middleware::{
    EncryptedSession, RateLimiter, SESSION_COOKIE_NAME, generate_session_id,
};
use crate::core::proxy::headers::inject_security_headers;
use crate::core::proxy::response::serve_html;
use crate::core::proxy::router::WafRouter;
use crate::features::tor::{circuit, control::TorControl};
use crate::features::webhook::{EventType, WebhookNotifier, WebhookPayload};
use crate::security::captcha::CaptchaManager;
use crate::security::crypto::CookieCrypto;
use crate::security::defense::DefenseMonitor;
use crate::security::waf::WafEngine;
use crate::web::ui;
use async_trait::async_trait;
use pingora::Result;
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Context for a single request.
#[derive(Default)]
pub struct RequestCtx {
    pub circuit_id: Option<String>,
    pub session_data: Option<EncryptedSession>,
    pub rate_key: Option<String>,
    pub is_error: bool,
    pub set_session_cookie: Option<String>,
    pub body_buffer: Vec<u8>,
    pub skip_body_scan: bool,
}

/// Main proxy service implementing `ProxyHttp`.
pub struct MaveProxy {
    config: Arc<Config>,
    rate_limiter: RateLimiter,
    session_rate_limiter: RateLimiter,
    defense_monitor: Arc<DefenseMonitor>,
    webhook: Arc<WebhookNotifier>,
    waf_engine: Arc<WafEngine>,
    cookie_crypto: CookieCrypto,
    tor_control: Option<TorControl>,
    waf_router: WafRouter,
}

impl MaveProxy {
    /// Creates a new `MaveProxy` service.
    pub fn new(
        config: Arc<Config>,
        rate_limiter: RateLimiter,
        session_rate_limiter: RateLimiter,
        defense_monitor: Arc<DefenseMonitor>,
        webhook: Arc<WebhookNotifier>,
        captcha: Arc<CaptchaManager>,
        waf_engine: Arc<WafEngine>,
    ) -> Self {
        let cookie_crypto = CookieCrypto::new(&config.session_secret);
        let tor_control = config
            .tor_control_addr
            .map(|addr| TorControl::new(addr, config.tor_control_password.clone()));

        let waf_router = WafRouter::new(
            config.clone(),
            captcha,
            cookie_crypto.clone(),
            tor_control.clone(),
            defense_monitor.clone(),
        );

        Self {
            config,
            rate_limiter,
            session_rate_limiter,
            defense_monitor,
            webhook,
            waf_engine,
            cookie_crypto,
            tor_control,
            waf_router,
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

    async fn handle_waf_and_router(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<bool> {
        let uri = session.req_header().uri.to_string();
        let waf_engine = self.waf_engine.clone();

        let waf_result = tokio::task::spawn_blocking(move || waf_engine.scan(&uri, "URI"))
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "WAF scan panic");
                crate::security::waf::WafResult::blocked("Internal WAF Error".to_string(), 100)
            });

        if waf_result.blocked {
            let method = session.req_header().method.as_str();
            let path = session.req_header().uri.path();
            warn!(
                http_method = %method,
                http_path = %path,
                circuit_id = ?ctx.circuit_id,
                rule = waf_result.reason.as_deref().unwrap_or("Unknown"),
                action = "BLOCK",
                "WAF block"
            );
            self.kill_circuit_if_possible(ctx.circuit_id.as_deref())
                .await;
            let request_id = ctx
                .session_data
                .as_ref()
                .map_or_else(generate_session_id, |s| s.session_id.clone());
            let html = ui::get_block_page(
                waf_result.reason.as_deref().unwrap_or("Security Violation"),
                &request_id,
                &self.config,
            );
            return serve_html(session, &self.config, 403, html, None).await;
        }

        if self.waf_router.handle_request(session, ctx).await? {
            return Ok(true);
        }

        Ok(false)
    }

    fn extract_circuit_id(session: &Session) -> Option<String> {
        let cid = session
            .req_header()
            .headers
            .get("x-circuit-id")
            .and_then(|v| v.to_str().ok())
            .map(std::string::ToString::to_string);

        if cid.is_some() {
            return cid;
        }

        session
            .req_header()
            .headers
            .get("x-i2p-destb64")
            .and_then(|v| v.to_str().ok())
            .map(|s| format!("i2p:{s}"))
    }

    fn extract_session(&self, session: &Session, ctx: &mut RequestCtx) {
        let cookie_header = session
            .req_header()
            .headers
            .get("Cookie")
            .and_then(|v| v.to_str().ok());

        if let Some(cookies) = cookie_header {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(value) = cookie.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
                    if let Some(decrypted) = self.cookie_crypto.decrypt(value) {
                        ctx.session_data = EncryptedSession::from_bytes(
                            &decrypted,
                            self.config.session_expiry_secs,
                        );
                    }
                    break;
                }
            }
        }
    }

    fn is_static_asset(session: &Session) -> bool {
        let path = session.req_header().uri.path();
        std::path::Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                matches!(
                    ext.to_ascii_lowercase().as_str(),
                    "css"
                        | "js"
                        | "mjs"
                        | "map"
                        | "png"
                        | "jpg"
                        | "jpeg"
                        | "gif"
                        | "webp"
                        | "avif"
                        | "bmp"
                        | "heic"
                        | "heif"
                        | "ico"
                        | "svg"
                        | "svgz"
                        | "woff"
                        | "woff2"
                        | "ttf"
                        | "eot"
                        | "otf"
                        | "mp4"
                        | "webm"
                        | "ogg"
                        | "ogv"
                        | "mp3"
                        | "wav"
                        | "flac"
                        | "aac"
                        | "m4a"
                        | "pdf"
                        | "txt"
                        | "md"
                        | "json"
                        | "xml"
                        | "rss"
                        | "atom"
                        | "manifest"
                        | "webmanifest"
                        | "appcache"
                        | "wasm"
                        | "zip"
                        | "gz"
                        | "br"
                        | "zst"
                )
            })
    }

    async fn check_flood(&self, ctx: &mut RequestCtx) -> bool {
        let session_id = ctx.session_data.as_ref().map(|s| s.session_id.as_str());
        ctx.rate_key = circuit::rate_limit_key(ctx.circuit_id.as_deref(), session_id);

        if ctx.rate_key.is_none()
            && let Some(ref cid) = ctx.circuit_id
        {
            ctx.rate_key = Some(cid.clone());
        }

        if let Some(ref circuit) = ctx.circuit_id {
            debug!(circuit_id = %circuit, "Request from Tor circuit");
            self.defense_monitor.record_request(Some(circuit), false);

            if self.defense_monitor.check_circuit_flood(circuit) {
                info!(circuit_id = %circuit, action = "KILL", "Circuit flood detected");
                self.kill_circuit_if_possible(Some(circuit)).await;

                self.webhook.notify(WebhookPayload {
                    event_type: EventType::CircuitKilled,
                    timestamp: i64::try_from(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    )
                    .unwrap_or(0),
                    circuit_id: Some(circuit.clone()),
                    severity: 5,
                    message: format!("Circuit killed due to flood: {circuit}"),
                });

                return true;
            }
        }
        false
    }

    async fn handle_honeypot(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        path: &str,
    ) -> Result<bool> {
        if !self.config.honeypot_paths.contains(path) {
            return Ok(false);
        }

        info!(path = %path, circuit_id = ?ctx.circuit_id, action = "HONEYPOT", "Honeypot trap triggered");
        self.kill_circuit_if_possible(ctx.circuit_id.as_deref())
            .await;

        self.webhook.notify(WebhookPayload {
            event_type: EventType::CircuitKilled,
            timestamp: i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )
            .unwrap_or(0),
            circuit_id: ctx.circuit_id.clone(),
            severity: 5,
            message: format!("Honeypot triggered: {path}"),
        });

        let html = ui::get_error_page(
            "Access Denied",
            "The requested resource is not available.",
            None,
            Some(&self.config),
        );
        serve_html(session, &self.config, 403, html, None).await
    }
}

#[async_trait]
impl ProxyHttp for MaveProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            circuit_id: None,
            session_data: None,
            rate_key: None,
            is_error: false,
            set_session_cookie: None,
            body_buffer: Vec::new(),
            skip_body_scan: false,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let path = session.req_header().uri.path();

        if path == "/.well-known/health" || path == "/health" {
            let is_internal = session.client_addr().is_some_and(|addr| {
                if let pingora::protocols::l4::socket::SocketAddr::Inet(inet) = addr {
                    inet.ip().is_loopback()
                } else {
                    false
                }
            });

            if is_internal {
                let mut header = ResponseHeader::build(200, None)?;
                header.insert_header("Content-Type", "text/plain")?;
                header.insert_header("Content-Length", "2")?;
                header.insert_header("Cache-Control", "no-store")?;
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(bytes::Bytes::from_static(b"OK")), true)
                    .await?;
                return Ok(true);
            }
        }

        ctx.circuit_id = Self::extract_circuit_id(session);
        self.extract_session(session, ctx);

        let path_owned = path.to_string();
        if self.handle_honeypot(session, ctx, &path_owned).await? {
            return Ok(true);
        }

        if ctx.circuit_id.is_none() {
            warn!("Request rejected: missing circuit ID");
            let html = ui::get_error_page(
                "Access Denied",
                "Direct IP access is not allowed. Please use the hidden service.",
                None,
                Some(&self.config),
            );
            return serve_html(session, &self.config, 403, html, None).await;
        }

        let is_static = Self::is_static_asset(session);

        if !is_static {
            if self.check_flood(ctx).await {
                let html = ui::get_error_page(
                    "Circuit Terminated",
                    "Your connection has been terminated due to excessive requests.",
                    None,
                    Some(&self.config),
                );
                return serve_html(session, &self.config, 429, html, None).await;
            }

            if let Some(ref key) = ctx.rate_key
                && !self.rate_limiter.check_and_record(key)
            {
                warn!(circuit_id = %key, action = "RATE_LIMIT", "Circuit rate limit exceeded");
                self.webhook.notify(WebhookPayload {
                    event_type: EventType::RateLimitExceeded,
                    timestamp: i64::try_from(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    )
                    .unwrap_or(0),
                    circuit_id: ctx.circuit_id.clone(),
                    severity: 3,
                    message: format!("Circuit rate limit exceeded for {key}"),
                });

                let uri = session.req_header().uri.to_string();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                return self
                    .waf_router
                    .handler
                    .serve_queue_page(session, ctx, &uri, now)
                    .await;
            }

            if let Some(ref enc_session) = ctx.session_data
                && !self
                    .session_rate_limiter
                    .check_and_record(&enc_session.session_id)
            {
                warn!(session_id = %enc_session.session_id, action = "RATE_LIMIT", "Session rate limit exceeded");
                let uri = session.req_header().uri.to_string();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                return self
                    .waf_router
                    .handler
                    .serve_queue_page(session, ctx, &uri, now)
                    .await;
            }
        }

        self.handle_waf_and_router(session, ctx).await
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if !self.config.features.waf_body_scan_enabled || ctx.skip_body_scan {
            return Ok(());
        }

        if let Some(b) = body {
            if ctx.body_buffer.is_empty() && !b.is_empty() {
                let peek_len = b.len().min(512);
                if let Some(mime) =
                    crate::security::waf::signatures::detect_safe_mime(&b[..peek_len])
                {
                    debug!(mime = %mime, "Skipping WAF scan for safe binary");
                    ctx.skip_body_scan = true;
                    return Ok(());
                }
            }

            if ctx.body_buffer.len() + b.len() > self.config.waf_body_scan_max_size {
                warn!(
                    max_size = self.config.waf_body_scan_max_size,
                    action = "BLOCK",
                    "Request body exceeds scan limit"
                );
                self.kill_circuit_if_possible(ctx.circuit_id.as_deref())
                    .await;
                return Err(pingora::Error::new(pingora::ErrorType::Custom(
                    "Request body too large for inspection",
                )));
            }
            ctx.body_buffer.extend_from_slice(b);
        }

        if end_of_stream && !ctx.body_buffer.is_empty() {
            let body_str = String::from_utf8_lossy(&ctx.body_buffer).to_string();
            let waf_engine = self.waf_engine.clone();

            let waf_result =
                tokio::task::spawn_blocking(move || waf_engine.scan(&body_str, "Body"))
                    .await
                    .unwrap_or(crate::security::waf::WafResult::safe());

            if waf_result.blocked {
                warn!(
                    circuit_id = ?ctx.circuit_id,
                    rule = waf_result.reason.as_deref().unwrap_or("Unknown"),
                    action = "BLOCK",
                    "WAF body scan block"
                );

                self.kill_circuit_if_possible(ctx.circuit_id.as_deref())
                    .await;

                return Err(pingora::Error::new(pingora::ErrorType::Custom(
                    "Blocked by MaveWAF Body Scan",
                )));
            }
        }

        Ok(())
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let addr = self
            .config
            .backend_url
            .strip_prefix("http://")
            .or_else(|| self.config.backend_url.strip_prefix("https://"))
            .unwrap_or(&self.config.backend_url);

        let peer = Box::new(HttpPeer::new(addr, false, String::new()));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request.remove_header("X-Forwarded-For");
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let status = upstream_response.status.as_u16();
        if status >= 500 || status == 403 {
            ctx.is_error = true;
        }

        if let Some(ref cookie) = ctx.set_session_cookie {
            upstream_response.insert_header("Set-Cookie", cookie)?;
        }

        inject_security_headers(upstream_response, &self.config)?;

        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let status = session.response_written().map_or(0, |r| r.status.as_u16());

        self.defense_monitor
            .record_request(ctx.circuit_id.as_deref(), ctx.is_error);

        let circuit = ctx.circuit_id.as_deref().unwrap_or("direct");
        debug!(circuit_id = %circuit, status = status, "Request completed");

        if status >= 400 {
            let path = session.req_header().uri.path();
            warn!(circuit_id = %circuit, status = status, http_path = %path, "Request error");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CaptchaStyle, FeatureFlags, WafMode};
    use pingora::http::RequestHeader;
    use pingora::upstreams::peer::Peer;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_test_config() -> Arc<Config> {
        Arc::new(Config {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            internal_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
            backend_url: "http://127.0.0.1:8080".to_string(),
            waf_mode: WafMode::Normal,
            rate_limit_rps: 10,
            rate_limit_burst: 10,
            features: FeatureFlags {
                captcha_enabled: false,
                webhook_enabled: false,
                waf_body_scan_enabled: false,
                coep_enabled: false,
            },
            captcha_secret: "test".to_string(),
            captcha_ttl: 60,
            captcha_difficulty: "easy".to_string(),
            captcha_style: CaptchaStyle::Simple,
            session_secret: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            session_expiry_secs: 60,
            tor_circuit_prefix: "fc00".to_string(),
            tor_control_addr: None,
            tor_control_password: None,
            torrc_path: None,
            defense_error_rate_threshold: 0.1,
            defense_circuit_flood_threshold: 10,
            defense_cooldown_secs: 10,
            webhook_url: None,
            max_captcha_failures: 3,
            captcha_gen_limit: 5,
            ssrf_allowed_hosts: vec![],
            waf_body_scan_max_size: 1024,
            rate_limit_session_rps: 10,
            rate_limit_session_burst: 10,
            app_name: "Test".to_string(),
            favicon_base64: String::new(),
            meta_title: "Test".to_string(),
            meta_description: "Test".to_string(),
            meta_keywords: "Test".to_string(),
            log_format: "json".to_string(),
            csp_extra_sources: String::new(),
            coop_policy: "same-origin-allow-popups".to_string(),
            honeypot_paths: std::collections::HashSet::new(),
        })
    }

    fn create_proxy(config: Arc<Config>) -> MaveProxy {
        let rate_limiter = RateLimiter::new(10, 10);
        let session_rate_limiter = RateLimiter::new(10, 10);
        let defense_monitor = Arc::new(DefenseMonitor::new(config.clone()));
        let webhook = Arc::new(WebhookNotifier::new(&config));
        let captcha = Arc::new(CaptchaManager::new(&config));
        let waf_engine = Arc::new(WafEngine::new(webhook.clone(), vec![]));

        MaveProxy::new(
            config,
            rate_limiter,
            session_rate_limiter,
            defense_monitor,
            webhook,
            captcha,
            waf_engine,
        )
    }

    fn mock_session() -> &'static mut Session {
        unsafe { &mut *(std::ptr::NonNull::<Session>::dangling().as_ptr()) }
    }

    #[test]
    fn test_mave_proxy_creation() {
        let config = create_test_config();
        let proxy = create_proxy(config);
        assert!(proxy.new_ctx().circuit_id.is_none());
    }

    #[tokio::test]
    async fn test_upstream_peer_selection() {
        let config = create_test_config();
        let proxy = create_proxy(config);
        let mut ctx = proxy.new_ctx();

        let peer = proxy.upstream_peer(mock_session(), &mut ctx).await.unwrap();
        let addr = peer.address().to_string();
        assert!(addr == "127.0.0.1:8080" || addr == "[::1]:8080");
        assert!(peer.sni().is_empty());
    }

    #[tokio::test]
    async fn test_upstream_request_filter() {
        let config = create_test_config();
        let proxy = create_proxy(config);
        let mut ctx = proxy.new_ctx();

        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("X-Forwarded-For", "1.2.3.4").unwrap();
        req.insert_header("Host", "example.com").unwrap();

        proxy
            .upstream_request_filter(mock_session(), &mut req, &mut ctx)
            .await
            .unwrap();

        assert!(req.headers.get("X-Forwarded-For").is_none());
        assert!(req.headers.get("Host").is_some());
    }

    #[tokio::test]
    async fn test_response_filter_headers() {
        let config = create_test_config();
        let proxy = create_proxy(config);
        let mut ctx = proxy.new_ctx();

        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("Server", "nginx").unwrap();
        resp.insert_header("X-Powered-By", "PHP").unwrap();

        proxy
            .response_filter(mock_session(), &mut resp, &mut ctx)
            .await
            .unwrap();

        assert!(resp.headers.get("Server").is_none());
        assert!(resp.headers.get("X-Powered-By").is_none());

        assert!(resp.headers.get("Strict-Transport-Security").is_some());
        assert!(resp.headers.get("Content-Security-Policy").is_some());
        assert!(resp.headers.get("X-Content-Type-Options").is_some());
        assert!(resp.headers.get("Referrer-Policy").is_some());
        assert!(resp.headers.get("Permissions-Policy").is_some());
    }

    #[tokio::test]
    async fn test_response_filter_error_status() {
        let config = create_test_config();
        let proxy = create_proxy(config);
        let mut ctx = proxy.new_ctx();

        let mut resp = ResponseHeader::build(500, None).unwrap();
        proxy
            .response_filter(mock_session(), &mut resp, &mut ctx)
            .await
            .unwrap();
        assert!(ctx.is_error);

        let mut resp_ok = ResponseHeader::build(200, None).unwrap();
        ctx.is_error = false;
        proxy
            .response_filter(mock_session(), &mut resp_ok, &mut ctx)
            .await
            .unwrap();
        assert!(!ctx.is_error);
    }

    #[tokio::test]
    async fn test_response_filter_with_cookie() {
        let config = create_test_config();
        let proxy = create_proxy(config);
        let mut ctx = proxy.new_ctx();
        ctx.set_session_cookie = Some("test_cookie=val".to_string());

        let mut resp = ResponseHeader::build(200, None).unwrap();

        proxy
            .response_filter(mock_session(), &mut resp, &mut ctx)
            .await
            .unwrap();

        assert_eq!(
            resp.headers.get("Set-Cookie").unwrap().to_str().unwrap(),
            "test_cookie=val"
        );
        assert!(resp.headers.get("Content-Security-Policy").is_some());
    }

    #[tokio::test]
    async fn test_request_body_filter_safe_mime() {
        let mut config_inner = (*create_test_config()).clone();
        config_inner.features.waf_body_scan_enabled = true;
        let config = Arc::new(config_inner);
        let proxy = create_proxy(config);
        let mut ctx = proxy.new_ctx();
        let png_header = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let mut body = Some(bytes::Bytes::from(png_header));

        proxy
            .request_body_filter(mock_session(), &mut body, false, &mut ctx)
            .await
            .unwrap();

        assert!(ctx.skip_body_scan);
    }

    #[tokio::test]
    async fn test_request_body_filter_size_limit() {
        let mut config_inner = (*create_test_config()).clone();
        config_inner.features.waf_body_scan_enabled = true;
        config_inner.waf_body_scan_max_size = 10;
        let config = Arc::new(config_inner);
        let proxy = create_proxy(config);
        let mut ctx = proxy.new_ctx();

        let data = vec![0u8; 20];
        let mut body = Some(bytes::Bytes::from(data));

        let res = proxy
            .request_body_filter(mock_session(), &mut body, false, &mut ctx)
            .await;

        assert!(res.is_err());
    }
}
