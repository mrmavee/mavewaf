//! Library definitions.
//!
//! Exports core modules, types, and the main proxy service implementation.

pub mod config;
pub mod core;
pub mod features;
pub mod security;
pub mod web;

#[cfg(any(test, feature = "testing"))]
pub mod test_utils;
pub use config::{Config, Result, WafError, WafMode};
pub use core::middleware::{
    EncryptedSession, RateLimiter, SESSION_COOKIE_NAME, format_set_cookie, generate_session_id,
};
pub use core::proxy::MaveProxy;
pub use core::proxy::pool::{UpstreamPool, create_pool};
pub use core::proxy::protocol::{ProxyProtocolConfig, run_proxy_listener};
pub use features::tor::control::TorControl;
pub use features::webhook::{EventType, WebhookNotifier, WebhookPayload};
pub use security::captcha::CaptchaManager;
pub use security::crypto::CookieCrypto;
pub use security::defense::DefenseMonitor;
pub use security::waf::WafEngine;
pub use web::ui::preload_templates;
