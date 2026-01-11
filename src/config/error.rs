//! Error types and result aliases.
//!
//! Defines the core `WafError` enumeration and common `Result` type.

use thiserror::Error;

/// WAF-specific errors.
#[derive(Debug, Error)]
pub enum WafError {
    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded for circuit: {circuit_id}")]
    RateLimited { circuit_id: String },

    /// CAPTCHA verification failed.
    #[error("CAPTCHA verification failed")]
    CaptchaFailed,

    /// Tor control protocol error.
    #[error("tor control error: {0}")]
    TorControl(String),

    /// Webhook notification error.
    #[error("webhook error: {0}")]
    Webhook(String),

    /// HTTP proxy error.
    #[error("proxy error: {0}")]
    Proxy(String),
}

/// Result type alias for `WafError`.
pub type Result<T> = std::result::Result<T, WafError>;
