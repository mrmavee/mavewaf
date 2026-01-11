//! Configuration management.
//!
//! Loads configuration from environment variables using dotenvy.
//! All settings are loaded at startup and stored in a thread-safe Arc.

mod error;
mod settings;

pub use error::{Result, WafError};
pub use settings::{CaptchaStyle, Config, FeatureFlags, WafMode};
