//! CAPTCHA generation.
//!
//! Implements image generation, difficulty management, and validation logic.

pub mod generator;
pub mod manager;

pub use generator::{CaptchaGenerator, CharPosition, Difficulty};
pub use manager::CaptchaManager;
