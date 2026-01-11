//! Proxy service implementation.
//!
//! Handles request filtering, upstream peer selection, response modification,
//! and integrates rate limiting, WAF defense, and UI responses.

pub mod challenge;
pub mod headers;
pub mod listener;
pub mod pool;
pub mod protocol;
pub mod router;
pub mod service;

pub use pool::{UpstreamPool, create_pool};
pub use service::MaveProxy;
