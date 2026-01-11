//! Request handlers.
//!
//! implements the logic for processing and filtering HTTP requests.

mod engine;
mod rules;

pub use engine::{WafEngine, WafResult};
pub use rules::RuleEngine;
