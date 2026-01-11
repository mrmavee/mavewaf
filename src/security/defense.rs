//! Defense mode management.
//!
//! Monitors error rates and circuit flooding to automatically switch
//! between normal and defense modes.

mod monitor;

pub use monitor::DefenseMonitor;
