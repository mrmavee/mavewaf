//! Rate limiting module using pingora-limits CM-Sketch.
//!
//! Provides per-circuit rate limiting with Burst and Sustained windows.
//! - Burst Window: 1 second (limits instantaneous spikes).
//! - Sustained Window: 10 seconds (enforces average RPS).

use pingora_limits::rate::Rate;
use std::sync::Arc;
use std::time::Duration;

pub struct RateLimiter {
    burst_rate: Arc<Rate>,
    sustained_rate: Arc<Rate>,
    max_burst: f64,
    max_sustained: f64,
}

impl RateLimiter {
    /// Creates a new `RateLimiter` with specified RPS and burst capacity.
    #[must_use]
    pub fn new(rps: u32, burst: u32) -> Self {
        let burst_limiter = Rate::new(Duration::from_secs(1));
        let sustained_limiter = Rate::new(Duration::from_secs(10));

        Self {
            burst_rate: Arc::new(burst_limiter),
            sustained_rate: Arc::new(sustained_limiter),
            max_burst: f64::from(burst),
            max_sustained: f64::from(rps * 10),
        }
    }

    /// Checks if a request checks out against the rate limits and records it.
    #[must_use]
    pub fn check_and_record(&self, key: &str) -> bool {
        self.burst_rate.observe(&key, 1);
        self.sustained_rate.observe(&key, 1);

        let curr_burst = self.burst_rate.rate(&key);
        if curr_burst > self.max_burst {
            return false;
        }

        let curr_sustained = self.sustained_rate.rate(&key);
        if curr_sustained > self.max_sustained {
            return false;
        }

        true
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self {
            burst_rate: Arc::clone(&self.burst_rate),
            sustained_rate: Arc::clone(&self.sustained_rate),
            max_burst: self.max_burst,
            max_sustained: self.max_sustained,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratelimit_allow_basic() {
        let limiter = RateLimiter::new(10, 5);
        assert!(limiter.check_and_record("test_key"));
    }

    #[test]
    fn test_ratelimit_different_keys_independent() {
        let limiter = RateLimiter::new(100, 10);
        assert!(limiter.check_and_record("key_a"));
        assert!(limiter.check_and_record("key_b"));
        assert!(limiter.check_and_record("key_c"));
    }

    #[test]
    fn test_ratelimit_clone() {
        let limiter1 = RateLimiter::new(10, 5);
        let limiter2 = limiter1.clone();
        assert!(limiter1.check_and_record("clone_key"));
        assert!(limiter2.check_and_record("clone_key"));
    }

    #[test]
    fn test_ratelimit_creation() {
        let limiter = RateLimiter::new(50, 25);
        assert!((limiter.max_burst - 25.0).abs() < f64::EPSILON);
        assert!((limiter.max_sustained - 500.0).abs() < f64::EPSILON);
    }
}
