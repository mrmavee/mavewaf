//! Session management.
//!
//! Provides HMAC-signed session cookies for rate limiting identity
//! using pipe-separated values encrypted via AES-GCM.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default)]
pub struct EncryptedSession {
    pub session_id: String,
    pub circuit_id: Option<String>,
    pub created_at: u64,
    pub queue_started_at: u64,
    pub queue_completed: bool,
    pub captcha_failures: u8,
    pub captcha_gen_count: u8,
    pub verified: bool,
    pub verified_at: u64,
    pub last_active_at: u64,
}

impl EncryptedSession {
    /// Serializes the session data into a pipe-separated byte vector.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.session_id,
            self.circuit_id.as_deref().unwrap_or(""),
            self.created_at,
            self.queue_started_at,
            u8::from(self.queue_completed),
            self.captcha_failures,
            self.captcha_gen_count,
            u8::from(self.verified),
            self.verified_at,
            self.last_active_at
        )
        .into_bytes()
    }

    /// Deserializes session data from bytes, checking expiration.
    #[must_use]
    pub fn from_bytes(data: &[u8], expiry_secs: u64) -> Option<Self> {
        let s = std::str::from_utf8(data).ok()?;
        let parts: Vec<&str> = s.split('|').collect();

        if parts.len() < 8 || parts.len() > 10 {
            return None;
        }

        let created_at: u64 = parts[2].parse().ok()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

        if now.saturating_sub(created_at) > expiry_secs {
            return None;
        }

        let verified_at = if parts.len() >= 9 {
            parts[8].parse().ok()?
        } else {
            0
        };

        let last_active_at = if parts.len() == 10 {
            parts[9].parse().ok()?
        } else {
            0
        };

        Some(Self {
            session_id: parts[0].to_string(),
            circuit_id: if parts[1].is_empty() {
                None
            } else {
                Some(parts[1].to_string())
            },
            created_at,
            queue_started_at: parts[3].parse().ok()?,
            queue_completed: parts[4] == "1",
            captcha_failures: parts[5].parse().ok()?,
            captcha_gen_count: parts[6].parse().ok()?,
            verified: parts[7] == "1",
            verified_at,
            last_active_at,
        })
    }
}

#[must_use]
pub fn generate_session_id() -> String {
    let random_bytes: [u8; 32] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(random_bytes)
}

#[must_use]
pub fn format_set_cookie(name: &str, value: &str, max_age: u64, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!("{name}={value}; HttpOnly{secure_flag}; SameSite=Strict; Path=/; Max-Age={max_age}")
}

pub const SESSION_COOKIE_NAME: &str = "mave_session";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_serialization_roundtrip() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let session = EncryptedSession {
            session_id: "test_session_id".to_string(),
            circuit_id: Some("test_circuit_id".to_string()),
            created_at: now,
            queue_started_at: now,
            queue_completed: true,
            captcha_failures: 1,
            captcha_gen_count: 2,
            verified: true,
            verified_at: now + 100,
            last_active_at: now,
        };

        let bytes = session.to_bytes();
        let decoded = EncryptedSession::from_bytes(&bytes, 3600).expect("Failed to deserialize");

        assert_eq!(session.session_id, decoded.session_id);
        assert_eq!(session.circuit_id, decoded.circuit_id);
        assert_eq!(session.created_at, decoded.created_at);
        assert_eq!(session.verified, decoded.verified);
        assert_eq!(session.verified_at, decoded.verified_at);
    }

    #[test]
    fn test_session_backward_compatibility() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let old_format_str = format!("old_id|old_circuit|{now}|{now}|1|0|0|1");
        let bytes = old_format_str.into_bytes();

        let decoded =
            EncryptedSession::from_bytes(&bytes, 3600).expect("Failed to decode old format");

        assert_eq!(decoded.session_id, "old_id");
        assert!(decoded.verified);
        assert_eq!(decoded.verified_at, 0);
    }

    #[test]
    fn test_session_expiry() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired_time = now - 3601;

        let session = EncryptedSession {
            created_at: expired_time,
            ..Default::default()
        };

        let bytes = session.to_bytes();
        let result = EncryptedSession::from_bytes(&bytes, 3600);

        assert!(result.is_none(), "Expired session should return None");
    }

    #[test]
    fn test_generate_session_id_randomness() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 43);
    }
}
