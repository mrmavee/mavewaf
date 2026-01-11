//! Cookie encryption.
//!
//! Implements AES-GCM encryption and HMAC signing for secure session tokens.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const TOKEN_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(Clone)]
pub struct CookieCrypto {
    master_key: [u8; 32],
}

impl CookieCrypto {
    /// Creates a new `CookieCrypto` instance using the provided secret.
    #[must_use]
    pub fn new(secret: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let result = hasher.finalize();
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&result);
        Self { master_key }
    }

    /// Encrypts data into a URL-safe string.
    ///
    /// # Panics
    ///
    /// Panics if AES-GCM encryption fails (e.g., due to an internal library error).
    #[must_use]
    pub fn encrypt(&self, plaintext: &[u8]) -> String {
        let mut token = [0u8; TOKEN_LEN];
        OsRng.fill_bytes(&mut token);

        let derived_key = self.derive_key(&token);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .expect("AES-GCM encryption failed");

        let mut combined = Vec::with_capacity(TOKEN_LEN + NONCE_LEN + ciphertext.len());
        combined.extend_from_slice(&token);
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        URL_SAFE_NO_PAD.encode(&combined)
    }

    /// Decrypts session data from a URL-safe string.
    #[must_use]
    pub fn decrypt(&self, encoded: &str) -> Option<Vec<u8>> {
        let combined = URL_SAFE_NO_PAD.decode(encoded).ok()?;

        if combined.len() < TOKEN_LEN + NONCE_LEN + TAG_LEN + 1 {
            return None;
        }

        let token = &combined[..TOKEN_LEN];
        let nonce = Nonce::from_slice(&combined[TOKEN_LEN..TOKEN_LEN + NONCE_LEN]);
        let ciphertext = &combined[TOKEN_LEN + NONCE_LEN..];

        let derived_key = self.derive_key(token);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
        cipher.decrypt(nonce, ciphertext).ok()
    }

    /// Derives a session key from the master key and token.
    ///
    /// # Panics
    ///
    /// Panics if HMAC initialization fails (invalid key length), though this is statically prevented
    /// by the fixed key size.
    fn derive_key(&self, token: &[u8]) -> [u8; 32] {
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(&self.master_key)
            .expect("HMAC accepts any key size");
        mac.update(token);
        let result = mac.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result.into_bytes());
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let crypto = CookieCrypto::new("super_secret_key_123");
        let plaintext = b"Hello, World!";

        let encrypted = crypto.encrypt(plaintext);
        let decrypted = crypto.decrypt(&encrypted).expect("Decryption failed");

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_unique_ciphertexts() {
        let crypto = CookieCrypto::new("secret");
        let plaintext = b"Data";

        let enc1 = crypto.encrypt(plaintext);
        let enc2 = crypto.encrypt(plaintext);

        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_invalid_data() {
        let crypto = CookieCrypto::new("secret");

        assert!(crypto.decrypt("invalid_base64_%%%").is_none());
        assert!(crypto.decrypt("short").is_none());

        let encrypted = crypto.encrypt(b"data");
        let mut bytes = URL_SAFE_NO_PAD.decode(&encrypted).unwrap();
        if let Some(last) = bytes.last_mut() {
            *last ^= 0xFF;
        }
        let corrupted = URL_SAFE_NO_PAD.encode(bytes);
        assert!(crypto.decrypt(&corrupted).is_none());
    }
}
