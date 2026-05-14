//! Unified Cryptographic Engine
//!
//! Single shared crypto backend for all protocols, eliminating:
//! - Multiple AES/ChaCha implementations in RAM
//! - Redundant key derivation
//! - Inconsistent random number generation
//!
//! Uses RustCrypto for all operations.

use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use parking_lot::RwLock;
use sha2::{Sha256, Sha384, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::Zeroizing;

/// Unified crypto engine shared by all protocols
pub struct CryptoEngine {
    /// AES-256-GCM cipher pool (reusable)
    aes_pool: RwLock<Vec<Aes256Gcm>>,

    /// ChaCha20-Poly1305 cipher pool
    chacha_pool: RwLock<Vec<ChaCha20Poly1305>>,

    /// Entropy pool for additional randomness
    entropy_pool: RwLock<Vec<u8>>,

    /// Key derivation cache (derived_key_id -> key material)
    kdf_cache: RwLock<lru::LruCache<String, Zeroizing<Vec<u8>>>>,
}

impl CryptoEngine {
    pub fn new() -> Self {
        Self {
            aes_pool: RwLock::new(Vec::with_capacity(16)),
            chacha_pool: RwLock::new(Vec::with_capacity(16)),
            entropy_pool: RwLock::new(vec![0u8; 4096]),
            kdf_cache: RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(256).unwrap(),
            )),
        }
    }

    /// Generate cryptographically secure random bytes
    pub fn random_bytes(&self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        getrandom::getrandom(&mut bytes).expect("Failed to generate random bytes");
        bytes
    }

    /// Generate random nonce for AEAD
    pub fn random_nonce_aes(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).expect("Failed to generate nonce");
        nonce
    }

    /// Derive key using HKDF-SHA256
    pub fn derive_key_sha256(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        len: usize,
    ) -> Zeroizing<Vec<u8>> {
        let hk = Hkdf::<Sha256>::new(salt, ikm);
        let mut okm = Zeroizing::new(vec![0u8; len]);
        hk.expand(info, &mut okm).expect("HKDF expand failed");
        okm
    }

    /// Derive key using HKDF-SHA384
    pub fn derive_key_sha384(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        len: usize,
    ) -> Zeroizing<Vec<u8>> {
        let hk = Hkdf::<Sha384>::new(salt, ikm);
        let mut okm = Zeroizing::new(vec![0u8; len]);
        hk.expand(info, &mut okm).expect("HKDF expand failed");
        okm
    }

    /// Derive key using HKDF-SHA512
    pub fn derive_key_sha512(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        len: usize,
    ) -> Zeroizing<Vec<u8>> {
        let hk = Hkdf::<Sha512>::new(salt, ikm);
        let mut okm = Zeroizing::new(vec![0u8; len]);
        hk.expand(info, &mut okm).expect("HKDF expand failed");
        okm
    }

    /// Cached key derivation (avoids recomputing same keys)
    pub fn derive_key_cached(
        &self,
        cache_id: &str,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        len: usize,
    ) -> Zeroizing<Vec<u8>> {
        // Check cache first
        if let Some(cached) = self.kdf_cache.write().get(cache_id) {
            return cached.clone();
        }

        // Derive and cache
        let key = self.derive_key_sha256(ikm, salt, info, len);
        self.kdf_cache.write().put(cache_id.to_string(), key.clone());
        key
    }

    /// AES-256-GCM encryption
    pub fn aes_gcm_encrypt(&self, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Prepend nonce to ciphertext
        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    /// AES-256-GCM decryption
    pub fn aes_gcm_decrypt(&self, key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 12 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let plaintext = cipher
            .decrypt(nonce, &ciphertext[12..])
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// ChaCha20-Poly1305 encryption
    pub fn chacha_encrypt(&self, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut result = nonce.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    /// ChaCha20-Poly1305 decryption
    pub fn chacha_decrypt(&self, key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::Nonce as ChaNonce;

        if ciphertext.len() < 12 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let nonce = ChaNonce::from_slice(&ciphertext[..12]);
        let plaintext = cipher
            .decrypt(nonce, &ciphertext[12..])
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// X25519 key exchange
    pub fn x25519_keypair(&self) -> (EphemeralSecret, PublicKey) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    /// X25519 shared secret derivation
    pub fn x25519_shared_secret(
        secret: EphemeralSecret,
        peer_public: &PublicKey,
    ) -> SharedSecret {
        secret.diffie_hellman(peer_public)
    }

    /// Clear sensitive data from memory
    pub fn secure_clear(&self) {
        self.kdf_cache.write().clear();
        self.entropy_pool.write().iter_mut().for_each(|b| *b = 0);
    }
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CryptoEngine {
    fn drop(&mut self) {
        self.secure_clear();
    }
}

/// Crypto errors
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key")]
    InvalidKey,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

/// Global shared crypto engine
pub static CRYPTO: once_cell::sync::Lazy<Arc<CryptoEngine>> =
    once_cell::sync::Lazy::new(|| Arc::new(CryptoEngine::new()));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let engine = CryptoEngine::new();
        let key = [0u8; 32];
        let plaintext = b"Hello, World!";

        let ciphertext = engine.aes_gcm_encrypt(&key, plaintext).unwrap();
        let decrypted = engine.aes_gcm_decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_chacha_roundtrip() {
        let engine = CryptoEngine::new();
        let key = [0u8; 32];
        let plaintext = b"Hello, ChaCha!";

        let ciphertext = engine.chacha_encrypt(&key, plaintext).unwrap();
        let decrypted = engine.chacha_decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_key_derivation() {
        let engine = CryptoEngine::new();
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let key1 = engine.derive_key_sha256(ikm, Some(salt), info, 32);
        let key2 = engine.derive_key_sha256(ikm, Some(salt), info, 32);

        assert_eq!(*key1, *key2);
    }
}
