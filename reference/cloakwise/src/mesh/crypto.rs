//! Optional ChaCha20-Poly1305 wrapping for mesh UDP payloads.

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

pub struct MeshCrypto {
    key: Key,
}

impl MeshCrypto {
    pub fn from_psk(psk: &str) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(None, psk.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"cloakwise-mesh-v1", &mut okm)
            .map_err(|e| anyhow::anyhow!("hkdf expand: {:?}", e))?;
        Ok(Self {
            key: *Key::from_slice(&okm),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let mut n = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut n);
        let nonce = Nonce::from_slice(&n);
        let ct = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("encrypt: {:?}", e))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(&self, buf: &[u8]) -> Result<Vec<u8>> {
        if buf.len() < 13 {
            anyhow::bail!("truncated");
        }
        let nonce = Nonce::from_slice(&buf[..12]);
        let cipher = ChaCha20Poly1305::new(&self.key);
        cipher
            .decrypt(nonce, &buf[12..])
            .map_err(|_| anyhow::anyhow!("decrypt failed"))
    }
}

pub fn maybe_encrypt(psk: Option<&str>, body: &[u8]) -> Result<Vec<u8>> {
    match psk.filter(|s| !s.is_empty()) {
        Some(p) => {
            let c = MeshCrypto::from_psk(p).context("mesh psk")?;
            c.encrypt(body)
        }
        None => Ok(body.to_vec()),
    }
}

pub fn maybe_decrypt(psk: Option<&str>, buf: &[u8]) -> Result<Vec<u8>> {
    match psk.filter(|s| !s.is_empty()) {
        Some(p) => {
            let c = MeshCrypto::from_psk(p).context("mesh psk")?;
            c.decrypt(buf)
        }
        None => Ok(buf.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psk_roundtrip() {
        let c = MeshCrypto::from_psk("test-psk").unwrap();
        let ct = c.encrypt(b"payload").unwrap();
        assert_eq!(c.decrypt(&ct).unwrap(), b"payload");
    }
}
