use hkdf::Hkdf;
use hybrid_array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use rand_core::CryptoRngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::HYBRID_SESSION_KEY_LEN;

#[derive(Debug, thiserror::Error)]
pub enum HybridKexError {
    #[error("ML-KEM decapsulation failed")]
    MlKemDecapsulationFailed,
    #[error("HKDF expand failed")]
    HkdfExpandFailed,
    #[error("invalid ciphertext length")]
    InvalidCiphertextLength,
}

type MlKemEk = <MlKem768 as KemCore>::EncapsulationKey;
type MlKemDk = <MlKem768 as KemCore>::DecapsulationKey;
type MlKemCtSize = <MlKem768 as KemCore>::CiphertextSize;
type MlKemCt = Array<u8, MlKemCtSize>;

pub struct HybridKexSecretKey {
    x25519_secret: EphemeralSecret,
    mlkem_dk: MlKemDk,
}

#[derive(Clone)]
pub struct HybridKexPublicKey {
    pub x25519_public: X25519Public,
    pub mlkem_ek: MlKemEk,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSessionKey {
    key: [u8; HYBRID_SESSION_KEY_LEN],
}

impl HybridSessionKey {
    pub fn as_bytes(&self) -> &[u8; HYBRID_SESSION_KEY_LEN] {
        &self.key
    }
}

pub struct HybridEncapsulation {
    pub x25519_public: X25519Public,
    mlkem_ct: MlKemCt,
}

impl HybridEncapsulation {
    pub fn mlkem_ciphertext_bytes(&self) -> &[u8] {
        self.mlkem_ct.as_ref()
    }
}

pub struct HybridX25519Mlkem;

impl HybridX25519Mlkem {
    pub fn generate_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> (HybridKexSecretKey, HybridKexPublicKey) {
        let x25519_secret = EphemeralSecret::random_from_rng(&mut *rng);
        let x25519_public = X25519Public::from(&x25519_secret);
        let (mlkem_dk, mlkem_ek) = MlKem768::generate(rng);

        let secret = HybridKexSecretKey {
            x25519_secret,
            mlkem_dk,
        };
        let public = HybridKexPublicKey {
            x25519_public,
            mlkem_ek,
        };
        (secret, public)
    }

    pub fn encapsulate(
        rng: &mut impl CryptoRngCore,
        responder_public: &HybridKexPublicKey,
    ) -> (HybridEncapsulation, HybridSessionKey) {
        let x25519_ephemeral = EphemeralSecret::random_from_rng(&mut *rng);
        let x25519_public = X25519Public::from(&x25519_ephemeral);
        let x25519_shared = x25519_ephemeral.diffie_hellman(&responder_public.x25519_public);

        let (mlkem_ct, mlkem_ss) = responder_public
            .mlkem_ek
            .encapsulate(rng)
            .expect("ML-KEM encapsulation cannot fail");

        let session_key = derive_hybrid_key(&x25519_shared, mlkem_ss.as_ref());

        let encap = HybridEncapsulation {
            x25519_public,
            mlkem_ct,
        };
        (encap, session_key)
    }

    pub fn decapsulate(
        secret: HybridKexSecretKey,
        encapsulation: &HybridEncapsulation,
    ) -> Result<HybridSessionKey, HybridKexError> {
        let x25519_shared = secret
            .x25519_secret
            .diffie_hellman(&encapsulation.x25519_public);

        let mlkem_ss = secret
            .mlkem_dk
            .decapsulate(&encapsulation.mlkem_ct)
            .map_err(|_| HybridKexError::MlKemDecapsulationFailed)?;

        Ok(derive_hybrid_key(&x25519_shared, mlkem_ss.as_ref()))
    }
}

fn derive_hybrid_key(x25519_shared: &SharedSecret, mlkem_shared: &[u8]) -> HybridSessionKey {
    let mut ikm = Vec::with_capacity(32 + mlkem_shared.len());
    ikm.extend_from_slice(x25519_shared.as_bytes());
    ikm.extend_from_slice(mlkem_shared);

    let hk = Hkdf::<Sha256>::new(Some(b"imperium-hybrid-kex-v1"), &ikm);
    let mut key = [0u8; HYBRID_SESSION_KEY_LEN];
    hk.expand(b"session-key", &mut key)
        .expect("HKDF-SHA256 expand to 32 bytes cannot fail");

    ikm.zeroize();
    HybridSessionKey { key }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn key_exchange_round_trip() {
        let mut rng = OsRng;

        let (secret_b, public_b) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (encap, session_key_a) = HybridX25519Mlkem::encapsulate(&mut rng, &public_b);
        let session_key_b = HybridX25519Mlkem::decapsulate(secret_b, &encap).unwrap();

        assert_eq!(session_key_a.as_bytes(), session_key_b.as_bytes());
    }

    #[test]
    fn different_sessions_produce_different_keys() {
        let mut rng = OsRng;

        let (_s1, p1) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (_, key1) = HybridX25519Mlkem::encapsulate(&mut rng, &p1);

        let (_s2, p2) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (_, key2) = HybridX25519Mlkem::encapsulate(&mut rng, &p2);

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
