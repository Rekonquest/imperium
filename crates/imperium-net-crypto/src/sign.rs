use ed25519_dalek::{
    Signature as Ed25519Sig, Signer, SigningKey as Ed25519Sk, Verifier,
    VerifyingKey as Ed25519Vk,
};
use ml_dsa::MlDsa65;
use rand_core::CryptoRngCore;
use signature_pq::Keypair as PqKeypair;
use signature_pq::Signer as PqSigner;
use signature_pq::Verifier as PqVerifier;
use zeroize::ZeroizeOnDrop;

#[derive(Debug, thiserror::Error)]
pub enum HybridSignError {
    #[error("Ed25519 signature verification failed")]
    Ed25519VerifyFailed,
    #[error("ML-DSA-65 signature verification failed")]
    MlDsaVerifyFailed,
}

type MlDsaSk = ml_dsa::SigningKey<MlDsa65>;
type MlDsaVk = ml_dsa::VerifyingKey<MlDsa65>;
type MlDsaSig = ml_dsa::Signature<MlDsa65>;

#[derive(ZeroizeOnDrop)]
pub struct HybridSigningKey {
    #[zeroize(skip)]
    ed25519_sk: Ed25519Sk,
    #[zeroize(skip)]
    mldsa_sk: MlDsaSk,
}

#[derive(Clone)]
pub struct HybridVerifyingKey {
    pub ed25519_vk: Ed25519Vk,
    pub mldsa_vk: MlDsaVk,
}

pub struct HybridSignature {
    pub ed25519_sig: Ed25519Sig,
    pub mldsa_sig: MlDsaSig,
}

impl HybridSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.ed25519_sig.to_bytes().as_ref());
        let encoded = self.mldsa_sig.encode();
        out.extend_from_slice(encoded.as_ref());
        out
    }
}

pub struct HybridEd25519Mldsa;

impl HybridEd25519Mldsa {
    pub fn generate_keypair(rng: &mut impl CryptoRngCore) -> (HybridSigningKey, HybridVerifyingKey) {
        let ed25519_sk = Ed25519Sk::generate(&mut *rng);
        let ed25519_vk = ed25519_sk.verifying_key();

        let mut seed_bytes = [0u8; 32];
        rng.fill_bytes(&mut seed_bytes);
        let mldsa_sk = MlDsaSk::from_seed(&seed_bytes.into());
        let mldsa_vk = mldsa_sk.verifying_key();

        let signing = HybridSigningKey {
            ed25519_sk,
            mldsa_sk,
        };
        let verifying = HybridVerifyingKey {
            ed25519_vk,
            mldsa_vk,
        };
        (signing, verifying)
    }

    pub fn sign(key: &HybridSigningKey, message: &[u8]) -> HybridSignature {
        let ed25519_sig = key.ed25519_sk.sign(message);
        let mldsa_sig = key.mldsa_sk.sign(message);

        HybridSignature {
            ed25519_sig,
            mldsa_sig,
        }
    }

    pub fn verify(
        key: &HybridVerifyingKey,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<(), HybridSignError> {
        key.ed25519_vk
            .verify(message, &signature.ed25519_sig)
            .map_err(|_| HybridSignError::Ed25519VerifyFailed)?;

        key.mldsa_vk
            .verify(message, &signature.mldsa_sig)
            .map_err(|_| HybridSignError::MlDsaVerifyFailed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_and_verify_round_trip() {
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let msg = b"operator-signed bootstrap token payload";

        let sig = HybridEd25519Mldsa::sign(&sk, msg);
        HybridEd25519Mldsa::verify(&vk, msg, &sig).unwrap();
    }

    #[test]
    fn tampered_message_fails_verification() {
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let msg = b"original message";
        let tampered = b"tampered message";

        let sig = HybridEd25519Mldsa::sign(&sk, msg);
        assert!(HybridEd25519Mldsa::verify(&vk, tampered, &sig).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let mut rng = OsRng;
        let (sk1, _vk1) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let (_sk2, vk2) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let msg = b"test message";

        let sig = HybridEd25519Mldsa::sign(&sk1, msg);
        assert!(HybridEd25519Mldsa::verify(&vk2, msg, &sig).is_err());
    }
}
