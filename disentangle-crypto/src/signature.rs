//! Post-Quantum Signatures using Dilithium5 (NIST ML-DSA Level 5)
//!
//! Dilithium5 provides:
//! - Public key: 2,592 bytes
//! - Secret key: 4,896 bytes  
//! - Signature: 4,627 bytes
//! - Security: NIST Level 5 (equivalent to AES-256)

use crate::{CryptoError, Result};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const PUBLIC_KEY_BYTES: usize = 2592;
pub const SECRET_KEY_BYTES: usize = 4896;
pub const SIGNATURE_BYTES: usize = 4627;

#[derive(Clone)]
pub struct SigningKey(dilithium5::SecretKey);

#[derive(Clone)]
pub struct VerifyingKey(dilithium5::PublicKey);

#[derive(Clone)]
pub struct Signature(Vec<u8>);

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Eq for VerifyingKey {}

impl std::hash::Hash for VerifyingKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Signature {}

impl SigningKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_KEY_BYTES {
            return Err(CryptoError::InvalidKeyLength {
                expected: SECRET_KEY_BYTES,
                got: bytes.len(),
            });
        }
        let sk = dilithium5::SecretKey::from_bytes(bytes).map_err(|_| {
            CryptoError::InvalidKeyLength {
                expected: SECRET_KEY_BYTES,
                got: bytes.len(),
            }
        })?;
        Ok(Self(sk))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_BYTES,
                got: bytes.len(),
            });
        }
        let pk = dilithium5::PublicKey::from_bytes(bytes).map_err(|_| {
            CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_BYTES,
                got: bytes.len(),
            }
        })?;
        Ok(Self(pk))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_BYTES {
            return Err(CryptoError::InvalidKeyLength {
                expected: SIGNATURE_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let (pk, sk) = dilithium5::keypair();
    (SigningKey(sk), VerifyingKey(pk))
}

pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    let signed = dilithium5::detached_sign(message, &signing_key.0);
    Signature(signed.as_bytes().to_vec())
}

pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<()> {
    let sig = dilithium5::DetachedSignature::from_bytes(&signature.0)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;
    dilithium5::verify_detached_signature(&sig, message, &verifying_key.0)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

impl Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Signature::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.to_bytes();
        let hex_preview = hex::encode(&bytes[..8]);
        f.debug_struct("VerifyingKey")
            .field("prefix", &format!("{}...", hex_preview))
            .finish()
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex_preview = hex::encode(&self.0[..8]);
        f.debug_struct("Signature")
            .field("prefix", &format!("{}...", hex_preview))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let (sk, pk) = generate_keypair();
        let message = b"test message for signing";
        let sig = sign(&sk, message);
        assert!(verify(&pk, message, &sig).is_ok());
    }

    #[test]
    fn test_invalid_signature_fails() {
        let (sk, pk) = generate_keypair();
        let message = b"test message";
        let sig = sign(&sk, message);
        let wrong_message = b"wrong message";
        assert!(verify(&pk, wrong_message, &sig).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let (sk, _) = generate_keypair();
        let (_, wrong_pk) = generate_keypair();
        let message = b"test message";
        let sig = sign(&sk, message);
        assert!(verify(&wrong_pk, message, &sig).is_err());
    }

    #[test]
    fn test_key_serialization() {
        let (_, pk) = generate_keypair();
        let bytes = pk.to_bytes();
        let restored = VerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, restored);
    }
}
