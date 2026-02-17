//! Post-Quantum Key Encapsulation using Kyber1024 (NIST ML-KEM Level 5)
//!
//! Kyber1024 provides:
//! - Public key: 1,568 bytes
//! - Secret key: 3,168 bytes
//! - Ciphertext: 1,568 bytes
//! - Shared secret: 32 bytes
//! - Security: NIST Level 5 (equivalent to AES-256)
//!
//! Used for:
//! - Stealth addresses (encrypting outputs to receivers)
//! - Hybrid key exchange in P2P transport (future)

use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as PqPublicKey, SecretKey as PqSecretKey, Ciphertext as PqCiphertext, SharedSecret as PqSharedSecret};
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use crate::{CryptoError, Result};

pub const ENCAPSULATION_KEY_BYTES: usize = 1568;
pub const DECAPSULATION_KEY_BYTES: usize = 3168;
pub const CIPHERTEXT_BYTES: usize = 1568;
pub const SHARED_SECRET_BYTES: usize = 32;

#[derive(Clone)]
pub struct EncapsulationKey(kyber1024::PublicKey);

#[derive(Clone)]
pub struct DecapsulationKey(kyber1024::SecretKey);

#[derive(Clone)]
pub struct Ciphertext(kyber1024::Ciphertext);

#[derive(Clone, PartialEq, Eq)]
pub struct SharedSecret([u8; SHARED_SECRET_BYTES]);

impl PartialEq for EncapsulationKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Eq for EncapsulationKey {}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Eq for Ciphertext {}

impl EncapsulationKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ENCAPSULATION_KEY_BYTES {
            return Err(CryptoError::InvalidKeyLength {
                expected: ENCAPSULATION_KEY_BYTES,
                got: bytes.len(),
            });
        }
        let pk = kyber1024::PublicKey::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: ENCAPSULATION_KEY_BYTES,
                got: bytes.len(),
            })?;
        Ok(Self(pk))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl DecapsulationKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DECAPSULATION_KEY_BYTES {
            return Err(CryptoError::InvalidKeyLength {
                expected: DECAPSULATION_KEY_BYTES,
                got: bytes.len(),
            });
        }
        let sk = kyber1024::SecretKey::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: DECAPSULATION_KEY_BYTES,
                got: bytes.len(),
            })?;
        Ok(Self(sk))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CIPHERTEXT_BYTES {
            return Err(CryptoError::InvalidKeyLength {
                expected: CIPHERTEXT_BYTES,
                got: bytes.len(),
            });
        }
        let ct = kyber1024::Ciphertext::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: CIPHERTEXT_BYTES,
                got: bytes.len(),
            })?;
        Ok(Self(ct))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
        &self.0
    }
}

pub fn generate_kem_keypair() -> (EncapsulationKey, DecapsulationKey) {
    let (pk, sk) = kyber1024::keypair();
    (EncapsulationKey(pk), DecapsulationKey(sk))
}

pub fn encapsulate(encapsulation_key: &EncapsulationKey) -> (Ciphertext, SharedSecret) {
    let (ss, ct) = kyber1024::encapsulate(&encapsulation_key.0);
    let mut secret = [0u8; SHARED_SECRET_BYTES];
    secret.copy_from_slice(ss.as_bytes());
    (Ciphertext(ct), SharedSecret(secret))
}

pub fn decapsulate(decapsulation_key: &DecapsulationKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
    let ss = kyber1024::decapsulate(&ciphertext.0, &decapsulation_key.0);
    let mut secret = [0u8; SHARED_SECRET_BYTES];
    secret.copy_from_slice(ss.as_bytes());
    Ok(SharedSecret(secret))
}

impl Serialize for EncapsulationKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for EncapsulationKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        EncapsulationKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Ciphertext {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for Ciphertext {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Ciphertext::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.to_bytes();
        let hex_preview = hex::encode(&bytes[..8]);
        f.debug_struct("EncapsulationKey")
            .field("prefix", &format!("{}...", hex_preview))
            .finish()
    }
}

impl std::fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecapsulationKey").field("bytes", &"[REDACTED]").finish()
    }
}

impl std::fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.to_bytes();
        let hex_preview = hex::encode(&bytes[..8]);
        f.debug_struct("Ciphertext")
            .field("prefix", &format!("{}...", hex_preview))
            .finish()
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret").field("bytes", &"[REDACTED]").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_roundtrip() {
        let (ek, dk) = generate_kem_keypair();
        let (ct, ss1) = encapsulate(&ek);
        let ss2 = decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let (ek1, _) = generate_kem_keypair();
        let (_, dk2) = generate_kem_keypair();
        let (ct, ss1) = encapsulate(&ek1);
        let ss2 = decapsulate(&dk2, &ct).unwrap();
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_key_serialization() {
        let (ek, _) = generate_kem_keypair();
        let bytes = ek.to_bytes();
        let restored = EncapsulationKey::from_bytes(&bytes).unwrap();
        assert_eq!(ek, restored);
    }
}
