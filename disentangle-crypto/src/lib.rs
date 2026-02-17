//! # Entangle Crypto
//!
//! Post-Quantum cryptographic primitives for Entangle Protocol v0.2.
//!
//! ## Cryptographic Suite
//!
//! | Component | Primitive | NIST Level |
//! |-----------|-----------|------------|
//! | Signatures | Dilithium5 (ML-DSA) | 5 |
//! | Key Encapsulation | Kyber1024 (ML-KEM) | 5 |
//! | Hashing | SHA3-256 | N/A |
//!
//! All primitives are quantum-resistant and deterministic.

pub mod signature;
pub mod kem;
pub mod hash;
pub mod types;

pub use signature::{SigningKey, VerifyingKey, Signature, sign, verify, generate_keypair};
pub use kem::{EncapsulationKey, DecapsulationKey, Ciphertext, SharedSecret, encapsulate, decapsulate, generate_kem_keypair};
pub use hash::{sha3_256, sha3_256_multi, Hash256};
pub use types::{PublicKey, SecretKey, NodeId};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("decapsulation failed")]
    DecapsulationFailed,
    #[error("serialization error: {0}")]
    SerializationError(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
