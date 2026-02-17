//! # Entangle ZKP
//!
//! Zero-knowledge proof system for Entangle Protocol.
//! Uses Plonky3 STARKs for privacy-preserving reputation proofs and confidential transactions.
//!
//! ## Features
//!
//! - Merkle tree for account state commitments (SHA3-256)
//! - STARK circuit for bucketed reputation proofs
//! - Hash-based amount commitments for confidential transactions
//! - Balance and range proof circuits
//! - Stealth addresses using Kyber1024 KEM
//! - Proof generation < 500ms target
//! - Zero-knowledge: verifier learns only bucket membership, not exact reputation
//!
//! ## Reputation Buckets
//!
//! To bridge the gap between ZK proofs (which prove predicates) and mass computation
//! (which requires values), reputation is discretized into buckets. Each bucket has
//! a public weight used in mass computation.
//!
//! ## Architecture
//!
//! ```text
//! AccountState[] --> MerkleTree --> root
//!                        |
//!                        v
//! ReputationCircuit(private: account, path; public: root, bucket)
//!                        |
//!                        v
//!                   ZkProof --> verify() --> bool
//!
//! ConfidentialTx --> BalanceCircuit + RangeCircuit --> ZkProof
//! ```

pub mod merkle;
pub mod types;
pub mod circuit;
pub mod proof;
pub mod confidential;
pub mod balance_circuit;
pub mod range_circuit;
pub mod stealth;
pub mod reputation_bucket;

pub use merkle::{AccountMerkleTree, MerkleProof};
pub use types::{ReputationClaim, AccountStateLeaf, SupporterTag, DiversityAwareReputationClaim};
pub use proof::{ReputationProver, ReputationVerifier};
pub use confidential::{AmountCommitment, ConfidentialAmount, Blinding};
pub use balance_circuit::{BalanceAir, BalanceWitness};
pub use range_circuit::{RangeAir, RangeWitness};
pub use stealth::{StealthAddress, ConfidentialOutput, StealthError};
pub use reputation_bucket::{ReputationBucket, BUCKET_WEIGHTS, reputation_to_bucket, bucket_weight};

#[derive(Debug, thiserror::Error)]
pub enum ZkpError {
    #[error("invalid merkle proof")]
    InvalidMerkleProof,
    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(String),
    #[error("proof verification failed")]
    ProofVerificationFailed,
    #[error("insufficient reputation: claimed {claimed}, required {required}")]
    InsufficientReputation { claimed: u64, required: u64 },
    #[error("serialization error: {0}")]
    SerializationError(String),
}

pub type Result<T> = std::result::Result<T, ZkpError>;
