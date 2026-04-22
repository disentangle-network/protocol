//! # Entangle ZKP
//!
//! Zero-knowledge reputation proofs for the Entangle Protocol, built on
//! Plonky3 STARKs. The headline surface of this crate is
//! [`ReputationProver`] / [`ReputationVerifier`]: a verifier learns only
//! that a claimant's reputation falls into a public bucket, never the
//! exact value.
//!
//! ## Default surface (reputation proofs)
//!
//! - [`ReputationProver`] / [`ReputationVerifier`] — bucketed STARK proofs
//! - [`AccountMerkleTree`] / [`MerkleProof`] — account-state commitments (SHA3-256)
//! - [`ReputationBucket`] / [`BUCKET_WEIGHTS`] — discretized reputation classes
//!   used by mass computation
//! - [`AccountStateLeaf`], [`ReputationClaim`], [`DiversityAwareReputationClaim`],
//!   [`SupporterTag`]
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
//! ```
//!
//! ## Reputation buckets
//!
//! To bridge the gap between ZK predicates and the mass computation used
//! by consensus, reputation is discretized into buckets. Each bucket has
//! a public weight. The circuit proves bucket membership without
//! revealing the underlying score.
//!
//! ## Primitives available for future applications
//!
//! Additional primitives — stealth addressing, hash-based amount
//! commitments, balance and range circuits for confidential
//! transactions — are implemented in this crate but gated behind the
//! `primitives-future` Cargo feature. They are not load-bearing for the
//! current enterprise positioning; they remain available for
//! applications that later need privacy-preserving payments or stealth
//! addressing. See the README for the full list and activation
//! instructions.

// Reputation-proof surface — always available.
pub mod circuit;
pub mod merkle;
pub mod proof;
pub mod reputation_bucket;
pub mod stark_config;
pub mod types;

// Primitives reserved for future applications. Gated so the default
// build surfaces only reputation proofs.
#[cfg(feature = "primitives-future")]
pub mod balance_circuit;
#[cfg(feature = "primitives-future")]
pub mod confidential;
#[cfg(feature = "primitives-future")]
pub mod range_circuit;
#[cfg(feature = "primitives-future")]
pub mod stealth;

// Headline re-exports: reputation proofs first.
pub use merkle::{AccountMerkleTree, MerkleProof};
pub use proof::{ReputationProver, ReputationVerifier};
pub use reputation_bucket::{
    bucket_weight, reputation_to_bucket, ReputationBucket, BUCKET_WEIGHTS,
};
pub use types::{AccountStateLeaf, DiversityAwareReputationClaim, ReputationClaim, SupporterTag};

// Future-application re-exports, gated with the modules above.
#[cfg(feature = "primitives-future")]
pub use balance_circuit::{BalanceAir, BalanceWitness};
#[cfg(feature = "primitives-future")]
pub use confidential::{AmountCommitment, Blinding, ConfidentialAmount};
#[cfg(feature = "primitives-future")]
pub use range_circuit::{RangeAir, RangeWitness};
#[cfg(feature = "primitives-future")]
pub use stealth::{ConfidentialOutput, StealthAddress, StealthError};

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
