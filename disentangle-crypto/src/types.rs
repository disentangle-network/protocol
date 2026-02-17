//! Core type aliases for Disentangle Protocol v0.3
//!
//! These types provide a unified interface across the protocol.

use crate::hash::Hash256;
use crate::signature::VerifyingKey;
use serde::{Deserialize, Serialize};

pub type NodeId = Hash256;
pub type PublicKey = VerifyingKey;
pub type SecretKey = crate::signature::SigningKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Epoch(pub u64);

impl Epoch {
    pub const DEPTH_PER_EPOCH: u64 = 100;

    /// Derive epoch from topological depth.
    /// Epoch is a deterministic function of depth: epoch = depth / DEPTH_PER_EPOCH.
    /// Since depth is a static property of a transaction (determined by its parents),
    /// epoch is also static — all nodes compute the same epoch for the same transaction.
    pub fn from_depth(depth: u64) -> Self {
        Self(depth / Self::DEPTH_PER_EPOCH)
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub Hash256);

impl AccountId {
    pub fn from_public_key(pk: &VerifyingKey) -> Self {
        Self(crate::hash::sha3_256(&pk.to_bytes()))
    }

    pub fn as_bytes(&self) -> &Hash256 {
        &self.0
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReputationScore(pub u64);

impl ReputationScore {
    pub const ZERO: Self = Self(0);
    pub const MIN_VOUCH_REQUIRED: Self = Self(50);

    pub fn from_tx_count(count: u64) -> Self {
        Self(count)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier(pub Hash256);

impl Nullifier {
    pub fn compute(secret_key_hash: &Hash256, epoch: Epoch, tx_nonce: &[u8]) -> Self {
        Self(crate::hash::compute_nullifier(
            secret_key_hash,
            epoch.0,
            tx_nonce,
        ))
    }

    pub fn as_bytes(&self) -> &Hash256 {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::HASH_BYTES;
    use crate::signature::generate_keypair;

    #[test]
    fn test_epoch_from_depth() {
        assert_eq!(Epoch::from_depth(0).0, 0);
        assert_eq!(Epoch::from_depth(99).0, 0);
        assert_eq!(Epoch::from_depth(100).0, 1);
        assert_eq!(Epoch::from_depth(250).0, 2);
    }

    #[test]
    fn test_account_id_from_pk() {
        let (_, pk) = generate_keypair();
        let id = AccountId::from_public_key(&pk);
        assert_eq!(id.0.len(), HASH_BYTES);
    }

    #[test]
    fn test_nullifier_determinism() {
        let sk_hash = crate::hash::sha3_256(b"secret");
        let epoch = Epoch(5);
        let nonce = b"tx_nonce";
        let n1 = Nullifier::compute(&sk_hash, epoch, nonce);
        let n2 = Nullifier::compute(&sk_hash, epoch, nonce);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_nullifier_epoch_dependence() {
        let sk_hash = crate::hash::sha3_256(b"secret");
        let nonce = b"tx_nonce";
        let n1 = Nullifier::compute(&sk_hash, Epoch(1), nonce);
        let n2 = Nullifier::compute(&sk_hash, Epoch(2), nonce);
        assert_ne!(n1, n2);
    }
}
