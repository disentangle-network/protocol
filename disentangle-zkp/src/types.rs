//! Core types for zero-knowledge reputation proofs.

use disentangle_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};

/// Leaf data for account state in Merkle tree.
/// This is what gets hashed to create leaf nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStateLeaf {
    /// Hash of the account's public key (identity commitment)
    pub account_id_hash: Hash256,
    /// Account's reputation score
    pub reputation_score: u64,
    /// Number of transactions by this account
    pub transaction_count: u64,
    /// First depth where this account appeared (topological depth, not block number)
    pub first_seen_depth: u64,
}

impl AccountStateLeaf {
    /// Create a new account state leaf.
    pub fn new(
        account_id_hash: Hash256,
        reputation_score: u64,
        transaction_count: u64,
        first_seen_depth: u64,
    ) -> Self {
        Self {
            account_id_hash,
            reputation_score,
            transaction_count,
            first_seen_depth,
        }
    }

    /// Compute the leaf hash for Merkle tree.
    /// Uses domain-separated SHA3-256.
    pub fn hash(&self) -> Hash256 {
        disentangle_crypto::hash::sha3_256_multi(&[
            b"ACCOUNT_LEAF_V1",
            &self.account_id_hash,
            &self.reputation_score.to_le_bytes(),
            &self.transaction_count.to_le_bytes(),
            &self.first_seen_depth.to_le_bytes(),
        ])
    }
}

/// A zero-knowledge reputation claim.
/// Proves that an account has at least `threshold` reputation
/// without revealing which account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationClaim {
    /// Minimum reputation being proven
    pub threshold: u64,
    /// Merkle root of all account states
    pub merkle_root: Hash256,
    /// The STARK proof data
    pub proof_data: Vec<u8>,
    /// Epoch this proof is valid for (prevents replay)
    pub epoch: u64,
}

impl ReputationClaim {
    /// Create a new reputation claim.
    pub fn new(threshold: u64, merkle_root: Hash256, proof_data: Vec<u8>, epoch: u64) -> Self {
        Self {
            threshold,
            merkle_root,
            proof_data,
            epoch,
        }
    }
}

/// Per-window supporter tag for diversity counting.
///
/// Enables unique supporter counting without global identity linkability:
/// - Same identity, same window, same tx → same tag (deduplication)
/// - Different windows or transactions → different tags (unlinkability)
///
/// Computed as: H(identity_secret || window_id || tx_id)
///
/// The ZK proof demonstrates:
/// 1. Prover knows identity_secret for an account in the Merkle tree
/// 2. The tag was correctly derived from that secret
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SupporterTag(pub Hash256);

impl SupporterTag {
    /// Compute a supporter tag (for testing/non-ZK scenarios).
    /// In production, this is computed inside the ZK circuit.
    pub fn compute(identity_secret: &[u8; 32], window_id: u64, tx_id: &Hash256) -> Self {
        let tag = disentangle_crypto::hash::sha3_256_multi(&[
            b"SUPPORTER_TAG_V1",
            identity_secret,
            &window_id.to_le_bytes(),
            tx_id,
        ]);
        Self(tag)
    }

    /// Get the underlying hash
    pub fn as_bytes(&self) -> &Hash256 {
        &self.0
    }
}

/// Claim that includes a supporter tag for diversity counting.
/// Combines reputation proof with unique supporter identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiversityAwareReputationClaim {
    /// The reputation claim (bucket membership proof)
    pub reputation: ReputationClaim,
    /// Supporter tag for this (window, transaction) pair
    pub supporter_tag: SupporterTag,
    /// Window ID this tag is valid for
    pub window_id: u64,
    /// Transaction ID this tag is computed for
    pub tx_id: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_state_leaf_hash_determinism() {
        let leaf = AccountStateLeaf::new([0u8; 32], 100, 50, 1000);
        let hash1 = leaf.hash();
        let hash2 = leaf.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_account_state_leaf_hash_changes_with_reputation() {
        let leaf1 = AccountStateLeaf::new([0u8; 32], 100, 50, 1000);
        let leaf2 = AccountStateLeaf::new([0u8; 32], 101, 50, 1000);
        assert_ne!(leaf1.hash(), leaf2.hash());
    }
}
