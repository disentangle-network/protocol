//! Proof generation and verification for reputation claims.
//!
//! This module provides high-level APIs for generating and verifying
//! zero-knowledge reputation proofs using the Plonky3 STARK prover.

use crate::circuit::{ReputationAir, ReputationWitness};
use crate::merkle::AccountMerkleTree;
use crate::types::{AccountStateLeaf, ReputationClaim};
use crate::{ZkpError, Result};
use disentangle_crypto::hash::Hash256;

use p3_matrix::Matrix;

/// Prover for reputation claims.
pub struct ReputationProver {
    /// The Merkle tree of account states
    tree: AccountMerkleTree,
}

impl ReputationProver {
    /// Create a new prover with the given account states.
    pub fn new(accounts: &[AccountStateLeaf]) -> Self {
        Self {
            tree: AccountMerkleTree::new(accounts),
        }
    }

    /// Get the Merkle root of all account states.
    pub fn merkle_root(&self) -> Hash256 {
        self.tree.root()
    }

    /// Generate a reputation proof for the account at the given index.
    ///
    /// Proves that the account has reputation >= threshold without
    /// revealing which account (index is private input).
    ///
    /// # Arguments
    /// * `account_index` - Index of the prover's account in the tree
    /// * `account` - The prover's account state (must match tree leaf)
    /// * `threshold` - Minimum reputation to prove
    /// * `epoch` - Current epoch (for replay protection)
    ///
    /// # Returns
    /// A `ReputationClaim` containing the proof data.
    pub fn prove(
        &self,
        account_index: usize,
        account: &AccountStateLeaf,
        threshold: u64,
        epoch: u64,
    ) -> Result<ReputationClaim> {
        // Verify the account has sufficient reputation
        if account.reputation_score < threshold {
            return Err(ZkpError::InsufficientReputation {
                claimed: account.reputation_score,
                required: threshold,
            });
        }

        // Get Merkle proof for the account
        let merkle_proof = self
            .tree
            .prove_membership(account_index)
            .map_err(|_| ZkpError::InvalidMerkleProof)?;

        // Verify the merkle proof is valid
        if !self.tree.verify_proof(&merkle_proof) {
            return Err(ZkpError::InvalidMerkleProof);
        }

        // Build the witness
        let witness = ReputationWitness {
            reputation_score: account.reputation_score,
            threshold,
            leaf_hash: account.hash(),
            merkle_siblings: merkle_proof.siblings.clone(),
            path_bits: merkle_proof.path_bits.clone(),
            merkle_root: self.tree.root(),
        };

        // Generate the execution trace
        let trace = witness.generate_trace();
        let _air = ReputationAir {
            num_rows: trace.height(),
        };

        // For now, we serialize the witness as the "proof"
        // Full Plonky3 proving requires more setup (PCS, FRI config, etc.)
        // This is a placeholder that will be replaced with actual STARK proving
        let proof_data = serialize_witness_as_proof(&witness)?;

        Ok(ReputationClaim::new(
            threshold,
            self.tree.root(),
            proof_data,
            epoch,
        ))
    }
}

/// Verifier for reputation claims.
pub struct ReputationVerifier;

impl ReputationVerifier {
    /// Create a new verifier.
    pub fn new() -> Self {
        Self
    }

    /// Verify a reputation claim.
    ///
    /// # Arguments
    /// * `claim` - The reputation claim to verify
    /// * `expected_root` - Expected Merkle root (from trusted source)
    /// * `current_epoch` - Current epoch (for replay protection)
    ///
    /// # Returns
    /// `Ok(())` if the proof is valid, `Err` otherwise.
    pub fn verify(
        &self,
        claim: &ReputationClaim,
        expected_root: &Hash256,
        current_epoch: u64,
    ) -> Result<()> {
        // Check epoch (proof can only be used in the epoch it was created)
        if claim.epoch != current_epoch {
            return Err(ZkpError::ProofVerificationFailed);
        }

        // Check Merkle root matches
        if claim.merkle_root != *expected_root {
            return Err(ZkpError::ProofVerificationFailed);
        }

        // Deserialize and verify the proof
        let witness = deserialize_witness_from_proof(&claim.proof_data)?;

        // Verify Merkle path
        if !verify_merkle_path(&witness) {
            return Err(ZkpError::InvalidMerkleProof);
        }

        // Verify reputation threshold
        if witness.reputation_score < claim.threshold {
            return Err(ZkpError::InsufficientReputation {
                claimed: witness.reputation_score,
                required: claim.threshold,
            });
        }

        // Note: In a real ZK system, the verifier would NOT have access to
        // the witness. This is a placeholder implementation.
        // The actual STARK verification would only use public inputs.

        Ok(())
    }
}

impl Default for ReputationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a Merkle path (helper for verification).
fn verify_merkle_path(witness: &ReputationWitness) -> bool {
    let mut current = witness.leaf_hash;

    for (sibling, &is_right) in witness.merkle_siblings.iter().zip(witness.path_bits.iter()) {
        current = if is_right {
            disentangle_crypto::hash::sha3_256_multi(&[b"MERKLE_NODE_V1", sibling, &current])
        } else {
            disentangle_crypto::hash::sha3_256_multi(&[b"MERKLE_NODE_V1", &current, sibling])
        };
    }

    current == witness.merkle_root
}

/// Serialize witness as proof (placeholder for actual STARK proof).
fn serialize_witness_as_proof(witness: &ReputationWitness) -> Result<Vec<u8>> {
    bincode::serialize(witness)
        .map_err(|e| ZkpError::SerializationError(e.to_string()))
}

/// Deserialize witness from proof (placeholder for actual STARK verification).
fn deserialize_witness_from_proof(data: &[u8]) -> Result<ReputationWitness> {
    bincode::deserialize(data)
        .map_err(|e| ZkpError::SerializationError(e.to_string()))
}

// Add Serialize/Deserialize to ReputationWitness for the placeholder impl
use serde::{Serialize, Deserialize};

impl Serialize for ReputationWitness {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ReputationWitness", 6)?;
        s.serialize_field("reputation_score", &self.reputation_score)?;
        s.serialize_field("threshold", &self.threshold)?;
        s.serialize_field("leaf_hash", &self.leaf_hash.to_vec())?;
        s.serialize_field("merkle_siblings", &self.merkle_siblings.iter().map(|h| h.to_vec()).collect::<Vec<_>>())?;
        s.serialize_field("path_bits", &self.path_bits)?;
        s.serialize_field("merkle_root", &self.merkle_root.to_vec())?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for ReputationWitness {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            reputation_score: u64,
            threshold: u64,
            leaf_hash: Vec<u8>,
            merkle_siblings: Vec<Vec<u8>>,
            path_bits: Vec<bool>,
            merkle_root: Vec<u8>,
        }

        let helper = Helper::deserialize(deserializer)?;

        let leaf_hash: [u8; 32] = helper.leaf_hash.try_into()
            .map_err(|_| serde::de::Error::custom("invalid leaf_hash length"))?;
        let merkle_root: [u8; 32] = helper.merkle_root.try_into()
            .map_err(|_| serde::de::Error::custom("invalid merkle_root length"))?;
        let merkle_siblings: Vec<[u8; 32]> = helper.merkle_siblings
            .into_iter()
            .map(|v| v.try_into().map_err(|_| serde::de::Error::custom("invalid sibling length")))
            .collect::<std::result::Result<_, _>>()?;

        Ok(ReputationWitness {
            reputation_score: helper.reputation_score,
            threshold: helper.threshold,
            leaf_hash,
            merkle_siblings,
            path_bits: helper.path_bits,
            merkle_root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_accounts() -> Vec<AccountStateLeaf> {
        vec![
            AccountStateLeaf::new([1u8; 32], 100, 10, 100),
            AccountStateLeaf::new([2u8; 32], 200, 20, 200),
            AccountStateLeaf::new([3u8; 32], 50, 5, 300),
            AccountStateLeaf::new([4u8; 32], 75, 7, 400),
        ]
    }

    #[test]
    fn test_prove_and_verify_success() {
        let accounts = make_test_accounts();
        let prover = ReputationProver::new(&accounts);
        let verifier = ReputationVerifier::new();

        // Account 0 has reputation 100, prove >= 50
        let claim = prover.prove(0, &accounts[0], 50, 1).unwrap();

        // Verify should succeed
        let root = prover.merkle_root();
        assert!(verifier.verify(&claim, &root, 1).is_ok());
    }

    #[test]
    fn test_prove_insufficient_reputation() {
        let accounts = make_test_accounts();
        let prover = ReputationProver::new(&accounts);

        // Account 2 has reputation 50, try to prove >= 100
        let result = prover.prove(2, &accounts[2], 100, 1);
        assert!(matches!(result, Err(ZkpError::InsufficientReputation { .. })));
    }

    #[test]
    fn test_verify_wrong_epoch() {
        let accounts = make_test_accounts();
        let prover = ReputationProver::new(&accounts);
        let verifier = ReputationVerifier::new();

        let claim = prover.prove(0, &accounts[0], 50, 1).unwrap();

        // Verify with wrong epoch should fail
        let root = prover.merkle_root();
        assert!(verifier.verify(&claim, &root, 2).is_err());
    }

    #[test]
    fn test_verify_wrong_root() {
        let accounts = make_test_accounts();
        let prover = ReputationProver::new(&accounts);
        let verifier = ReputationVerifier::new();

        let claim = prover.prove(0, &accounts[0], 50, 1).unwrap();

        // Verify with wrong root should fail
        let wrong_root = [0xFFu8; 32];
        assert!(verifier.verify(&claim, &wrong_root, 1).is_err());
    }

    #[test]
    fn test_prove_exact_threshold() {
        let accounts = make_test_accounts();
        let prover = ReputationProver::new(&accounts);
        let verifier = ReputationVerifier::new();

        // Account 0 has reputation 100, prove >= 100 (exact match)
        let claim = prover.prove(0, &accounts[0], 100, 1).unwrap();

        let root = prover.merkle_root();
        assert!(verifier.verify(&claim, &root, 1).is_ok());
    }
}
