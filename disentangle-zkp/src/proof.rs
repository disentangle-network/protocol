//! Proof generation and verification for reputation claims.
//!
//! This module provides high-level APIs for generating and verifying
//! zero-knowledge reputation proofs using the Plonky3 STARK prover.

use crate::circuit::{ReputationAir, ReputationWitness};
use crate::merkle::AccountMerkleTree;
use crate::stark_config::{self, StarkConfigType};
use crate::types::{AccountStateLeaf, ReputationClaim};
use crate::{Result, ZkpError};

use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::Proof;

use disentangle_crypto::hash::Hash256;

/// BabyBear prime modulus.
const BABYBEAR_PRIME: u64 = 2013265921;

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

        // Generate the execution trace and pad to power-of-2 rows
        let trace = pad_trace_to_power_of_two(witness.generate_trace());
        let air = ReputationAir {
            num_rows: trace.height(),
        };

        // Build public values: threshold and merkle root split into field elements
        let public_values = build_public_values(threshold, &self.tree.root());

        // Create the deterministic STARK config
        let (config, perm) = stark_config::create_stark_config();
        let mut challenger = stark_config::create_challenger(&perm);

        // Generate the STARK proof
        let stark_proof =
            p3_uni_stark::prove(&config, &air, &mut challenger, trace, &public_values);

        // Serialize the proof
        let proof_data = bincode::serialize(&stark_proof)
            .map_err(|e| ZkpError::SerializationError(e.to_string()))?;

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

        // Deserialize the STARK proof
        let stark_proof: Proof<StarkConfigType> = bincode::deserialize(&claim.proof_data)
            .map_err(|e| ZkpError::SerializationError(e.to_string()))?;

        // Reconstruct the AIR (verifier only needs the structure, not the witness)
        let air = ReputationAir::default();

        // Reconstruct public values from the claim's public fields
        let public_values = build_public_values(claim.threshold, &claim.merkle_root);

        // Create a fresh config and challenger (must match prover's config exactly)
        let (config, perm) = stark_config::create_stark_config();
        let mut challenger = stark_config::create_challenger(&perm);

        // Verify the STARK proof
        p3_uni_stark::verify(&config, &air, &mut challenger, &stark_proof, &public_values)
            .map_err(|_| ZkpError::ProofVerificationFailed)?;

        Ok(())
    }
}

impl Default for ReputationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the public values vector from threshold and merkle root.
///
/// Public values encode:
/// - `[0]`: threshold (reduced mod BabyBear prime)
/// - `[1]`: merkle_root low 4 bytes as u32 (reduced mod BabyBear prime)
/// - `[2]`: merkle_root bytes 4..8 as u32 (reduced mod BabyBear prime)
fn build_public_values(threshold: u64, merkle_root: &Hash256) -> Vec<BabyBear> {
    vec![
        u64_to_field(threshold),
        bytes_to_field_u32(&merkle_root[0..4]),
        bytes_to_field_u32(&merkle_root[4..8]),
    ]
}

/// Convert u64 to BabyBear field element (reduced mod prime).
fn u64_to_field(val: u64) -> BabyBear {
    BabyBear::from_canonical_u32((val % BABYBEAR_PRIME) as u32)
}

/// Convert 4 bytes (little-endian) to a BabyBear field element.
fn bytes_to_field_u32(bytes: &[u8]) -> BabyBear {
    let mut val: u32 = 0;
    for (i, &b) in bytes.iter().take(4).enumerate() {
        val |= (b as u32) << (i * 8);
    }
    BabyBear::from_canonical_u32(val % (BABYBEAR_PRIME as u32))
}

/// Minimum trace height for FRI compatibility.
///
/// FRI folding requires enough evaluation points for the query protocol
/// to work. With `log_blowup: 2` and `num_queries: 28`, we need at least
/// 2^3 = 8 rows to produce a valid proof.
const MIN_TRACE_HEIGHT: usize = 8;

/// Pad a trace to have a power-of-2 number of rows (minimum 8).
///
/// STARK proving requires traces with 2^k rows and FRI needs a minimum
/// domain size. Zero rows are appended as needed.
fn pad_trace_to_power_of_two(trace: RowMajorMatrix<BabyBear>) -> RowMajorMatrix<BabyBear> {
    let width = trace.width();
    let height = trace.height();
    let target_height = height.next_power_of_two().max(MIN_TRACE_HEIGHT);

    if height == target_height {
        return trace;
    }

    let mut values = trace.values;
    values.resize(target_height * width, BabyBear::zero());
    RowMajorMatrix::new(values, width)
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
        assert!(matches!(
            result,
            Err(ZkpError::InsufficientReputation { .. })
        ));
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
