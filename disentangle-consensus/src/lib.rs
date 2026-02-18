//! # Entangle Consensus v0.2
//!
//! Topological mass computation and conflict resolution.
//! All arithmetic uses fixed-point integers for determinism.
//!
//! ## Changes from v0.1
//! - Reputation now comes from ZK-proven claims (reputation_claim field)
//! - No direct account lookups - privacy preserving
//! - Nullifier-based double-spend prevention
//!
//! ## Zero-Knowledge Verification
//!
//! The consensus module now supports optional ZK verification of reputation claims.
//! When a `VerificationContext` is provided, reputation claims are verified against
//! cryptographic proofs before being used in topological mass computation.
//!
//! ```text
//! Transaction with reputation_claim + optional ReputationClaim proof
//!                     |
//!                     v
//! VerificationContext (expected_root, current_epoch)
//!                     |
//!                     v
//! compute_topological_mass_verified() --> MassResult with verified_claims
//! ```

use disentangle_crypto::hash::Hash256;
use disentangle_dag::{fp_from_ratio, fp_mul, FixedPoint, TransactionDAG, SCALE};
use disentangle_zkp::{bucket_weight, ReputationClaim, ReputationVerifier};
use std::collections::HashMap;

// Re-export ZKP types for convenience
pub use disentangle_zkp::{
    AccountMerkleTree, AccountStateLeaf, ReputationBucket, ReputationProver,
};

pub type NodeId = Hash256;

#[derive(Debug, Clone)]
pub struct MassResult {
    pub total_mass: FixedPoint,
    pub supporters: usize,
    pub diversity_score: FixedPoint,
    pub claimed_reputation: u64,
    /// Number of reputation claims that were verified with ZK proofs
    pub verified_claims: usize,
    /// Number of reputation claims that failed verification
    pub failed_verifications: usize,
}

/// Context for ZK verification of reputation claims.
/// Provides the expected Merkle root and current epoch for proof validation.
#[derive(Debug, Clone)]
pub struct VerificationContext {
    /// Expected Merkle root of account states (from trusted source)
    pub expected_root: Hash256,
    /// Current epoch (for replay protection)
    pub current_epoch: u64,
    /// Whether to reject transactions with invalid proofs
    /// If false, invalid proofs result in reputation_claim being treated as 0
    pub strict_mode: bool,
}

impl VerificationContext {
    /// Create a new verification context.
    pub fn new(expected_root: Hash256, current_epoch: u64) -> Self {
        Self {
            expected_root,
            current_epoch,
            strict_mode: false,
        }
    }

    /// Create a strict verification context that rejects invalid proofs.
    pub fn strict(expected_root: Hash256, current_epoch: u64) -> Self {
        Self {
            expected_root,
            current_epoch,
            strict_mode: true,
        }
    }
}

/// Error types for consensus verification.
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("ZK proof verification failed for transaction {tx_id:?}")]
    VerificationFailed { tx_id: NodeId },
    #[error("Missing ZK proof for transaction {tx_id:?} (required in strict mode)")]
    MissingProof { tx_id: NodeId },
}

/// Map of transaction ID to optional ReputationClaim proof.
/// Transactions without proofs will have their reputation treated as 0 in verified mode.
pub type ProofMap = HashMap<NodeId, ReputationClaim>;

/// Compute topological mass without ZK verification (backward compatible).
/// Trusts the reputation_claim field directly.
///
/// Uses bucketed reputation weights for consistency with ZK-verified computation.
/// Each supporter's contribution is weighted by their reputation bucket.
pub fn compute_topological_mass(
    dag: &mut TransactionDAG,
    root: &NodeId,
    fork_block: u64,
) -> MassResult {
    let descendants = dag.descendants(root);
    let mut supporter_claims: HashMap<Hash256, u64> = HashMap::new();
    let mut descendant_data: Vec<(NodeId, u64)> = Vec::new();
    for node_id in &descendants {
        if let Some(tx) = dag.get(node_id) {
            let pk_hash = disentangle_crypto::hash::sha3_256(&tx.ephemeral_pk.to_bytes());
            supporter_claims.insert(pk_hash, tx.reputation_claim);
            descendant_data.push((*node_id, tx.reputation_claim));
        }
    }
    let unique_supporters = supporter_claims.len();
    let total_claimed: u64 = supporter_claims.values().sum();
    // Diversity score: unique supporters * (1 + log factor for total reputation)
    let log_rep = integer_log1p(total_claimed as i32);
    let diversity_score = (unique_supporters as i32) * (SCALE + log_rep / 10);
    let mut total_mass: i64 = 0;
    for (node_id, reputation_claim) in descendant_data {
        let path_weight = dag.find_best_path_weight(root, &node_id, 15, fork_block);
        // Use bucket weight for reputation bonus (consistent with ZK proofs)
        let rep_bonus = bucket_weight(reputation_claim);
        let contribution = fp_mul(path_weight, rep_bonus);
        total_mass += contribution as i64;
    }
    let scaled_mass = (total_mass * diversity_score as i64) / SCALE as i64;
    MassResult {
        total_mass: scaled_mass.min(i32::MAX as i64) as FixedPoint,
        supporters: unique_supporters,
        diversity_score,
        claimed_reputation: total_claimed,
        verified_claims: 0,
        failed_verifications: 0,
    }
}

/// Compute topological mass with ZK verification of reputation claims.
///
/// This function verifies reputation proofs before accepting reputation values.
/// Transactions with valid proofs use their proven threshold as reputation.
/// Transactions without proofs (or with invalid proofs) have reputation treated as 0.
///
/// # Arguments
/// * `dag` - The transaction DAG
/// * `root` - Root node to compute mass from
/// * `fork_block` - Block height for filtering (reserved for future use)
/// * `ctx` - Verification context with expected Merkle root and epoch
/// * `proofs` - Map of transaction IDs to their reputation proofs
///
/// # Returns
/// * `Ok(MassResult)` - Mass computation with verified reputation
/// * `Err(ConsensusError)` - If strict mode and a proof fails verification
pub fn compute_topological_mass_verified(
    dag: &mut TransactionDAG,
    root: &NodeId,
    fork_block: u64,
    ctx: &VerificationContext,
    proofs: &ProofMap,
) -> Result<MassResult, ConsensusError> {
    let verifier = ReputationVerifier::new();
    let descendants = dag.descendants(root);
    let mut supporter_claims: HashMap<Hash256, u64> = HashMap::new();
    let mut descendant_data: Vec<(NodeId, u64)> = Vec::new();
    let mut verified_count = 0usize;
    let mut failed_count = 0usize;

    for node_id in &descendants {
        if let Some(tx) = dag.get(node_id) {
            let pk_hash = disentangle_crypto::hash::sha3_256(&tx.ephemeral_pk.to_bytes());

            // Try to verify the reputation claim with a ZK proof
            let verified_reputation = if let Some(claim) = proofs.get(node_id) {
                match verifier.verify(claim, &ctx.expected_root, ctx.current_epoch) {
                    Ok(()) => {
                        // Proof valid: use the proven threshold as reputation
                        verified_count += 1;
                        claim.threshold
                    }
                    Err(_) => {
                        // Proof invalid
                        failed_count += 1;
                        if ctx.strict_mode {
                            return Err(ConsensusError::VerificationFailed { tx_id: *node_id });
                        }
                        0 // Treat as zero reputation in non-strict mode
                    }
                }
            } else {
                // No proof provided
                if ctx.strict_mode && tx.reputation_claim > 0 {
                    return Err(ConsensusError::MissingProof { tx_id: *node_id });
                }
                0 // No proof means zero verified reputation
            };

            supporter_claims.insert(pk_hash, verified_reputation);
            descendant_data.push((*node_id, verified_reputation));
        }
    }

    let unique_supporters = supporter_claims.len();
    let total_claimed: u64 = supporter_claims.values().sum();
    let log_rep = integer_log1p(total_claimed as i32);
    let diversity_score = (unique_supporters as i32) * (SCALE + log_rep / 10);

    let mut total_mass: i64 = 0;
    for (node_id, reputation_claim) in descendant_data {
        let path_weight = dag.find_best_path_weight(root, &node_id, 15, fork_block);
        // Use bucket weight for reputation bonus (consistent with ZK proofs)
        let rep_bonus = bucket_weight(reputation_claim);
        let contribution = fp_mul(path_weight, rep_bonus);
        total_mass += contribution as i64;
    }

    let scaled_mass = (total_mass * diversity_score as i64) / SCALE as i64;

    Ok(MassResult {
        total_mass: scaled_mass.min(i32::MAX as i64) as FixedPoint,
        supporters: unique_supporters,
        diversity_score,
        claimed_reputation: total_claimed,
        verified_claims: verified_count,
        failed_verifications: failed_count,
    })
}

/// Verify a single reputation claim against a verification context.
/// Useful for pre-validation before adding transactions to the DAG.
pub fn verify_reputation_claim(claim: &ReputationClaim, ctx: &VerificationContext) -> bool {
    let verifier = ReputationVerifier::new();
    verifier
        .verify(claim, &ctx.expected_root, ctx.current_epoch)
        .is_ok()
}

fn integer_log1p(x: i32) -> FixedPoint {
    if x <= 0 {
        return 0;
    }
    let mut result = 0;
    let mut val = x + 1;
    while val > 1 {
        result += SCALE / 4;
        val /= 2;
    }
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictWinner {
    BranchA,
    BranchB,
}

pub fn resolve_conflict(
    dag: &mut TransactionDAG,
    branch_a: &NodeId,
    branch_b: &NodeId,
    fork_block: u64,
) -> (ConflictWinner, MassResult, MassResult) {
    let mass_a = compute_topological_mass(dag, branch_a, fork_block);
    let mass_b = compute_topological_mass(dag, branch_b, fork_block);
    let winner = if mass_a.total_mass > mass_b.total_mass {
        ConflictWinner::BranchA
    } else if mass_b.total_mass > mass_a.total_mass {
        ConflictWinner::BranchB
    } else if branch_a < branch_b {
        ConflictWinner::BranchA
    } else {
        ConflictWinner::BranchB
    };
    (winner, mass_a, mass_b)
}

pub fn is_finalized(
    dag: &mut TransactionDAG,
    branch: &NodeId,
    competitors: &[NodeId],
    fork_block: u64,
) -> bool {
    const FINALITY_RATIO: i32 = 10;
    let branch_mass = compute_topological_mass(dag, branch, fork_block);
    for competitor in competitors {
        let comp_mass = compute_topological_mass(dag, competitor, fork_block);
        if branch_mass.total_mass < fp_mul(FINALITY_RATIO * SCALE, comp_mass.total_mass) {
            return false;
        }
    }
    true
}

/// Compute Jaccard curvature for a child-parent edge using ancestor-depth neighbor sets.
///
/// # Determinism Boundary
/// This function returns a fixed-point integer for deterministic consensus.
/// All curvature values used in consensus-critical computations (mass calculation,
/// conflict resolution, finality checks) MUST use fixed-point arithmetic.
///
/// # Note
/// For consensus-critical path weight computation, prefer using
/// `TransactionDAG::discrete_curvature()` directly, which uses cached values
/// and is optimized for the confirmation window traversal.
///
/// This function is provided for display, debugging, and analysis purposes
/// where the ancestor-based curvature computation is acceptable.
pub fn compute_curvature(dag: &TransactionDAG, child: &NodeId, parent: &NodeId) -> FixedPoint {
    // Use ancestor-depth neighbor sets for deterministic curvature
    let ancestors_child = dag.ancestors(child, disentangle_dag::ANCESTOR_DEPTH);
    let ancestors_parent = dag.ancestors(parent, disentangle_dag::ANCESTOR_DEPTH);

    let intersection_count = ancestors_child.intersection(&ancestors_parent).count() as i32;
    let union_count = ancestors_child.union(&ancestors_parent).count() as i32;

    if union_count == 0 {
        return 0;
    }

    2 * fp_from_ratio(intersection_count, union_count) - SCALE
}

/// Verify a confidential transaction's balance proof.
///
/// For now, this is a placeholder that verifies commitments are well-formed.
/// Full verification requires the STARK proof to be generated and verified.
///
/// # Arguments
/// * `input_commitments` - Commitments to input amounts
/// * `output_commitments` - Commitments to output amounts
/// * `_proof_data` - STARK proof data (currently unused, reserved for future)
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise
pub fn verify_confidential_balance(
    input_commitments: &[disentangle_zkp::AmountCommitment],
    output_commitments: &[disentangle_zkp::AmountCommitment],
    _proof_data: &[u8],
) -> bool {
    // TODO: Implement full STARK proof verification
    // For now, just check that we have matching numbers
    !input_commitments.is_empty() && !output_commitments.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use disentangle_crypto::signature::generate_keypair;
    use disentangle_crypto::types::{Epoch, Nullifier};
    use disentangle_dag::Transaction;
    use disentangle_simhash::SimHash;
    use disentangle_zkp::{AccountStateLeaf, ReputationProver};

    #[test]
    fn test_integer_log1p() {
        assert_eq!(integer_log1p(0), 0);
        assert_eq!(integer_log1p(1), SCALE / 4);
        assert!(integer_log1p(100) > integer_log1p(10));
    }

    fn make_test_tx(depth_seed: u64, parents: Vec<NodeId>, reputation: u64) -> Transaction {
        let (sk, pk) = generate_keypair();
        let history_root = [depth_seed as u8; 32];
        let parent_hashes: Vec<Hash256> = parents.iter().copied().collect();
        let simhash = SimHash::from_structural(&parent_hashes, &history_root);
        let nullifier =
            Nullifier::compute(&[depth_seed as u8; 32], Epoch(0), &depth_seed.to_le_bytes());
        let mut tx = Transaction {
            id: [0u8; 32],
            ephemeral_pk: pk,
            signature: disentangle_crypto::sign(&sk, b"test"),
            parents,
            simhash,
            nullifier,
            reputation_claim: reputation,
            confidential_outputs: vec![],
        };
        tx.id = tx.compute_id();
        tx
    }

    #[test]
    fn test_compute_topological_mass_backward_compatible() {
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        let result = compute_topological_mass(&mut dag, &gid, 0);
        assert!(result.total_mass > 0);
        assert_eq!(result.supporters, 1);
        assert_eq!(result.claimed_reputation, 100);
        assert_eq!(result.verified_claims, 0); // No verification in backward compatible mode
        assert_eq!(result.failed_verifications, 0);
    }

    #[test]
    fn test_verification_context_creation() {
        let root = [1u8; 32];
        let ctx = VerificationContext::new(root, 1);
        assert_eq!(ctx.expected_root, root);
        assert_eq!(ctx.current_epoch, 1);
        assert!(!ctx.strict_mode);

        let strict_ctx = VerificationContext::strict(root, 1);
        assert!(strict_ctx.strict_mode);
    }

    #[test]
    fn test_verified_mass_no_proofs() {
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Create verification context with arbitrary root
        let ctx = VerificationContext::new([0u8; 32], 1);
        let proofs = ProofMap::new();

        // Without proofs, reputation is treated as 0 in non-strict mode
        let result = compute_topological_mass_verified(&mut dag, &gid, 0, &ctx, &proofs).unwrap();
        assert_eq!(result.verified_claims, 0);
        assert_eq!(result.claimed_reputation, 0); // No verified reputation
    }

    #[test]
    fn test_verified_mass_with_valid_proof() {
        let mut dag = TransactionDAG::new();

        // Create account state for ZK proof
        let account_id_hash = [1u8; 32];
        let accounts = vec![
            AccountStateLeaf::new(account_id_hash, 100, 10, 0),
            AccountStateLeaf::new([2u8; 32], 50, 5, 100),
        ];

        // Create prover and generate proof
        let prover = ReputationProver::new(&accounts);
        let merkle_root = prover.merkle_root();
        let epoch = 1u64;

        // Create a transaction
        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Generate a valid proof for threshold 50
        let claim = prover.prove(0, &accounts[0], 50, epoch).unwrap();

        // Create verification context with correct root
        let ctx = VerificationContext::new(merkle_root, epoch);
        let mut proofs = ProofMap::new();
        proofs.insert(gid, claim);

        let result = compute_topological_mass_verified(&mut dag, &gid, 0, &ctx, &proofs).unwrap();
        assert_eq!(result.verified_claims, 1);
        assert_eq!(result.failed_verifications, 0);
        assert_eq!(result.claimed_reputation, 50); // Verified threshold is 50
    }

    #[test]
    fn test_verified_mass_wrong_epoch() {
        let mut dag = TransactionDAG::new();

        let accounts = vec![AccountStateLeaf::new([1u8; 32], 100, 10, 0)];
        let prover = ReputationProver::new(&accounts);
        let merkle_root = prover.merkle_root();

        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Generate proof for epoch 1
        let claim = prover.prove(0, &accounts[0], 50, 1).unwrap();

        // Verify with epoch 2 (should fail)
        let ctx = VerificationContext::new(merkle_root, 2);
        let mut proofs = ProofMap::new();
        proofs.insert(gid, claim);

        let result = compute_topological_mass_verified(&mut dag, &gid, 0, &ctx, &proofs).unwrap();
        assert_eq!(result.verified_claims, 0);
        assert_eq!(result.failed_verifications, 1);
        assert_eq!(result.claimed_reputation, 0); // Failed verification = 0 reputation
    }

    #[test]
    fn test_verified_mass_wrong_root() {
        let mut dag = TransactionDAG::new();

        let accounts = vec![AccountStateLeaf::new([1u8; 32], 100, 10, 0)];
        let prover = ReputationProver::new(&accounts);

        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        let claim = prover.prove(0, &accounts[0], 50, 1).unwrap();

        // Verify with wrong root
        let ctx = VerificationContext::new([0xFFu8; 32], 1);
        let mut proofs = ProofMap::new();
        proofs.insert(gid, claim);

        let result = compute_topological_mass_verified(&mut dag, &gid, 0, &ctx, &proofs).unwrap();
        assert_eq!(result.verified_claims, 0);
        assert_eq!(result.failed_verifications, 1);
    }

    #[test]
    fn test_strict_mode_missing_proof() {
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![], 100); // Has reputation_claim > 0
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        let ctx = VerificationContext::strict([0u8; 32], 1);
        let proofs = ProofMap::new(); // No proofs

        let result = compute_topological_mass_verified(&mut dag, &gid, 0, &ctx, &proofs);
        assert!(matches!(result, Err(ConsensusError::MissingProof { .. })));
    }

    #[test]
    fn test_strict_mode_invalid_proof() {
        let mut dag = TransactionDAG::new();

        let accounts = vec![AccountStateLeaf::new([1u8; 32], 100, 10, 0)];
        let prover = ReputationProver::new(&accounts);

        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        let claim = prover.prove(0, &accounts[0], 50, 1).unwrap();

        // Strict mode with wrong epoch should fail
        let ctx = VerificationContext::strict(prover.merkle_root(), 2);
        let mut proofs = ProofMap::new();
        proofs.insert(gid, claim);

        let result = compute_topological_mass_verified(&mut dag, &gid, 0, &ctx, &proofs);
        assert!(matches!(
            result,
            Err(ConsensusError::VerificationFailed { .. })
        ));
    }

    #[test]
    fn test_verify_reputation_claim_helper() {
        let accounts = vec![AccountStateLeaf::new([1u8; 32], 100, 10, 0)];
        let prover = ReputationProver::new(&accounts);
        let merkle_root = prover.merkle_root();

        let claim = prover.prove(0, &accounts[0], 50, 1).unwrap();

        // Valid verification
        let ctx = VerificationContext::new(merkle_root, 1);
        assert!(verify_reputation_claim(&claim, &ctx));

        // Wrong epoch
        let ctx_wrong_epoch = VerificationContext::new(merkle_root, 2);
        assert!(!verify_reputation_claim(&claim, &ctx_wrong_epoch));

        // Wrong root
        let ctx_wrong_root = VerificationContext::new([0xFFu8; 32], 1);
        assert!(!verify_reputation_claim(&claim, &ctx_wrong_root));
    }

    #[test]
    fn test_multi_transaction_verified_mass() {
        let mut dag = TransactionDAG::new();

        // Create accounts for multiple participants
        let accounts = vec![
            AccountStateLeaf::new([1u8; 32], 100, 10, 0),
            AccountStateLeaf::new([2u8; 32], 200, 20, 100),
            AccountStateLeaf::new([3u8; 32], 50, 5, 200),
        ];
        let prover = ReputationProver::new(&accounts);
        let merkle_root = prover.merkle_root();
        let epoch = 1u64;

        // Create genesis
        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Create child transaction
        let mut child = make_test_tx(1, vec![gid], 200);
        child.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"child");
        child.id = child.compute_id();
        let cid = child.id;
        dag.insert_genesis(child);

        // Generate proofs
        let claim1 = prover.prove(0, &accounts[0], 75, epoch).unwrap();
        let claim2 = prover.prove(1, &accounts[1], 150, epoch).unwrap();

        let ctx = VerificationContext::new(merkle_root, epoch);
        let mut proofs = ProofMap::new();
        proofs.insert(gid, claim1);
        proofs.insert(cid, claim2);

        let result = compute_topological_mass_verified(&mut dag, &gid, 0, &ctx, &proofs).unwrap();
        assert_eq!(result.verified_claims, 2);
        assert_eq!(result.failed_verifications, 0);
        assert_eq!(result.supporters, 2);
        // Total reputation: 75 + 150 = 225
        assert_eq!(result.claimed_reputation, 225);
    }

    #[test]
    fn test_resolve_conflict_equal_mass_tiebreaker() {
        // Test that resolve_conflict returns deterministic winner when masses are exactly equal
        let mut dag = TransactionDAG::new();

        // Create genesis
        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Create two competing branches with EXACTLY the same structure
        // so they produce identical topological mass
        let branch_a = make_test_tx(1, vec![gid], 100);
        let branch_a_id = branch_a.id;
        dag.insert_genesis(branch_a.clone());

        let branch_b = make_test_tx(1, vec![gid], 100);
        let branch_b_id = branch_b.id;
        dag.insert_genesis(branch_b);

        // Both branches have same parent, block, reputation -> should have equal mass
        let (winner, mass_a, mass_b) = resolve_conflict(&mut dag, &branch_a_id, &branch_b_id, 1);

        // Verify masses are equal (or very close due to fixed-point rounding)
        assert_eq!(
            mass_a.total_mass, mass_b.total_mass,
            "Masses should be equal for identical transactions"
        );

        // Tiebreaker should use lexicographic comparison of node IDs
        let expected_winner = if branch_a_id < branch_b_id {
            ConflictWinner::BranchA
        } else {
            ConflictWinner::BranchB
        };

        assert_eq!(
            winner, expected_winner,
            "Winner should be determined by lexicographic NodeId comparison when masses are equal"
        );

        // Verify determinism: calling again should produce same result
        let (winner2, _, _) = resolve_conflict(&mut dag, &branch_a_id, &branch_b_id, 1);
        assert_eq!(winner, winner2, "Conflict resolution must be deterministic");
    }

    #[test]
    fn test_is_finalized() {
        // Test finality check: transaction becomes finalized when it has 10x mass advantage
        let mut dag = TransactionDAG::new();

        // Create genesis
        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Create competing branches
        let branch_a = make_test_tx(1, vec![gid], 100);
        let branch_a_id = branch_a.id;
        dag.insert_genesis(branch_a);

        let branch_b = make_test_tx(1, vec![gid], 100);
        let branch_b_id = branch_b.id;
        dag.insert_genesis(branch_b);

        // Initially, neither branch should be finalized (equal mass)
        assert!(
            !is_finalized(&mut dag, &branch_a_id, &[branch_b_id], 1),
            "Branch A should not be finalized with equal mass"
        );

        // Build descendants on branch A to increase its mass
        let mut current_parent = branch_a_id;
        for i in 2..12 {
            let tx = make_test_tx(i, vec![current_parent], 100);
            current_parent = tx.id;
            dag.insert_genesis(tx);
        }

        // Now branch A should have much more mass and be finalized
        assert!(
            is_finalized(&mut dag, &branch_a_id, &[branch_b_id], 1),
            "Branch A should be finalized with 10+ descendants vs 1 competitor"
        );

        // Branch B should NOT be finalized
        assert!(
            !is_finalized(&mut dag, &branch_b_id, &[branch_a_id], 1),
            "Branch B should not be finalized when competitor has much more mass"
        );
    }

    #[test]
    fn test_compute_curvature_known_neighbors() {
        // Test compute_curvature with controlled neighbor sets
        let mut dag = TransactionDAG::new();

        // Create genesis
        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Create a simple chain: genesis -> A -> B
        let tx_a = make_test_tx(1, vec![gid], 100);
        let aid = tx_a.id;
        dag.insert_genesis(tx_a);

        let tx_b = make_test_tx(2, vec![aid], 100);
        let bid = tx_b.id;
        dag.insert_genesis(tx_b);

        // Compute curvature between child (B) and parent (A)
        let curv = compute_curvature(&dag, &bid, &aid);

        // In a chain, A's ancestors include genesis, B's ancestors include both genesis and A
        // So there's some overlap -> positive but not maximum curvature
        // Jaccard formula: 2 * (intersection/union) - 1
        // Should be less than SCALE (which represents 1.0)
        assert!(curv < SCALE, "Chain curvature should be less than 1.0");

        // Should be greater than -SCALE (which represents -1.0)
        assert!(curv > -SCALE, "Curvature should be greater than -1.0");
    }

    #[test]
    fn test_compute_curvature_triangle() {
        // Test curvature in a triangle structure
        // Note: Jaccard curvature with ancestor-based neighbor sets may be negative
        // even in triangles, depending on the ratio of shared to total ancestors
        let mut dag = TransactionDAG::new();

        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Create two branches from genesis
        let tx_a = make_test_tx(1, vec![gid], 100);
        let aid = tx_a.id;
        dag.insert_genesis(tx_a);

        let tx_b = make_test_tx(2, vec![gid], 100);
        let bid = tx_b.id;
        dag.insert_genesis(tx_b);

        // Create transaction C that references both A and B (forming a triangle)
        let tx_c = make_test_tx(3, vec![aid, bid], 100);
        let cid = tx_c.id;
        dag.insert_genesis(tx_c);

        // Compute curvature from C to A
        // C's ancestors: {genesis, A, B}
        // A's ancestors: {genesis}
        // Intersection: {genesis}, Union: {genesis, A, B}
        // Jaccard: 2 * (1/3) - 1 = 2/3 - 1 = -1/3 (negative)
        let curv_c_a = compute_curvature(&dag, &cid, &aid);

        // The curvature should be within valid range [-1, 1] in fixed-point
        assert!(curv_c_a >= -SCALE, "Curvature should be >= -1.0");
        assert!(curv_c_a <= SCALE, "Curvature should be <= 1.0");

        // Test that it's deterministic
        let curv_c_a_2 = compute_curvature(&dag, &cid, &aid);
        assert_eq!(
            curv_c_a, curv_c_a_2,
            "Curvature computation must be deterministic"
        );
    }

    #[test]
    fn test_integer_log1p_edge_cases() {
        // Test edge case: input 0 should return 0
        assert_eq!(integer_log1p(0), 0, "log1p(0) should be 0");

        // Test edge case: negative input should return 0
        assert_eq!(integer_log1p(-1), 0, "log1p(negative) should be 0");
        assert_eq!(integer_log1p(-100), 0, "log1p(negative) should be 0");

        // Test small positive values
        assert_eq!(
            integer_log1p(1),
            SCALE / 4,
            "log1p(1) should return SCALE/4"
        );

        // Test that function is monotonically increasing for positive inputs
        let log_10 = integer_log1p(10);
        let log_100 = integer_log1p(100);
        let log_1000 = integer_log1p(1000);
        assert!(log_10 < log_100, "log should be monotonically increasing");
        assert!(log_100 < log_1000, "log should be monotonically increasing");

        // Test large value doesn't overflow
        let log_large = integer_log1p(i32::MAX / 2);
        assert!(log_large > 0, "Should handle large values without overflow");
        assert!(log_large < i32::MAX, "Result should be reasonable");
    }

    #[test]
    fn test_mass_overflow_clamping() {
        // Test that large mass values are handled correctly
        // Note: We can't use u64::MAX because it will overflow during summation
        // The clamping happens at the final scaled_mass step (i64 -> i32)
        let mut dag = TransactionDAG::new();

        // Create genesis with moderate reputation (avoid overflow in sum)
        let genesis = make_test_tx(0, vec![], 10000);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Build a chain of moderate-reputation transactions
        let mut current = gid;
        for i in 1..100 {
            let tx = make_test_tx(i, vec![current], 10000);
            current = tx.id;
            dag.insert_genesis(tx);
        }

        // Compute mass - should not panic, final result should be clamped to i32::MAX
        let result = compute_topological_mass(&mut dag, &gid, 0);

        // Result should be positive
        assert!(result.total_mass > 0, "Mass should be positive");

        // Should have counted all supporters
        assert!(result.supporters > 0, "Should count supporters");

        // With 100 transactions, we should have significant mass
        assert!(result.supporters >= 10, "Should have multiple supporters");
    }

    #[test]
    fn test_bootstrap_ramping_effect() {
        // Test that conflicts during bootstrap period (blocks 1000-6000) have reduced curvature weighting
        let mut dag = TransactionDAG::new();

        // Create genesis at block 0
        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Create transactions at different bootstrap phases
        // Early bootstrap (block 1500) - should have reduced alpha
        let tx_early = make_test_tx(1500, vec![gid], 100);
        let early_id = tx_early.id;
        dag.insert_genesis(tx_early);

        // Mid bootstrap (block 3500) - moderate alpha
        let tx_mid = make_test_tx(3500, vec![gid], 100);
        let mid_id = tx_mid.id;
        dag.insert_genesis(tx_mid);

        // Post bootstrap (block 7000) - full alpha
        let tx_post = make_test_tx(7000, vec![gid], 100);
        let post_id = tx_post.id;
        dag.insert_genesis(tx_post);

        // The fork_block parameter affects how curvature is weighted via bootstrap ramping
        // We can't directly observe alpha, but we can verify that mass computation
        // doesn't panic and produces reasonable results at different bootstrap phases

        let mass_early = compute_topological_mass(&mut dag, &early_id, 1500);
        let mass_mid = compute_topological_mass(&mut dag, &mid_id, 3500);
        let mass_post = compute_topological_mass(&mut dag, &post_id, 7000);

        // All should produce valid mass values
        assert!(
            mass_early.total_mass > 0,
            "Early bootstrap should produce valid mass"
        );
        assert!(
            mass_mid.total_mass > 0,
            "Mid bootstrap should produce valid mass"
        );
        assert!(
            mass_post.total_mass > 0,
            "Post bootstrap should produce valid mass"
        );

        // The actual ramping effect is tested indirectly through the integration test
        // This test just verifies that the fork_block parameter is accepted and doesn't break anything
    }

    #[test]
    fn test_resolve_conflict_asymmetric_masses() {
        // Test conflict resolution with clearly different masses
        let mut dag = TransactionDAG::new();

        let genesis = make_test_tx(0, vec![], 100);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Branch A: single transaction
        let branch_a = make_test_tx(1, vec![gid], 100);
        let aid = branch_a.id;
        dag.insert_genesis(branch_a);

        // Branch B: multiple descendants (more mass)
        let branch_b = make_test_tx(1, vec![gid], 100);
        let bid = branch_b.id;
        dag.insert_genesis(branch_b);

        let mut current = bid;
        for i in 2..10 {
            let tx = make_test_tx(i, vec![current], 100);
            current = tx.id;
            dag.insert_genesis(tx);
        }

        let (winner, mass_a, mass_b) = resolve_conflict(&mut dag, &aid, &bid, 1);

        // Branch B should have more mass due to descendants
        assert!(
            mass_b.total_mass > mass_a.total_mass,
            "Branch with more descendants should have higher mass"
        );
        assert_eq!(
            winner,
            ConflictWinner::BranchB,
            "Branch with higher mass should win"
        );
    }

    #[test]
    fn test_compute_curvature_no_shared_ancestors() {
        // Test curvature when there are no shared ancestors (should be negative)
        let mut dag = TransactionDAG::new();

        // Create two separate genesis blocks (for testing purposes)
        let genesis_a = make_test_tx(0, vec![], 100);
        let gid_a = genesis_a.id;
        dag.insert_genesis(genesis_a);

        let genesis_b = make_test_tx(0, vec![], 100);
        let gid_b = genesis_b.id;
        dag.insert_genesis(genesis_b);

        // Create children of each genesis
        let tx_a = make_test_tx(1, vec![gid_a], 100);
        let aid = tx_a.id;
        dag.insert_genesis(tx_a);

        // Create a bridge transaction connecting the two clusters
        let bridge = make_test_tx(2, vec![gid_b, aid], 100);
        let bridge_id = bridge.id;
        dag.insert_genesis(bridge);

        // Curvature from bridge to aid should be negative or low
        // because they have different ancestor sets
        let curv = compute_curvature(&dag, &bridge_id, &aid);

        // The actual value depends on implementation, but it should be
        // less than a highly connected triangle
        assert!(
            curv < SCALE,
            "Bridge between disjoint clusters should have lower curvature than fully connected"
        );
    }
}
