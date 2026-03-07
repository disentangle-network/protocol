//! Integration tests for disentangle-consensus.
//!
//! These tests exercise the public API through realistic multi-step scenarios:
//! mass computation flows, conflict resolution, finalization thresholds,
//! curvature integration, multi-hop mass, bootstrap ramping, and edge cases.
//!
//! ZK-verified mass paths (compute_topological_mass_verified) are NOT tested
//! here -- they are covered by inline tests and the STARK integration tests.

use disentangle_consensus::{
    compute_curvature, compute_topological_mass, is_finalized, resolve_conflict, ConflictWinner,
};
use disentangle_crypto::hash::Hash256;
use disentangle_crypto::signature::generate_keypair;
use disentangle_crypto::types::{Epoch, Nullifier};
use disentangle_dag::{Transaction, TransactionDAG, SCALE};
use disentangle_simhash::SimHash;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a test transaction with a unique nullifier derived from `seed`.
/// `reputation` controls the reputation_claim field.
fn make_tx(seed: u64, parents: Vec<Hash256>, reputation: u64) -> Transaction {
    let (sk, pk) = generate_keypair();
    let history_root = [seed as u8; 32];
    let parent_hashes: Vec<Hash256> = parents.to_vec();
    let simhash = SimHash::from_structural(&parent_hashes, &history_root);
    let nullifier = Nullifier::compute(&[seed as u8; 32], Epoch(0), &seed.to_le_bytes());
    let mut tx = Transaction {
        id: [0u8; 32],
        ephemeral_pk: pk,
        signature: disentangle_crypto::sign(&sk, b"test"),
        parents,
        simhash,
        nullifier,
        reputation_claim: reputation,
        confidential_outputs: vec![],
        payload: None,
    };
    tx.id = tx.compute_id();
    tx
}

/// Insert a chain of `n` transactions descending from a single root.
/// Each new transaction has exactly one parent (the previous one).
/// Returns the list of transaction IDs in order (root first).
fn build_linear_chain(
    dag: &mut TransactionDAG,
    root_id: Hash256,
    start_seed: u64,
    n: usize,
    reputation: u64,
) -> Vec<Hash256> {
    let mut ids = vec![root_id];
    let mut current = root_id;
    for i in 0..n {
        let seed = start_seed + i as u64;
        let tx = make_tx(seed, vec![current], reputation);
        let id = tx.id;
        dag.insert_genesis(tx);
        ids.push(id);
        current = id;
    }
    ids
}

// ===========================================================================
// 1. Mass computation flow: DAG with multiple transactions
// ===========================================================================

#[test]
fn mass_computation_accounts_for_depth_and_supporters() {
    let mut dag = TransactionDAG::new();

    // Genesis
    let genesis = make_tx(0, vec![], 100);
    let gid = genesis.id;
    dag.insert_genesis(genesis);

    // Add several descendants to increase mass
    let chain = build_linear_chain(&mut dag, gid, 10, 5, 100);

    // Mass at root should account for all descendants
    let result = compute_topological_mass(&mut dag, &gid);
    assert!(
        result.total_mass > 0,
        "Mass should be positive with descendants"
    );
    assert!(
        result.supporters > 1,
        "Should count multiple unique supporters (got {})",
        result.supporters
    );

    // Mass at the tip (last in chain) should be lower -- it has no descendants
    let tip = *chain.last().unwrap();
    let tip_result = compute_topological_mass(&mut dag, &tip);
    assert!(
        result.total_mass > tip_result.total_mass,
        "Root mass ({}) should exceed tip mass ({}) because root has more descendants",
        result.total_mass,
        tip_result.total_mass,
    );
}

// ===========================================================================
// 2. Conflict resolution: higher-mass branch wins
// ===========================================================================

#[test]
fn conflict_resolution_heavier_branch_wins() {
    let mut dag = TransactionDAG::new();

    // Genesis (fork point)
    let genesis = make_tx(0, vec![], 100);
    let gid = genesis.id;
    dag.insert_genesis(genesis);

    // Branch A: single transaction
    let branch_a = make_tx(1, vec![gid], 100);
    let aid = branch_a.id;
    dag.insert_genesis(branch_a);

    // Branch B: long chain (more mass)
    let branch_b = make_tx(2, vec![gid], 100);
    let bid = branch_b.id;
    dag.insert_genesis(branch_b);
    build_linear_chain(&mut dag, bid, 100, 8, 100);

    let (winner, mass_a, mass_b) = resolve_conflict(&mut dag, &aid, &bid);

    assert!(
        mass_b.total_mass > mass_a.total_mass,
        "Branch B (chain of 9) should have more mass than Branch A (single tx)"
    );
    assert_eq!(
        winner,
        ConflictWinner::BranchB,
        "The heavier branch should win the conflict"
    );
}

// ===========================================================================
// 3. Finalization: accumulated mass triggers finality
// ===========================================================================

#[test]
fn finalization_triggered_by_mass_dominance() {
    let mut dag = TransactionDAG::new();

    let genesis = make_tx(0, vec![], 100);
    let gid = genesis.id;
    dag.insert_genesis(genesis);

    // Branch A: will become dominant
    let branch_a = make_tx(1, vec![gid], 200);
    let aid = branch_a.id;
    dag.insert_genesis(branch_a);

    // Branch B: competitor (stays weak)
    let branch_b = make_tx(2, vec![gid], 10);
    let bid = branch_b.id;
    dag.insert_genesis(branch_b);

    // Initially neither is finalized
    assert!(
        !is_finalized(&mut dag, &aid, &[bid]),
        "Branch A should not be finalized with only one tx"
    );

    // Build up Branch A with many high-reputation descendants
    let mut current = aid;
    for i in 10..30 {
        let tx = make_tx(i, vec![current], 500);
        current = tx.id;
        dag.insert_genesis(tx);
    }

    // Branch A should now be finalized (10x+ mass advantage)
    assert!(
        is_finalized(&mut dag, &aid, &[bid]),
        "Branch A should be finalized with 20 high-reputation descendants"
    );

    // Branch B should NOT be finalized
    assert!(
        !is_finalized(&mut dag, &bid, &[aid]),
        "Branch B should not be finalized against the dominant Branch A"
    );
}

// ===========================================================================
// 4. Curvature integration: shared parents yield positive curvature
// ===========================================================================

#[test]
fn curvature_shared_parents_positive() {
    let mut dag = TransactionDAG::new();

    // Genesis
    let genesis = make_tx(0, vec![], 100);
    let gid = genesis.id;
    dag.insert_genesis(genesis);

    // Two siblings sharing the same parent
    let sibling_a = make_tx(1, vec![gid], 100);
    let aid = sibling_a.id;
    dag.insert_genesis(sibling_a);

    let sibling_b = make_tx(2, vec![gid], 100);
    let bid = sibling_b.id;
    dag.insert_genesis(sibling_b);

    // Both have ancestors(depth=2) = {genesis}
    // Jaccard = |{genesis}| / |{genesis}| = 1.0
    // kappa = 2 * 1.0 - 1.0 = +1.0 (positive curvature)
    let curv = compute_curvature(&dag, &aid, &bid);
    assert_eq!(
        curv, SCALE,
        "Siblings sharing all ancestors should have maximum positive curvature (+1.0)"
    );

    // Now add a child referencing both siblings (triangle merge)
    let merge = make_tx(3, vec![aid, bid], 100);
    let mid = merge.id;
    dag.insert_genesis(merge);

    // merge ancestors(2) = {A, B, genesis}
    // A ancestors(2) = {genesis}
    // intersection = {genesis}, union = {A, B, genesis}
    // Jaccard = 1/3, kappa = 2/3 - 1 = -1/3
    let curv_merge_a = compute_curvature(&dag, &mid, &aid);
    assert!(
        (-SCALE..=SCALE).contains(&curv_merge_a),
        "Curvature should be in valid range [-1, +1]"
    );
}

// ===========================================================================
// 5. Multi-hop mass: nodes several levels deep
// ===========================================================================

#[test]
fn multi_hop_mass_deep_chain() {
    let mut dag = TransactionDAG::new();

    let genesis = make_tx(0, vec![], 50);
    let gid = genesis.id;
    dag.insert_genesis(genesis);

    // Build a 10-deep chain
    let chain = build_linear_chain(&mut dag, gid, 10, 10, 50);

    // Mass at genesis includes ALL 10 descendants
    let root_mass = compute_topological_mass(&mut dag, &gid);

    // Mass at depth 5 includes only 5 descendants
    let mid_mass = compute_topological_mass(&mut dag, &chain[5]);

    // Mass at depth 9 includes only 1 descendant (the tip)
    let near_tip_mass = compute_topological_mass(&mut dag, &chain[9]);

    assert!(
        root_mass.total_mass >= mid_mass.total_mass,
        "Root mass ({}) should be >= mid-chain mass ({})",
        root_mass.total_mass,
        mid_mass.total_mass,
    );
    assert!(
        mid_mass.total_mass >= near_tip_mass.total_mass,
        "Mid-chain mass ({}) should be >= near-tip mass ({})",
        mid_mass.total_mass,
        near_tip_mass.total_mass,
    );
    assert!(
        root_mass.supporters > near_tip_mass.supporters,
        "Root should have more supporters ({}) than near-tip ({})",
        root_mass.supporters,
        near_tip_mass.supporters,
    );
}

// ===========================================================================
// 6. Mass computation on linear chain
// ===========================================================================

#[test]
fn mass_computation_linear_chain() {
    let mut dag = TransactionDAG::new();

    let genesis = make_tx(0, vec![], 100);
    let gid = genesis.id;
    dag.insert_genesis(genesis);

    let mut current = gid;
    for i in 1..=8 {
        let tx = make_tx(i, vec![current], 100);
        current = tx.id;
        dag.insert_genesis(tx);
    }

    let result = compute_topological_mass(&mut dag, &gid);
    assert!(result.total_mass > 0, "Mass should be positive");
    assert!(
        result.supporters > 1,
        "Should count multiple supporters in chain"
    );
}

// ===========================================================================
// 7. Edge case: empty DAG (no descendants)
// ===========================================================================

#[test]
fn edge_case_single_node_dag() {
    let mut dag = TransactionDAG::new();

    let genesis = make_tx(0, vec![], 100);
    let gid = genesis.id;
    dag.insert_genesis(genesis);

    // Mass of a lone genesis node: it is its own descendant
    let result = compute_topological_mass(&mut dag, &gid);

    // Should have exactly 1 supporter (itself)
    assert_eq!(
        result.supporters, 1,
        "Single-node DAG should have exactly 1 supporter"
    );
    assert!(
        result.total_mass > 0,
        "Single-node mass should still be positive"
    );
    assert_eq!(
        result.claimed_reputation, 100,
        "Should reflect the genesis reputation claim"
    );
}

// ===========================================================================
// 8. Edge case: disconnected nodes
// ===========================================================================

#[test]
fn edge_case_disconnected_nodes() {
    let mut dag = TransactionDAG::new();

    // Two disconnected genesis nodes
    let g1 = make_tx(0, vec![], 100);
    let g1id = g1.id;
    dag.insert_genesis(g1);

    let g2 = make_tx(1, vec![], 200);
    let g2id = g2.id;
    dag.insert_genesis(g2);

    // Mass of g1 should not include g2
    let mass_g1 = compute_topological_mass(&mut dag, &g1id);
    let mass_g2 = compute_topological_mass(&mut dag, &g2id);

    assert_eq!(
        mass_g1.supporters, 1,
        "g1 should have 1 supporter (only itself, not g2)"
    );
    assert_eq!(
        mass_g2.supporters, 1,
        "g2 should have 1 supporter (only itself, not g1)"
    );

    // Conflict resolution between disconnected nodes: the one with higher
    // reputation should win (they both have exactly 1 descendant: themselves)
    let (winner, _, _) = resolve_conflict(&mut dag, &g1id, &g2id);

    // Both have 1 supporter. g2 has higher reputation (200 vs 100),
    // so it should have higher mass.
    let mass_g1_val = compute_topological_mass(&mut dag, &g1id).total_mass;
    let mass_g2_val = compute_topological_mass(&mut dag, &g2id).total_mass;

    if mass_g2_val > mass_g1_val {
        assert_eq!(winner, ConflictWinner::BranchB);
    } else if mass_g1_val > mass_g2_val {
        assert_eq!(winner, ConflictWinner::BranchA);
    }
    // If equal, tiebreaker is lexicographic -- either winner is valid
}

// ===========================================================================
// 9. Conflict resolution determinism
// ===========================================================================

#[test]
fn conflict_resolution_is_deterministic() {
    let mut dag = TransactionDAG::new();

    let genesis = make_tx(0, vec![], 100);
    let gid = genesis.id;
    dag.insert_genesis(genesis);

    let branch_a = make_tx(1, vec![gid], 100);
    let aid = branch_a.id;
    dag.insert_genesis(branch_a);

    let branch_b = make_tx(2, vec![gid], 100);
    let bid = branch_b.id;
    dag.insert_genesis(branch_b);

    // Resolve multiple times -- must always produce the same winner
    let (w1, m1a, m1b) = resolve_conflict(&mut dag, &aid, &bid);
    let (w2, m2a, m2b) = resolve_conflict(&mut dag, &aid, &bid);
    let (w3, m3a, m3b) = resolve_conflict(&mut dag, &aid, &bid);

    assert_eq!(
        w1, w2,
        "Conflict resolution must be deterministic (run 1 vs 2)"
    );
    assert_eq!(
        w2, w3,
        "Conflict resolution must be deterministic (run 2 vs 3)"
    );
    assert_eq!(m1a.total_mass, m2a.total_mass);
    assert_eq!(m1b.total_mass, m2b.total_mass);
    assert_eq!(m2a.total_mass, m3a.total_mass);
    assert_eq!(m2b.total_mass, m3b.total_mass);
}

// ===========================================================================
// 10. Curvature between unrelated nodes
// ===========================================================================

#[test]
fn curvature_unrelated_nodes_negative() {
    let mut dag = TransactionDAG::new();

    // Two independent genesis nodes
    let g1 = make_tx(0, vec![], 100);
    let g1id = g1.id;
    dag.insert_genesis(g1);

    let g2 = make_tx(1, vec![], 100);
    let g2id = g2.id;
    dag.insert_genesis(g2);

    // Children of separate genesis nodes
    let child_a = make_tx(10, vec![g1id], 100);
    let aid = child_a.id;
    dag.insert_genesis(child_a);

    let child_b = make_tx(11, vec![g2id], 100);
    let bid = child_b.id;
    dag.insert_genesis(child_b);

    // child_a ancestors(2) = {g1}
    // child_b ancestors(2) = {g2}
    // intersection = {}, union = {g1, g2}
    // Jaccard = 0/2 = 0, kappa = 2*0 - 1 = -1.0
    let curv = compute_curvature(&dag, &aid, &bid);
    assert_eq!(
        curv, -SCALE,
        "Nodes with no shared ancestors should have curvature = -1.0"
    );
}
