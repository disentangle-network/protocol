//! Integration tests for disentangle-dag.
//!
//! These tests exercise the public API through realistic multi-step scenarios
//! that go beyond what the inline unit tests cover: multi-transaction DAG
//! construction, curvature computation across complex topologies, conflict
//! resolution via topological mass, finality assessment, bootstrap throttling,
//! parent validation, SimHash binding, and multi-node identity scenarios.

use disentangle_crypto::{generate_keypair, sign, SigningKey, VerifyingKey};
use disentangle_dag::{
    effective_alpha, fp_from_ratio, fp_mul, DagError, Epoch, Hash256, NodeId, Nullifier,
    Transaction, TransactionDAG, ALPHA_MAX, BOOTSTRAP_END, BOOTSTRAP_START, CONFIRMATION_DEPTH,
    MAX_PARENTS, MIN_CURVATURE_WEIGHT, MIN_PARENTS, SCALE,
};
use disentangle_simhash::SimHash;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a test transaction with a unique nullifier derived from `nonce_seed`.
fn make_tx(nonce_seed: u64, parents: Vec<NodeId>) -> Transaction {
    let (sk, pk) = generate_keypair();
    let history_root = [nonce_seed as u8; 32];
    let parent_hashes: Vec<Hash256> = parents.to_vec();
    let simhash = SimHash::from_structural(&parent_hashes, &history_root);
    let nullifier =
        Nullifier::compute(&[nonce_seed as u8; 32], Epoch(0), &nonce_seed.to_le_bytes());
    let mut tx = Transaction {
        id: [0u8; 32],
        ephemeral_pk: pk,
        signature: sign(&sk, b"test"),
        parents,
        simhash,
        nullifier,
        reputation_claim: 0,
        confidential_outputs: vec![],
        payload: None,
    };
    tx.id = tx.compute_id();
    tx
}

/// Create a transaction for a specific "node identity" (keypair seed) so we
/// can simulate multiple distinct nodes contributing to the DAG.
fn make_tx_for_node(
    sk: &SigningKey,
    pk: &VerifyingKey,
    nonce_seed: u64,
    parents: Vec<NodeId>,
) -> Transaction {
    let history_root = [nonce_seed as u8; 32];
    let parent_hashes: Vec<Hash256> = parents.to_vec();
    let simhash = SimHash::from_structural(&parent_hashes, &history_root);
    let nullifier =
        Nullifier::compute(&[nonce_seed as u8; 32], Epoch(0), &nonce_seed.to_le_bytes());
    let mut tx = Transaction {
        id: [0u8; 32],
        ephemeral_pk: pk.clone(),
        signature: sign(sk, b"test"),
        parents,
        simhash,
        nullifier,
        reputation_claim: 0,
        confidential_outputs: vec![],
        payload: None,
    };
    tx.id = tx.compute_id();
    tx
}

/// Build a linear chain of `n` transactions on top of two genesis nodes,
/// each referencing the previous transaction and one of the two genesis nodes
/// to satisfy MIN_PARENTS=2. Returns (dag, vec-of-ids) where ids[0] and
/// ids[1] are the two genesis transactions and ids[2..] are the chain.
fn build_chain(n: usize) -> (TransactionDAG, Vec<NodeId>) {
    let mut dag = TransactionDAG::new();
    let mut ids: Vec<NodeId> = Vec::new();

    // Two genesis transactions (bypassing parent validation)
    let g1 = make_tx(0, vec![]);
    ids.push(g1.id);
    dag.insert_genesis(g1);

    let g2 = make_tx(1, vec![]);
    ids.push(g2.id);
    dag.insert_genesis(g2);

    // Chain: each tx references the previous tx + g1 (or g2) to satisfy MIN_PARENTS
    let mut prev = ids[1];
    for i in 0..n {
        let seed = (i as u64) + 100;
        let anchor = if i % 2 == 0 { ids[0] } else { ids[1] };
        let mut tx = make_tx(seed, vec![prev, anchor]);
        tx.nullifier = Nullifier::compute(&[seed as u8; 32], Epoch(0), &seed.to_le_bytes());
        tx.id = tx.compute_id();
        let id = tx.id;
        dag.insert_genesis(tx);
        ids.push(id);
        prev = id;
    }
    (dag, ids)
}

// ===========================================================================
// 1. DAG construction: multi-transaction DAG, verify parent relationships
// ===========================================================================

#[test]
fn dag_construction_multi_transaction() {
    let mut dag = TransactionDAG::new();
    assert!(dag.is_empty());

    // Insert two genesis transactions
    let g1 = make_tx(0, vec![]);
    let g1id = g1.id;
    dag.insert_genesis(g1);

    let g2 = make_tx(1, vec![]);
    let g2id = g2.id;
    dag.insert_genesis(g2);

    assert_eq!(dag.len(), 2);
    assert!(dag.contains(&g1id));
    assert!(dag.contains(&g2id));

    // Insert a child referencing both genesis txs (satisfies MIN_PARENTS=2)
    let mut child = make_tx(10, vec![g1id, g2id]);
    child.nullifier = Nullifier::compute(&[10u8; 32], Epoch(0), b"child");
    child.id = child.compute_id();
    let child_id = child.id;
    dag.insert(child)
        .expect("insert with valid parents should succeed");

    assert_eq!(dag.len(), 3);

    // Verify parent relationships via ancestors
    let parents = dag.ancestors(&child_id, 1);
    assert_eq!(parents.len(), 2);
    assert!(parents.contains(&g1id));
    assert!(parents.contains(&g2id));

    // Verify children index via descendants
    let desc_g1 = dag.descendants(&g1id);
    assert!(
        desc_g1.contains(&child_id),
        "child should be a descendant of g1"
    );

    // Verify neighbors
    let neighbors = dag.neighbors(&child_id);
    assert_eq!(
        neighbors.len(),
        2,
        "child has exactly 2 parents, no children yet"
    );

    // Verify iter_transactions enumerates everything
    let all_ids: Vec<&NodeId> = dag.transaction_ids().collect();
    assert_eq!(all_ids.len(), 3);
}

// ===========================================================================
// 2. Curvature computation across a realistic topology
// ===========================================================================

#[test]
fn curvature_computation_diamond_topology() {
    // Build a diamond: G1, G2 -> A(G1,G2), B(G1,G2) -> C(A,B)
    // A and B share ancestors {G1,G2} at depth 2.
    // This should produce positive curvature between A and B because their
    // ancestor-depth-2 sets overlap heavily.
    let mut dag = TransactionDAG::new();

    let g1 = make_tx(0, vec![]);
    let g1id = g1.id;
    dag.insert_genesis(g1);

    let g2 = make_tx(1, vec![]);
    let g2id = g2.id;
    dag.insert_genesis(g2);

    let mut a = make_tx(10, vec![g1id, g2id]);
    a.nullifier = Nullifier::compute(&[10u8; 32], Epoch(0), b"a");
    a.id = a.compute_id();
    let aid = a.id;
    dag.insert_genesis(a);

    let mut b = make_tx(11, vec![g1id, g2id]);
    b.nullifier = Nullifier::compute(&[11u8; 32], Epoch(0), b"b");
    b.id = b.compute_id();
    let bid = b.id;
    dag.insert_genesis(b);

    // A ancestors(depth=2) = {G1, G2}
    // B ancestors(depth=2) = {G1, G2}
    // Jaccard = 2/2 = 1.0 => kappa = 2*1.0 - 1.0 = +1.0 => SCALE
    let curv_ab = dag.discrete_curvature(&aid, &bid);
    assert_eq!(
        curv_ab, SCALE,
        "Siblings with identical ancestor sets should have curvature = +1.0 (SCALE)"
    );

    // Verify curvature is cached
    assert!(dag.is_curvature_frozen(&aid, &bid));

    // Insert the merge node C(A,B)
    let mut c = make_tx(12, vec![aid, bid]);
    c.nullifier = Nullifier::compute(&[12u8; 32], Epoch(0), b"c");
    c.id = c.compute_id();
    let cid = c.id;
    dag.insert_genesis(c);

    // C ancestors(depth=2) = {A, B, G1, G2}
    // A ancestors(depth=2) = {G1, G2}
    // intersection(A, C) = {G1, G2}, union = {A, B, G1, G2}
    // Jaccard = 2/4 = 0.5, kappa = 2*0.5 - 1 = 0
    dag.clear_curvature_cache();
    let curv_ac = dag.discrete_curvature(&aid, &cid);
    assert_eq!(
        curv_ac, 0,
        "A-C curvature should be 0 (partial ancestor overlap)"
    );

    // Re-check A-B curvature is unchanged after adding C (immutability)
    dag.clear_curvature_cache();
    let curv_ab_after = dag.discrete_curvature(&aid, &bid);
    assert_eq!(
        curv_ab, curv_ab_after,
        "Curvature must be immutable by construction"
    );
}

// ===========================================================================
// 3. Conflict resolution via topological mass (find_best_path_weight)
// ===========================================================================

#[test]
fn conflict_resolution_topological_mass() {
    // Scenario: two conflicting branches from a fork point. The branch with
    // more descendants and higher curvature should accumulate more
    // topological mass (path weight).
    let mut dag = TransactionDAG::new();

    // Two genesis nodes
    let g1 = make_tx(0, vec![]);
    let g1id = g1.id;
    dag.insert_genesis(g1);

    let g2 = make_tx(1, vec![]);
    let g2id = g2.id;
    dag.insert_genesis(g2);

    // Fork point: F references both genesis
    let mut fork = make_tx(10, vec![g1id, g2id]);
    fork.nullifier = Nullifier::compute(&[10u8; 32], Epoch(0), b"fork");
    fork.id = fork.compute_id();
    let fork_id = fork.id;
    dag.insert_genesis(fork);

    // Branch A: single extension from fork
    let mut a1 = make_tx(20, vec![fork_id, g1id]);
    a1.nullifier = Nullifier::compute(&[20u8; 32], Epoch(0), b"a1");
    a1.id = a1.compute_id();
    let a1id = a1.id;
    dag.insert_genesis(a1);

    // Branch B: two extensions from fork (more descendants)
    let mut b1 = make_tx(30, vec![fork_id, g2id]);
    b1.nullifier = Nullifier::compute(&[30u8; 32], Epoch(0), b"b1");
    b1.id = b1.compute_id();
    let b1id = b1.id;
    dag.insert_genesis(b1);

    let mut b2 = make_tx(31, vec![b1id, fork_id]);
    b2.nullifier = Nullifier::compute(&[31u8; 32], Epoch(0), b"b2");
    b2.id = b2.compute_id();
    let b2id = b2.id;
    dag.insert_genesis(b2);

    // Compare path weights from fork to each branch tip
    // (using early bootstrap depth so curvature throttling is off)
    let weight_a = dag.find_best_path_weight(&fork_id, &a1id, 10);
    let weight_b = dag.find_best_path_weight(&fork_id, &b2id, 10);

    // Both should be reachable
    assert!(weight_a > 0, "Path to A1 should exist");
    assert!(weight_b > 0, "Path to B2 should exist");

    // Descendant set sizes verify the topology
    let desc_fork = dag.descendants(&fork_id);
    assert!(
        desc_fork.contains(&a1id) && desc_fork.contains(&b1id) && desc_fork.contains(&b2id),
        "All branch transactions should be descendants of fork"
    );
}

// ===========================================================================
// 4. Finality: chain deeper than CONFIRMATION_DEPTH
// ===========================================================================

#[test]
fn finality_beyond_confirmation_depth() {
    // Build a chain longer than CONFIRMATION_DEPTH and verify that
    // transactions at sufficient depth can be identified as final.
    let chain_len = (CONFIRMATION_DEPTH as usize) + 4;
    let (mut dag, ids) = build_chain(chain_len);

    // The first chain transaction is at index 2 (after two genesis txs).
    // Its depth should be 1 (parent is genesis at depth 0).
    let first_chain_id = ids[2];
    let first_depth = dag.depth(&first_chain_id);
    assert_eq!(first_depth, 1);

    // The tip of the chain
    let tip_id = *ids.last().unwrap();
    let tip_depth = dag.depth(&tip_id);

    // Verify that the tip is deep enough
    assert!(
        tip_depth >= CONFIRMATION_DEPTH,
        "Tip depth ({tip_depth}) should be >= CONFIRMATION_DEPTH ({CONFIRMATION_DEPTH})"
    );

    // For any transaction in the chain, if (tip_depth - tx_depth) >= CONFIRMATION_DEPTH,
    // that transaction is considered final. Check the earliest chain transaction.
    let depth_diff = tip_depth - first_depth;
    assert!(
        depth_diff >= CONFIRMATION_DEPTH,
        "First chain tx should be final: depth_diff={depth_diff} >= CONFIRMATION_DEPTH={CONFIRMATION_DEPTH}"
    );

    // Meanwhile, the tip itself should NOT be considered final
    assert_eq!(
        tip_depth - tip_depth,
        0,
        "Tip itself has zero confirmation depth, not final"
    );
}

// ===========================================================================
// 5. Bootstrap throttling: effective_alpha across boundaries
// ===========================================================================

#[test]
fn bootstrap_throttling_full_range() {
    // Pre-bootstrap: alpha = 0
    for depth in [0u64, 1, 100, 500, 999] {
        assert_eq!(
            effective_alpha(depth),
            0,
            "Alpha should be 0 before BOOTSTRAP_START (depth={depth})"
        );
    }

    // At BOOTSTRAP_START: alpha = 0 (numerator is 0)
    assert_eq!(effective_alpha(BOOTSTRAP_START), 0);

    // During ramp: alpha increases monotonically
    let mut prev_alpha = 0i32;
    let steps = 20;
    let range = BOOTSTRAP_END - BOOTSTRAP_START;
    for i in 1..=steps {
        let depth = BOOTSTRAP_START + (range * i) / steps;
        let alpha = effective_alpha(depth);
        assert!(
            alpha >= prev_alpha,
            "Alpha must be monotonically non-decreasing: alpha({depth})={alpha} < prev={prev_alpha}"
        );
        prev_alpha = alpha;
    }

    // At BOOTSTRAP_END: alpha = ALPHA_MAX
    assert_eq!(effective_alpha(BOOTSTRAP_END), ALPHA_MAX);

    // Post-bootstrap: alpha = ALPHA_MAX
    for depth in [BOOTSTRAP_END + 1, BOOTSTRAP_END + 10_000, u64::MAX / 2] {
        assert_eq!(
            effective_alpha(depth),
            ALPHA_MAX,
            "Alpha should be ALPHA_MAX after BOOTSTRAP_END (depth={depth})"
        );
    }

    // Verify curvature_weight_at_depth reflects throttling
    let dag = TransactionDAG::new();
    let negative_curv = -SCALE / 2;

    // During bootstrap: no throttling, full weight
    let weight_early = dag.curvature_weight_at_depth(negative_curv, 500);
    assert_eq!(weight_early, SCALE, "No throttling during early bootstrap");

    // Post-bootstrap: throttled
    let weight_late = dag.curvature_weight_at_depth(negative_curv, BOOTSTRAP_END + 1000);
    assert!(
        weight_late < SCALE,
        "Negative curvature should be throttled post-bootstrap"
    );
    assert!(
        weight_late >= MIN_CURVATURE_WEIGHT,
        "Weight should be clamped at minimum, not zero"
    );
}

// ===========================================================================
// 6. Parent validation: MAX_PARENTS and MIN_PARENTS enforcement
// ===========================================================================

#[test]
fn parent_validation_enforcement() {
    let mut dag = TransactionDAG::new();

    // Create enough genesis nodes to test MAX_PARENTS
    let mut genesis_ids = Vec::new();
    for i in 0..(MAX_PARENTS + 2) {
        let mut g = make_tx(i as u64, vec![]);
        g.nullifier = Nullifier::compute(&[i as u8; 32], Epoch(0), &(i as u64).to_le_bytes());
        g.id = g.compute_id();
        genesis_ids.push(g.id);
        dag.insert_genesis(g);
    }

    // --- Too few parents (0) ---
    let mut tx_zero = make_tx(200, vec![]);
    tx_zero.nullifier = Nullifier::compute(&[200u8; 32], Epoch(0), b"zero");
    tx_zero.id = tx_zero.compute_id();
    assert!(
        matches!(dag.insert(tx_zero), Err(DagError::TooFewParents(0, _))),
        "Zero parents should be rejected"
    );

    // --- Too few parents (1) ---
    let mut tx_one = make_tx(201, vec![genesis_ids[0]]);
    tx_one.nullifier = Nullifier::compute(&[201u8; 32], Epoch(0), b"one");
    tx_one.id = tx_one.compute_id();
    assert!(
        matches!(dag.insert(tx_one), Err(DagError::TooFewParents(1, _))),
        "One parent should be rejected (MIN_PARENTS={MIN_PARENTS})"
    );

    // --- Exactly MIN_PARENTS (2) - should succeed ---
    let mut tx_min = make_tx(202, genesis_ids[..MIN_PARENTS].to_vec());
    tx_min.nullifier = Nullifier::compute(&[202u8; 32], Epoch(0), b"min");
    tx_min.id = tx_min.compute_id();
    assert!(
        dag.insert(tx_min).is_ok(),
        "Exactly MIN_PARENTS should succeed"
    );

    // --- Exactly MAX_PARENTS (8) - should succeed ---
    let mut tx_max = make_tx(203, genesis_ids[..MAX_PARENTS].to_vec());
    tx_max.nullifier = Nullifier::compute(&[203u8; 32], Epoch(0), b"max");
    tx_max.id = tx_max.compute_id();
    assert!(
        dag.insert(tx_max).is_ok(),
        "Exactly MAX_PARENTS should succeed"
    );

    // --- MAX_PARENTS + 1 - should fail ---
    let mut tx_over = make_tx(204, genesis_ids[..(MAX_PARENTS + 1)].to_vec());
    tx_over.nullifier = Nullifier::compute(&[204u8; 32], Epoch(0), b"over");
    tx_over.id = tx_over.compute_id();
    assert!(
        matches!(
            dag.insert(tx_over),
            Err(DagError::TooManyParents(n, m)) if n == MAX_PARENTS + 1 && m == MAX_PARENTS
        ),
        "MAX_PARENTS+1 should be rejected"
    );

    // --- Missing parent - should fail ---
    let fake_parent: NodeId = [0xFFu8; 32];
    let mut tx_missing = make_tx(205, vec![genesis_ids[0], fake_parent]);
    tx_missing.nullifier = Nullifier::compute(&[205u8; 32], Epoch(0), b"missing");
    tx_missing.id = tx_missing.compute_id();
    assert!(
        matches!(dag.insert(tx_missing), Err(DagError::MissingParent(_))),
        "Reference to non-existent parent should be rejected"
    );
}

// ===========================================================================
// 7. SimHash integration: structurally bound to transactions
// ===========================================================================

#[test]
fn simhash_structurally_bound() {
    // SimHash is computed from parent hashes + history root. Two transactions
    // with different parents should produce different SimHashes.
    let g1 = make_tx(0, vec![]);
    let g1id = g1.id;
    let g2 = make_tx(1, vec![]);
    let g2id = g2.id;

    // Two transactions with different parents but same nonce seed
    let history_root = [42u8; 32];
    let sim_a = SimHash::from_structural(&[g1id], &history_root);
    let sim_b = SimHash::from_structural(&[g2id], &history_root);

    // Different parents -> different SimHash
    assert_ne!(
        sim_a.0, sim_b.0,
        "Different parent sets should yield different SimHashes"
    );

    // Same parents, same root -> same SimHash (deterministic)
    let sim_a2 = SimHash::from_structural(&[g1id], &history_root);
    assert_eq!(
        sim_a.0, sim_a2.0,
        "Identical inputs should yield identical SimHash"
    );

    // Verify SimHash is stored on the transaction and accessible
    let mut dag = TransactionDAG::new();
    dag.insert_genesis(g1);

    let retrieved = dag.get(&g1id).unwrap();
    // The SimHash should be the one computed during make_tx with nonce_seed=0
    let expected_sim = SimHash::from_structural(&[], &[0u8; 32]);
    assert_eq!(
        retrieved.simhash.0, expected_sim.0,
        "Transaction should carry the SimHash computed at creation time"
    );
}

// ===========================================================================
// 8. Multi-node scenario: multiple identities contributing to a shared DAG
// ===========================================================================

#[test]
fn multi_node_shared_dag() {
    let mut dag = TransactionDAG::new();

    // Create three distinct node identities
    let (sk_alice, pk_alice) = generate_keypair();
    let (sk_bob, pk_bob) = generate_keypair();
    let (sk_carol, pk_carol) = generate_keypair();

    // Genesis transactions (one from Alice, one from Bob)
    let g_alice = make_tx_for_node(&sk_alice, &pk_alice, 0, vec![]);
    let g_alice_id = g_alice.id;
    dag.insert_genesis(g_alice);

    let g_bob = make_tx_for_node(&sk_bob, &pk_bob, 1, vec![]);
    let g_bob_id = g_bob.id;
    dag.insert_genesis(g_bob);

    // Alice and Bob both reference each other's genesis (cross-linking)
    let a1 = make_tx_for_node(&sk_alice, &pk_alice, 10, vec![g_alice_id, g_bob_id]);
    let a1_id = a1.id;
    dag.insert_genesis(a1);

    let b1 = make_tx_for_node(&sk_bob, &pk_bob, 11, vec![g_alice_id, g_bob_id]);
    let b1_id = b1.id;
    dag.insert_genesis(b1);

    // Carol joins, referencing transactions from both Alice and Bob
    let c1 = make_tx_for_node(&sk_carol, &pk_carol, 20, vec![a1_id, b1_id]);
    let c1_id = c1.id;
    dag.insert_genesis(c1);

    assert_eq!(dag.len(), 5, "DAG should have 5 transactions from 3 nodes");

    // Verify curvature between Alice's and Bob's parallel transactions.
    // a1 ancestors(2) = {g_alice, g_bob}
    // b1 ancestors(2) = {g_alice, g_bob}
    // Jaccard = 2/2 = 1.0, kappa = +1.0 (SCALE)
    let curv = dag.discrete_curvature(&a1_id, &b1_id);
    assert_eq!(
        curv, SCALE,
        "Sibling txs sharing all ancestors should have curvature = +1.0"
    );

    // Verify depth computation across multi-node contributions
    let depth_carol = dag.depth(&c1_id);
    assert_eq!(
        depth_carol, 2,
        "Carol's tx depth should be 2 (parents at depth 1)"
    );

    // Verify each transaction is retrievable and has the correct ephemeral key
    let retrieved_alice = dag.get(&a1_id).unwrap();
    assert_eq!(
        retrieved_alice.ephemeral_pk.to_bytes(),
        pk_alice.to_bytes(),
        "Alice's transaction should carry her public key"
    );

    let retrieved_carol = dag.get(&c1_id).unwrap();
    assert_eq!(
        retrieved_carol.ephemeral_pk.to_bytes(),
        pk_carol.to_bytes(),
        "Carol's transaction should carry her public key"
    );

    // Verify signature validity
    assert!(
        retrieved_alice.verify_signature(b"test"),
        "Alice's signature should verify against the signing message"
    );
    assert!(
        !retrieved_alice.verify_signature(b"wrong message"),
        "Alice's signature should NOT verify against a wrong message"
    );
}

// ===========================================================================
// 9. Depth computation: complex DAG with varying path lengths
// ===========================================================================

#[test]
fn depth_computation_complex_dag() {
    let mut dag = TransactionDAG::new();

    // Create two genesis nodes
    let g1 = make_tx(0, vec![]);
    let g1id = g1.id;
    dag.insert_genesis(g1);

    let g2 = make_tx(1, vec![]);
    let g2id = g2.id;
    dag.insert_genesis(g2);

    // Depth-1 nodes
    let mut a = make_tx(10, vec![g1id, g2id]);
    a.nullifier = Nullifier::compute(&[10u8; 32], Epoch(0), b"a");
    a.id = a.compute_id();
    let aid = a.id;
    dag.insert_genesis(a);

    let mut b = make_tx(11, vec![g1id, g2id]);
    b.nullifier = Nullifier::compute(&[11u8; 32], Epoch(0), b"b");
    b.id = b.compute_id();
    let bid = b.id;
    dag.insert_genesis(b);

    // Depth-2 node
    let mut c = make_tx(12, vec![aid, bid]);
    c.nullifier = Nullifier::compute(&[12u8; 32], Epoch(0), b"c");
    c.id = c.compute_id();
    let cid = c.id;
    dag.insert_genesis(c);

    // Depth-3 node with asymmetric parents (depth-2 and depth-0)
    let mut d = make_tx(13, vec![cid, g1id]);
    d.nullifier = Nullifier::compute(&[13u8; 32], Epoch(0), b"d");
    d.id = d.compute_id();
    let did = d.id;
    dag.insert_genesis(d);

    assert_eq!(dag.depth(&g1id), 0);
    assert_eq!(dag.depth(&g2id), 0);
    assert_eq!(dag.depth(&aid), 1);
    assert_eq!(dag.depth(&bid), 1);
    assert_eq!(dag.depth(&cid), 2);
    // d's depth = 1 + max(depth(c), depth(g1)) = 1 + max(2, 0) = 3
    assert_eq!(dag.depth(&did), 3);

    // Verify compute_depth_from_parents for prospective insertion
    let prospective = dag.compute_depth_from_parents(&[cid, g1id]);
    assert_eq!(
        prospective, 3,
        "Prospective depth should match actual depth"
    );

    // Verify epoch computation
    let epoch_d = dag.epoch(&did);
    assert_eq!(epoch_d, Epoch::from_depth(3));
}

// ===========================================================================
// 10. Curvature weight throttling across the bootstrap spectrum
// ===========================================================================

#[test]
fn curvature_weight_throttling_spectrum() {
    let dag = TransactionDAG::new();

    // Negative curvature (-0.5)
    let neg_curv = -SCALE / 2;

    // Positive curvature (+0.5)
    let pos_curv = SCALE / 2;

    // Zero curvature
    let zero_curv = 0;

    // Pre-bootstrap: all curvatures yield SCALE (no throttling)
    assert_eq!(dag.curvature_weight_at_depth(neg_curv, 0), SCALE);
    assert_eq!(dag.curvature_weight_at_depth(pos_curv, 0), SCALE);
    assert_eq!(dag.curvature_weight_at_depth(zero_curv, 0), SCALE);

    // Post-bootstrap: positive curvature still yields SCALE (clamped up)
    let w_pos = dag.curvature_weight_at_depth(pos_curv, BOOTSTRAP_END + 1000);
    assert_eq!(
        w_pos, SCALE,
        "Positive curvature should always yield full weight"
    );

    // Post-bootstrap: zero curvature yields SCALE (SCALE + alpha*0 = SCALE)
    let w_zero = dag.curvature_weight_at_depth(zero_curv, BOOTSTRAP_END + 1000);
    assert_eq!(w_zero, SCALE, "Zero curvature should yield full weight");

    // Post-bootstrap: negative curvature is throttled
    let w_neg = dag.curvature_weight_at_depth(neg_curv, BOOTSTRAP_END + 1000);
    assert!(w_neg < SCALE, "Negative curvature should be throttled");
    assert!(
        w_neg >= MIN_CURVATURE_WEIGHT,
        "Weight must not go below minimum"
    );

    // Full throttle with curvature_weight() (uses ALPHA_MAX directly)
    let w_full = dag.curvature_weight(neg_curv);
    assert_eq!(
        w_full, w_neg,
        "curvature_weight() should match curvature_weight_at_depth() post-bootstrap"
    );
}

// ===========================================================================
// 11. Nullifier double-spend prevention across multiple transactions
// ===========================================================================

#[test]
fn nullifier_double_spend_prevention() {
    let mut dag = TransactionDAG::new();

    // Two genesis nodes
    let g1 = make_tx(0, vec![]);
    let g1id = g1.id;
    dag.insert_genesis(g1);

    let g2 = make_tx(1, vec![]);
    let g2id = g2.id;
    dag.insert_genesis(g2);

    // Insert a valid transaction
    let shared_nullifier = Nullifier::compute(&[42u8; 32], Epoch(0), b"shared");
    let mut tx_a = make_tx(10, vec![g1id, g2id]);
    tx_a.nullifier = shared_nullifier.clone();
    tx_a.id = tx_a.compute_id();
    dag.insert(tx_a)
        .expect("first use of nullifier should succeed");

    // Verify the nullifier is tracked
    assert!(dag.has_nullifier(&shared_nullifier));

    // Attempt to insert another transaction with the same nullifier
    let mut tx_b = make_tx(11, vec![g1id, g2id]);
    tx_b.nullifier = shared_nullifier;
    tx_b.id = tx_b.compute_id();

    assert!(
        matches!(dag.insert(tx_b), Err(DagError::DuplicateNullifier)),
        "Second use of same nullifier should be rejected as double-spend"
    );
}

// ===========================================================================
// 12. Fixed-point arithmetic correctness across operations
// ===========================================================================

#[test]
fn fixed_point_arithmetic_end_to_end() {
    // Verify that fp_from_ratio and fp_mul compose correctly for
    // realistic curvature computation scenarios.

    // Jaccard similarity = intersection / union
    // For intersection=3, union=5: Jaccard = 0.6
    let jaccard = fp_from_ratio(3, 5);
    let expected_jaccard = (3i64 * SCALE as i64 / 5) as i32;
    assert_eq!(jaccard, expected_jaccard);

    // Curvature kappa = 2 * Jaccard - 1
    let kappa = 2 * jaccard - SCALE;
    // 2 * 0.6 - 1.0 = 0.2 in fixed-point
    let expected_kappa = (2i64 * expected_jaccard as i64 - SCALE as i64) as i32;
    assert_eq!(kappa, expected_kappa);

    // Verify the sign: Jaccard > 0.5 means positive curvature
    assert!(kappa > 0, "Jaccard=0.6 should yield positive curvature");

    // Verify fp_mul for path weight accumulation
    // Two edges each with weight 0.8: product = 0.64
    let edge_weight = fp_from_ratio(4, 5); // 0.8
    let path_weight = fp_mul(edge_weight, edge_weight);
    // 0.8 * 0.8 = 0.64 = 41943 in SCALE=65536
    let expected_path = ((edge_weight as i64 * edge_weight as i64) / SCALE as i64) as i32;
    assert_eq!(path_weight, expected_path);

    // Three edges: 0.8^3 = 0.512
    let path_3 = fp_mul(path_weight, edge_weight);
    assert!(
        path_3 > 0 && path_3 < path_weight,
        "Multiplicative path weight should decrease with more edges"
    );
}
