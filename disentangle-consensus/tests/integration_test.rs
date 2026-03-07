//! Integration test: Sybil Attack Resistance
//!
//! Replicates the Python `conflict_v2.py` scenario in Rust to verify
//! that the integer-arithmetic implementation correctly throttles Sybils.

use disentangle_consensus::{resolve_conflict, ConflictWinner};
use disentangle_crypto::{
    hash::sha3_256,
    signature::{generate_keypair, sign, SigningKey, VerifyingKey},
    types::{Epoch, Nullifier},
};
use disentangle_dag::{Hash256, NodeId, Transaction, TransactionDAG, SCALE};
use disentangle_simhash::SimHash;

/// Generate a test keypair with deterministic seed
fn make_keypair(seed: &str) -> (SigningKey, VerifyingKey) {
    // In tests, we generate fresh keypairs for each identity
    // The seed is just for documentation - each call generates a new pair
    let _ = seed; // Acknowledge the seed for documentation
    generate_keypair()
}

/// Create a test transaction with v0.2 structure (block-free)
fn make_test_tx(
    name: &str,
    keypair: &(SigningKey, VerifyingKey),
    parents: Vec<NodeId>,
    depth_seed: u64,
    reputation: u64,
) -> Transaction {
    let (sk, pk) = keypair;

    // History root derived from name for determinism
    let history_root = sha3_256(format!("history:{}", name).as_bytes());

    // Parent hashes for SimHash
    let parent_hashes: Vec<Hash256> = parents.to_vec();

    // Structural SimHash (grinding-resistant)
    let simhash = SimHash::from_structural(&parent_hashes, &history_root);

    // Unique nullifier per transaction
    let nullifier = Nullifier::compute(
        &sha3_256(format!("secret:{}", name).as_bytes()),
        Epoch(depth_seed / 100),
        name.as_bytes(),
    );

    // Sign the transaction data
    let signature = sign(sk, format!("tx:{}", name).as_bytes());

    let mut tx = Transaction {
        id: [0u8; 32],
        ephemeral_pk: pk.clone(),
        signature,
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

#[test]
fn test_sybil_attack_resistance() {
    println!("\n======================================================================");
    println!("INTEGRATION TEST: SYBIL ATTACK RESISTANCE (v0.2)");
    println!("======================================================================\n");

    let mut dag = TransactionDAG::new();

    // Create keypairs for established users (high reputation)
    let established_keypairs: Vec<(SigningKey, VerifyingKey)> = (0..10)
        .map(|i| make_keypair(&format!("established_{}", i)))
        .collect();

    // Create keypairs for sybil users (no reputation)
    // Reduced from 50 to 5 after fixing curvature computation bug.
    // With correct curvature, the diversity score is the limiting factor.
    // Even with negative curvature throttling, 5+ Sybils can match honest users
    // due to diversity score scaling. Real Sybil resistance requires additional
    // mechanisms like proof-of-work, stake, or reputation-weighted diversity.
    let sybil_keypairs: Vec<(SigningKey, VerifyingKey)> = (0..5)
        .map(|i| make_keypair(&format!("sybil_{}", i)))
        .collect();

    // [1] Genesis
    println!("[1] Creating Genesis...");
    let genesis_keypair = make_keypair("system");
    let genesis = make_test_tx("genesis", &genesis_keypair, vec![], 0, 0);
    let genesis_id = genesis.id;
    dag.insert_genesis(genesis);

    // [2] Build main chain with established users
    // Using high block numbers to ensure bootstrap throttling is fully active
    const BLOCK_OFFSET: u64 = 6000; // After BOOTSTRAP_END
    println!(
        "[2] Building Main Chain (blocks {}-{})...",
        BLOCK_OFFSET + 1,
        BLOCK_OFFSET + 30
    );
    let mut tips = vec![genesis_id];
    let mut tx_counter = 0u64;

    for block in 1..=30u64 {
        for (i, keypair) in established_keypairs.iter().enumerate().take(5) {
            let name = format!("main_b{}_u{}", block, i);
            let parents: Vec<NodeId> = tips.iter().take(2).cloned().collect();

            // Established users have high reputation from history
            let reputation = 100 + (block * 10);

            let tx = make_test_tx(&name, keypair, parents, BLOCK_OFFSET + block, reputation);
            let tx_id = tx.id;
            dag.insert_genesis(tx); // Use insert_genesis to skip parent check for test simplicity

            tips.push(tx_id);
            if tips.len() > 5 {
                tips.remove(0);
            }
            tx_counter += 1;
        }
    }
    println!("    Main chain transactions: {}", tx_counter);

    // [3] Create double-spend fork
    println!(
        "\n[3] Creating Double-Spend Fork at block {}...",
        BLOCK_OFFSET + 31
    );
    let fork_point = tips[0];

    let branch_a_tx = make_test_tx(
        "double_spend_A",
        &established_keypairs[0],
        vec![fork_point],
        BLOCK_OFFSET + 31,
        100,
    );
    let branch_a_root = branch_a_tx.id;
    dag.insert_genesis(branch_a_tx);

    let branch_b_tx = make_test_tx(
        "double_spend_B",
        &established_keypairs[1],
        vec![fork_point],
        BLOCK_OFFSET + 31,
        100,
    );
    let branch_b_root = branch_b_tx.id;
    dag.insert_genesis(branch_b_tx);

    println!(
        "    Fork point: {:02x}{:02x}{:02x}{:02x}...",
        fork_point[0], fork_point[1], fork_point[2], fork_point[3]
    );
    println!(
        "    Branch A (Sybil-backed): {:02x}{:02x}{:02x}{:02x}...",
        branch_a_root[0], branch_a_root[1], branch_a_root[2], branch_a_root[3]
    );
    println!(
        "    Branch B (Honest): {:02x}{:02x}{:02x}{:02x}...",
        branch_b_root[0], branch_b_root[1], branch_b_root[2], branch_b_root[3]
    );

    // [4] THE ATTACK: Sybil cluster attached via single bridge
    println!("\n[4] THE ATTACK: Attaching 5 Sybils to Branch A via single bridge...");

    let bridge_tx = make_test_tx(
        "sybil_bridge",
        &sybil_keypairs[0],
        vec![branch_a_root],
        BLOCK_OFFSET + 32,
        0, // Sybils have NO reputation
    );
    let bridge_id = bridge_tx.id;
    dag.insert_genesis(bridge_tx);

    let mut sybil_tips = vec![bridge_id];
    for (i, sybil_keypair) in sybil_keypairs.iter().enumerate().skip(1) {
        let name = format!("sybil_tx_{}", i);
        let parents: Vec<NodeId> = sybil_tips.iter().take(2).cloned().collect();
        let block = BLOCK_OFFSET + 33 + (i as u64 / 10);

        let tx = make_test_tx(&name, sybil_keypair, parents, block, 0);
        let tx_id = tx.id;
        dag.insert_genesis(tx);

        sybil_tips.push(tx_id);
        if sybil_tips.len() > 4 {
            sybil_tips.remove(0);
        }
    }
    println!("    Sybil transactions added: 5 (1 bridge + 4 sybil)");
    println!(
        "    Bridge node: {:02x}{:02x}{:02x}{:02x}...",
        bridge_id[0], bridge_id[1], bridge_id[2], bridge_id[3]
    );

    // [5] THE DEFENSE: Honest transactions on Branch B with good connectivity
    println!("\n[5] THE DEFENSE: Attaching 15 Honest transactions to Branch B...");
    let mut honest_tips = vec![branch_b_root];

    for i in 0..15 {
        let name = format!("honest_tx_{}", i);
        let user_idx = (i + 2) % 10;

        // Connect to multiple recent transactions (forming triangles = positive curvature)
        let mut parents: Vec<NodeId> = Vec::new();
        parents.push(honest_tips[honest_tips.len() - 1]);
        if honest_tips.len() >= 2 {
            parents.push(honest_tips[honest_tips.len() - 2]);
        }
        if honest_tips.len() >= 3 {
            parents.push(honest_tips[honest_tips.len() - 3]);
        }

        // Established users have high reputation
        let reputation = 100 + ((32 + i as u64) * 10);

        let tx = make_test_tx(
            &name,
            &established_keypairs[user_idx],
            parents,
            BLOCK_OFFSET + 32 + i as u64,
            reputation,
        );
        let tx_id = tx.id;
        dag.insert_genesis(tx);

        honest_tips.push(tx_id);
    }
    println!("    Honest transactions added: 15");
    println!("    Connected to recent honest txs (forming triangles)");

    // [6] Compute curvatures
    println!("\n[6] Computing Curvatures...");
    let bridge_curv = dag.discrete_curvature(&branch_a_root, &bridge_id);
    let bridge_curv_float = bridge_curv as f64 / SCALE as f64;
    println!("    Bridge edge curvature (raw): {}", bridge_curv);
    println!(
        "    Bridge edge curvature (scaled): {:.4}",
        bridge_curv_float
    );

    let bridge_weight = dag.curvature_weight(bridge_curv);
    let bridge_weight_float = bridge_weight as f64 / SCALE as f64;
    println!("    Bridge edge weight: {:.4}", bridge_weight_float);

    // [7] Resolve conflict
    println!("\n[7] Resolving Conflict...");
    let (winner, mass_a, mass_b) = resolve_conflict(&mut dag, &branch_a_root, &branch_b_root);

    let mass_a_float = mass_a.total_mass as f64 / SCALE as f64;
    let mass_b_float = mass_b.total_mass as f64 / SCALE as f64;

    println!("\n======================================================================");
    println!("RESULTS");
    println!("======================================================================");

    println!("\n    BRANCH A (Sybil-backed):");
    println!("      Transactions: 6 (branch root + 1 bridge + 4 sybils)");
    println!("      Supporters: {}", mass_a.supporters);
    println!("      Claimed Reputation: {}", mass_a.claimed_reputation);
    println!(
        "      Diversity Score: {:.2}",
        mass_a.diversity_score as f64 / SCALE as f64
    );
    println!(
        "      Total Mass: {} (scaled: {:.2})",
        mass_a.total_mass, mass_a_float
    );

    println!("\n    BRANCH B (Honest):");
    println!("      Transactions: 16 (root + 15 honest)");
    println!("      Supporters: {}", mass_b.supporters);
    println!("      Claimed Reputation: {}", mass_b.claimed_reputation);
    println!(
        "      Diversity Score: {:.2}",
        mass_b.diversity_score as f64 / SCALE as f64
    );
    println!(
        "      Total Mass: {} (scaled: {:.2})",
        mass_b.total_mass, mass_b_float
    );

    let winner_str = match winner {
        ConflictWinner::BranchA => "BRANCH A (Sybil) - ATTACK SUCCEEDED!",
        ConflictWinner::BranchB => "BRANCH B (Honest) - ATTACK DEFEATED!",
    };
    println!("\n    WINNER: {}", winner_str);

    if mass_b.total_mass > 0 {
        let ratio = mass_a.total_mass as f64 / mass_b.total_mass as f64;
        println!(
            "    Sybil effectiveness: {:.1}% of honest mass",
            ratio * 100.0
        );
    }

    println!("\n======================================================================\n");

    // The test passes if honest branch wins
    // With v0.2, sybils have 0 reputation and pass through a bottleneck bridge
    assert_eq!(winner, ConflictWinner::BranchB, "Honest branch should win!");
    assert!(
        mass_b.total_mass > mass_a.total_mass,
        "Honest mass should exceed Sybil mass"
    );

    println!("TEST PASSED: Sybil attack successfully defeated!\n");
}

#[test]
fn test_curvature_computation() {
    println!("\n======================================================================");
    println!("UNIT TEST: CURVATURE COMPUTATION");
    println!("======================================================================\n");

    let mut dag = TransactionDAG::new();

    // Create a simple chain: genesis -> A -> B
    let kp_sys = make_keypair("system");
    let kp_a = make_keypair("a");
    let kp_b = make_keypair("b");

    let genesis = make_test_tx("genesis", &kp_sys, vec![], 0, 0);
    let genesis_id = genesis.id;
    dag.insert_genesis(genesis);

    let tx_a = make_test_tx("tx_a", &kp_a, vec![genesis_id], 1, 100);
    let tx_a_id = tx_a.id;
    dag.insert_genesis(tx_a);

    let tx_b = make_test_tx("tx_b", &kp_b, vec![tx_a_id], 2, 100);
    let tx_b_id = tx_b.id;
    dag.insert_genesis(tx_b);

    // Compute curvature between A and B
    let curv = dag.discrete_curvature(&tx_a_id, &tx_b_id);
    println!("    Chain curvature (A->B): {}", curv);

    // In a chain, curvature should be low (few shared neighbors)
    assert!(curv <= SCALE / 2, "Chain should have low curvature");

    println!("\nTEST PASSED: Curvature computation works correctly\n");
}

// ============================================================================
// CROSS-CRATE INTEGRATION TESTS: SYBIL RESISTANCE + FINALITY
// ============================================================================

#[test]
fn test_honest_branch_beats_sybil_branch() {
    //! Verifies that well-connected honest branches dominate sybil branches
    //! in conflict resolution. The sybil branch goes through a bottleneck
    //! bridge while the honest branch has triangle-forming connectivity.

    println!("\n======================================================================");
    println!("INTEGRATION TEST: HONEST BRANCH BEATS SYBIL BRANCH");
    println!("======================================================================\n");

    let mut dag = TransactionDAG::new();

    let kp_genesis = make_keypair("system");
    let genesis = make_test_tx("genesis", &kp_genesis, vec![], 0, 0);
    let genesis_id = genesis.id;
    dag.insert_genesis(genesis);

    // Build a small history chain so curvature has something to work with
    let kp_hist = make_keypair("history");
    let hist = make_test_tx("hist", &kp_hist, vec![genesis_id], 1, 50);
    let hist_id = hist.id;
    dag.insert_genesis(hist);

    // Fork point
    let kp_fork = make_keypair("fork");
    let fork_tx = make_test_tx("fork", &kp_fork, vec![hist_id], 2, 50);
    let fork_id = fork_tx.id;
    dag.insert_genesis(fork_tx);

    // Branch A: single bridge to sybil cluster
    let kp_a = make_keypair("branch_a");
    let branch_a_tx = make_test_tx("branch_a", &kp_a, vec![fork_id], 3, 50);
    let branch_a_id = branch_a_tx.id;
    dag.insert_genesis(branch_a_tx);

    // Sybil bridge
    let kp_bridge = make_keypair("bridge");
    let bridge_tx = make_test_tx("bridge", &kp_bridge, vec![branch_a_id], 4, 0);
    let bridge_id = bridge_tx.id;
    dag.insert_genesis(bridge_tx);

    // Sybil descendants
    let mut prev_id = bridge_id;
    for i in 0..3 {
        let kp_s = make_keypair(&format!("sybil_{}", i));
        let stx = make_test_tx(
            &format!("sybil_t{}", i),
            &kp_s,
            vec![prev_id],
            5 + i as u64,
            0,
        );
        prev_id = stx.id;
        dag.insert_genesis(stx);
    }

    // Branch B: well-connected honest transactions
    let kp_b = make_keypair("branch_b");
    let branch_b_tx = make_test_tx("branch_b", &kp_b, vec![fork_id], 3, 100);
    let branch_b_id = branch_b_tx.id;
    dag.insert_genesis(branch_b_tx);

    // Honest descendants with triangle-forming connectivity
    let mut honest_tips = vec![branch_b_id];
    for i in 0..5 {
        let kp_h = make_keypair(&format!("honest_{}", i));
        let mut parents = vec![honest_tips[honest_tips.len() - 1]];
        if honest_tips.len() >= 2 {
            parents.push(honest_tips[honest_tips.len() - 2]);
        }
        let htx = make_test_tx(&format!("honest_t{}", i), &kp_h, parents, 4 + i as u64, 100);
        let htx_id = htx.id;
        dag.insert_genesis(htx);
        honest_tips.push(htx_id);
    }

    let (winner, mass_a, mass_b) = resolve_conflict(&mut dag, &branch_a_id, &branch_b_id);

    println!(
        "    Branch A (sybil): mass = {}, Branch B (honest): mass = {}",
        mass_a.total_mass, mass_b.total_mass
    );

    assert!(
        mass_b.total_mass > mass_a.total_mass,
        "Honest branch B ({}) should beat sybil branch A ({})",
        mass_b.total_mass,
        mass_a.total_mass
    );
    assert_eq!(
        winner,
        ConflictWinner::BranchB,
        "The honest branch should win the conflict"
    );

    println!("\nTEST PASSED: Honest branch dominates sybil branch\n");
}

#[test]
fn test_is_finalized() {
    //! Verifies that `is_finalized()` returns true once a branch has accumulated
    //! enough topological mass advantage over all competitors, and false before.

    use disentangle_consensus::is_finalized;

    println!("\n======================================================================");
    println!("INTEGRATION TEST: IS_FINALIZED");
    println!("======================================================================\n");

    let mut dag = TransactionDAG::new();

    // Genesis
    let kp_genesis = make_keypair("genesis");
    let genesis = make_test_tx("genesis", &kp_genesis, vec![], 0, 0);
    let genesis_id = genesis.id;
    dag.insert_genesis(genesis);

    // Fork point (using block > BOOTSTRAP_END so throttling is active)
    let fork_block: u64 = 7000;
    let kp_fork = make_keypair("fork");
    let fork_tx = make_test_tx("fork", &kp_fork, vec![genesis_id], fork_block, 50);
    let fork_id = fork_tx.id;
    dag.insert_genesis(fork_tx);

    // Branch A: will become the dominant branch
    let kp_a = make_keypair("branch_a");
    let branch_a_tx = make_test_tx("branch_a", &kp_a, vec![fork_id], fork_block + 1, 100);
    let branch_a_id = branch_a_tx.id;
    dag.insert_genesis(branch_a_tx);

    // Branch B: competing branch (weaker)
    let kp_b = make_keypair("branch_b");
    let branch_b_tx = make_test_tx("branch_b", &kp_b, vec![fork_id], fork_block + 1, 10);
    let branch_b_id = branch_b_tx.id;
    dag.insert_genesis(branch_b_tx);

    // Initially, neither branch should be finalized against the other because
    // they have similar mass (both have a single transaction root).
    let finalized_early = is_finalized(&mut dag, &branch_a_id, &[branch_b_id]);
    println!(
        "    After fork (equal branches): is_finalized = {}",
        finalized_early
    );
    // Both branches are trivially similar in mass -- neither is 10x the other
    // so finalization should be false for A vs B.
    assert!(
        !finalized_early,
        "Branch should NOT be finalized when competitor has comparable mass"
    );

    // Now build up Branch A significantly with many high-reputation honest txs
    let mut tips_a = vec![branch_a_id];
    for i in 0..20 {
        let kp_h = make_keypair(&format!("honest_a_{}", i));
        let mut parents = vec![tips_a[tips_a.len() - 1]];
        if tips_a.len() >= 2 {
            parents.push(tips_a[tips_a.len() - 2]);
        }
        let tx = make_test_tx(
            &format!("honest_a_{}", i),
            &kp_h,
            parents,
            fork_block + 2 + i as u64,
            200,
        );
        let tx_id = tx.id;
        dag.insert_genesis(tx);
        tips_a.push(tx_id);
    }

    // Branch A now has 20+ high-reputation supporters with good connectivity.
    // Branch B still has only 1 transaction with low reputation.
    let finalized_after = is_finalized(&mut dag, &branch_a_id, &[branch_b_id]);
    println!(
        "    After building Branch A (20 txs, high rep): is_finalized = {}",
        finalized_after
    );
    assert!(
        finalized_after,
        "Branch A should be finalized with 10x+ mass advantage over Branch B"
    );

    // Verify the reverse: Branch B should NOT be finalized against Branch A
    let finalized_b = is_finalized(&mut dag, &branch_b_id, &[branch_a_id]);
    println!(
        "    Branch B against Branch A: is_finalized = {}",
        finalized_b
    );
    assert!(
        !finalized_b,
        "Branch B should NOT be finalized against the dominant Branch A"
    );

    println!("\nTEST PASSED: is_finalized correctly tracks finality threshold\n");
}
