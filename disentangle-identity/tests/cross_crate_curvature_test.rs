//! Cross-Crate Curvature Formula Equivalence Test
//!
//! Verifies that the DAG curvature formula (`TransactionDAG::discrete_curvature()`)
//! and the identity curvature formula (`IdentityGraph::identity_curvature()`) produce
//! identical results when given equivalent graph structures.
//!
//! Both formulas implement Jaccard curvature: kappa_J = 2 * |N(a) intersect N(b)| / |N(a) union N(b)| - 1
//! but over different "neighbor" definitions:
//!   - DAG: ancestors(node, ANCESTOR_DEPTH) -- parents + grandparents
//!   - Identity: neighbors(did) -- direct graph neighbors (both directions)
//!
//! This test constructs equivalent topologies in both representations and verifies
//! they produce the same curvature values, ensuring the two implementations stay in sync.

use disentangle_crypto::hash::sha3_256;
use disentangle_crypto::signature::{generate_keypair, SigningKey, VerifyingKey};
use disentangle_crypto::types::{Epoch, Nullifier};
use disentangle_dag::{
    fp_from_ratio, FixedPoint, Hash256, NodeId, Transaction, TransactionDAG, SCALE,
};
use disentangle_identity::{IdentityGraph, IntroductionContext, IntroductionTransaction, DID};
use disentangle_simhash::SimHash;

/// Helper: create a test transaction for the DAG
fn make_dag_tx(
    name: &str,
    keypair: &(SigningKey, VerifyingKey),
    parents: Vec<NodeId>,
    depth: u64,
) -> Transaction {
    let (sk, pk) = keypair;
    let history_root = sha3_256(format!("history:{}", name).as_bytes());
    let parent_hashes: Vec<Hash256> = parents.to_vec();
    let simhash = SimHash::from_structural(&parent_hashes, &history_root);
    let nullifier = Nullifier::compute(
        &sha3_256(format!("secret:{}", name).as_bytes()),
        Epoch::from_depth(depth),
        name.as_bytes(),
    );
    let signature = disentangle_crypto::sign(sk, format!("tx:{}", name).as_bytes());

    let mut tx = Transaction {
        id: [0u8; 32],
        ephemeral_pk: pk.clone(),
        signature,
        parents,
        simhash,
        nullifier,
        reputation_claim: 0,
        confidential_outputs: vec![],
    };
    tx.id = tx.compute_id();
    tx
}

/// Manually compute Jaccard curvature from two neighbor sets.
///
/// kappa_J = 2 * |A intersect B| / |A union B| - 1
fn jaccard_curvature(set_a: &[&str], set_b: &[&str]) -> FixedPoint {
    use std::collections::HashSet;
    let a: HashSet<&str> = set_a.iter().copied().collect();
    let b: HashSet<&str> = set_b.iter().copied().collect();

    let intersection_count = a.intersection(&b).count() as i32;
    let union_count = a.union(&b).count() as i32;

    if union_count == 0 {
        return 0;
    }

    2 * fp_from_ratio(intersection_count, union_count) - SCALE
}

#[test]
fn test_curvature_formula_equivalence_shared_neighbors() {
    //! Test case 1: Two nodes with shared neighbors.
    //!
    //! Identity graph: A--C, A--D, B--C, B--D (A and B share C and D)
    //! DAG equivalent: build a structure where ancestors(u, ANCESTOR_DEPTH) and
    //! ancestors(v, ANCESTOR_DEPTH) produce the same Jaccard overlap.
    //!
    //! Both should produce the same kappa_J value.

    println!("\n======================================================================");
    println!("CROSS-CRATE TEST: CURVATURE FORMULA EQUIVALENCE (shared neighbors)");
    println!("======================================================================\n");

    // --- Identity graph side ---
    let mut id_graph = IdentityGraph::new();

    let (sk_a, pk_a) = generate_keypair();
    let did_a = DID::new(&pk_a, false);
    let (sk_b, pk_b) = generate_keypair();
    let did_b = DID::new(&pk_b, false);
    let (_, pk_c) = generate_keypair();
    let did_c = DID::new(&pk_c, false);
    let (_, pk_d) = generate_keypair();
    let did_d = DID::new(&pk_d, false);

    // A introduces C and D
    id_graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_a.clone(),
        introduced_did: did_c.clone(),
        edge_name: "Friend".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_a, b"intro_a_c"),
        parents: vec![],
        depth: 100,
    });
    id_graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_a.clone(),
        introduced_did: did_d.clone(),
        edge_name: "Friend".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_a, b"intro_a_d"),
        parents: vec![],
        depth: 101,
    });

    // B introduces C and D
    id_graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_b.clone(),
        introduced_did: did_c.clone(),
        edge_name: "Friend".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_b, b"intro_b_c"),
        parents: vec![],
        depth: 102,
    });
    id_graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_b.clone(),
        introduced_did: did_d.clone(),
        edge_name: "Friend".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_b, b"intro_b_d"),
        parents: vec![],
        depth: 103,
    });

    let id_curvature = id_graph.identity_curvature(&did_a, &did_b);
    println!(
        "    Identity curvature (A, B): {} (scaled: {:.4})",
        id_curvature,
        id_curvature as f64 / SCALE as f64
    );

    // Verify that the identity curvature matches the manual Jaccard computation.
    // Neighbors(A) = {C, D}, Neighbors(B) = {C, D}
    // Intersection = {C, D} = 2, Union = {C, D} = 2
    // Jaccard = 2/2 = 1.0, kappa = 2*1.0 - 1 = 1.0
    let expected = jaccard_curvature(&["C", "D"], &["C", "D"]);
    println!(
        "    Expected (manual Jaccard): {} (scaled: {:.4})",
        expected,
        expected as f64 / SCALE as f64
    );

    assert_eq!(
        id_curvature, expected,
        "Identity curvature should match manual Jaccard computation"
    );

    // --- DAG side ---
    // Build a DAG where two nodes have the same ancestor overlap.
    // With ANCESTOR_DEPTH=2:
    //   - We need two nodes u, v whose ancestors(u, 2) and ancestors(v, 2) have
    //     the same Jaccard as {C,D} vs {C,D} = 1.0.
    //   - If u and v share the same set of parents, their depth-1 ancestors are identical.
    //   - For depth-2, the shared parents' own parents also matter.
    //
    // Structure: genesis -> P (shared parent) -> u and v
    //   ancestors(u, 1) = {P}, ancestors(v, 1) = {P}
    //   ancestors(u, 2) = {P, genesis}, ancestors(v, 2) = {P, genesis}
    //   Jaccard = 1.0, kappa = 1.0

    let mut dag = TransactionDAG::new();

    let kp_genesis = generate_keypair();
    let genesis = make_dag_tx("genesis", &kp_genesis, vec![], 0);
    let genesis_id = genesis.id;
    dag.insert_genesis(genesis);

    let kp_p = generate_keypair();
    let p_tx = make_dag_tx("parent_p", &kp_p, vec![genesis_id], 1);
    let p_id = p_tx.id;
    dag.insert_genesis(p_tx);

    let kp_u = generate_keypair();
    let u_tx = make_dag_tx("node_u", &kp_u, vec![p_id], 2);
    let u_id = u_tx.id;
    dag.insert_genesis(u_tx);

    let kp_v = generate_keypair();
    let v_tx = make_dag_tx("node_v", &kp_v, vec![p_id], 2);
    let v_id = v_tx.id;
    dag.insert_genesis(v_tx);

    let dag_curvature = dag.discrete_curvature(&u_id, &v_id);
    println!(
        "    DAG curvature (u, v): {} (scaled: {:.4})",
        dag_curvature,
        dag_curvature as f64 / SCALE as f64
    );

    // Both should yield maximum Jaccard curvature (1.0) = SCALE
    assert_eq!(
        dag_curvature, SCALE,
        "DAG curvature should equal SCALE (1.0) for identical ancestor sets"
    );
    assert_eq!(
        id_curvature, SCALE,
        "Identity curvature should equal SCALE (1.0) for identical neighbor sets"
    );
    assert_eq!(
        dag_curvature, id_curvature,
        "DAG and identity curvature should be identical for equivalent structures"
    );

    println!(
        "\nTEST PASSED: Curvature formulas produce identical results for shared-neighbor case\n"
    );
}

#[test]
fn test_curvature_formula_equivalence_disjoint() {
    //! Test case 2: Two nodes with NO shared neighbors.
    //!
    //! Identity graph: A--C, B--D (no overlap between A's and B's neighbors)
    //! DAG equivalent: two nodes with disjoint ancestor sets.
    //!
    //! Both should produce kappa_J = 2 * 0/N - 1 = -1.0

    println!("\n======================================================================");
    println!("CROSS-CRATE TEST: CURVATURE FORMULA EQUIVALENCE (disjoint)");
    println!("======================================================================\n");

    // --- Identity graph ---
    let mut id_graph = IdentityGraph::new();

    let (sk_a, pk_a) = generate_keypair();
    let did_a = DID::new(&pk_a, false);
    let (sk_b, pk_b) = generate_keypair();
    let did_b = DID::new(&pk_b, false);
    let (_, pk_c) = generate_keypair();
    let did_c = DID::new(&pk_c, false);
    let (_, pk_d) = generate_keypair();
    let did_d = DID::new(&pk_d, false);

    // A--C only, B--D only
    id_graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_a.clone(),
        introduced_did: did_c.clone(),
        edge_name: "Friend".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_a, b"intro_a_c"),
        parents: vec![],
        depth: 100,
    });
    id_graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_b.clone(),
        introduced_did: did_d.clone(),
        edge_name: "Friend".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_b, b"intro_b_d"),
        parents: vec![],
        depth: 101,
    });

    let id_curvature = id_graph.identity_curvature(&did_a, &did_b);
    println!(
        "    Identity curvature (A, B): {} (scaled: {:.4})",
        id_curvature,
        id_curvature as f64 / SCALE as f64
    );

    // Neighbors(A) = {C}, Neighbors(B) = {D}
    // Intersection = 0, Union = {C, D} = 2
    // Jaccard = 0/2 = 0, kappa = 2*0 - 1 = -1.0 = -SCALE
    let expected = jaccard_curvature(&["C"], &["D"]);
    assert_eq!(
        id_curvature, expected,
        "Identity curvature should be -SCALE for disjoint neighbors"
    );
    assert_eq!(
        id_curvature, -SCALE,
        "Identity curvature should be exactly -SCALE (-1.0)"
    );

    // --- DAG side ---
    // Two nodes with completely disjoint ancestor sets:
    // genesis1 -> u, genesis2 -> v
    // ancestors(u, 2) = {genesis1}, ancestors(v, 2) = {genesis2}
    // Jaccard = 0/2 = 0, kappa = -SCALE

    let mut dag = TransactionDAG::new();

    let kp_g1 = generate_keypair();
    let g1 = make_dag_tx("genesis1", &kp_g1, vec![], 0);
    let g1_id = g1.id;
    dag.insert_genesis(g1);

    let kp_g2 = generate_keypair();
    let g2 = make_dag_tx("genesis2", &kp_g2, vec![], 0);
    let g2_id = g2.id;
    dag.insert_genesis(g2);

    let kp_u = generate_keypair();
    let u_tx = make_dag_tx("node_u", &kp_u, vec![g1_id], 1);
    let u_id = u_tx.id;
    dag.insert_genesis(u_tx);

    let kp_v = generate_keypair();
    let v_tx = make_dag_tx("node_v", &kp_v, vec![g2_id], 1);
    let v_id = v_tx.id;
    dag.insert_genesis(v_tx);

    let dag_curvature = dag.discrete_curvature(&u_id, &v_id);
    println!(
        "    DAG curvature (u, v): {} (scaled: {:.4})",
        dag_curvature,
        dag_curvature as f64 / SCALE as f64
    );

    assert_eq!(
        dag_curvature, -SCALE,
        "DAG curvature should be -SCALE for disjoint ancestor sets"
    );
    assert_eq!(
        dag_curvature, id_curvature,
        "DAG and identity curvature should match for disjoint case"
    );

    println!("\nTEST PASSED: Curvature formulas produce identical results for disjoint case\n");
}

#[test]
fn test_curvature_formula_equivalence_partial_overlap() {
    //! Test case 3: Two nodes with partial overlap.
    //!
    //! Identity graph: A--C, A--D, B--C, B--E
    //!   Neighbors(A) = {C, D}, Neighbors(B) = {C, E}
    //!   Intersection = {C} = 1, Union = {C, D, E} = 3
    //!   Jaccard = 1/3, kappa = 2/3 - 1 = -1/3
    //!
    //! DAG equivalent: build matching ancestor sets.

    println!("\n======================================================================");
    println!("CROSS-CRATE TEST: CURVATURE FORMULA EQUIVALENCE (partial overlap)");
    println!("======================================================================\n");

    // --- Identity graph ---
    let mut id_graph = IdentityGraph::new();

    let (sk_a, pk_a) = generate_keypair();
    let did_a = DID::new(&pk_a, false);
    let (sk_b, pk_b) = generate_keypair();
    let did_b = DID::new(&pk_b, false);
    let (_, pk_c) = generate_keypair();
    let did_c = DID::new(&pk_c, false);
    let (_, pk_d) = generate_keypair();
    let did_d = DID::new(&pk_d, false);
    let (_, pk_e) = generate_keypair();
    let did_e = DID::new(&pk_e, false);

    // A--C, A--D
    id_graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_a.clone(),
        introduced_did: did_c.clone(),
        edge_name: "Friend".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_a, b"a_c"),
        parents: vec![],
        depth: 100,
    });
    id_graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_a.clone(),
        introduced_did: did_d.clone(),
        edge_name: "Friend".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_a, b"a_d"),
        parents: vec![],
        depth: 101,
    });

    // B--C, B--E
    id_graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_b.clone(),
        introduced_did: did_c.clone(),
        edge_name: "Friend".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_b, b"b_c"),
        parents: vec![],
        depth: 102,
    });
    id_graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_b.clone(),
        introduced_did: did_e.clone(),
        edge_name: "Friend".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_b, b"b_e"),
        parents: vec![],
        depth: 103,
    });

    let id_curvature = id_graph.identity_curvature(&did_a, &did_b);
    println!(
        "    Identity curvature (A, B): {} (scaled: {:.4})",
        id_curvature,
        id_curvature as f64 / SCALE as f64
    );

    // Manual: intersection=1, union=3, Jaccard=1/3, kappa=2/3-1=-1/3
    let expected = jaccard_curvature(&["C", "D"], &["C", "E"]);
    println!(
        "    Expected (manual): {} (scaled: {:.4})",
        expected,
        expected as f64 / SCALE as f64
    );

    assert_eq!(
        id_curvature, expected,
        "Identity curvature should match manual Jaccard for partial overlap"
    );

    // --- DAG side ---
    // Build a DAG where ancestors(u, 1) = {P_shared, P_only_u}
    //   and ancestors(v, 1) = {P_shared, P_only_v}
    // Since ANCESTOR_DEPTH=2 and these parents have no grandparents
    // (they are genesis-level), ancestors(u, 2) = ancestors(u, 1).
    //
    // Actually, with ANCESTOR_DEPTH=2, ancestors include grandparents too.
    // To get exactly the partial overlap, we need:
    //   ancestors(u, 2) with 2 elements (one shared, one unique to u)
    //   ancestors(v, 2) with 2 elements (one shared, one unique to v)
    //
    // Structure:
    //   shared_genesis (no parents) -> used as shared parent
    //   unique_u_genesis (no parents)
    //   unique_v_genesis (no parents)
    //   u has parents = [shared_genesis, unique_u_genesis]
    //   v has parents = [shared_genesis, unique_v_genesis]
    //   ancestors(u, 1) = {shared, unique_u}, ancestors(u, 2) = {shared, unique_u}
    //   ancestors(v, 1) = {shared, unique_v}, ancestors(v, 2) = {shared, unique_v}
    //   (No grandparents because the parents are genesis nodes with no parents.)
    //   Intersection = {shared} = 1, Union = {shared, unique_u, unique_v} = 3
    //   Jaccard = 1/3, kappa = -1/3

    let mut dag = TransactionDAG::new();

    let kp_shared = generate_keypair();
    let shared = make_dag_tx("shared_parent", &kp_shared, vec![], 0);
    let shared_id = shared.id;
    dag.insert_genesis(shared);

    let kp_uu = generate_keypair();
    let uu = make_dag_tx("unique_u_parent", &kp_uu, vec![], 0);
    let uu_id = uu.id;
    dag.insert_genesis(uu);

    let kp_uv = generate_keypair();
    let uv = make_dag_tx("unique_v_parent", &kp_uv, vec![], 0);
    let uv_id = uv.id;
    dag.insert_genesis(uv);

    let kp_u = generate_keypair();
    let u_tx = make_dag_tx("node_u", &kp_u, vec![shared_id, uu_id], 1);
    let u_id = u_tx.id;
    dag.insert_genesis(u_tx);

    let kp_v = generate_keypair();
    let v_tx = make_dag_tx("node_v", &kp_v, vec![shared_id, uv_id], 1);
    let v_id = v_tx.id;
    dag.insert_genesis(v_tx);

    let dag_curvature = dag.discrete_curvature(&u_id, &v_id);
    println!(
        "    DAG curvature (u, v): {} (scaled: {:.4})",
        dag_curvature,
        dag_curvature as f64 / SCALE as f64
    );

    // Both should be approximately -1/3 * SCALE
    // Allow a tolerance of 1 for fixed-point rounding
    let tolerance = 1;
    assert!(
        (dag_curvature - id_curvature).abs() <= tolerance,
        "DAG curvature ({}) and identity curvature ({}) should match within tolerance {}",
        dag_curvature,
        id_curvature,
        tolerance,
    );

    // Also verify against the manual computation
    assert!(
        (dag_curvature - expected).abs() <= tolerance,
        "DAG curvature ({}) should match manual Jaccard ({}) within tolerance {}",
        dag_curvature,
        expected,
        tolerance,
    );

    println!("\nTEST PASSED: Curvature formulas produce equivalent results for partial overlap\n");
}

#[test]
fn test_curvature_formula_equivalence_empty_neighbors() {
    //! Test case 4: Both nodes have no neighbors.
    //!
    //! Both formulas should return 0 when the union of neighbor sets is empty.

    println!("\n======================================================================");
    println!("CROSS-CRATE TEST: CURVATURE FORMULA EQUIVALENCE (empty)");
    println!("======================================================================\n");

    // --- Identity graph ---
    let id_graph = IdentityGraph::new();
    let (_, pk_a) = generate_keypair();
    let did_a = DID::new(&pk_a, false);
    let (_, pk_b) = generate_keypair();
    let did_b = DID::new(&pk_b, false);

    let id_curvature = id_graph.identity_curvature(&did_a, &did_b);
    println!("    Identity curvature (no neighbors): {}", id_curvature);
    assert_eq!(
        id_curvature, 0,
        "Identity curvature should be 0 for nodes with no neighbors"
    );

    // --- DAG side ---
    // Two genesis transactions with no parents
    let mut dag = TransactionDAG::new();

    let kp_u = generate_keypair();
    let u_tx = make_dag_tx("node_u", &kp_u, vec![], 0);
    let u_id = u_tx.id;
    dag.insert_genesis(u_tx);

    let kp_v = generate_keypair();
    let v_tx = make_dag_tx("node_v", &kp_v, vec![], 0);
    let v_id = v_tx.id;
    dag.insert_genesis(v_tx);

    let dag_curvature = dag.discrete_curvature(&u_id, &v_id);
    println!("    DAG curvature (no ancestors): {}", dag_curvature);
    assert_eq!(
        dag_curvature, 0,
        "DAG curvature should be 0 for nodes with no ancestors"
    );

    assert_eq!(
        dag_curvature, id_curvature,
        "Both formulas should return 0 for the empty case"
    );

    println!("\nTEST PASSED: Curvature formulas agree on empty neighbor sets\n");
}
