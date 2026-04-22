//! Integration Tests for Oracle Distribution
//!
//! Verifies the deterministic coherence-to-value computation that
//! translates protocol-observable agent scores into external resource
//! weights.

use std::collections::HashMap;

use disentangle_economy::oracle::{AgentScore, DistributionRoot, OracleQuery, RegionSelector};

#[test]
fn oracle_query_and_distribution() {
    let query = OracleQuery::new(RegionSelector::Global, 0, 100);

    let mut scores = HashMap::new();
    let mut s_alice = AgentScore {
        did: "did:disentangle:alice".to_string(),
        mass_delta: 10.0,
        curvature_derivative: 0.6,
        diversity: 5,
        composite: 0.0,
    };
    s_alice.compute_composite();

    let mut s_bob = AgentScore {
        did: "did:disentangle:bob".to_string(),
        mass_delta: 8.0,
        curvature_derivative: 0.4,
        diversity: 3,
        composite: 0.0,
    };
    s_bob.compute_composite();

    scores.insert("did:disentangle:alice".to_string(), s_alice);
    scores.insert("did:disentangle:bob".to_string(), s_bob);

    let distribution = DistributionRoot::new(&query, scores, 100);

    // Verify weights sum to 1.0
    let sum: f64 = distribution.weights.values().sum();
    assert!((sum - 1.0).abs() < 1e-9);

    // alice has 0.6/(0.6+0.4) = 0.6, bob has 0.4
    assert!(
        (distribution.weights["did:disentangle:alice"] - 0.6).abs() < 1e-9,
        "Alice weight should be 0.6, got {}",
        distribution.weights["did:disentangle:alice"]
    );
    assert!(
        (distribution.weights["did:disentangle:bob"] - 0.4).abs() < 1e-9,
        "Bob weight should be 0.4, got {}",
        distribution.weights["did:disentangle:bob"]
    );

    // Non-zero merkle root
    assert_ne!(distribution.merkle_root, [0u8; 32]);
}

#[test]
fn oracle_distribution_negative_derivatives_equal_weight() {
    // All agents have negative curvature derivative => composite=0 => equal distribution
    let query = OracleQuery::new(
        RegionSelector::Explicit(vec![
            "did:alice".to_string(),
            "did:bob".to_string(),
            "did:carol".to_string(),
        ]),
        0,
        50,
    );

    let mut scores = HashMap::new();
    for (name, deriv) in [("did:alice", -0.3), ("did:bob", -0.1), ("did:carol", -0.5)] {
        let mut s = AgentScore {
            did: name.to_string(),
            mass_delta: 0.0,
            curvature_derivative: deriv,
            diversity: 1,
            composite: 0.0,
        };
        s.compute_composite();
        scores.insert(name.to_string(), s);
    }

    let distribution = DistributionRoot::new(&query, scores, 50);

    // All equal: 1/3 each
    for weight in distribution.weights.values() {
        assert!(
            (weight - 1.0 / 3.0).abs() < 1e-9,
            "Expected equal weight ~0.333, got {}",
            weight
        );
    }
}

#[test]
fn oracle_single_positive_agent_gets_full_weight() {
    let query = OracleQuery::new(RegionSelector::Global, 0, 100);

    let mut scores = HashMap::new();

    let mut s_positive = AgentScore {
        did: "did:positive".to_string(),
        mass_delta: 5.0,
        curvature_derivative: 0.8,
        diversity: 4,
        composite: 0.0,
    };
    s_positive.compute_composite();

    let mut s_negative = AgentScore {
        did: "did:negative".to_string(),
        mass_delta: -2.0,
        curvature_derivative: -0.3,
        diversity: 2,
        composite: 0.0,
    };
    s_negative.compute_composite();

    scores.insert("did:positive".to_string(), s_positive);
    scores.insert("did:negative".to_string(), s_negative);

    let distribution = DistributionRoot::new(&query, scores, 100);

    // Only "did:positive" has composite > 0 (0.8), "did:negative" has 0
    // So positive gets 0.8/0.8 = 1.0, negative gets 0/0.8 = 0.0
    assert!(
        (distribution.weights["did:positive"] - 1.0).abs() < 1e-9,
        "Positive agent should get full weight"
    );
    assert!(
        distribution.weights["did:negative"].abs() < 1e-9,
        "Negative agent should get zero weight"
    );
}
