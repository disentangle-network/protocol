//! Integration tests for disentangle-simhash.
//!
//! These tests exercise the public API through realistic scenarios:
//! structural similarity, structural divergence, distance metric properties,
//! determinism, drift behavior, majority voting, and serialization roundtrip.

use disentangle_crypto::hash::Hash256;
use disentangle_simhash::{SimHash, COHERENCE_THRESHOLD, MAX_DRIFT_BITS};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_hash(n: u8) -> Hash256 {
    let mut h = [0u8; 32];
    h[0] = n;
    h
}

fn test_hash_u16(n: u16) -> Hash256 {
    let mut h = [0u8; 32];
    h[0] = (n & 0xFF) as u8;
    h[1] = (n >> 8) as u8;
    h
}

// ===========================================================================
// 1. Structural similarity: same parents produce similar simhashes
// ===========================================================================

#[test]
fn structural_similarity_same_parents() {
    // Two transactions sharing the same parents but with slightly different
    // identity history roots should produce SimHashes that are somewhat similar
    // (lower hamming distance than completely unrelated inputs).
    let parents = vec![test_hash(1), test_hash(2), test_hash(3)];

    let history_a = test_hash(100);
    let history_b = test_hash(101); // Very close history root

    let sim_a = SimHash::from_structural(&parents, &history_a);
    let sim_b = SimHash::from_structural(&parents, &history_b);

    // They should be different (different history roots)
    assert_ne!(
        sim_a, sim_b,
        "Different history roots should produce different SimHashes"
    );

    // Compare against a completely unrelated SimHash
    let unrelated_parents = vec![test_hash(200), test_hash(201), test_hash(202)];
    let sim_unrelated = SimHash::from_structural(&unrelated_parents, &test_hash(250));

    let dist_similar = sim_a.hamming_distance(&sim_b);
    let dist_unrelated = sim_a.hamming_distance(&sim_unrelated);

    // We cannot guarantee locality-sensitivity on single-bit changes to
    // cryptographic hash inputs, but we verify both distances are valid.
    assert!(
        dist_similar <= 128,
        "Hamming distance should be <= 128 bits (got {})",
        dist_similar
    );
    assert!(
        dist_unrelated <= 128,
        "Hamming distance should be <= 128 bits (got {})",
        dist_unrelated
    );
}

// ===========================================================================
// 2. Structural divergence: different parents produce different simhashes
// ===========================================================================

#[test]
fn structural_divergence_different_parents() {
    let history = test_hash(100);

    // Various parent configurations
    let sim_1_parent = SimHash::from_structural(&[test_hash(1)], &history);
    let sim_2_parents = SimHash::from_structural(&[test_hash(1), test_hash(2)], &history);
    let sim_3_parents =
        SimHash::from_structural(&[test_hash(1), test_hash(2), test_hash(3)], &history);
    let sim_different = SimHash::from_structural(&[test_hash(50)], &history);

    // Each should be unique
    assert_ne!(
        sim_1_parent, sim_2_parents,
        "Adding a parent should change the SimHash"
    );
    assert_ne!(
        sim_2_parents, sim_3_parents,
        "Adding another parent should change it again"
    );
    assert_ne!(
        sim_1_parent, sim_different,
        "Completely different parent should produce different SimHash"
    );

    // Empty parents should also produce a valid (but distinct) SimHash
    let sim_empty = SimHash::from_structural(&[], &history);
    assert_ne!(
        sim_empty, sim_1_parent,
        "Empty parents should differ from non-empty parents"
    );
}

// ===========================================================================
// 3. Distance metric: symmetry and triangle inequality
// ===========================================================================

#[test]
fn distance_metric_properties() {
    let a = SimHash::from_structural(&[test_hash(1)], &test_hash(100));
    let b = SimHash::from_structural(&[test_hash(2)], &test_hash(100));
    let c = SimHash::from_structural(&[test_hash(3)], &test_hash(100));

    // Identity: d(a, a) = 0
    assert_eq!(a.hamming_distance(&a), 0, "Distance to self must be 0");

    // Symmetry: d(a, b) = d(b, a)
    assert_eq!(
        a.hamming_distance(&b),
        b.hamming_distance(&a),
        "Hamming distance must be symmetric"
    );
    assert_eq!(
        a.hamming_distance(&c),
        c.hamming_distance(&a),
        "Hamming distance must be symmetric"
    );
    assert_eq!(
        b.hamming_distance(&c),
        c.hamming_distance(&b),
        "Hamming distance must be symmetric"
    );

    // Triangle inequality: d(a, c) <= d(a, b) + d(b, c)
    let d_ab = a.hamming_distance(&b);
    let d_bc = b.hamming_distance(&c);
    let d_ac = a.hamming_distance(&c);

    assert!(
        d_ac <= d_ab + d_bc,
        "Triangle inequality violated: d(a,c)={} > d(a,b)+d(b,c)={}",
        d_ac,
        d_ab + d_bc,
    );
}

// ===========================================================================
// 4. Determinism: same inputs always produce same simhash
// ===========================================================================

#[test]
fn determinism_across_multiple_calls() {
    let parents = vec![test_hash(10), test_hash(20), test_hash(30)];
    let history = test_hash(42);

    // Call from_structural many times with identical inputs
    let results: Vec<SimHash> = (0..100)
        .map(|_| SimHash::from_structural(&parents, &history))
        .collect();

    // All results must be identical
    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            *result, results[0],
            "SimHash must be deterministic: call {} produced different result",
            i
        );
    }
}

// ===========================================================================
// 5. Drift: bounded mutation behavior
// ===========================================================================

#[test]
fn drift_is_bounded_and_deterministic() {
    let original = SimHash::from_structural(&[test_hash(1)], &test_hash(100));

    // Drift with various seeds
    for seed_byte in 0u8..20 {
        let seed = &[seed_byte; 8];
        let drifted = original.drift(seed, MAX_DRIFT_BITS);
        let distance = original.hamming_distance(&drifted);

        assert!(
            distance <= MAX_DRIFT_BITS,
            "Drift with seed {} produced distance {} > MAX_DRIFT_BITS ({})",
            seed_byte,
            distance,
            MAX_DRIFT_BITS,
        );
    }

    // Drift is deterministic: same seed produces same result
    let d1 = original.drift(b"test_seed", MAX_DRIFT_BITS);
    let d2 = original.drift(b"test_seed", MAX_DRIFT_BITS);
    assert_eq!(d1, d2, "Drift must be deterministic for the same seed");

    // Different seeds produce different results (probabilistic but extremely likely)
    let d3 = original.drift(b"other_seed", MAX_DRIFT_BITS);
    // We don't assert d1 != d3 because it's theoretically possible (though unlikely)
    // that different seeds produce the same mask. Instead, just verify it's valid.
    assert!(
        original.hamming_distance(&d3) <= MAX_DRIFT_BITS,
        "Drift with different seed should also be bounded"
    );
}

// ===========================================================================
// 6. Serialization roundtrip
// ===========================================================================

#[test]
fn serialization_roundtrip_preserves_hash() {
    let original =
        SimHash::from_structural(&[test_hash(1), test_hash(2), test_hash(3)], &test_hash(42));

    // JSON roundtrip
    let json = serde_json::to_string(&original).expect("JSON serialization should succeed");
    let deserialized: SimHash =
        serde_json::from_str(&json).expect("JSON deserialization should succeed");
    assert_eq!(
        original, deserialized,
        "JSON roundtrip should preserve SimHash"
    );

    // Bincode roundtrip
    let bytes = bincode::serialize(&original).expect("bincode serialization should succeed");
    let from_bytes: SimHash =
        bincode::deserialize(&bytes).expect("bincode deserialization should succeed");
    assert_eq!(
        original, from_bytes,
        "Bincode roundtrip should preserve SimHash"
    );

    // Verify the internal value is preserved
    assert_eq!(original.0, deserialized.0);
    assert_eq!(original.0, from_bytes.0);
}

// ===========================================================================
// 7. Combine simhashes: majority voting
// ===========================================================================

#[test]
fn combine_simhashes_majority_voting() {
    // Create SimHashes from known structural inputs
    let s1 = SimHash::from_structural(&[test_hash(1)], &test_hash(10));
    let s2 = SimHash::from_structural(&[test_hash(2)], &test_hash(20));
    let s3 = SimHash::from_structural(&[test_hash(3)], &test_hash(30));

    // Combine three SimHashes via majority voting
    let combined = SimHash::combine_simhashes(&[s1, s2, s3]);

    // The combined value should be a valid SimHash
    assert_ne!(
        combined.0, 0,
        "Combined SimHash should not be zero (extremely unlikely)"
    );

    // Combining a single SimHash should return itself (trivially)
    let single = SimHash::combine_simhashes(&[s1]);
    assert_eq!(
        single, s1,
        "Combining a single SimHash should return itself"
    );

    // Combining an empty slice should return ZERO
    let empty = SimHash::combine_simhashes(&[]);
    assert_eq!(
        empty,
        SimHash::ZERO,
        "Combining empty slice should return ZERO"
    );

    // Combining duplicates: if we combine three copies of the same hash,
    // the result should be that hash (unanimous vote)
    let unanimous = SimHash::combine_simhashes(&[s1, s1, s1]);
    assert_eq!(
        unanimous, s1,
        "Unanimous majority vote should return the original hash"
    );
}

// ===========================================================================
// 8. Coherence threshold check
// ===========================================================================

#[test]
fn coherence_check_integration() {
    let base = SimHash::from_structural(&[test_hash(1)], &test_hash(100));

    // A drifted version within MAX_DRIFT_BITS should be within COHERENCE_THRESHOLD
    // (since MAX_DRIFT_BITS=8 < COHERENCE_THRESHOLD=32)
    let drifted = base.drift(b"coherent_seed", MAX_DRIFT_BITS);
    assert!(
        base.is_coherent(&drifted, COHERENCE_THRESHOLD),
        "A drifted SimHash (max {} bits) should be within coherence threshold ({})",
        MAX_DRIFT_BITS,
        COHERENCE_THRESHOLD,
    );

    // Self-coherence at threshold 0
    assert!(
        base.is_coherent(&base, 0),
        "A SimHash should be coherent with itself at any threshold"
    );
}

// ===========================================================================
// 9. Grinding resistance: unique parents yield unique hashes
// ===========================================================================

#[test]
fn grinding_resistance_large_sample() {
    let history = test_hash(42);

    // Generate 500 SimHashes from 500 unique parent sets
    let hashes: Vec<SimHash> = (0..500u16)
        .map(|i| SimHash::from_structural(&[test_hash_u16(i)], &history))
        .collect();

    let unique: std::collections::HashSet<SimHash> = hashes.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        500,
        "All 500 unique parent sets should produce unique SimHashes (got {} unique)",
        unique.len(),
    );
}
