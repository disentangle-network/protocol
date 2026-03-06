//! Formal Safety Invariants for the Coherence Membrane
//!
//! Property-based tests that formalize the safety guarantees the membrane
//! system must satisfy. Each invariant defines a mathematical property that
//! holds across the full input space, verified by proptest.
//!
//! These invariants specify what "safe cross-coherence interaction" means:
//! the membrane can only attenuate (never amplify), basis scope is
//! non-bypassable, and structural properties are independent of payload content.

use disentangle_membrane::{
    simhash_from_bytes, CoherenceBasis, CoherenceFilter, CoherenceLevel, LevelTemporality,
    Membrane, TemporalSignature,
};
use disentangle_simhash::SimHash;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

fn arb_simhash() -> impl Strategy<Value = SimHash> {
    any::<u128>().prop_map(SimHash)
}

fn arb_basis(max_sigs: usize) -> impl Strategy<Value = CoherenceBasis> {
    (
        proptest::collection::vec(any::<u128>(), 1..=max_sigs),
        0u32..=128u32,
    )
        .prop_map(|(seeds, threshold)| CoherenceBasis {
            signatures: seeds.into_iter().map(SimHash).collect(),
            threshold,
        })
}

fn arb_level_temporality() -> impl Strategy<Value = LevelTemporality> {
    (0u32..100, 0.0f64..20.0).prop_map(|(level, temp)| LevelTemporality {
        level: CoherenceLevel(level),
        temporality: TemporalSignature(temp),
    })
}

// ---------------------------------------------------------------------------
// Invariant 1: Non-degradation
//
// For any membrane configuration, effective_bandwidth is always in
// [0, max_bandwidth]. The membrane can only attenuate -- never amplify.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn invariant_non_degradation(
        local_lt in arb_level_temporality(),
        peer_lt in arb_level_temporality(),
        max_bw in 0.0f64..100.0,
    ) {
        let basis = CoherenceBasis {
            signatures: vec![SimHash(0)],
            threshold: 64,
        };
        let mut membrane = Membrane::new(local_lt, basis);
        membrane.set_max_bandwidth(max_bw);
        membrane.set_peer(peer_lt);

        let eff_bw = membrane.effective_bandwidth();

        prop_assert!(
            eff_bw >= 0.0,
            "effective_bandwidth {} is negative (max_bw={})",
            eff_bw, max_bw,
        );
        prop_assert!(
            eff_bw <= membrane.max_bandwidth() + f64::EPSILON,
            "effective_bandwidth {} exceeds max_bandwidth {} -- membrane amplified!",
            eff_bw, membrane.max_bandwidth(),
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant 2: Bandwidth monotonicity
//
// For fixed max_bandwidth and temporality, effective_bandwidth is
// monotonically non-increasing as level_gap increases.
// Similarly for temporal_gap with fixed level.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn invariant_bandwidth_monotonic_in_level_gap(
        base_level in 0u32..50,
        temporality in 0.0f64..10.0,
        max_bw in 0.1f64..100.0,
    ) {
        let basis = CoherenceBasis {
            signatures: vec![SimHash(0)],
            threshold: 64,
        };

        let local = LevelTemporality {
            level: CoherenceLevel(base_level),
            temporality: TemporalSignature(temporality),
        };

        let mut prev_bw = f64::MAX;

        // Increase level_gap from 0 to 49
        for gap in 0u32..50 {
            let peer = LevelTemporality {
                level: CoherenceLevel(base_level + gap),
                temporality: TemporalSignature(temporality), // same temporality
            };

            let mut membrane = Membrane::new(local.clone(), basis.clone());
            membrane.set_max_bandwidth(max_bw);
            membrane.set_peer(peer);

            let eff_bw = membrane.effective_bandwidth();

            prop_assert!(
                eff_bw <= prev_bw + f64::EPSILON,
                "bandwidth increased from {} to {} when level_gap increased to {}",
                prev_bw, eff_bw, gap,
            );
            prev_bw = eff_bw;
        }
    }

    #[test]
    fn invariant_bandwidth_monotonic_in_temporal_gap(
        level in 0u32..50,
        base_temp in 0.0f64..10.0,
        max_bw in 0.1f64..100.0,
    ) {
        let basis = CoherenceBasis {
            signatures: vec![SimHash(0)],
            threshold: 64,
        };

        let local = LevelTemporality {
            level: CoherenceLevel(level),
            temporality: TemporalSignature(base_temp),
        };

        let mut prev_bw = f64::MAX;

        // Increase temporal_gap in increments of 0.5
        for step in 0u32..40 {
            let temporal_gap = step as f64 * 0.5;
            let peer = LevelTemporality {
                level: CoherenceLevel(level), // same level
                temporality: TemporalSignature(base_temp + temporal_gap),
            };

            let mut membrane = Membrane::new(local.clone(), basis.clone());
            membrane.set_max_bandwidth(max_bw);
            membrane.set_peer(peer);

            let eff_bw = membrane.effective_bandwidth();

            prop_assert!(
                eff_bw <= prev_bw + f64::EPSILON,
                "bandwidth increased from {} to {} when temporal_gap increased to {}",
                prev_bw, eff_bw, temporal_gap,
            );
            prev_bw = eff_bw;
        }
    }
}

// ---------------------------------------------------------------------------
// Invariant 3: Basis scope non-bypassability
//
// For any payload hash with hamming distance > basis_threshold to ALL
// basis elements, the filter must reject it. No lambda value can override.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn invariant_basis_scope_non_bypassable(
        basis_val in any::<u128>(),
        threshold in 0u32..64,
        lambda in 0.0f64..=1.0,
    ) {
        let basis_sig = SimHash(basis_val);
        // The bitwise complement has hamming distance = 128, always > any threshold < 128
        let distant_sig = SimHash(!basis_val);

        let basis = CoherenceBasis {
            signatures: vec![basis_sig],
            threshold,
        };
        let filter = CoherenceFilter::new(basis, lambda);

        let result = filter.filter_hash(distant_sig, Some(b"payload"));

        // Hamming distance is 128, threshold is at most 63 -- must be rejected
        prop_assert!(
            !result.passed,
            "out-of-basis payload passed filter! threshold={}, lambda={}, resonance={}",
            threshold, lambda, result.resonance,
        );
        prop_assert!(
            result.projected_payload.is_none(),
            "rejected payload should have no projected content",
        );
    }

    /// Generalized version: generate random payloads and verify that any
    /// payload whose minimum hamming distance to all basis elements exceeds
    /// the threshold is rejected, regardless of lambda.
    #[test]
    fn invariant_basis_scope_general(
        basis in arb_basis(5),
        payload_hash in arb_simhash(),
    ) {
        // Compute minimum hamming distance to basis
        let min_dist = basis.signatures.iter()
            .map(|s| s.hamming_distance(&payload_hash))
            .min()
            .unwrap();

        // Test with lambda=0.0 (maximally open)
        let filter = CoherenceFilter::new(basis.clone(), 0.0);
        let result = filter.filter_hash(payload_hash, Some(b"test"));

        if min_dist > basis.threshold {
            prop_assert!(
                !result.passed,
                "payload with min_dist={} > threshold={} passed at lambda=0.0!",
                min_dist, basis.threshold,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Invariant 4: Square preservation symmetry
//
// square_preserving is true iff level_gap == 0 AND temporal_gap < TEMPORAL_EPSILON (0.1).
// This is a structural invariant, independent of payload content.
// ---------------------------------------------------------------------------

const TEMPORAL_EPSILON: f64 = 0.1;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn invariant_square_preservation_structural(
        local_lt in arb_level_temporality(),
        peer_lt in arb_level_temporality(),
    ) {
        let basis = CoherenceBasis {
            signatures: vec![SimHash(0)],
            threshold: 64,
        };
        let mut membrane = Membrane::new(local_lt.clone(), basis);
        membrane.set_peer(peer_lt.clone());

        let (level_gap, temporal_gap) = local_lt.gap(&peer_lt);
        let is_sp = membrane.is_square_preserving();

        let should_be_sp = level_gap == 0 && temporal_gap < TEMPORAL_EPSILON;

        prop_assert_eq!(
            is_sp, should_be_sp,
            "square_preserving mismatch: level_gap={}, temporal_gap={}, \
             expected={}, got={}",
            level_gap, temporal_gap, should_be_sp, is_sp,
        );
    }

    /// Square preservation must not depend on payload content.
    #[test]
    fn invariant_square_preservation_payload_independent(
        local_lt in arb_level_temporality(),
        peer_lt in arb_level_temporality(),
        payload_a in proptest::collection::vec(any::<u8>(), 1..256),
        payload_b in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let basis = CoherenceBasis {
            signatures: vec![simhash_from_bytes(&payload_a)],
            threshold: 128, // very wide basis so both payloads are in scope
        };

        let mut membrane_a = Membrane::new(local_lt.clone(), basis.clone());
        membrane_a.set_peer(peer_lt.clone());
        let result_a = membrane_a.transfer(&payload_a);

        let mut membrane_b = Membrane::new(local_lt, basis);
        membrane_b.set_peer(peer_lt);
        let result_b = membrane_b.transfer(&payload_b);

        prop_assert_eq!(
            result_a.square_preserving, result_b.square_preserving,
            "square_preserving changed between different payloads \
             through identical membrane configuration",
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant 5: Lambda bounds
//
// lambda=0.0: any payload within basis scope passes.
// lambda=1.0: only exact basis matches (resonance=1.0) pass.
// Lambda interpolates monotonically between these extremes.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// At lambda=0.0, any in-basis payload must pass.
    #[test]
    fn invariant_lambda_zero_open(
        basis in arb_basis(5),
        payload_hash in arb_simhash(),
    ) {
        let filter = CoherenceFilter::new(basis.clone(), 0.0);
        let result = filter.filter_hash(payload_hash, Some(b"test"));

        let min_dist = basis.signatures.iter()
            .map(|s| s.hamming_distance(&payload_hash))
            .min()
            .unwrap();

        if min_dist <= basis.threshold {
            prop_assert!(
                result.passed,
                "in-basis payload (dist={}, threshold={}) rejected at lambda=0.0",
                min_dist, basis.threshold,
            );
        }
    }

    /// At lambda=1.0, only exact basis matches pass.
    #[test]
    fn invariant_lambda_one_exact_only(
        basis in arb_basis(5),
        payload_hash in arb_simhash(),
    ) {
        let filter = CoherenceFilter::new(basis.clone(), 1.0);
        let result = filter.filter_hash(payload_hash, Some(b"test"));

        let is_exact_match = basis.signatures.iter()
            .any(|s| s.hamming_distance(&payload_hash) == 0);

        if result.passed {
            prop_assert!(
                is_exact_match,
                "non-exact payload passed at lambda=1.0! resonance={}",
                result.resonance,
            );
        }
        if is_exact_match {
            prop_assert!(
                result.passed,
                "exact basis match rejected at lambda=1.0!",
            );
        }
    }

    /// Lambda monotonicity: for a fixed payload and basis, increasing lambda
    /// can only make the filter more restrictive (never less).
    /// If payload is rejected at lambda=L, it must also be rejected at any L' > L.
    #[test]
    fn invariant_lambda_monotonic(
        basis in arb_basis(3),
        payload_hash in arb_simhash(),
    ) {
        let mut prev_passed = true;

        // Walk lambda from 0.0 to 1.0 in 0.05 steps
        for step in 0u32..=20 {
            let lambda = step as f64 / 20.0;
            let filter = CoherenceFilter::new(basis.clone(), lambda);
            let result = filter.filter_hash(payload_hash, Some(b"test"));

            if !prev_passed {
                prop_assert!(
                    !result.passed,
                    "payload rejected at lower lambda but passed at lambda={}",
                    lambda,
                );
            }
            prev_passed = result.passed;
        }
    }
}

// ---------------------------------------------------------------------------
// Invariant 6: Bandwidth non-negativity
//
// effective_bandwidth >= 0.0 for all valid inputs.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn invariant_bandwidth_non_negative(
        local_lt in arb_level_temporality(),
        peer_lt in arb_level_temporality(),
        max_bw in 0.0f64..1000.0,
    ) {
        let basis = CoherenceBasis {
            signatures: vec![SimHash(0)],
            threshold: 64,
        };
        let mut membrane = Membrane::new(local_lt, basis);
        membrane.set_max_bandwidth(max_bw);
        membrane.set_peer(peer_lt);

        let eff_bw = membrane.effective_bandwidth();

        prop_assert!(
            eff_bw >= 0.0,
            "effective_bandwidth is negative: {} (max_bw={})",
            eff_bw, max_bw,
        );
    }

    /// Also verify for the no-peer case (should be zero, not negative).
    #[test]
    fn invariant_bandwidth_non_negative_no_peer(
        local_lt in arb_level_temporality(),
        max_bw in 0.0f64..1000.0,
    ) {
        let basis = CoherenceBasis {
            signatures: vec![SimHash(0)],
            threshold: 64,
        };
        let mut membrane = Membrane::new(local_lt, basis);
        membrane.set_max_bandwidth(max_bw);
        // No peer set -- unknown peer case

        let eff_bw = membrane.effective_bandwidth();

        prop_assert!(
            eff_bw >= 0.0,
            "effective_bandwidth is negative with no peer: {}",
            eff_bw,
        );
        prop_assert_eq!(
            eff_bw, 0.0,
            "unknown peer should produce zero bandwidth, got {}",
            eff_bw,
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant 7: Sybil resistance (bounded influence / idempotence)
//
// For a fixed filter configuration, processing N copies of the same
// payload produces the same result each time. The filter is stateless
// per-transfer -- repeated submissions don't accumulate advantage.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn invariant_sybil_resistance_idempotence(
        basis in arb_basis(5),
        lambda in 0.0f64..=1.0,
        payload_hash in arb_simhash(),
        repetitions in 2usize..50,
    ) {
        let filter = CoherenceFilter::new(basis, lambda);

        let first_result = filter.filter_hash(payload_hash, Some(b"payload"));

        for i in 1..repetitions {
            let result = filter.filter_hash(payload_hash, Some(b"payload"));

            prop_assert_eq!(
                result.passed, first_result.passed,
                "pass/fail changed on repetition {} of {}",
                i, repetitions,
            );
            prop_assert!(
                (result.resonance - first_result.resonance).abs() < f64::EPSILON,
                "resonance changed from {} to {} on repetition {}",
                first_result.resonance, result.resonance, i,
            );
            prop_assert_eq!(
                result.dropped_components, first_result.dropped_components,
                "dropped_components changed on repetition {}",
                i,
            );
        }
    }

    /// Full membrane transfer idempotence: the same payload through the same
    /// membrane configuration produces identical results.
    #[test]
    fn invariant_sybil_resistance_membrane_transfer(
        local_lt in arb_level_temporality(),
        peer_lt in arb_level_temporality(),
        payload in proptest::collection::vec(any::<u8>(), 1..256),
        repetitions in 2usize..20,
    ) {
        let basis = CoherenceBasis {
            signatures: vec![simhash_from_bytes(&payload)],
            threshold: 64,
        };

        // Collect results from independent membrane instances with identical config
        let mut results = Vec::with_capacity(repetitions);
        for _ in 0..repetitions {
            let mut membrane = Membrane::new(local_lt.clone(), basis.clone());
            membrane.set_peer(peer_lt.clone());
            results.push(membrane.transfer(&payload));
        }

        let first = &results[0];
        for (i, result) in results.iter().enumerate().skip(1) {
            prop_assert_eq!(
                result.filter_result.passed, first.filter_result.passed,
                "pass/fail changed on transfer repetition {}",
                i,
            );
            prop_assert!(
                (result.effective_bandwidth - first.effective_bandwidth).abs() < f64::EPSILON,
                "effective_bandwidth changed from {} to {} on repetition {}",
                first.effective_bandwidth, result.effective_bandwidth, i,
            );
            prop_assert_eq!(
                result.square_preserving, first.square_preserving,
                "square_preserving changed on repetition {}",
                i,
            );
        }
    }
}
