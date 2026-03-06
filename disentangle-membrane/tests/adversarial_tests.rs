use disentangle_membrane::{CoherenceBasis, CoherenceFilter};
use disentangle_simhash::SimHash;
use proptest::prelude::*;

// ===========================================================================
// Phase 5: Property-Based Adversarial Tests
// ===========================================================================

// Property 2: Adversarial payload cannot bypass filter.
// No matter how the payload is constructed, the resonance score is bounded
// by the geometric relationship between payload hash and basis — there is
// no encoding trick that lets high-level structure sneak through a low-level
// membrane.
proptest! {
    #[test]
    fn prop_adversarial_encoding_filtered(
        payload in proptest::collection::vec(any::<u8>(), 1..1024),
        basis_count in 1usize..5,
        basis_seeds in proptest::collection::vec(any::<u128>(), 1..5),
        threshold in 10u32..64,
        lambda in 0.0f64..1.0,
    ) {
        // Build a low-level basis (few signatures)
        let signatures: Vec<SimHash> = basis_seeds.iter()
            .take(basis_count)
            .map(|&s| SimHash(s))
            .collect();

        let basis = CoherenceBasis {
            signatures,
            threshold,
        };
        let filter = CoherenceFilter::new(basis, lambda);

        let result = filter.filter(&payload);

        // Resonance is always in [0.0, 1.0]
        prop_assert!(result.resonance >= 0.0, "resonance below 0: {}", result.resonance);
        prop_assert!(result.resonance <= 1.0, "resonance above 1: {}", result.resonance);

        // If passed, resonance must be >= lambda AND within basis scope
        if result.passed {
            prop_assert!(result.resonance >= lambda - f64::EPSILON,
                "passed but resonance {} < lambda {}", result.resonance, lambda);
            prop_assert!(result.projected_payload.is_some(),
                "passed but no projected payload");
            prop_assert_eq!(result.dropped_components, 0);
        }

        // If not passed, projected_payload must be None
        if !result.passed {
            prop_assert!(result.projected_payload.is_none(),
                "failed but has projected payload");
        }
    }

    // Property 3: Bandwidth monotonically tracks mutual coherence.
    // Sender cannot unilaterally increase membrane bandwidth.
    #[test]
    fn prop_bandwidth_requires_mutual_coherence(
        curvature_seq in proptest::collection::vec(0.0f64..1.0, 2..20),
    ) {
        let basis = CoherenceBasis {
            signatures: vec![SimHash(0x1234_5678_9ABC_DEF0_1234_5678_9ABC_DEF0)],
            threshold: 32,
        };
        let mut filter = CoherenceFilter::new(basis, 0.5);

        for &curvature in &curvature_seq {
            filter.adapt_lambda(curvature);
            let bw = filter.bandwidth();
            let expected_lambda = (1.0 - curvature).clamp(0.0, 1.0);
            let expected_bw = 1.0 - expected_lambda;

            prop_assert!(
                (bw - expected_bw).abs() < 1e-10,
                "bandwidth {} doesn't match expected {} for curvature {}",
                bw, expected_bw, curvature
            );

            // Bandwidth is always determined by curvature, not by sender action
            prop_assert!((0.0..=1.0).contains(&bw));
        }
    }

    // Property 5: No admin bypass.
    // Even at lambda=0.0, payloads outside the basis scope are still dropped.
    #[test]
    fn prop_no_total_bypass(
        basis_val in any::<u128>(),
        threshold in 0u32..32, // narrow scope
    ) {
        let basis_sig = SimHash(basis_val);
        let anti_sig = SimHash(!basis_val); // maximum hamming distance

        let basis = CoherenceBasis {
            signatures: vec![basis_sig],
            threshold,
        };
        // lambda=0.0 → maximally open
        let filter = CoherenceFilter::new(basis, 0.0);

        // Exact match always passes
        let exact = filter.filter_hash(basis_sig, Some(b"exact"));
        prop_assert!(exact.passed, "exact match should always pass");

        // Anti-signature: hamming distance = 128, always outside narrow scope
        // (threshold < 32 means scope requires distance <= 31)
        let anti = filter.filter_hash(anti_sig, None);
        prop_assert!(
            !anti.passed,
            "anti-signature (distance 128) should be outside basis scope (threshold {})",
            threshold
        );
    }
}

// Property 4: Square preservation requires matching.
// Verified structurally — square_preserving is only true when both gaps
// are within epsilon.
#[test]
fn prop_square_preservation_requires_match() {
    use disentangle_membrane::{CoherenceLevel, LevelTemporality, Membrane, TemporalSignature};

    let basis = CoherenceBasis {
        signatures: vec![SimHash(0)],
        threshold: 64,
    };

    // Test a range of gaps
    for level_gap in 0..5u32 {
        for temporal_gap_x10 in 0..20u32 {
            let temporal_gap = temporal_gap_x10 as f64 / 10.0;

            let local = LevelTemporality {
                level: CoherenceLevel(10),
                temporality: TemporalSignature(5.0),
            };
            let peer = LevelTemporality {
                level: CoherenceLevel(10 + level_gap),
                temporality: TemporalSignature(5.0 + temporal_gap),
            };

            let mut membrane = Membrane::new(local, basis.clone());
            membrane.set_peer(peer);

            let is_sp = membrane.is_square_preserving();

            // Skip temporal_gap_x10 == 1 (exact boundary, floating point ambiguous:
            // 5.0 + 0.1 - 5.0 ≈ 0.0999... in IEEE 754)
            if temporal_gap_x10 == 1 && level_gap == 0 {
                continue;
            }

            if level_gap > 0 || temporal_gap_x10 > 1 {
                assert!(
                    !is_sp,
                    "should NOT be square preserving with level_gap={}, temporal_gap={}",
                    level_gap, temporal_gap
                );
            }
            if level_gap == 0 && temporal_gap_x10 == 0 {
                assert!(
                    is_sp,
                    "SHOULD be square preserving with level_gap={}, temporal_gap={}",
                    level_gap, temporal_gap
                );
            }
        }
    }
}
