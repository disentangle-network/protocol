use disentangle_membrane::{
    CoherenceBasis, CoherenceFilter, CoherenceLevel, LevelTemporality, Membrane, SpectralFilter,
    TemporalSignature,
};
use disentangle_simhash::SimHash;

// ===========================================================================
// Phase 1: Level-Temporality Measurement
// ===========================================================================

#[test]
fn test_level_single_cluster() {
    // All identical SimHashes → level 1
    let hash = SimHash(0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0);
    let hashes = vec![hash; 10];
    let level = CoherenceLevel::from_history(&hashes, 32);
    assert_eq!(level.0, 1);
}

#[test]
fn test_level_diverse() {
    // N distinct clusters → level N
    // Use SimHashes with maximum hamming distance from each other
    let hashes = vec![
        SimHash(0x0000_0000_0000_0000_0000_0000_0000_0000),
        SimHash(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF),
        SimHash(0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA),
        SimHash(0x5555_5555_5555_5555_5555_5555_5555_5555),
    ];
    // With threshold=10, all 4 should be distinct clusters
    // (hamming distances between them are 128, 64, 64, etc.)
    let level = CoherenceLevel::from_history(&hashes, 10);
    assert_eq!(level.0, 4);
}

#[test]
fn test_level_empty_history() {
    let level = CoherenceLevel::from_history(&[], 32);
    assert_eq!(level.0, 0);
}

#[test]
fn test_temporality_fast() {
    // Transactions at every depth → low temporality (mean gap = 1.0)
    let depths: Vec<u64> = (0..100).collect();
    let ts = TemporalSignature::from_depths(&depths);
    assert!((ts.0 - 1.0).abs() < f64::EPSILON);
}

#[test]
fn test_temporality_slow() {
    // Transactions every 10 depths → high temporality (mean gap = 10.0)
    let depths: Vec<u64> = (0..10).map(|i| i * 10).collect();
    let ts = TemporalSignature::from_depths(&depths);
    assert!((ts.0 - 10.0).abs() < f64::EPSILON);
}

#[test]
fn test_temporality_single_depth() {
    let ts = TemporalSignature::from_depths(&[42]);
    assert!((ts.0 - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_gap_symmetric() {
    let a = LevelTemporality {
        level: CoherenceLevel(5),
        temporality: TemporalSignature(2.0),
    };
    let b = LevelTemporality {
        level: CoherenceLevel(3),
        temporality: TemporalSignature(7.0),
    };
    let (lg_ab, tg_ab) = a.gap(&b);
    let (lg_ba, tg_ba) = b.gap(&a);
    assert_eq!(lg_ab, lg_ba);
    assert!((tg_ab - tg_ba).abs() < f64::EPSILON);
}

#[test]
fn test_gap_self_zero() {
    let a = LevelTemporality {
        level: CoherenceLevel(5),
        temporality: TemporalSignature(3.17),
    };
    let (lg, tg) = a.gap(&a);
    assert_eq!(lg, 0);
    assert!((tg - 0.0).abs() < f64::EPSILON);
}

// ===========================================================================
// Phase 2: Coherence Projection Filter — SimHash Path
// ===========================================================================

#[test]
fn test_filter_identical_basis() {
    // Payload matching a basis element → resonance 1.0, full pass
    let sig = SimHash(0xABCD_EF01_2345_6789_ABCD_EF01_2345_6789);
    let basis = CoherenceBasis {
        signatures: vec![sig],
        threshold: 32,
    };
    let filter = CoherenceFilter::new(basis, 0.5);

    let result = filter.filter_hash(sig, Some(b"test"));
    assert!(result.passed);
    assert!((result.resonance - 1.0).abs() < f64::EPSILON);
    assert!(result.projected_payload.is_some());
    assert_eq!(result.dropped_components, 0);
}

#[test]
fn test_filter_orthogonal() {
    // Payload that is bitwise NOT of basis element → maximum distance, dropped
    let sig = SimHash(0xABCD_EF01_2345_6789_ABCD_EF01_2345_6789);
    let anti_sig = SimHash(!sig.0);
    let basis = CoherenceBasis {
        signatures: vec![sig],
        threshold: 32,
    };
    let filter = CoherenceFilter::new(basis, 0.0);

    let result = filter.filter_hash(anti_sig, Some(b"adversarial"));
    // hamming distance = 128, resonance = 0.0
    assert!(!result.passed);
    assert!(result.resonance < f64::EPSILON);
    assert!(result.projected_payload.is_none());
}

#[test]
fn test_filter_partial() {
    // Payload partially resonant → intermediate resonance
    // Flip 32 bits: distance=32, resonance=1.0 - 32/128 = 0.75
    let sig = SimHash(0x0000_0000_0000_0000_0000_0000_0000_0000);
    let partial = SimHash(0xFFFF_FFFF_0000_0000_0000_0000_0000_0000); // 32 bits differ
    let basis = CoherenceBasis {
        signatures: vec![sig],
        threshold: 64,
    };
    let filter = CoherenceFilter::new(basis, 0.5);

    let result = filter.filter_hash(partial, Some(b"partial"));
    assert_eq!(result.resonance, 0.75);
    assert!(result.passed); // 0.75 >= 0.5 (lambda)
}

#[test]
fn test_lambda_zero_passes_all() {
    // lambda=0.0 → everything within basis scope passes
    let sig = SimHash(0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA);
    let basis = CoherenceBasis {
        signatures: vec![sig],
        threshold: 128, // wide scope
    };
    let filter = CoherenceFilter::new(basis, 0.0);

    // Even distant payloads pass (lambda=0.0, any resonance >= 0.0)
    for i in 0u128..10 {
        let test_hash = SimHash(i.wrapping_mul(0x1234_5678_9ABC_DEF0));
        let result = filter.filter_hash(test_hash, Some(b"anything"));
        assert!(
            result.passed,
            "lambda=0.0 should pass in-basis payloads, resonance={}",
            result.resonance
        );
    }
}

#[test]
fn test_lambda_one_blocks_all() {
    // lambda=1.0 → only exact basis matches pass (resonance=1.0 required)
    let sig = SimHash(0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0);
    let basis = CoherenceBasis {
        signatures: vec![sig],
        threshold: 128,
    };
    let filter = CoherenceFilter::new(basis, 1.0);

    // Exact match passes
    let exact = filter.filter_hash(sig, Some(b"exact"));
    assert!(exact.passed);
    assert!((exact.resonance - 1.0).abs() < f64::EPSILON);

    // Even 1-bit difference fails
    let near = SimHash(sig.0 ^ 1);
    let near_result = filter.filter_hash(near, Some(b"near"));
    assert!(!near_result.passed);
}

#[test]
fn test_adapt_lambda_from_curvature() {
    // High mutual curvature → lambda decreases (more open)
    let basis = CoherenceBasis {
        signatures: vec![SimHash(0)],
        threshold: 32,
    };
    let mut filter = CoherenceFilter::new(basis, 0.8);

    // High curvature (0.9) → lambda should drop to 0.1
    filter.adapt_lambda(0.9);
    assert!((filter.lambda() - 0.1).abs() < f64::EPSILON);

    // Low curvature (0.1) → lambda should rise to 0.9
    filter.adapt_lambda(0.1);
    assert!((filter.lambda() - 0.9).abs() < f64::EPSILON);

    // Perfect alignment (1.0) → lambda = 0.0 (fully open)
    filter.adapt_lambda(1.0);
    assert!((filter.lambda() - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_extend_basis_widens_filter() {
    // Adding a signature to basis increases pass rate for similar payloads
    let sig1 = SimHash(0x0000_0000_0000_0000_0000_0000_0000_0000);
    let basis = CoherenceBasis {
        signatures: vec![sig1],
        threshold: 16,
    };
    let mut filter = CoherenceFilter::new(basis, 0.5);

    // This hash is far from sig1 — should fail
    let distant = SimHash(0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000);
    let result1 = filter.filter_hash(distant, None);
    assert!(!result1.passed);

    // Extend basis with a signature near distant
    let sig2 = SimHash(0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0001);
    filter.extend_basis(sig2);

    // Now the distant hash should pass (close to sig2)
    let result2 = filter.filter_hash(distant, None);
    assert!(result2.passed);
}

#[test]
fn test_bandwidth_monotonic() {
    // Bandwidth monotonically increases as lambda decreases
    let basis = CoherenceBasis {
        signatures: vec![SimHash(0)],
        threshold: 32,
    };

    let mut prev_bw = 0.0f64;
    for i in (0..=10).rev() {
        let lambda = i as f64 / 10.0;
        let filter = CoherenceFilter::new(basis.clone(), lambda);
        let bw = filter.bandwidth();
        assert!(
            bw >= prev_bw,
            "bandwidth should increase as lambda decreases: lambda={}, bw={}, prev={}",
            lambda,
            bw,
            prev_bw
        );
        prev_bw = bw;
    }
}

#[test]
fn test_empty_basis_blocks_all() {
    let basis = CoherenceBasis {
        signatures: vec![],
        threshold: 128,
    };
    let filter = CoherenceFilter::new(basis, 0.0);
    let result = filter.filter(b"anything");
    assert!(!result.passed);
    assert!(result.resonance < f64::EPSILON);
}

// ===========================================================================
// Phase 2: Coherence Projection Filter — Spectral Path
// ===========================================================================

#[test]
fn test_spectral_preserves_high_energy() {
    // Create feature vectors with one dominant direction
    let vectors: Vec<Vec<f64>> = (0..50)
        .map(|i| {
            let t = i as f64;
            // Strong signal in dimension 0, weak noise elsewhere
            vec![10.0 * t, 0.1 * (t % 3.0), 0.1 * (t % 7.0)]
        })
        .collect();

    let filter = SpectralFilter::from_history(&vectors, 0.9);

    // Should retain 1 dimension (the dominant direction)
    assert!(
        filter.retained_dimensions() <= 2,
        "expected 1-2 retained dimensions, got {}",
        filter.retained_dimensions()
    );
    assert_eq!(filter.total_dimensions(), 3);

    // A payload aligned with the dominant direction should pass
    let aligned = vec![100.0, 0.0, 0.0];
    let result = filter.filter(&aligned);
    assert!(
        result.resonance > 0.8,
        "aligned payload should have high resonance, got {}",
        result.resonance
    );
}

#[test]
fn test_spectral_drops_noise() {
    // Create feature vectors with clear structure in 2D, noise in extra dimensions
    let vectors: Vec<Vec<f64>> = (0..100)
        .map(|i| {
            let t = i as f64;
            vec![
                10.0 * t.cos(),        // signal
                10.0 * t.sin(),        // signal
                0.01 * (i % 5) as f64, // noise
                0.01 * (i % 3) as f64, // noise
            ]
        })
        .collect();

    let mut filter = SpectralFilter::from_history(&vectors, 0.95);
    filter.set_lambda(0.3);

    // A payload purely in the noise dimensions should have low resonance
    let noise_only = vec![0.0, 0.0, 100.0, 100.0];
    let result = filter.filter(&noise_only);
    assert!(
        result.resonance < 0.5,
        "noise-only payload should have low resonance, got {}",
        result.resonance
    );
}

// ===========================================================================
// Phase 3: Edge Membrane
// ===========================================================================

#[test]
fn test_matched_peers_max_bandwidth() {
    let lt = LevelTemporality {
        level: CoherenceLevel(5),
        temporality: TemporalSignature(2.0),
    };
    let basis = CoherenceBasis {
        signatures: vec![SimHash(0)],
        threshold: 64,
    };
    let mut membrane = Membrane::new(lt.clone(), basis);
    membrane.set_peer(lt);

    let bw = membrane.effective_bandwidth();
    assert!(
        (bw - membrane.max_bandwidth()).abs() < f64::EPSILON,
        "matched peers should have max bandwidth, got {}",
        bw
    );
}

#[test]
fn test_level_gap_reduces_bandwidth() {
    let local = LevelTemporality {
        level: CoherenceLevel(5),
        temporality: TemporalSignature(2.0),
    };
    let peer = LevelTemporality {
        level: CoherenceLevel(10),           // gap = 5
        temporality: TemporalSignature(2.0), // no temporal gap
    };
    let basis = CoherenceBasis {
        signatures: vec![SimHash(0)],
        threshold: 64,
    };
    let mut membrane = Membrane::new(local, basis);
    membrane.set_peer(peer);

    let bw = membrane.effective_bandwidth();
    let expected = 1.0 / (1.0 + 5.0); // level_factor with gap=5
    assert!(
        (bw - expected).abs() < 1e-10,
        "expected bandwidth {}, got {}",
        expected,
        bw
    );
}

#[test]
fn test_temporal_gap_reduces_bandwidth() {
    let local = LevelTemporality {
        level: CoherenceLevel(5),
        temporality: TemporalSignature(2.0),
    };
    let peer = LevelTemporality {
        level: CoherenceLevel(5),            // no level gap
        temporality: TemporalSignature(6.0), // temporal gap = 4.0
    };
    let basis = CoherenceBasis {
        signatures: vec![SimHash(0)],
        threshold: 64,
    };
    let mut membrane = Membrane::new(local, basis);
    membrane.set_peer(peer);

    let bw = membrane.effective_bandwidth();
    let expected = 1.0 / (1.0 + 4.0); // temporality_factor with gap=4
    assert!(
        (bw - expected).abs() < 1e-10,
        "expected bandwidth {}, got {}",
        expected,
        bw
    );
}

#[test]
fn test_both_gaps_compound() {
    let local = LevelTemporality {
        level: CoherenceLevel(3),
        temporality: TemporalSignature(1.0),
    };
    let peer = LevelTemporality {
        level: CoherenceLevel(6),            // level gap = 3
        temporality: TemporalSignature(5.0), // temporal gap = 4.0
    };
    let basis = CoherenceBasis {
        signatures: vec![SimHash(0)],
        threshold: 64,
    };
    let mut membrane = Membrane::new(local, basis);
    membrane.set_peer(peer);

    let bw = membrane.effective_bandwidth();
    let expected = (1.0 / 4.0) * (1.0 / 5.0); // 1/(1+3) * 1/(1+4)
    assert!(
        (bw - expected).abs() < 1e-10,
        "expected bandwidth {}, got {}",
        expected,
        bw
    );
}

#[test]
fn test_square_preserving_only_when_matched() {
    let local = LevelTemporality {
        level: CoherenceLevel(5),
        temporality: TemporalSignature(2.0),
    };
    let basis = CoherenceBasis {
        signatures: vec![SimHash(0)],
        threshold: 64,
    };

    // Matched peer → square preserving
    let mut membrane = Membrane::new(local.clone(), basis.clone());
    membrane.set_peer(local.clone());
    assert!(membrane.is_square_preserving());

    // Level gap → not square preserving
    let mut membrane2 = Membrane::new(local.clone(), basis.clone());
    membrane2.set_peer(LevelTemporality {
        level: CoherenceLevel(6),
        temporality: TemporalSignature(2.0),
    });
    assert!(!membrane2.is_square_preserving());

    // Temporal gap → not square preserving
    let mut membrane3 = Membrane::new(local.clone(), basis.clone());
    membrane3.set_peer(LevelTemporality {
        level: CoherenceLevel(5),
        temporality: TemporalSignature(3.0),
    });
    assert!(!membrane3.is_square_preserving());
}

#[test]
fn test_unknown_peer_conservative() {
    let local = LevelTemporality {
        level: CoherenceLevel(5),
        temporality: TemporalSignature(2.0),
    };
    let basis = CoherenceBasis {
        signatures: vec![SimHash(0)],
        threshold: 64,
    };
    let membrane = Membrane::new(local, basis);

    // No peer set → zero bandwidth
    assert!(membrane.effective_bandwidth() < f64::EPSILON);
    assert!(!membrane.is_square_preserving());
}

// ===========================================================================
// Phase 4: Foliation
// ===========================================================================

use disentangle_membrane::{Foliation, NodeId};

fn make_node(id: u8) -> NodeId {
    let mut bytes = [0u8; 32];
    bytes[0] = id;
    NodeId(bytes)
}

#[test]
fn test_identical_lt_same_leaf() {
    let mut fol = Foliation::new(1, 1.0);
    let lt = LevelTemporality {
        level: CoherenceLevel(5),
        temporality: TemporalSignature(2.0),
    };

    let leaf_a = fol.classify(make_node(1), lt.clone());
    let leaf_b = fol.classify(make_node(2), lt);

    assert_eq!(leaf_a, leaf_b);
    assert!(fol.same_leaf(&make_node(1), &make_node(2)));
}

#[test]
fn test_different_level_different_leaf() {
    let mut fol = Foliation::new(0, 1.0); // level_epsilon=0 → any level difference separates

    let lt_a = LevelTemporality {
        level: CoherenceLevel(5),
        temporality: TemporalSignature(2.0),
    };
    let lt_b = LevelTemporality {
        level: CoherenceLevel(6),
        temporality: TemporalSignature(2.0),
    };

    let leaf_a = fol.classify(make_node(1), lt_a);
    let leaf_b = fol.classify(make_node(2), lt_b);

    assert_ne!(leaf_a, leaf_b);
    assert!(!fol.same_leaf(&make_node(1), &make_node(2)));
}

#[test]
fn test_epsilon_boundary() {
    let mut fol = Foliation::new(1, 1.0); // level_epsilon=1, temporal_epsilon=1.0

    let lt_a = LevelTemporality {
        level: CoherenceLevel(5),
        temporality: TemporalSignature(2.0),
    };
    // Exactly at epsilon: level gap=1, temporal gap=1.0
    let lt_b = LevelTemporality {
        level: CoherenceLevel(6),
        temporality: TemporalSignature(3.0),
    };

    let leaf_a = fol.classify(make_node(1), lt_a);
    let leaf_b = fol.classify(make_node(2), lt_b);

    assert_eq!(
        leaf_a, leaf_b,
        "nodes at exactly epsilon distance should be in same leaf"
    );
}

#[test]
fn test_reclassify_on_evolution() {
    let mut fol = Foliation::new(0, 0.5);

    let lt_low = LevelTemporality {
        level: CoherenceLevel(1),
        temporality: TemporalSignature(1.0),
    };
    let lt_high = LevelTemporality {
        level: CoherenceLevel(10),
        temporality: TemporalSignature(1.0),
    };

    let node = make_node(1);
    let other = make_node(2);

    // Initially classify both low
    fol.classify(node, lt_low.clone());
    fol.classify(other, lt_low.clone());
    assert!(fol.same_leaf(&node, &other));

    // Node evolves to high level → reclassified to different leaf
    fol.classify(node, lt_high);
    assert!(!fol.same_leaf(&node, &other));
}

#[test]
fn test_inter_leaf_gap() {
    let mut fol = Foliation::new(0, 0.5);

    let lt_a = LevelTemporality {
        level: CoherenceLevel(2),
        temporality: TemporalSignature(1.0),
    };
    let lt_b = LevelTemporality {
        level: CoherenceLevel(8),
        temporality: TemporalSignature(4.0),
    };

    let leaf_a = fol.classify(make_node(1), lt_a);
    let leaf_b = fol.classify(make_node(2), lt_b);

    let (lg, tg) = fol.inter_leaf_gap(leaf_a, leaf_b);
    assert_eq!(lg, 6);
    assert!((tg - 3.0).abs() < f64::EPSILON);
}
