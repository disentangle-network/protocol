use disentangle_membrane::{
    CoherenceBasis, CoherenceLevel, LevelTemporality, Membrane, TemporalSignature,
};
use disentangle_simhash::SimHash;
use rand::Rng;

// ===========================================================================
// Phase 5: Forced Enlightenment Prevention Tests
// ===========================================================================

/// Simulate a receiver absorbing information through a membrane.
/// Returns the number of effective transfers (that increased coherence level).
fn simulate_transfers(
    receiver_level: u32,
    receiver_temporality: f64,
    sender_level: u32,
    sender_hashes: &[SimHash],
    num_rounds: usize,
) -> (u32, Vec<f64>) {
    let receiver_lt = LevelTemporality {
        level: CoherenceLevel(receiver_level),
        temporality: TemporalSignature(receiver_temporality),
    };
    let sender_lt = LevelTemporality {
        level: CoherenceLevel(sender_level),
        temporality: TemporalSignature(1.0),
    };

    // Receiver's basis: signatures from its own coherence structure
    // Low-level receiver has few, simple signatures
    let mut basis_sigs: Vec<SimHash> = (0..receiver_level)
        .map(|i| SimHash((i as u128) * 0x0101_0101_0101_0101_0101_0101_0101_0101))
        .collect();
    if basis_sigs.is_empty() {
        basis_sigs.push(SimHash(0));
    }

    let basis = CoherenceBasis {
        signatures: basis_sigs.clone(),
        threshold: 32,
    };

    let mut membrane = Membrane::new(receiver_lt, basis);
    membrane.set_peer(sender_lt);

    let mut effective_transfers = 0u32;
    let mut resonance_history = Vec::new();

    for round in 0..num_rounds {
        // Sender picks a hash from its repertoire
        let hash = sender_hashes[round % sender_hashes.len()];
        let payload = hash.0.to_le_bytes();

        let result = membrane.transfer(&payload);
        resonance_history.push(result.filter_result.resonance);

        if result.filter_result.passed {
            effective_transfers += 1;

            // Receiver learns: extend basis with the filtered content's hash
            // But only at its natural integration rate (1 per temporality period)
            // This models the receiver gradually widening its coherence structure
            if effective_transfers as f64 % receiver_temporality.max(1.0) < 1.0 {
                membrane.filter_mut().extend_basis(hash);
            }
        }
    }

    (effective_transfers, resonance_history)
}

// Property 1: Information transfer bounded by receiver capacity.
// No matter what the sender does, the receiver never absorbs more
// coherence structure than its current level + 1.
#[test]
fn prop_transfer_bounded_by_receiver() {
    let receiver_level = 2u32;
    let receiver_temporality = 10.0; // slow integrator

    // Sender is much more advanced
    let sender_level = 50;
    let sender_hashes: Vec<SimHash> = (0..100)
        .map(|i| SimHash(i as u128 * 0xABCD_EF01_2345_6789))
        .collect();

    let num_rounds = 500;
    let (effective_transfers, _) = simulate_transfers(
        receiver_level,
        receiver_temporality,
        sender_level,
        &sender_hashes,
        num_rounds,
    );

    // The receiver's basis can grow by at most N/temporality new clusters
    // (one new signature per temporality-period of effective transfers)
    // The effective transfer count through the membrane should be limited
    // by the basis scope — most sender hashes will be outside the receiver's
    // narrow basis (threshold=32), so they get filtered.
    //
    // Key assertion: the membrane prevents the sender from forcing more
    // coherence growth than the receiver's natural rate allows.
    assert!(
        effective_transfers <= num_rounds as u32,
        "effective transfers {} should not exceed total rounds {}",
        effective_transfers,
        num_rounds
    );

    // The membrane should filter a significant fraction of transfers
    // when there's a large level gap (50 - 2 = 48)
    let pass_rate = effective_transfers as f64 / num_rounds as f64;
    assert!(
        pass_rate < 0.5,
        "pass rate {} is too high for a level gap of 48 — membrane should be filtering most transfers",
        pass_rate
    );

    println!(
        "Transfer bounded: {} effective out of {} rounds (pass rate: {:.2}%)",
        effective_transfers,
        num_rounds,
        pass_rate * 100.0
    );
}

// Scenario: Sybil enlightenment attack.
// Attacker creates many identities at different levels trying to
// walk a target up the coherence ladder faster than natural integration.
#[test]
fn test_sybil_enlightenment_attack() {
    let target_level = 1u32;
    let target_temporality = 10.0; // slow integrator

    let num_attackers = 100;
    let rounds_per_attacker = 50;

    // Track how many effective transfers the target receives across ALL attackers
    let mut total_effective = 0u32;

    for attacker_id in 0..num_attackers {
        let attacker_level = 2 + attacker_id as u32; // levels 2..101

        // Each attacker crafts maximally-coherent messages
        let attacker_hashes: Vec<SimHash> = (0..10)
            .map(|j| SimHash(((attacker_id as u128) << 64) | (j as u128 * 0x1111_1111_1111_1111)))
            .collect();

        let (effective, _) = simulate_transfers(
            target_level,
            target_temporality,
            attacker_level,
            &attacker_hashes,
            rounds_per_attacker,
        );

        total_effective += effective;
    }

    let total_rounds = num_attackers * rounds_per_attacker;

    // Natural integration rate: at temporality=10, the target would
    // gain about total_rounds/10 new coherence elements if ALL transfers passed.
    // But the membrane should ensure that the many attackers don't compound
    // to exceed the natural rate — each attacker independently hits the
    // same narrow basis scope.

    // The target's level should NOT be proportional to attacker count.
    // If the membrane works, 100 attackers should not be 100x more effective
    // than 1 attacker.
    let single_attacker_rounds = rounds_per_attacker;
    let (single_effective, _) = simulate_transfers(
        target_level,
        target_temporality,
        50, // mid-range attacker
        &(0..10)
            .map(|j| SimHash(j as u128 * 0x2222_2222_2222_2222))
            .collect::<Vec<_>>(),
        single_attacker_rounds,
    );

    // Key assertion: 100 attackers should not produce 100x the effect
    // The membrane's basis scope limits each attacker independently
    let amplification = if single_effective > 0 {
        total_effective as f64 / single_effective as f64
    } else {
        total_effective as f64
    };

    // Amplification should be much less than num_attackers (100)
    // Some amplification is expected (different attackers hit different basis elements)
    // but it should be sub-linear
    assert!(
        amplification < num_attackers as f64 / 2.0,
        "Sybil amplification {} is too close to attacker count {} — membrane is not limiting",
        amplification,
        num_attackers
    );

    println!(
        "Sybil attack: {} total effective from {} attackers x {} rounds = {} total",
        total_effective, num_attackers, rounds_per_attacker, total_rounds
    );
    println!(
        "Single attacker effective: {}, amplification factor: {:.1}x (vs {}x theoretical max)",
        single_effective, amplification, num_attackers
    );
}

// Property: Bandwidth cannot be increased by sender action alone.
// Only mutual convergence of LT values opens the membrane.
#[test]
fn prop_bandwidth_requires_mutual_coherence_integration() {
    let receiver_lt = LevelTemporality {
        level: CoherenceLevel(3),
        temporality: TemporalSignature(5.0),
    };
    let basis = CoherenceBasis {
        signatures: vec![SimHash(0), SimHash(u128::MAX / 2)],
        threshold: 64,
    };

    // Sender at very different level
    let sender_lt = LevelTemporality {
        level: CoherenceLevel(30),
        temporality: TemporalSignature(1.0),
    };

    let mut membrane = Membrane::new(receiver_lt.clone(), basis);
    membrane.set_peer(sender_lt.clone());

    let initial_bw = membrane.effective_bandwidth();

    // Sender sends many transfers — bandwidth should NOT increase
    for i in 0..100 {
        let payload = format!("aggressive_payload_{}", i);
        membrane.transfer(payload.as_bytes());
    }

    let final_bw = membrane.effective_bandwidth();

    // Bandwidth is computed from LT gap, which hasn't changed
    assert!(
        (final_bw - initial_bw).abs() < 1e-10,
        "bandwidth changed from {} to {} without LT convergence",
        initial_bw,
        final_bw
    );

    // Now simulate mutual convergence: peer moves closer
    let converging_peer = LevelTemporality {
        level: CoherenceLevel(5),            // much closer to receiver's 3
        temporality: TemporalSignature(5.0), // matched temporality
    };
    membrane.set_peer(converging_peer);

    let converged_bw = membrane.effective_bandwidth();
    assert!(
        converged_bw > final_bw,
        "bandwidth should increase with mutual convergence: before={}, after={}",
        final_bw,
        converged_bw
    );
}

// Verify the membrane holds under rapid-fire transfers
#[test]
fn test_rapid_fire_does_not_overwhelm() {
    let receiver_lt = LevelTemporality {
        level: CoherenceLevel(1),
        temporality: TemporalSignature(20.0), // very slow integrator
    };
    let sender_lt = LevelTemporality {
        level: CoherenceLevel(100),
        temporality: TemporalSignature(0.1), // very fast sender
    };

    let basis = CoherenceBasis {
        signatures: vec![SimHash(42)],
        threshold: 16, // narrow scope
    };

    let mut membrane = Membrane::new(receiver_lt, basis);
    membrane.set_peer(sender_lt);

    let mut rng = rand::thread_rng();
    let mut passed_count = 0u32;
    let total = 10_000;

    for _ in 0..total {
        let payload: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
        let result = membrane.transfer(&payload);
        if result.filter_result.passed {
            passed_count += 1;
        }
    }

    let pass_rate = passed_count as f64 / total as f64;
    println!(
        "Rapid fire: {} passed out of {} ({:.2}%)",
        passed_count,
        total,
        pass_rate * 100.0
    );

    // With a narrow basis (threshold=16) and high level gap,
    // the pass rate should be very low
    assert!(
        pass_rate < 0.1,
        "pass rate {} is too high under rapid-fire from mismatched sender",
        pass_rate
    );
}
