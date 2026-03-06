//! Spectral filter evolution simulation tests.
//!
//! Parallel to `coherence_evolution_tests.rs`, but uses the eigendecomposition-based
//! `SpectralFilter` instead of the SimHash-based `CoherenceFilter`. This enables
//! direct comparison of both filtering approaches under identical scenarios.
//!
//! ## Key differences from SimHash path
//!
//! - **SimHash path**: operates on 128-bit locality-sensitive hashes with hamming
//!   distance. Binary, discrete. Basis membership is a scope check.
//! - **Spectral path**: operates on continuous f64 feature vectors with energy
//!   (eigenvalue) decomposition. Projects onto principal components. Energy
//!   retention determines coupling strength.
//!
//! ## Critical design insight: anisotropic distributions
//!
//! The spectral filter uses eigendecomposition of the *covariance* matrix. Covariance
//! is computed from *centered* data (mean-subtracted). This means that mean offsets
//! alone do NOT create different principal component structures -- only per-dimension
//! *variance* differences do. Nodes must generate features with high variance along
//! their "signal" dimensions and near-zero variance along "noise" dimensions to
//! produce covariance matrices with genuinely different eigenspaces.
//!
//! ## Research questions
//!
//! - Does spectral filtering preserve a high-coherence node's feature space during
//!   interaction with a low-coherence node?
//! - Do compatible peers (overlapping feature distributions) converge via spectral
//!   filtering?
//! - Are incompatible peers (orthogonal feature distributions) isolated by spectral
//!   filtering?
//! - How do spectral filtering metrics (energy retention, pass rates) compare to
//!   SimHash metrics (resonance, hamming distance)?

use disentangle_membrane::{LevelTemporality, Membrane, SpectralFilter};
use disentangle_simhash::SimHash;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// ===========================================================================
// Constants
// ===========================================================================

/// Feature vector dimensionality for all simulations.
const FEATURE_DIM: usize = 8;

/// Minimum feature history size before a SpectralFilter can be built.
/// Eigendecomposition needs at least dim+1 samples for meaningful covariance.
const MIN_HISTORY: usize = FEATURE_DIM + 2;

// ===========================================================================
// Simulation infrastructure
// ===========================================================================

/// A simulated node using spectral filtering on continuous feature vectors.
///
/// Unlike the SimHash path (which uses discrete binary hashes), this node
/// generates continuous feature vectors with per-dimension variance control.
/// High variance along "signal" dimensions creates strong principal components;
/// near-zero variance along "noise" dimensions keeps the eigenspace focused.
struct SpectralSimulationNode {
    /// Human-readable identifier for logging.
    _id: &'static str,
    /// Accumulated feature vectors (analogous to SimHash hash_history).
    feature_history: Vec<Vec<f64>>,
    /// Center of this node's feature distribution.
    distribution_mean: Vec<f64>,
    /// Per-dimension standard deviations (anisotropic distribution).
    /// High values along signal dimensions, near-zero along noise dimensions.
    distribution_stds: Vec<f64>,
    /// Energy threshold for spectral filter construction.
    energy_threshold: f64,
    /// Lambda (coupling selectivity) for the spectral filter.
    lambda: f64,
    /// Deterministic RNG seeded per-node.
    rng: StdRng,
}

impl SpectralSimulationNode {
    /// Create a new spectral simulation node with anisotropic feature generation.
    ///
    /// `id`: human-readable name.
    /// `seed`: RNG seed for deterministic behavior.
    /// `distribution_mean`: center of feature generation distribution.
    /// `distribution_stds`: per-dimension standard deviations. Must match FEATURE_DIM.
    ///   Use large values for signal dimensions and near-zero for noise dimensions.
    /// `initial_samples`: number of initial feature vectors to seed history.
    /// `energy_threshold`: minimum energy fraction for spectral filter.
    /// `lambda`: coupling selectivity (0.0 = open, 1.0 = closed).
    fn new(
        id: &'static str,
        seed: u64,
        distribution_mean: Vec<f64>,
        distribution_stds: Vec<f64>,
        initial_samples: usize,
        energy_threshold: f64,
        lambda: f64,
    ) -> Self {
        assert_eq!(
            distribution_mean.len(),
            FEATURE_DIM,
            "distribution mean must match FEATURE_DIM"
        );
        assert_eq!(
            distribution_stds.len(),
            FEATURE_DIM,
            "distribution stds must match FEATURE_DIM"
        );
        let mut rng = StdRng::seed_from_u64(seed);
        let mut feature_history = Vec::new();

        // Seed initial history with samples from this node's anisotropic distribution.
        for _ in 0..initial_samples {
            let fv = generate_anisotropic_feature(&mut rng, &distribution_mean, &distribution_stds);
            feature_history.push(fv);
        }

        SpectralSimulationNode {
            _id: id,
            feature_history,
            distribution_mean,
            distribution_stds,
            energy_threshold,
            lambda,
            rng,
        }
    }

    /// Generate a new feature vector from this node's anisotropic distribution.
    fn generate_feature(&mut self) -> Vec<f64> {
        generate_anisotropic_feature(
            &mut self.rng,
            &self.distribution_mean,
            &self.distribution_stds,
        )
    }

    /// Build a SpectralFilter from this node's current feature history.
    /// Returns None if insufficient history.
    fn build_filter(&self) -> Option<SpectralFilter> {
        if self.feature_history.len() < MIN_HISTORY {
            return None;
        }
        let mut filter = SpectralFilter::from_history(&self.feature_history, self.energy_threshold);
        filter.set_lambda(self.lambda);
        Some(filter)
    }

    /// Number of feature vectors in history.
    fn history_size(&self) -> usize {
        self.feature_history.len()
    }

    /// Integrate a feature vector into this node's history (learning).
    fn integrate(&mut self, fv: Vec<f64>) {
        self.feature_history.push(fv);
    }
}

/// Generate a feature vector with per-dimension mean and standard deviation.
/// Each component: mean[i] + stds[i] * N(0,1).
/// This creates anisotropic distributions where covariance has structure.
fn generate_anisotropic_feature(rng: &mut StdRng, mean: &[f64], stds: &[f64]) -> Vec<f64> {
    let mut result = Vec::with_capacity(mean.len());
    for (&m, &s) in mean.iter().zip(stds.iter()) {
        let normal_sample = box_muller(rng);
        result.push(m + s * normal_sample);
    }
    result
}

/// Box-Muller transform: generate a standard normal sample from uniform samples.
fn box_muller(rng: &mut StdRng) -> f64 {
    let u1: f64 = rng.gen_range(0.0001f64..1.0);
    let u2: f64 = rng.gen_range(0.0f64..1.0);
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

/// Metrics collected during a spectral exchange round.
#[derive(Debug, Clone)]
struct RoundMetrics {
    /// Whether the receiver's filter passed the sender's feature vector.
    passed: bool,
    /// Coupling coefficient (energy fraction captured by projection).
    resonance: f64,
    /// Number of dimensions dropped by the filter.
    dropped_dimensions: usize,
}

/// Execute one round of spectral exchange: sender generates a feature vector,
/// receiver builds a SpectralFilter from their history and filters it.
/// If the vector passes, receiver integrates it.
/// Returns None if receiver has insufficient history for a filter.
fn spectral_exchange(
    sender: &mut SpectralSimulationNode,
    receiver: &mut SpectralSimulationNode,
) -> Option<RoundMetrics> {
    let feature_vec = sender.generate_feature();

    let filter = receiver.build_filter()?;

    let result = filter.filter(&feature_vec);

    let metrics = RoundMetrics {
        passed: result.passed,
        resonance: result.resonance,
        dropped_dimensions: result.dropped_components,
    };

    if result.passed {
        receiver.integrate(feature_vec);
    }

    Some(metrics)
}

/// Execute one bidirectional round of spectral exchange.
/// Returns (a_metrics, b_metrics) -- either may be None if the receiver
/// lacks sufficient history for filter construction.
fn spectral_bidirectional_step(
    node_a: &mut SpectralSimulationNode,
    node_b: &mut SpectralSimulationNode,
) -> (Option<RoundMetrics>, Option<RoundMetrics>) {
    // A sends to B (B filters)
    let b_metrics = spectral_exchange(node_a, node_b);

    // B sends to A (A filters)
    let a_metrics = spectral_exchange(node_b, node_a);

    (a_metrics, b_metrics)
}

/// Summary statistics for a simulation run.
#[derive(Debug)]
struct SimulationSummary {
    total_rounds: usize,
    passes: usize,
    mean_resonance: f64,
    mean_dropped: f64,
    /// Resonance trend: mean resonance in first half vs second half.
    early_resonance: f64,
    late_resonance: f64,
}

impl SimulationSummary {
    fn from_metrics(metrics: &[RoundMetrics]) -> Self {
        let total = metrics.len();
        if total == 0 {
            return SimulationSummary {
                total_rounds: 0,
                passes: 0,
                mean_resonance: 0.0,
                mean_dropped: 0.0,
                early_resonance: 0.0,
                late_resonance: 0.0,
            };
        }

        let passes = metrics.iter().filter(|m| m.passed).count();
        let mean_resonance = metrics.iter().map(|m| m.resonance).sum::<f64>() / total as f64;
        let mean_dropped = metrics
            .iter()
            .map(|m| m.dropped_dimensions as f64)
            .sum::<f64>()
            / total as f64;

        let midpoint = total / 2;
        let early_resonance = if midpoint > 0 {
            metrics[..midpoint].iter().map(|m| m.resonance).sum::<f64>() / midpoint as f64
        } else {
            0.0
        };
        let late_resonance = if total - midpoint > 0 {
            metrics[midpoint..].iter().map(|m| m.resonance).sum::<f64>() / (total - midpoint) as f64
        } else {
            0.0
        };

        SimulationSummary {
            total_rounds: total,
            passes,
            mean_resonance,
            mean_dropped,
            early_resonance,
            late_resonance,
        }
    }

    fn pass_rate(&self) -> f64 {
        if self.total_rounds == 0 {
            0.0
        } else {
            self.passes as f64 / self.total_rounds as f64
        }
    }
}

impl std::fmt::Display for SimulationSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rounds={}, passes={} ({:.1}%), mean_resonance={:.4}, \
             mean_dropped={:.1}, resonance_trend={:.4}->{:.4}",
            self.total_rounds,
            self.passes,
            self.pass_rate() * 100.0,
            self.mean_resonance,
            self.mean_dropped,
            self.early_resonance,
            self.late_resonance,
        )
    }
}

// ===========================================================================
// Test 1: Spectral coherence preservation
// ===========================================================================

/// Model a high-coherence node (rich feature history from an anisotropic
/// distribution concentrated along dims 0-1) interacting with a low-coherence
/// node (sparse history from an anisotropic distribution concentrated along
/// dims 4-5). Their covariance eigenspaces are orthogonal.
///
/// The high-coherence node has high variance along dims 0-1 and near-zero
/// variance elsewhere. Its principal components span the dim-0/dim-1 subspace.
/// The low-coherence node has high variance along dims 4-5.
///
/// Expected: The high-coherence node's filter rejects most incoming features
/// from the low-coherence node because their energy concentrates in dimensions
/// the high node's eigenspace does not span. The high node's feature space
/// is preserved.
#[test]
fn test_spectral_coherence_preservation() {
    let num_rounds = 200;

    // High-coherence node: anisotropic distribution concentrated along dims 0-1.
    // High variance (2.0) along dims 0-1, near-zero (0.01) elsewhere.
    let high_mean = vec![3.0, 2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
    let high_stds = vec![2.0, 1.5, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01];
    let mut node_high = SpectralSimulationNode::new(
        "spectral_high",
        42,
        high_mean,
        high_stds.clone(),
        50,   // rich history
        0.90, // high energy threshold => retains fewer components
        0.5,  // moderate lambda
    );

    // Low-coherence node: anisotropic distribution concentrated along dims 4-5.
    // Orthogonal eigenspace to the high node.
    let low_mean = vec![0.0, 0.0, 0.0, 0.0, 3.0, 2.0, 0.0, 0.0];
    let low_stds = vec![0.01, 0.01, 0.01, 0.01, 2.0, 1.5, 0.01, 0.01];
    let mut node_low = SpectralSimulationNode::new(
        "spectral_low",
        99,
        low_mean,
        low_stds.clone(),
        15,   // sparse history (but >= MIN_HISTORY)
        0.90, // same energy threshold
        0.5,  // same lambda
    );

    let initial_history_high = node_high.history_size();

    println!("=== Spectral Coherence Preservation ===");
    println!(
        "Initial: high(history={}, signal_dims=0-1), low(history={}, signal_dims=4-5)",
        initial_history_high,
        node_low.history_size()
    );

    let mut high_receiving_metrics: Vec<RoundMetrics> = Vec::new();
    let mut low_receiving_metrics: Vec<RoundMetrics> = Vec::new();

    for round in 0..num_rounds {
        let (a_metrics, b_metrics) = spectral_bidirectional_step(&mut node_high, &mut node_low);

        if let Some(m) = a_metrics {
            high_receiving_metrics.push(m);
        }
        if let Some(m) = b_metrics {
            low_receiving_metrics.push(m);
        }

        if (round + 1) % 50 == 0 {
            let high_summary = SimulationSummary::from_metrics(&high_receiving_metrics);
            let low_summary = SimulationSummary::from_metrics(&low_receiving_metrics);
            println!(
                "  Round {}: high_recv=[{}], low_recv=[{}]",
                round + 1,
                high_summary,
                low_summary
            );
        }
    }

    let high_summary = SimulationSummary::from_metrics(&high_receiving_metrics);
    let low_summary = SimulationSummary::from_metrics(&low_receiving_metrics);

    println!("Final high_recv: {}", high_summary);
    println!("Final low_recv: {}", low_summary);

    // ASSERTION 1: High-coherence node should reject most incoming features
    // from the low-coherence node (orthogonal eigenspaces).
    assert!(
        high_summary.pass_rate() < 0.5,
        "High-coherence node accepted too many features from orthogonal low-coherence \
         node: {:.1}% pass rate (expected <50%)",
        high_summary.pass_rate() * 100.0
    );

    // ASSERTION 2: The high node's history should not have grown excessively.
    let high_growth = node_high.history_size() - initial_history_high;
    let max_expected_growth = (num_rounds as f64 * 0.5) as usize;
    assert!(
        high_growth <= max_expected_growth,
        "High-coherence node's history grew by {} (max expected {}). \
         Feature space may be diluted.",
        high_growth,
        max_expected_growth
    );

    // ASSERTION 3: The high node's filter should still have strong
    // energy retention on its own features (self-coherence check).
    let self_filter = node_high
        .build_filter()
        .expect("should have enough history");
    let mut self_resonance_sum = 0.0;
    let self_samples = 20;
    let mut self_rng = StdRng::seed_from_u64(777);
    for _ in 0..self_samples {
        let fv =
            generate_anisotropic_feature(&mut self_rng, &node_high.distribution_mean, &high_stds);
        let result = self_filter.filter(&fv);
        self_resonance_sum += result.resonance;
    }
    let self_resonance = self_resonance_sum / self_samples as f64;
    println!(
        "High node self-resonance after interaction: {:.4}",
        self_resonance
    );

    // Self-resonance should remain high -- the node's own features should
    // still project well onto its own principal components.
    assert!(
        self_resonance > 0.3,
        "High-coherence node's self-resonance degraded to {:.4} -- \
         feature space was corrupted by interaction",
        self_resonance
    );

    // ASSERTION 4: Mean resonance at the high node should be notably lower
    // than self-resonance (orthogonal features couple poorly).
    assert!(
        high_summary.mean_resonance < self_resonance,
        "Incoming orthogonal features resonate as well as self-features: \
         incoming={:.4} vs self={:.4}",
        high_summary.mean_resonance,
        self_resonance
    );

    println!(
        "Coherence preservation confirmed: high node pass_rate={:.1}%, \
         self_resonance={:.4}, incoming_resonance={:.4}, history_growth={}",
        high_summary.pass_rate() * 100.0,
        self_resonance,
        high_summary.mean_resonance,
        high_growth
    );

    // Print low node summary for completeness.
    let _ = low_summary;
}

// ===========================================================================
// Test 2: Spectral convergence of compatible peers
// ===========================================================================

/// Model two nodes with overlapping feature distributions (shared principal
/// components). Both nodes have high variance along dims 0-1, creating
/// covariance matrices that share the same eigenspace. Their means differ
/// slightly, but the variance structure overlaps.
///
/// Expected: Both nodes' filter pass rates are high because their features
/// project well onto each other's principal components. History grows as they
/// integrate each other's features.
#[test]
fn test_spectral_convergence_compatible_peers() {
    let num_rounds = 200;

    // Node A: high variance along dims 0-1, slight mean offset.
    let mean_a = vec![2.0, 1.5, 0.5, 0.0, 0.0, 0.0, 0.0, 0.0];
    let stds_a = vec![2.0, 1.5, 0.3, 0.01, 0.01, 0.01, 0.01, 0.01];

    // Node B: high variance along dims 0-1 (SAME eigenspace), different mean.
    let mean_b = vec![1.5, 2.0, 0.3, 0.0, 0.0, 0.0, 0.0, 0.0];
    let stds_b = vec![1.8, 1.8, 0.3, 0.01, 0.01, 0.01, 0.01, 0.01];

    let mut node_a = SpectralSimulationNode::new(
        "compat_a", 100, mean_a, stds_a, 25,  // decent initial history
        0.8, // moderate energy threshold
        0.3, // lower lambda = more open
    );

    let mut node_b = SpectralSimulationNode::new("compat_b", 200, mean_b, stds_b, 25, 0.8, 0.3);

    let initial_history_a = node_a.history_size();
    let initial_history_b = node_b.history_size();

    println!("=== Spectral Convergence: Compatible Peers ===");
    println!(
        "Initial: A(history={}), B(history={})",
        initial_history_a, initial_history_b
    );

    let mut a_receiving_metrics: Vec<RoundMetrics> = Vec::new();
    let mut b_receiving_metrics: Vec<RoundMetrics> = Vec::new();

    for round in 0..num_rounds {
        let (a_metrics, b_metrics) = spectral_bidirectional_step(&mut node_a, &mut node_b);

        if let Some(m) = a_metrics {
            a_receiving_metrics.push(m);
        }
        if let Some(m) = b_metrics {
            b_receiving_metrics.push(m);
        }

        if (round + 1) % 50 == 0 {
            let a_summary = SimulationSummary::from_metrics(&a_receiving_metrics);
            let b_summary = SimulationSummary::from_metrics(&b_receiving_metrics);
            println!(
                "  Round {}: A=[pass_rate={:.1}%, resonance={:.4}], \
                 B=[pass_rate={:.1}%, resonance={:.4}], \
                 A_history={}, B_history={}",
                round + 1,
                a_summary.pass_rate() * 100.0,
                a_summary.mean_resonance,
                b_summary.pass_rate() * 100.0,
                b_summary.mean_resonance,
                node_a.history_size(),
                node_b.history_size(),
            );
        }
    }

    let a_summary = SimulationSummary::from_metrics(&a_receiving_metrics);
    let b_summary = SimulationSummary::from_metrics(&b_receiving_metrics);

    println!("Final A recv: {}", a_summary);
    println!("Final B recv: {}", b_summary);

    // ASSERTION 1: Both nodes should have received transfers.
    // Overlapping eigenspaces mean features project onto each other's basis.
    assert!(
        a_summary.passes > 0,
        "Node A received 0 transfers from compatible peer B"
    );
    assert!(
        b_summary.passes > 0,
        "Node B received 0 transfers from compatible peer A"
    );

    // ASSERTION 2: Pass rates should be meaningful (>20%).
    // Compatible peers with shared eigenspace should couple well.
    assert!(
        a_summary.pass_rate() > 0.2,
        "Node A pass rate too low for compatible peer: {:.1}% (expected >20%)",
        a_summary.pass_rate() * 100.0
    );
    assert!(
        b_summary.pass_rate() > 0.2,
        "Node B pass rate too low for compatible peer: {:.1}% (expected >20%)",
        b_summary.pass_rate() * 100.0
    );

    // ASSERTION 3: Both nodes' histories should have grown from mutual learning.
    let growth_a = node_a.history_size() - initial_history_a;
    let growth_b = node_b.history_size() - initial_history_b;
    assert!(
        growth_a > 0,
        "Node A history did not grow despite compatible interaction"
    );
    assert!(
        growth_b > 0,
        "Node B history did not grow despite compatible interaction"
    );

    // ASSERTION 4: Mean resonance should be decent for overlapping eigenspaces.
    assert!(
        a_summary.mean_resonance > 0.2,
        "Mean resonance at A too low: {:.4} (expected >0.2 for overlapping eigenspaces)",
        a_summary.mean_resonance
    );
    assert!(
        b_summary.mean_resonance > 0.2,
        "Mean resonance at B too low: {:.4} (expected >0.2 for overlapping eigenspaces)",
        b_summary.mean_resonance
    );

    // ASSERTION 5: Resonance should show stability or improvement over time.
    // As nodes integrate each other's features, their eigenspaces align further.
    assert!(
        a_summary.late_resonance >= a_summary.early_resonance * 0.7,
        "Node A resonance degraded over time: {:.4} -> {:.4}",
        a_summary.early_resonance,
        a_summary.late_resonance
    );
    assert!(
        b_summary.late_resonance >= b_summary.early_resonance * 0.7,
        "Node B resonance degraded over time: {:.4} -> {:.4}",
        b_summary.early_resonance,
        b_summary.late_resonance
    );

    println!(
        "Convergence confirmed: A growth={}, B growth={}, \
         A pass_rate={:.1}%, B pass_rate={:.1}%",
        growth_a,
        growth_b,
        a_summary.pass_rate() * 100.0,
        b_summary.pass_rate() * 100.0,
    );
    println!(
        "Resonance trends: A {:.4}->{:.4}, B {:.4}->{:.4}",
        a_summary.early_resonance,
        a_summary.late_resonance,
        b_summary.early_resonance,
        b_summary.late_resonance,
    );
}

// ===========================================================================
// Test 3: Spectral isolation of incompatible peers
// ===========================================================================

/// Model two nodes with orthogonal feature distributions. Node A has high
/// variance along dims 0-1 and near-zero elsewhere. Node B has high variance
/// along dims 4-5 and near-zero elsewhere. Their covariance eigenspaces are
/// completely disjoint.
///
/// Expected: Filter pass rates remain low because features from one node
/// project to near-zero energy in the other's eigenspace. The spectral filter
/// effectively isolates nodes with orthogonal coherence structures.
///
/// ## Key finding: anisotropic covariance is essential
///
/// With isotropic noise (same std in all dims), the covariance matrix is
/// approximately proportional to identity, making ALL dimensions principal
/// components. Orthogonality of means is irrelevant -- only orthogonality
/// of *variance structure* produces spectral isolation.
#[test]
fn test_spectral_isolation_incompatible_peers() {
    let num_rounds = 200;

    // Node A: high variance along dims 0-1, near-zero elsewhere.
    // Covariance eigenspace spans {e0, e1}.
    let mean_a = vec![3.0, 2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
    let stds_a = vec![2.0, 1.5, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01];
    let mut node_a = SpectralSimulationNode::new(
        "ortho_a", 300, mean_a, stds_a, 30,   // decent history
        0.90, // energy threshold
        0.5,  // moderate lambda
    );

    // Node B: high variance along dims 4-5, near-zero elsewhere.
    // Covariance eigenspace spans {e4, e5} -- orthogonal to A.
    let mean_b = vec![0.0, 0.0, 0.0, 0.0, 3.0, 2.0, 0.0, 0.0];
    let stds_b = vec![0.01, 0.01, 0.01, 0.01, 2.0, 1.5, 0.01, 0.01];
    let mut node_b = SpectralSimulationNode::new("ortho_b", 400, mean_b, stds_b, 30, 0.90, 0.5);

    let initial_history_a = node_a.history_size();
    let initial_history_b = node_b.history_size();

    println!("=== Spectral Isolation: Incompatible Peers ===");
    println!(
        "Initial: A(history={}, eigenspace={{e0,e1}}), B(history={}, eigenspace={{e4,e5}})",
        node_a.history_size(),
        node_b.history_size()
    );

    let mut a_receiving_metrics: Vec<RoundMetrics> = Vec::new();
    let mut b_receiving_metrics: Vec<RoundMetrics> = Vec::new();

    for round in 0..num_rounds {
        let (a_metrics, b_metrics) = spectral_bidirectional_step(&mut node_a, &mut node_b);

        if let Some(m) = a_metrics {
            a_receiving_metrics.push(m);
        }
        if let Some(m) = b_metrics {
            b_receiving_metrics.push(m);
        }

        if (round + 1) % 50 == 0 {
            let a_summary = SimulationSummary::from_metrics(&a_receiving_metrics);
            let b_summary = SimulationSummary::from_metrics(&b_receiving_metrics);
            println!(
                "  Round {}: A_recv=[pass_rate={:.1}%, resonance={:.4}, dropped={:.1}], \
                 B_recv=[pass_rate={:.1}%, resonance={:.4}, dropped={:.1}]",
                round + 1,
                a_summary.pass_rate() * 100.0,
                a_summary.mean_resonance,
                a_summary.mean_dropped,
                b_summary.pass_rate() * 100.0,
                b_summary.mean_resonance,
                b_summary.mean_dropped,
            );
        }
    }

    let a_summary = SimulationSummary::from_metrics(&a_receiving_metrics);
    let b_summary = SimulationSummary::from_metrics(&b_receiving_metrics);

    println!("Final A recv: {}", a_summary);
    println!("Final B recv: {}", b_summary);

    // ASSERTION 1: Pass rates should be very low for orthogonal eigenspaces.
    assert!(
        a_summary.pass_rate() < 0.3,
        "Node A pass rate too high for orthogonal peer: {:.1}% (expected <30%)",
        a_summary.pass_rate() * 100.0
    );
    assert!(
        b_summary.pass_rate() < 0.3,
        "Node B pass rate too high for orthogonal peer: {:.1}% (expected <30%)",
        b_summary.pass_rate() * 100.0
    );

    // ASSERTION 2: Mean resonance should be low (features don't project well
    // onto orthogonal eigenspace).
    assert!(
        a_summary.mean_resonance < 0.5,
        "Mean resonance at A too high for orthogonal features: {:.4} (expected <0.5)",
        a_summary.mean_resonance
    );
    assert!(
        b_summary.mean_resonance < 0.5,
        "Mean resonance at B too high for orthogonal features: {:.4} (expected <0.5)",
        b_summary.mean_resonance
    );

    // ASSERTION 3: History growth should be minimal.
    let growth_a = node_a.history_size() - initial_history_a;
    let growth_b = node_b.history_size() - initial_history_b;
    let max_growth = (num_rounds as f64 * 0.3) as usize;
    assert!(
        growth_a <= max_growth,
        "Node A history grew too much for orthogonal interaction: {} (max {})",
        growth_a,
        max_growth
    );
    assert!(
        growth_b <= max_growth,
        "Node B history grew too much for orthogonal interaction: {} (max {})",
        growth_b,
        max_growth
    );

    // ASSERTION 4: Confirm that each node's self-resonance remains high.
    let filter_a = node_a.build_filter().expect("A should have enough history");
    let filter_b = node_b.build_filter().expect("B should have enough history");

    let mut self_resonance_a = 0.0;
    let mut self_resonance_b = 0.0;
    let self_samples = 20;
    let mut rng_a = StdRng::seed_from_u64(888);
    let mut rng_b = StdRng::seed_from_u64(999);

    for _ in 0..self_samples {
        let fv_a = generate_anisotropic_feature(
            &mut rng_a,
            &node_a.distribution_mean,
            &node_a.distribution_stds,
        );
        let fv_b = generate_anisotropic_feature(
            &mut rng_b,
            &node_b.distribution_mean,
            &node_b.distribution_stds,
        );
        self_resonance_a += filter_a.filter(&fv_a).resonance;
        self_resonance_b += filter_b.filter(&fv_b).resonance;
    }
    self_resonance_a /= self_samples as f64;
    self_resonance_b /= self_samples as f64;

    println!(
        "Self-resonance after orthogonal interaction: A={:.4}, B={:.4}",
        self_resonance_a, self_resonance_b
    );

    assert!(
        self_resonance_a > 0.3,
        "Node A self-resonance degraded to {:.4} after orthogonal interaction",
        self_resonance_a
    );
    assert!(
        self_resonance_b > 0.3,
        "Node B self-resonance degraded to {:.4} after orthogonal interaction",
        self_resonance_b
    );

    // ASSERTION 5: Incompatible peers should have significantly lower resonance
    // than self-resonance, confirming spectral separation.
    assert!(
        a_summary.mean_resonance < self_resonance_a,
        "Orthogonal features should resonate less than self-features at A: \
         incoming={:.4} vs self={:.4}",
        a_summary.mean_resonance,
        self_resonance_a
    );
    assert!(
        b_summary.mean_resonance < self_resonance_b,
        "Orthogonal features should resonate less than self-features at B: \
         incoming={:.4} vs self={:.4}",
        b_summary.mean_resonance,
        self_resonance_b
    );

    println!(
        "Isolation confirmed: A pass_rate={:.1}%, B pass_rate={:.1}%, \
         A growth={}, B growth={}, \
         A self_res={:.4} vs incoming_res={:.4}, \
         B self_res={:.4} vs incoming_res={:.4}",
        a_summary.pass_rate() * 100.0,
        b_summary.pass_rate() * 100.0,
        growth_a,
        growth_b,
        self_resonance_a,
        a_summary.mean_resonance,
        self_resonance_b,
        b_summary.mean_resonance,
    );
}

// ===========================================================================
// Test 4: Comparative analysis -- SimHash vs Spectral
// ===========================================================================

/// Run both filtering approaches on equivalent scenarios and compare metrics.
/// This test is informational -- it prints comparative data but uses relaxed
/// assertions. Marked #[ignore] since it runs both simulation frameworks.
#[test]
#[ignore]
fn test_comparative_simhash_vs_spectral() {
    let num_rounds = 200;

    println!("=== Comparative Analysis: SimHash vs Spectral ===\n");

    // --- Scenario 1: Incompatible peers ---
    println!("--- Scenario: Incompatible Peers ---");

    // SimHash path: two nodes with disjoint hash bases.
    let cluster_threshold = 32;
    let mut sh_high = SimulationNodeSimHash::new("sh_high", 15, 2.0, 48, cluster_threshold);
    let mut sh_low = SimulationNodeSimHash::new("sh_low", 3, 8.0, 48, cluster_threshold);

    let mut sh_high_passes = 0u32;
    let mut sh_low_passes = 0u32;
    for round in 0..num_rounds {
        let (h_recv, l_recv) = simhash_bidirectional_step(&mut sh_high, &mut sh_low, round);
        if h_recv {
            sh_high_passes += 1;
        }
        if l_recv {
            sh_low_passes += 1;
        }
    }

    let sh_high_pass_rate = sh_high_passes as f64 / num_rounds as f64;
    let sh_low_pass_rate = sh_low_passes as f64 / num_rounds as f64;

    // Spectral path: two nodes with orthogonal anisotropic distributions.
    let mean_a = vec![3.0, 2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
    let stds_a = vec![2.0, 1.5, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01];
    let mean_b = vec![0.0, 0.0, 0.0, 0.0, 3.0, 2.0, 0.0, 0.0];
    let stds_b = vec![0.01, 0.01, 0.01, 0.01, 2.0, 1.5, 0.01, 0.01];
    let mut sp_a = SpectralSimulationNode::new("sp_a", 500, mean_a, stds_a, 30, 0.90, 0.5);
    let mut sp_b = SpectralSimulationNode::new("sp_b", 600, mean_b, stds_b, 30, 0.90, 0.5);

    let mut sp_a_metrics: Vec<RoundMetrics> = Vec::new();
    let mut sp_b_metrics: Vec<RoundMetrics> = Vec::new();
    for _ in 0..num_rounds {
        let (a_m, b_m) = spectral_bidirectional_step(&mut sp_a, &mut sp_b);
        if let Some(m) = a_m {
            sp_a_metrics.push(m);
        }
        if let Some(m) = b_m {
            sp_b_metrics.push(m);
        }
    }

    let sp_a_summary = SimulationSummary::from_metrics(&sp_a_metrics);
    let sp_b_summary = SimulationSummary::from_metrics(&sp_b_metrics);

    println!(
        "  SimHash: high_pass_rate={:.1}%, low_pass_rate={:.1}%",
        sh_high_pass_rate * 100.0,
        sh_low_pass_rate * 100.0
    );
    println!(
        "  Spectral: A_pass_rate={:.1}%, B_pass_rate={:.1}%",
        sp_a_summary.pass_rate() * 100.0,
        sp_b_summary.pass_rate() * 100.0
    );
    println!(
        "  Spectral mean resonance: A={:.4}, B={:.4}",
        sp_a_summary.mean_resonance, sp_b_summary.mean_resonance
    );

    // --- Scenario 2: Compatible peers ---
    println!("\n--- Scenario: Compatible Peers ---");

    // SimHash path: shared vocabulary.
    let mut sh_a = SimulationNodeSimHash::new("sh_compat_a", 8, 3.0, 48, cluster_threshold);
    let mut sh_b = SimulationNodeSimHash::new("sh_compat_b", 6, 3.0, 48, cluster_threshold);
    let vocab = generate_shared_vocabulary_for_comparison("shared_ctx", 20);
    sh_a.seed_shared_context(&vocab);
    sh_b.seed_shared_context(&vocab);

    let mut sh_a_passes = 0u32;
    let mut sh_b_passes = 0u32;
    for round in 0..num_rounds {
        let (a_recv, b_recv) =
            simhash_bidirectional_step_shared(&mut sh_a, &mut sh_b, round, &vocab);
        if a_recv {
            sh_a_passes += 1;
        }
        if b_recv {
            sh_b_passes += 1;
        }
    }

    let sh_a_pass_rate = sh_a_passes as f64 / num_rounds as f64;
    let sh_b_pass_rate = sh_b_passes as f64 / num_rounds as f64;

    // Spectral path: overlapping anisotropic distributions (shared eigenspace).
    let mean_ca = vec![2.0, 1.5, 0.5, 0.0, 0.0, 0.0, 0.0, 0.0];
    let stds_ca = vec![2.0, 1.5, 0.3, 0.01, 0.01, 0.01, 0.01, 0.01];
    let mean_cb = vec![1.5, 2.0, 0.3, 0.0, 0.0, 0.0, 0.0, 0.0];
    let stds_cb = vec![1.8, 1.8, 0.3, 0.01, 0.01, 0.01, 0.01, 0.01];
    let mut sp_ca = SpectralSimulationNode::new("sp_compat_a", 700, mean_ca, stds_ca, 25, 0.8, 0.3);
    let mut sp_cb = SpectralSimulationNode::new("sp_compat_b", 800, mean_cb, stds_cb, 25, 0.8, 0.3);

    let mut sp_ca_metrics: Vec<RoundMetrics> = Vec::new();
    let mut sp_cb_metrics: Vec<RoundMetrics> = Vec::new();
    for _ in 0..num_rounds {
        let (a_m, b_m) = spectral_bidirectional_step(&mut sp_ca, &mut sp_cb);
        if let Some(m) = a_m {
            sp_ca_metrics.push(m);
        }
        if let Some(m) = b_m {
            sp_cb_metrics.push(m);
        }
    }

    let sp_ca_summary = SimulationSummary::from_metrics(&sp_ca_metrics);
    let sp_cb_summary = SimulationSummary::from_metrics(&sp_cb_metrics);

    println!(
        "  SimHash: A_pass_rate={:.1}%, B_pass_rate={:.1}%",
        sh_a_pass_rate * 100.0,
        sh_b_pass_rate * 100.0
    );
    println!(
        "  Spectral: A_pass_rate={:.1}%, B_pass_rate={:.1}%",
        sp_ca_summary.pass_rate() * 100.0,
        sp_cb_summary.pass_rate() * 100.0
    );
    println!(
        "  Spectral mean resonance: A={:.4}, B={:.4}",
        sp_ca_summary.mean_resonance, sp_cb_summary.mean_resonance
    );
    println!(
        "  Spectral resonance trends: A {:.4}->{:.4}, B {:.4}->{:.4}",
        sp_ca_summary.early_resonance,
        sp_ca_summary.late_resonance,
        sp_cb_summary.early_resonance,
        sp_cb_summary.late_resonance
    );

    println!("\n=== Summary ===");
    println!(
        "  Incompatible isolation: SimHash {:.1}% / Spectral {:.1}% pass rate",
        (sh_high_pass_rate + sh_low_pass_rate) / 2.0 * 100.0,
        (sp_a_summary.pass_rate() + sp_b_summary.pass_rate()) / 2.0 * 100.0
    );
    println!(
        "  Compatible coupling: SimHash {:.1}% / Spectral {:.1}% pass rate",
        (sh_a_pass_rate + sh_b_pass_rate) / 2.0 * 100.0,
        (sp_ca_summary.pass_rate() + sp_cb_summary.pass_rate()) / 2.0 * 100.0
    );

    // Relaxed assertion: both methods should isolate incompatible peers.
    let sh_incompat_avg = (sh_high_pass_rate + sh_low_pass_rate) / 2.0;
    let sp_incompat_avg = (sp_a_summary.pass_rate() + sp_b_summary.pass_rate()) / 2.0;
    assert!(
        sh_incompat_avg < 0.5,
        "SimHash failed to isolate incompatible peers: {:.1}%",
        sh_incompat_avg * 100.0
    );
    assert!(
        sp_incompat_avg < 0.5,
        "Spectral failed to isolate incompatible peers: {:.1}%",
        sp_incompat_avg * 100.0
    );
}

// ===========================================================================
// SimHash simulation helpers for comparison test
// ===========================================================================

/// Minimal SimHash simulation node for the comparison test.
/// Mirrors the structure from coherence_evolution_tests.rs.
struct SimulationNodeSimHash {
    id: &'static str,
    hash_history: Vec<SimHash>,
    tx_depth_history: Vec<u64>,
    membrane: Membrane,
    current_depth: u64,
    cluster_threshold: u32,
    base_temporality: f64,
}

/// A pre-computed payload with its SimHash (for shared context scenarios).
#[derive(Clone)]
struct KnownPayload {
    bytes: Vec<u8>,
    simhash: SimHash,
}

impl SimulationNodeSimHash {
    fn new(
        id: &'static str,
        initial_level: u32,
        temporality: f64,
        basis_threshold: u32,
        cluster_threshold: u32,
    ) -> Self {
        use disentangle_membrane::{CoherenceBasis, CoherenceLevel, TemporalSignature};

        let mut hash_history: Vec<SimHash> = Vec::new();
        let mut basis_sigs: Vec<SimHash> = Vec::new();

        for i in 0..initial_level {
            let centroid = SimHash(
                (i as u128)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C835)
                    .wrapping_add(0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210),
            );
            hash_history.push(centroid);
            basis_sigs.push(centroid);
        }

        if basis_sigs.is_empty() {
            let seed = SimHash(0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0);
            basis_sigs.push(seed);
            hash_history.push(seed);
        }

        let mut tx_depth_history: Vec<u64> = Vec::new();
        let depth_gap = temporality.max(1.0) as u64;
        for i in 0..initial_level.max(2) {
            tx_depth_history.push(i as u64 * depth_gap);
        }

        let current_depth = tx_depth_history.last().copied().unwrap_or(0);

        let lt = LevelTemporality {
            level: CoherenceLevel::from_history(&hash_history, cluster_threshold),
            temporality: TemporalSignature::from_depths(&tx_depth_history),
        };

        let basis = CoherenceBasis {
            signatures: basis_sigs,
            threshold: basis_threshold,
        };

        let membrane = Membrane::new(lt, basis);

        SimulationNodeSimHash {
            id,
            hash_history,
            tx_depth_history,
            membrane,
            current_depth,
            cluster_threshold,
            base_temporality: temporality,
        }
    }

    fn seed_shared_context(&mut self, vocab: &[KnownPayload]) {
        for kp in vocab {
            self.membrane.filter_mut().extend_basis(kp.simhash);
            self.hash_history.push(kp.simhash);
        }
    }

    fn recompute_lt(&self) -> LevelTemporality {
        use disentangle_membrane::{CoherenceLevel, TemporalSignature};
        LevelTemporality {
            level: CoherenceLevel::from_history(&self.hash_history, self.cluster_threshold),
            temporality: TemporalSignature::from_depths(&self.tx_depth_history),
        }
    }

    fn generate_payload(&self, round: usize) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(self.id.as_bytes());
        input.extend_from_slice(&(round as u64).to_le_bytes());
        disentangle_crypto::sha3_256(&input).to_vec()
    }

    fn receive(&mut self, payload: &[u8]) -> bool {
        use disentangle_membrane::simhash_from_bytes;
        let result = self.membrane.transfer(payload);
        let passed = result.filter_result.passed;

        if passed {
            let received_hash = simhash_from_bytes(payload);
            self.hash_history.push(received_hash);
            self.membrane.filter_mut().extend_basis(received_hash);
            self.current_depth += self.base_temporality.max(1.0) as u64;
            self.tx_depth_history.push(self.current_depth);
        }

        passed
    }
}

fn simhash_bidirectional_step(
    node_a: &mut SimulationNodeSimHash,
    node_b: &mut SimulationNodeSimHash,
    round: usize,
) -> (bool, bool) {
    let payload_a_to_b = node_a.generate_payload(round);
    let payload_b_to_a = node_b.generate_payload(round);

    let lt_a = node_a.recompute_lt();
    let lt_b = node_b.recompute_lt();
    node_a.membrane.set_peer(lt_b);
    node_b.membrane.set_peer(lt_a);

    let b_received = node_b.receive(&payload_a_to_b);
    let a_received = node_a.receive(&payload_b_to_a);

    (a_received, b_received)
}

fn simhash_bidirectional_step_shared(
    node_a: &mut SimulationNodeSimHash,
    node_b: &mut SimulationNodeSimHash,
    round: usize,
    vocab: &[KnownPayload],
) -> (bool, bool) {
    let a_idx = round % vocab.len();
    let b_idx = (round + vocab.len() / 2) % vocab.len();

    let payload_a_to_b = vocab[a_idx].bytes.clone();
    let payload_b_to_a = vocab[b_idx].bytes.clone();

    let lt_a = node_a.recompute_lt();
    let lt_b = node_b.recompute_lt();
    node_a.membrane.set_peer(lt_b);
    node_b.membrane.set_peer(lt_a);

    let b_received = node_b.receive(&payload_a_to_b);
    let a_received = node_a.receive(&payload_b_to_a);

    (a_received, b_received)
}

fn generate_shared_vocabulary_for_comparison(prefix: &str, count: usize) -> Vec<KnownPayload> {
    use disentangle_membrane::simhash_from_bytes;
    (0..count)
        .map(|i| {
            let mut input = Vec::new();
            input.extend_from_slice(prefix.as_bytes());
            input.extend_from_slice(&(i as u64).to_le_bytes());
            let bytes = disentangle_crypto::sha3_256(&input).to_vec();
            let simhash = simhash_from_bytes(&bytes);
            KnownPayload { bytes, simhash }
        })
        .collect()
}
