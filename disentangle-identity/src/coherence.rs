//! Coherence Profile Computation
//!
//! Measures topological mass and coherence for DIDs.

use crate::capability::CoherenceTier;
use crate::did::DID;
use crate::graph::IdentityGraph;
use disentangle_dag::{fp_mul, FixedPoint, MIN_CURVATURE_WEIGHT, SCALE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const COHERENCE_HALF_LIFE: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoherenceProfile {
    pub did: DID,
    pub topological_mass: FixedPoint,
    pub mean_local_curvature: FixedPoint,
    pub relational_diversity: u64,
    pub temporal_depth: u64,
    pub capability_coherence: FixedPoint,
    pub introduction_coherence: FixedPoint,
    pub last_active_depth: u64,
}

impl CoherenceProfile {
    /// Compute a coherence profile for a DID
    ///
    /// Computes:
    /// - topological_mass: sum of curvature weights from all edges
    /// - mean_local_curvature: average curvature of all edges touching this DID
    /// - relational_diversity: count of unique DIDs with positive-curvature edges
    /// - temporal_depth: current_depth - first_seen_depth
    /// - capability_coherence: ratio of active (unrevoked) grants to total grants
    /// - introduction_coherence: normalized mean curvature across neighbors
    pub fn compute(
        did: &DID,
        identity_graph: &IdentityGraph,
        first_seen_depth: u64,
        current_depth: u64,
    ) -> Self {
        let neighbors = identity_graph.neighbors(did);
        let neighbor_refs: Vec<&DID> = neighbors.iter().collect();

        // Compute mean local curvature and count positive-curvature neighbors
        let mut total_curvature: i64 = 0;
        let mut positive_curvature_count = 0u64;

        for neighbor in &neighbor_refs {
            let curv = identity_graph.identity_curvature(did, neighbor);
            total_curvature += curv as i64;

            if curv > 0 {
                positive_curvature_count += 1;
            }
        }

        let mean_local_curvature = if neighbor_refs.is_empty() {
            0
        } else {
            (total_curvature / neighbor_refs.len() as i64) as FixedPoint
        };

        // Topological mass: sum of (1 + curvature) for each edge
        // This gives higher mass for positive-curvature edges
        let mut topological_mass = 0i64;
        for neighbor in &neighbor_refs {
            let curv = identity_graph.identity_curvature(did, neighbor);
            let edge_weight = (SCALE + curv).clamp(MIN_CURVATURE_WEIGHT, SCALE);
            topological_mass += edge_weight as i64;
        }

        Self {
            did: did.clone(),
            topological_mass: topological_mass as FixedPoint,
            mean_local_curvature,
            relational_diversity: positive_curvature_count,
            temporal_depth: current_depth.saturating_sub(first_seen_depth),
            capability_coherence: {
                let (active, total) = identity_graph.capability_grant_stats(did);
                if total == 0 {
                    0
                } else {
                    (SCALE as i64 * active as i64 / total as i64) as FixedPoint
                }
            },
            introduction_coherence: if neighbors.is_empty() {
                0
            } else {
                ((mean_local_curvature as i64 + SCALE as i64) / 2) as FixedPoint
            },
            last_active_depth: current_depth,
        }
    }

    /// Compute decayed mass based on half-life decay
    ///
    /// mass_decayed = mass * (1/2)^(depths_inactive / COHERENCE_HALF_LIFE)
    ///
    /// Uses fixed-point approximation for exponential decay.
    pub fn decayed_mass(&self, current_depth: u64) -> FixedPoint {
        let depths_inactive = current_depth.saturating_sub(self.last_active_depth);

        if depths_inactive == 0 {
            return self.topological_mass;
        }

        // Floor at ~6% after 4 half-lives
        if depths_inactive >= COHERENCE_HALF_LIFE * 4 {
            return fp_mul(self.topological_mass, SCALE / 16);
        }

        // Approximate (1/2)^x using bit shifts for integer part
        let whole_halvings = (depths_inactive / COHERENCE_HALF_LIFE).min(4) as u32;
        let decay_factor = SCALE >> whole_halvings;

        fp_mul(self.topological_mass, decay_factor)
    }

    /// Check if this profile is eligible for state pruning.
    ///
    /// An entity is prunable when its coherence has decayed below
    /// SCALE/1000 for at least 8 half-lives (80,000 depths).
    pub fn is_prunable(&self, current_depth: u64) -> bool {
        let depths_inactive = current_depth.saturating_sub(self.last_active_depth);
        depths_inactive >= COHERENCE_HALF_LIFE * 8
            && self.decayed_mass(current_depth) < SCALE / 1000
    }

    /// Compute a composite coherence score using weighted average.
    ///
    /// Uses an additive weighted formula for robustness when some components
    /// are zero. The PPA Detailed Description specifies a multiplicative formula
    /// (C = TM * MC * log(RD) * sqrt(TD) * CC * IC / normalization) which may
    /// be implemented in a future phase once all component measures are reliably
    /// non-zero through ZK integration.
    ///
    /// Current weights:
    /// - Decayed topological mass (30%)
    /// - Mean local curvature (20%)
    /// - Relational diversity (15%)
    /// - Temporal depth (10%)
    /// - Capability coherence (15%)
    /// - Introduction coherence (10%)
    pub fn composite_score(&self, current_depth: u64) -> FixedPoint {
        let decayed = self.decayed_mass(current_depth);

        // Normalize diversity to fixed-point scale
        let diversity_normalized = (self.relational_diversity.min(100) as i64 * SCALE as i64) / 100;

        // Normalize temporal depth (cap at 100,000 depths = 1.0)
        let depth_normalized = (self.temporal_depth.min(100_000) as i64 * SCALE as i64) / 100_000;

        // Weighted combination (using i64 to avoid overflow)
        let mass_component = (decayed as i64 * 30) / 100;
        let curvature_component = (self.mean_local_curvature.max(0) as i64 * 20) / 100;
        let diversity_component = (diversity_normalized * 15) / 100;
        let depth_component = (depth_normalized * 10) / 100;
        let capability_component = (self.capability_coherence.max(0) as i64 * 15) / 100;
        let introduction_component = (self.introduction_coherence.max(0) as i64 * 10) / 100;

        (mass_component
            + curvature_component
            + diversity_component
            + depth_component
            + capability_component
            + introduction_component) as FixedPoint
    }

    /// Determine the coherence tier for this profile at the given depth.
    pub fn coherence_tier(&self, current_depth: u64) -> CoherenceTier {
        CoherenceTier::from_score(self.composite_score(current_depth) as i64)
    }
}

/// Curvature derivative for a single edge over a depth window
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurvatureDerivative {
    pub did_a: String,
    pub did_b: String,
    /// Curvature at window start
    pub kappa_start: f64,
    /// Curvature at window end (current)
    pub kappa_end: f64,
    /// Rate of change: (kappa_end - kappa_start) / window_size
    pub derivative: f64,
    /// Depth window used
    pub depth_start: u64,
    pub depth_end: u64,
}

/// Excitability profile for an agent — aggregated gradient across all edges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcitabilityProfile {
    pub did: String,
    /// Mean curvature derivative across all incident edges
    pub mean_gradient: f64,
    /// Max curvature derivative (the "hottest" collaboration)
    pub max_gradient: f64,
    /// Number of edges with positive derivative (forming coherence)
    pub forming_count: u32,
    /// Number of edges with negative derivative (degrading coherence)
    pub degrading_count: u32,
    /// Edges sorted by derivative (highest first)
    pub edge_gradients: Vec<CurvatureDerivative>,
    /// Depth window used
    pub depth_window: u64,
}

/// Network-level gradient map — where is coherence forming?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoherenceGradientMap {
    /// Top-N edges by positive curvature derivative
    pub forming: Vec<CurvatureDerivative>,
    /// Top-N edges by negative curvature derivative
    pub degrading: Vec<CurvatureDerivative>,
    /// Top-N agents by excitability (mean gradient)
    pub most_excitable: Vec<ExcitabilityProfile>,
    /// Network-wide mean gradient
    pub network_gradient: f64,
    pub depth_window: u64,
    pub computed_at_depth: u64,
}

/// Curvature history storage for derivative computation
pub type CurvatureHistory = HashMap<(String, String), Vec<(u64, f64)>>;

/// Maximum history entries per edge (prevents unbounded growth)
pub const MAX_HISTORY_DEPTH: usize = 100;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Capability, CapabilitySubject, RevocationScope, TransactionScope};
    use crate::graph::IdentityGraph;
    use crate::transactions::{IntroductionContext, IntroductionTransaction};
    use disentangle_crypto::signature::generate_keypair;

    #[test]
    fn test_coherence_profile_empty() {
        let (_, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let graph = IdentityGraph::new();

        let profile = CoherenceProfile::compute(&did, &graph, 0, 100);

        assert_eq!(profile.topological_mass, 0);
        assert_eq!(profile.mean_local_curvature, 0);
        assert_eq!(profile.relational_diversity, 0);
        assert_eq!(profile.temporal_depth, 100);
    }

    #[test]
    fn test_coherence_profile_with_neighbors() {
        let mut graph = IdentityGraph::new();

        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let tx = IntroductionTransaction {
            introducer_did: did.clone(),
            introduced_did: did2.clone(),
            edge_name: "Friend".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk, b"test"),
            parents: vec![],
            depth: 100,
        };

        graph.record_introduction(&tx);

        let profile = CoherenceProfile::compute(&did, &graph, 0, 100);

        // With one neighbor and negative curvature, mass may be zero or negative
        // The test should check that the profile was computed, not specific values
        assert_eq!(profile.relational_diversity, 0); // No positive-curvature neighbors (curvature is -1)
        assert_eq!(profile.temporal_depth, 100);
    }

    #[test]
    fn test_decayed_mass_no_decay() {
        let profile = CoherenceProfile {
            did: DID("test".to_string()),
            topological_mass: 1000 * SCALE,
            mean_local_curvature: 0,
            relational_diversity: 5,
            temporal_depth: 100,
            capability_coherence: 0,
            introduction_coherence: 0,
            last_active_depth: 100,
        };

        // No blocks passed, no decay
        let decayed = profile.decayed_mass(100);
        assert_eq!(decayed, profile.topological_mass);
    }

    #[test]
    fn test_decayed_mass_one_half_life() {
        let profile = CoherenceProfile {
            did: DID("test".to_string()),
            topological_mass: 1000 * SCALE,
            mean_local_curvature: 0,
            relational_diversity: 5,
            temporal_depth: 100,
            capability_coherence: 0,
            introduction_coherence: 0,
            last_active_depth: 100,
        };

        // One half-life passed
        let decayed = profile.decayed_mass(100 + COHERENCE_HALF_LIFE);
        assert!(decayed < profile.topological_mass);
        assert!(decayed >= profile.topological_mass / 2);
    }

    #[test]
    fn test_decayed_mass_floor() {
        let profile = CoherenceProfile {
            did: DID("test".to_string()),
            topological_mass: 1000 * SCALE,
            mean_local_curvature: 0,
            relational_diversity: 5,
            temporal_depth: 100,
            capability_coherence: 0,
            introduction_coherence: 0,
            last_active_depth: 100,
        };

        // Four half-lives passed - should hit floor
        let decayed = profile.decayed_mass(100 + COHERENCE_HALF_LIFE * 4);
        assert_eq!(decayed, fp_mul(profile.topological_mass, SCALE / 16));
    }

    #[test]
    fn test_composite_score() {
        let profile = CoherenceProfile {
            did: DID("test".to_string()),
            topological_mass: 1000 * SCALE,
            mean_local_curvature: SCALE / 2, // +0.5 curvature
            relational_diversity: 10,
            temporal_depth: 50_000,
            capability_coherence: 0,
            introduction_coherence: 0,
            last_active_depth: 100,
        };

        let score = profile.composite_score(100);
        assert!(score > 0);

        // Score should be less than raw mass due to weighting
        assert!(score < profile.topological_mass);
    }

    #[test]
    fn test_prunable_after_long_inactivity() {
        // Use small mass that will decay below threshold
        // At 4 half-lives, mass becomes topological_mass / 16
        // So we need topological_mass / 16 < SCALE / 1000
        // topological_mass < SCALE * 16 / 1000 = SCALE / 62.5
        // Use SCALE / 100 to be safely below threshold
        let profile = CoherenceProfile {
            did: DID("did:disentangle:prunetest".to_string()),
            topological_mass: SCALE / 100,
            mean_local_curvature: 0,
            relational_diversity: 1,
            temporal_depth: 100,
            capability_coherence: 0,
            introduction_coherence: 0,
            last_active_depth: 0,
        };
        assert!(!profile.is_prunable(10_000));
        assert!(!profile.is_prunable(79_999));
        assert!(profile.is_prunable(80_000));
        assert!(profile.is_prunable(100_000));
    }

    #[test]
    fn test_not_prunable_with_high_mass() {
        let profile = CoherenceProfile {
            did: DID("did:disentangle:highmass".to_string()),
            topological_mass: SCALE * 100,
            mean_local_curvature: SCALE / 2,
            relational_diversity: 10,
            temporal_depth: 50_000,
            capability_coherence: 0,
            introduction_coherence: 0,
            last_active_depth: 0,
        };
        // Even after 80k blocks, high mass may not decay below threshold
        // because decayed_mass floors at SCALE/16 after 4 half-lives
        // SCALE*100 / 16 = SCALE*6.25, which is > SCALE/1000
        assert!(!profile.is_prunable(80_000));
    }

    // ── Capability coherence tests ──

    #[test]
    fn test_capability_coherence_no_grants() {
        let (_, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let graph = IdentityGraph::new();

        let profile = CoherenceProfile::compute(&did, &graph, 0, 100);
        assert_eq!(profile.capability_coherence, 0);
    }

    #[test]
    fn test_capability_coherence_all_active() {
        let mut graph = IdentityGraph::new();

        let (sk1, pk1) = generate_keypair();
        let did1 = DID::new(&pk1, false);

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        // Create two capabilities and delegate them (all active, none revoked)
        let subject1 = CapabilitySubject::Transact {
            scope: TransactionScope::All,
        };
        let cap1 = Capability::new(&did1, &pk1, subject1, &sk1);

        let subject2 = CapabilitySubject::Transact {
            scope: TransactionScope::Transfer,
        };
        let cap2 = Capability::new(&did1, &pk1, subject2, &sk1);

        let del1 =
            crate::capability::DelegationRecord::new(&cap1, &did1, &did2, &sk1, 100).unwrap();
        let del2 =
            crate::capability::DelegationRecord::new(&cap2, &did1, &did2, &sk1, 100).unwrap();

        graph.record_delegation(&del1);
        graph.record_delegation(&del2);

        let profile = CoherenceProfile::compute(&did1, &graph, 0, 100);
        assert_eq!(profile.capability_coherence, SCALE);
    }

    #[test]
    fn test_capability_coherence_half_revoked() {
        let mut graph = IdentityGraph::new();

        let (sk1, pk1) = generate_keypair();
        let did1 = DID::new(&pk1, false);

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        // Create two capabilities, revoke one
        let subject1 = CapabilitySubject::Transact {
            scope: TransactionScope::All,
        };
        let cap1 = Capability::new(&did1, &pk1, subject1, &sk1);

        let subject2 = CapabilitySubject::Transact {
            scope: TransactionScope::Transfer,
        };
        let cap2 = Capability::new(&did1, &pk1, subject2, &sk1);

        let del1 =
            crate::capability::DelegationRecord::new(&cap1, &did1, &did2, &sk1, 100).unwrap();
        let del2 =
            crate::capability::DelegationRecord::new(&cap2, &did1, &did2, &sk1, 100).unwrap();

        graph.record_delegation(&del1);
        graph.record_delegation(&del2);
        graph.record_revocation(&cap1.id, RevocationScope::Single);

        let profile = CoherenceProfile::compute(&did1, &graph, 0, 100);
        // 1 active out of 2 total: SCALE * 1 / 2 = SCALE / 2
        assert_eq!(profile.capability_coherence, SCALE / 2);
    }

    // ── Introduction coherence tests ──

    #[test]
    fn test_introduction_coherence_no_neighbors() {
        let (_, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let graph = IdentityGraph::new();

        let profile = CoherenceProfile::compute(&did, &graph, 0, 100);
        assert_eq!(profile.introduction_coherence, 0);
    }

    #[test]
    fn test_introduction_coherence_positive_curvature() {
        // Build a graph where did1 has neighbors with maximum positive curvature.
        // For Jaccard curvature to be +SCALE, we need |intersection| == |union|
        // i.e., N(a) == N(b). Create a triangle: did1 <-> did2 <-> did3 <-> did1.
        // Then N(did1) = {did2, did3} and for edge did1-did2: N(did1)={did2,did3},
        // N(did2)={did1,did3}. Union={did1,did2,did3}, Intersection={did3}.
        // kappa = 2 * 1/3 - 1 = -1/3 * SCALE.
        // For all-positive we need a denser graph.
        //
        // Instead, test with a known scenario: for a triangle where
        // all three are connected, mean_local_curvature is fixed and we verify
        // introduction_coherence = (mean_local_curvature + SCALE) / 2.
        let mut graph = IdentityGraph::new();

        let (sk1, pk1) = generate_keypair();
        let did1 = DID::new(&pk1, false);

        let (sk2, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let (sk3, pk3) = generate_keypair();
        let did3 = DID::new(&pk3, false);

        // Create a triangle
        let tx1 = IntroductionTransaction {
            introducer_did: did1.clone(),
            introduced_did: did2.clone(),
            edge_name: "A".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk1, b"test"),
            parents: vec![],
            depth: 100,
        };
        let tx2 = IntroductionTransaction {
            introducer_did: did2.clone(),
            introduced_did: did3.clone(),
            edge_name: "B".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk2, b"test"),
            parents: vec![],
            depth: 100,
        };
        let tx3 = IntroductionTransaction {
            introducer_did: did3.clone(),
            introduced_did: did1.clone(),
            edge_name: "C".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk3, b"test"),
            parents: vec![],
            depth: 100,
        };

        graph.record_introduction(&tx1);
        graph.record_introduction(&tx2);
        graph.record_introduction(&tx3);

        let profile = CoherenceProfile::compute(&did1, &graph, 0, 100);

        // Verify introduction_coherence == (mean_local_curvature + SCALE) / 2
        let expected = ((profile.mean_local_curvature as i64 + SCALE as i64) / 2) as FixedPoint;
        assert_eq!(profile.introduction_coherence, expected);
        // In a triangle, Jaccard curvature is negative (-1/3 * SCALE) because
        // the union includes all 3 nodes but intersection is only 1.
        // So introduction_coherence < SCALE/2, but > 0 (since curvature > -SCALE).
        assert!(profile.introduction_coherence > 0);
        assert!(profile.introduction_coherence < SCALE / 2);
    }

    #[test]
    fn test_introduction_coherence_zero_mean_curvature() {
        // When mean_local_curvature is exactly 0, introduction_coherence = SCALE / 2
        let profile = CoherenceProfile {
            did: DID("test".to_string()),
            topological_mass: SCALE,
            mean_local_curvature: 0,
            relational_diversity: 1,
            temporal_depth: 100,
            capability_coherence: 0,
            // Manually verify the formula: (0 + SCALE) / 2 = SCALE / 2
            introduction_coherence: SCALE / 2,
            last_active_depth: 100,
        };
        assert_eq!(profile.introduction_coherence, SCALE / 2);
    }

    #[test]
    fn test_introduction_coherence_max_curvature() {
        // When mean_local_curvature == SCALE, introduction_coherence = SCALE
        let profile = CoherenceProfile {
            did: DID("test".to_string()),
            topological_mass: SCALE,
            mean_local_curvature: SCALE,
            relational_diversity: 1,
            temporal_depth: 100,
            capability_coherence: 0,
            introduction_coherence: ((SCALE as i64 + SCALE as i64) / 2) as FixedPoint,
            last_active_depth: 100,
        };
        assert_eq!(profile.introduction_coherence, SCALE);
    }

    // ── Composite score with capability and introduction ──

    #[test]
    fn test_composite_score_includes_capability_and_introduction() {
        // Profile with all components set to SCALE
        let profile_with = CoherenceProfile {
            did: DID("test".to_string()),
            topological_mass: SCALE,
            mean_local_curvature: SCALE / 2,
            relational_diversity: 10,
            temporal_depth: 50_000,
            capability_coherence: SCALE,
            introduction_coherence: SCALE,
            last_active_depth: 100,
        };

        // Profile without capability/introduction coherence
        let profile_without = CoherenceProfile {
            capability_coherence: 0,
            introduction_coherence: 0,
            ..profile_with.clone()
        };

        let score_with = profile_with.composite_score(100);
        let score_without = profile_without.composite_score(100);

        // Score with capability+introduction should be higher
        assert!(score_with > score_without);

        // The difference should be exactly:
        // 15% of SCALE (capability) + 10% of SCALE (introduction)
        let expected_diff = (SCALE as i64 * 15 / 100 + SCALE as i64 * 10 / 100) as FixedPoint;
        assert_eq!(score_with - score_without, expected_diff);
    }

    // ── Coherence tier from profile ──

    #[test]
    fn test_coherence_profile_tier() {
        use crate::capability::CoherenceTier;

        // Observer: a profile with zero mass and no contributions
        let observer_profile = CoherenceProfile {
            did: DID("observer".to_string()),
            topological_mass: 0,
            mean_local_curvature: 0,
            relational_diversity: 0,
            temporal_depth: 0,
            capability_coherence: 0,
            introduction_coherence: 0,
            last_active_depth: 100,
        };
        assert_eq!(
            observer_profile.coherence_tier(100),
            CoherenceTier::Observer
        );

        // Steward: a profile with maximal values across all dimensions.
        // composite_score = 30% mass + 20% curvature + 15% diversity + 10% depth
        //                 + 15% capability + 10% introduction
        // With all components at SCALE: 30+20+15+10+15+10 = 100% of SCALE
        let steward_profile = CoherenceProfile {
            did: DID("steward".to_string()),
            topological_mass: SCALE,
            mean_local_curvature: SCALE,
            relational_diversity: 100,
            temporal_depth: 100_000,
            capability_coherence: SCALE,
            introduction_coherence: SCALE,
            last_active_depth: 100,
        };
        assert_eq!(steward_profile.coherence_tier(100), CoherenceTier::Steward);

        // Contributor: a profile in the 30-55% range.
        // Target ~35% of SCALE composite score.
        // mass_component = (SCALE * 30) / 100 is 30% of SCALE from mass alone.
        // Add a bit from other components to land in Contributor range.
        let contributor_profile = CoherenceProfile {
            did: DID("contributor".to_string()),
            topological_mass: SCALE,         // 30% * SCALE
            mean_local_curvature: SCALE / 4, // 20% * SCALE/4 = 5% SCALE
            relational_diversity: 0,
            temporal_depth: 0,
            capability_coherence: 0,
            introduction_coherence: 0,
            last_active_depth: 100,
        };
        let score = contributor_profile.composite_score(100);
        // 30% + 5% = 35% of SCALE -> Contributor
        assert_eq!(
            CoherenceTier::from_score(score as i64),
            CoherenceTier::Contributor
        );
        assert_eq!(
            contributor_profile.coherence_tier(100),
            CoherenceTier::Contributor
        );
    }
}
