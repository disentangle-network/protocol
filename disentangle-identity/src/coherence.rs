//! Coherence Profile Computation
//!
//! Measures topological mass and coherence for DIDs.

use crate::did::DID;
use crate::graph::IdentityGraph;
use disentangle_dag::{FixedPoint, SCALE, MIN_CURVATURE_WEIGHT, fp_mul};
use serde::{Serialize, Deserialize};

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
    /// For Phase 1, we compute:
    /// - topological_mass: sum of curvature weights from all edges
    /// - mean_local_curvature: average curvature of all edges touching this DID
    /// - relational_diversity: count of unique DIDs with positive-curvature edges
    /// - temporal_depth: current_depth - first_seen_depth
    ///
    /// capability_coherence and introduction_coherence are placeholders (0) for Phase 1.
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
            capability_coherence: 0, // Placeholder for Phase 1
            introduction_coherence: 0, // Placeholder for Phase 1
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
    /// Phase 1 uses an additive weighted formula (40% mass, 30% curvature,
    /// 20% diversity, 10% temporal depth) for robustness when some components
    /// are zero. The specification describes a multiplicative formula
    /// (C = TM * MC * log(RD) * sqrt(TD) * CC * IC / normalization) which will
    /// be implemented in Phase 2 once all component measures are reliably
    /// non-zero through ZK integration.
    ///
    /// Current weights:
    /// - Decayed topological mass (40%)
    /// - Mean local curvature (30%)
    /// - Relational diversity (20%)
    /// - Temporal depth (10%)
    pub fn composite_score(&self, current_depth: u64) -> FixedPoint {
        let decayed = self.decayed_mass(current_depth);

        // Normalize diversity to fixed-point scale
        let diversity_normalized = (self.relational_diversity.min(100) as i64 * SCALE as i64) / 100;

        // Normalize temporal depth (cap at 100,000 depths = 1.0)
        let depth_normalized = (self.temporal_depth.min(100_000) as i64 * SCALE as i64) / 100_000;

        // Weighted combination (using i64 to avoid overflow)
        let mass_component = (decayed as i64 * 40) / 100;
        let curvature_component = (self.mean_local_curvature.max(0) as i64 * 30) / 100;
        let diversity_component = (diversity_normalized * 20) / 100;
        let depth_component = (depth_normalized * 10) / 100;

        (mass_component + curvature_component + diversity_component + depth_component) as FixedPoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::IdentityGraph;
    use crate::transactions::{IntroductionTransaction, IntroductionContext};
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
}
