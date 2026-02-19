//! CoherenceOracle Types
//!
//! Deterministic coherence-to-value computation for external resource distribution.
//! The protocol is a lens, not a bank.
//!
//! Allocation formula (Paper Definition 5, eq. 6):
//!   a(i) = R * max(0, meangrad(i)) / sum_k max(0, meangrad(k))
//!
//! Where meangrad(i) is the mean curvature derivative (Definition 4):
//!   meangrad(i) = (1/|N(i)|) * sum_{j in N(i)} d_kappa_J(i,j)/dd
//!
//! Eligible set: A_elig = {i : topomass(i) >= theta_min}

use disentangle_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleQuery {
    pub id: Hash256,
    /// Region to evaluate (neighborhood hash, intent ID, or specific DID set)
    pub region: RegionSelector,
    /// Depth window for evaluation
    pub depth_start: u64,
    pub depth_end: u64,
    /// Minimum topological mass for eligibility (CoherenceMinimum / theta_min)
    #[serde(default)]
    pub min_coherence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegionSelector {
    /// A specific neighborhood
    Neighborhood(String),
    /// Participants of a SharedIntent
    Intent(Hash256),
    /// Explicit set of DIDs
    Explicit(Vec<String>),
    /// Entire network
    Global,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionRoot {
    pub query_id: Hash256,
    pub region: RegionSelector,
    pub depth_window: (u64, u64),
    /// Per-agent distribution weights (normalized to sum to 1.0)
    pub weights: HashMap<String, f64>,
    /// Per-agent scoring breakdown
    pub scores: HashMap<String, AgentScore>,
    /// Merkle root of (did, weight) pairs for external verification (binary merkle tree)
    pub merkle_root: Hash256,
    pub computed_at_depth: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentScore {
    pub did: String,
    /// Topological mass delta over the depth window (diagnostic)
    pub mass_delta: f64,
    /// Rate of curvature change -- the dopaminergic signal (meangrad)
    pub curvature_derivative: f64,
    /// Distinct positive-curvature collaborators in region (diagnostic)
    pub diversity: u32,
    /// Allocation weight: max(0, curvature_derivative) per paper eq. 6
    pub composite: f64,
}

impl OracleQuery {
    pub fn new(region: RegionSelector, depth_start: u64, depth_end: u64) -> Self {
        Self::with_min_coherence(region, depth_start, depth_end, 0.0)
    }

    pub fn with_min_coherence(
        region: RegionSelector,
        depth_start: u64,
        depth_end: u64,
        min_coherence: f64,
    ) -> Self {
        let id = Self::compute_id(&region, depth_start, depth_end);

        Self {
            id,
            region,
            depth_start,
            depth_end,
            min_coherence,
        }
    }

    fn compute_id(region: &RegionSelector, depth_start: u64, depth_end: u64) -> Hash256 {
        use disentangle_crypto::hash::sha3_256_multi;

        let region_bytes = match region {
            RegionSelector::Neighborhood(hash) => hash.as_bytes().to_vec(),
            RegionSelector::Intent(hash) => hash.to_vec(),
            RegionSelector::Explicit(dids) => dids.join(",").as_bytes().to_vec(),
            RegionSelector::Global => b"GLOBAL".to_vec(),
        };

        sha3_256_multi(&[
            b"ORACLE_QUERY_V1",
            &region_bytes,
            &depth_start.to_le_bytes(),
            &depth_end.to_le_bytes(),
        ])
    }
}

impl DistributionRoot {
    pub fn new(
        query: &OracleQuery,
        scores: HashMap<String, AgentScore>,
        computed_at_depth: u64,
    ) -> Self {
        // Compute total score (sum of composites, which are max(0, meangrad))
        let total_score: f64 = scores.values().map(|s| s.composite).sum();

        // Normalize weights to sum to 1.0 (paper eq. 6: a(i) = R * w(i) / sum w(k))
        let weights: HashMap<String, f64> = if total_score > 0.0 {
            scores
                .iter()
                .map(|(did, score)| (did.clone(), score.composite / total_score))
                .collect()
        } else {
            // If no one has positive score, equal distribution
            let equal_weight = if scores.is_empty() {
                0.0
            } else {
                1.0 / scores.len() as f64
            };
            scores
                .keys()
                .map(|did| (did.clone(), equal_weight))
                .collect()
        };

        // Compute merkle root of (did, weight) pairs using binary merkle tree
        let merkle_root = Self::compute_merkle_root(&weights);

        Self {
            query_id: query.id,
            region: query.region.clone(),
            depth_window: (query.depth_start, query.depth_end),
            weights,
            scores,
            merkle_root,
            computed_at_depth,
        }
    }

    /// Binary merkle tree over sorted (did, weight) leaf hashes.
    /// Leaves are sorted by DID for deterministic ordering.
    /// Pairwise SHA3-256 hashing up the tree; odd nodes are promoted.
    fn compute_merkle_root(weights: &HashMap<String, f64>) -> Hash256 {
        use disentangle_crypto::hash::sha3_256;

        if weights.is_empty() {
            return [0u8; 32];
        }

        // Sort by DID for deterministic ordering
        let mut sorted: Vec<_> = weights.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));

        // Hash each (did, weight) pair into a leaf
        let mut level: Vec<Hash256> = sorted
            .iter()
            .map(|(did, weight)| {
                let weight_bytes = weight.to_le_bytes();
                let combined = [did.as_bytes(), &weight_bytes].concat();
                sha3_256(&combined)
            })
            .collect();

        // Build binary merkle tree: pairwise hash up until one root remains
        while level.len() > 1 {
            let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    // Hash pair
                    let combined = [level[i].as_slice(), level[i + 1].as_slice()].concat();
                    next_level.push(sha3_256(&combined));
                    i += 2;
                } else {
                    // Odd node: promote to next level
                    next_level.push(level[i]);
                    i += 1;
                }
            }
            level = next_level;
        }

        level[0]
    }
}

impl AgentScore {
    /// Compute composite score per paper Definition 5 (eq. 6):
    ///   weight = max(0, meangrad(i))
    ///
    /// Where meangrad is the mean curvature derivative (already computed and
    /// stored in `curvature_derivative`). The oracle rewards agents who are
    /// ACTIVELY CREATING coherence (high derivative).
    ///
    /// mass_delta and diversity are retained as diagnostic fields but do NOT
    /// factor into the allocation formula.
    pub fn compute_composite(&mut self) {
        self.composite = self.curvature_derivative.max(0.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle_query_creation() {
        let query = OracleQuery::new(RegionSelector::Global, 100, 200);

        assert_eq!(query.depth_start, 100);
        assert_eq!(query.depth_end, 200);
        assert_eq!(query.min_coherence, 0.0);
    }

    #[test]
    fn test_oracle_query_with_min_coherence() {
        let query = OracleQuery::with_min_coherence(RegionSelector::Global, 100, 200, 5.0);

        assert_eq!(query.min_coherence, 5.0);
        // Same query ID regardless of min_coherence (it's a filter, not a query parameter)
        let query2 = OracleQuery::new(RegionSelector::Global, 100, 200);
        assert_eq!(query.id, query2.id);
    }

    #[test]
    fn test_agent_score_composite_paper_formula() {
        // Paper formula: composite = max(0, curvature_derivative)
        let mut score = AgentScore {
            did: "did:disentangle:alice".to_string(),
            mass_delta: 10.0,
            curvature_derivative: 0.5,
            diversity: 3,
            composite: 0.0,
        };

        score.compute_composite();

        // Paper formula: max(0, 0.5) = 0.5
        assert_eq!(score.composite, 0.5);
    }

    #[test]
    fn test_agent_score_negative_derivative() {
        let mut score = AgentScore {
            did: "did:disentangle:sybil".to_string(),
            mass_delta: -5.0,
            curvature_derivative: -0.2,
            diversity: 5,
            composite: 0.0,
        };

        score.compute_composite();

        // Negative derivative should result in zero score
        assert_eq!(score.composite, 0.0);
    }

    #[test]
    fn test_distribution_normalization() {
        let query = OracleQuery::new(RegionSelector::Global, 0, 100);

        let mut scores = HashMap::new();

        let mut score1 = AgentScore {
            did: "did:alice".to_string(),
            mass_delta: 10.0,
            curvature_derivative: 0.3,
            diversity: 2,
            composite: 0.0,
        };
        score1.compute_composite(); // max(0, 0.3) = 0.3

        let mut score2 = AgentScore {
            did: "did:bob".to_string(),
            mass_delta: 5.0,
            curvature_derivative: 0.7,
            diversity: 6,
            composite: 0.0,
        };
        score2.compute_composite(); // max(0, 0.7) = 0.7

        scores.insert("did:alice".to_string(), score1);
        scores.insert("did:bob".to_string(), score2);

        let distribution = DistributionRoot::new(&query, scores, 100);

        // Total = 1.0, so alice gets 0.3/1.0 = 0.3, bob gets 0.7/1.0 = 0.7
        assert!((distribution.weights["did:alice"] - 0.3).abs() < 0.001);
        assert!((distribution.weights["did:bob"] - 0.7).abs() < 0.001);

        // Weights should sum to 1.0
        let sum: f64 = distribution.weights.values().sum();
        assert!((sum - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_distribution_zero_scores() {
        let query = OracleQuery::new(RegionSelector::Global, 0, 100);

        let mut scores = HashMap::new();

        // All agents have negative curvature derivative
        let mut score1 = AgentScore {
            did: "did:alice".to_string(),
            mass_delta: -10.0,
            curvature_derivative: -0.5,
            diversity: 2,
            composite: 0.0,
        };
        score1.compute_composite(); // 0 (negative derivative)

        let mut score2 = AgentScore {
            did: "did:bob".to_string(),
            mass_delta: 5.0,
            curvature_derivative: -0.3,
            diversity: 3,
            composite: 0.0,
        };
        score2.compute_composite(); // 0 (negative derivative)

        scores.insert("did:alice".to_string(), score1);
        scores.insert("did:bob".to_string(), score2);

        let distribution = DistributionRoot::new(&query, scores, 100);

        // Equal distribution when all scores are zero
        assert!((distribution.weights["did:alice"] - 0.5).abs() < 0.001);
        assert!((distribution.weights["did:bob"] - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_query_id_deterministic() {
        let query1 = OracleQuery::new(RegionSelector::Global, 100, 200);
        let query2 = OracleQuery::new(RegionSelector::Global, 100, 200);

        assert_eq!(query1.id, query2.id);
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let query = OracleQuery::new(RegionSelector::Global, 0, 100);

        let mut scores = HashMap::new();
        let mut s1 = AgentScore {
            did: "did:alice".to_string(),
            mass_delta: 0.0,
            curvature_derivative: 0.5,
            diversity: 1,
            composite: 0.0,
        };
        s1.compute_composite();
        let mut s2 = AgentScore {
            did: "did:bob".to_string(),
            mass_delta: 0.0,
            curvature_derivative: 0.5,
            diversity: 1,
            composite: 0.0,
        };
        s2.compute_composite();

        scores.insert("did:alice".to_string(), s1.clone());
        scores.insert("did:bob".to_string(), s2.clone());
        let d1 = DistributionRoot::new(&query, scores, 100);

        // Build again in different insertion order
        let mut scores2 = HashMap::new();
        scores2.insert("did:bob".to_string(), s2);
        scores2.insert("did:alice".to_string(), s1);
        let d2 = DistributionRoot::new(&query, scores2, 100);

        assert_eq!(d1.merkle_root, d2.merkle_root);
        assert_ne!(d1.merkle_root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_binary_tree_structure() {
        // Verify the merkle root changes when weight ratios change
        let query = OracleQuery::new(RegionSelector::Global, 0, 100);

        // Distribution A: alice=0.3, bob=0.7
        let mut scores_a = HashMap::new();
        let mut sa1 = AgentScore {
            did: "did:alice".to_string(),
            mass_delta: 0.0,
            curvature_derivative: 0.3,
            diversity: 1,
            composite: 0.0,
        };
        sa1.compute_composite();
        let mut sa2 = AgentScore {
            did: "did:bob".to_string(),
            mass_delta: 0.0,
            curvature_derivative: 0.7,
            diversity: 1,
            composite: 0.0,
        };
        sa2.compute_composite();
        scores_a.insert("did:alice".to_string(), sa1);
        scores_a.insert("did:bob".to_string(), sa2);
        let da = DistributionRoot::new(&query, scores_a, 100);

        // Distribution B: alice=0.7, bob=0.3 (swapped)
        let mut scores_b = HashMap::new();
        let mut sb1 = AgentScore {
            did: "did:alice".to_string(),
            mass_delta: 0.0,
            curvature_derivative: 0.7,
            diversity: 1,
            composite: 0.0,
        };
        sb1.compute_composite();
        let mut sb2 = AgentScore {
            did: "did:bob".to_string(),
            mass_delta: 0.0,
            curvature_derivative: 0.3,
            diversity: 1,
            composite: 0.0,
        };
        sb2.compute_composite();
        scores_b.insert("did:alice".to_string(), sb1);
        scores_b.insert("did:bob".to_string(), sb2);
        let db = DistributionRoot::new(&query, scores_b, 100);

        // Different weight ratios produce different merkle roots
        assert_ne!(da.merkle_root, db.merkle_root);
    }

    #[test]
    fn test_merkle_root_empty() {
        let weights: HashMap<String, f64> = HashMap::new();
        let root = DistributionRoot::compute_merkle_root(&weights);
        assert_eq!(root, [0u8; 32]);
    }
}
