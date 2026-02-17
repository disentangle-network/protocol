//! CoherenceOracle Types
//!
//! Deterministic coherence-to-value computation for external resource distribution.
//! The protocol is a lens, not a bank.

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
    /// Merkle root of (did, weight) pairs for external verification
    pub merkle_root: Hash256,
    pub computed_at_depth: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentScore {
    pub did: String,
    pub mass_delta: f64,
    pub curvature_delta: f64,
    pub diversity: u32, // distinct collaborators in region
    pub composite: f64, // mass_delta * max(curvature_delta, 0) * diversity
}

impl OracleQuery {
    pub fn new(region: RegionSelector, depth_start: u64, depth_end: u64) -> Self {
        // Compute query ID from parameters
        let id = Self::compute_id(&region, depth_start, depth_end);

        Self {
            id,
            region,
            depth_start,
            depth_end,
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
        // Compute total score
        let total_score: f64 = scores.values().map(|s| s.composite).sum();

        // Normalize weights to sum to 1.0
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

        // Compute merkle root of (did, weight) pairs
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

    fn compute_merkle_root(weights: &HashMap<String, f64>) -> Hash256 {
        use disentangle_crypto::hash::sha3_256;

        // Sort by DID for deterministic ordering
        let mut sorted: Vec<_> = weights.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));

        // Hash each (did, weight) pair
        let leaves: Vec<Hash256> = sorted
            .iter()
            .map(|(did, weight)| {
                let weight_bytes = weight.to_le_bytes();
                let combined = [did.as_bytes(), &weight_bytes].concat();
                sha3_256(&combined)
            })
            .collect();

        // Simple hash of all leaves for now (full merkle tree in production)
        if leaves.is_empty() {
            [0u8; 32]
        } else {
            let combined: Vec<u8> = leaves.iter().flat_map(|h| h.iter().copied()).collect();
            sha3_256(&combined)
        }
    }
}

impl AgentScore {
    /// Compute composite score from deltas and diversity
    /// Score = max(mass_delta, 0) * max(curvature_delta, 0) * diversity
    pub fn compute_composite(&mut self) {
        let mass_component = self.mass_delta.max(0.0);
        let curvature_component = self.curvature_delta.max(0.0);
        let diversity_component = self.diversity as f64;

        self.composite = mass_component * curvature_component * diversity_component;
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
    }

    #[test]
    fn test_agent_score_composite() {
        let mut score = AgentScore {
            did: "did:disentangle:alice".to_string(),
            mass_delta: 10.0,
            curvature_delta: 0.5,
            diversity: 3,
            composite: 0.0,
        };

        score.compute_composite();

        // 10.0 * 0.5 * 3.0 = 15.0
        assert_eq!(score.composite, 15.0);
    }

    #[test]
    fn test_agent_score_negative_delta() {
        let mut score = AgentScore {
            did: "did:disentangle:sybil".to_string(),
            mass_delta: -5.0,
            curvature_delta: -0.3,
            diversity: 5,
            composite: 0.0,
        };

        score.compute_composite();

        // Negative deltas should result in zero score
        assert_eq!(score.composite, 0.0);
    }

    #[test]
    fn test_distribution_normalization() {
        let query = OracleQuery::new(RegionSelector::Global, 0, 100);

        let mut scores = HashMap::new();

        let mut score1 = AgentScore {
            did: "did:alice".to_string(),
            mass_delta: 10.0,
            curvature_delta: 1.0,
            diversity: 2,
            composite: 0.0,
        };
        score1.compute_composite(); // 10 * 1 * 2 = 20

        let mut score2 = AgentScore {
            did: "did:bob".to_string(),
            mass_delta: 5.0,
            curvature_delta: 1.0,
            diversity: 6,
            composite: 0.0,
        };
        score2.compute_composite(); // 5 * 1 * 6 = 30

        scores.insert("did:alice".to_string(), score1);
        scores.insert("did:bob".to_string(), score2);

        let distribution = DistributionRoot::new(&query, scores, 100);

        // Total = 50, so alice gets 20/50 = 0.4, bob gets 30/50 = 0.6
        assert!((distribution.weights["did:alice"] - 0.4).abs() < 0.001);
        assert!((distribution.weights["did:bob"] - 0.6).abs() < 0.001);

        // Weights should sum to 1.0
        let sum: f64 = distribution.weights.values().sum();
        assert!((sum - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_distribution_zero_scores() {
        let query = OracleQuery::new(RegionSelector::Global, 0, 100);

        let mut scores = HashMap::new();

        // All agents have negative or zero deltas
        let mut score1 = AgentScore {
            did: "did:alice".to_string(),
            mass_delta: -10.0,
            curvature_delta: 0.5,
            diversity: 2,
            composite: 0.0,
        };
        score1.compute_composite(); // 0 (negative mass)

        let mut score2 = AgentScore {
            did: "did:bob".to_string(),
            mass_delta: 5.0,
            curvature_delta: -0.3,
            diversity: 3,
            composite: 0.0,
        };
        score2.compute_composite(); // 0 (negative curvature)

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
}
