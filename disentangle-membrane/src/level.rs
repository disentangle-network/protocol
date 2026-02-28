use disentangle_simhash::SimHash;
use serde::{Deserialize, Serialize};

/// Depth of a node's coherence structure. Proxy: the number of distinct
/// SimHash clusters in the node's transaction history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CoherenceLevel(pub u32);

/// Mean inter-transaction depth gap. Low = fast integrator, high = slow.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TemporalSignature(pub f64);

/// Combined level-temporality measurement for a node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LevelTemporality {
    pub level: CoherenceLevel,
    pub temporality: TemporalSignature,
}

impl CoherenceLevel {
    /// Compute from a set of SimHashes representing a node's history.
    /// Clusters by hamming distance, counts distinct clusters.
    /// A node producing transactions with diverse but internally-coherent
    /// topological signatures has deeper coherence structure.
    pub fn from_history(hashes: &[SimHash], cluster_threshold: u32) -> Self {
        if hashes.is_empty() {
            return CoherenceLevel(0);
        }

        // Greedy clustering: each hash either joins an existing cluster
        // (within threshold hamming distance) or starts a new one.
        let mut centroids: Vec<SimHash> = Vec::new();

        for hash in hashes {
            let in_existing = centroids
                .iter()
                .any(|c| hash.hamming_distance(c) <= cluster_threshold);
            if !in_existing {
                centroids.push(*hash);
            }
        }

        CoherenceLevel(centroids.len() as u32)
    }
}

impl TemporalSignature {
    /// Mean inter-transaction depth gap. Low = fast integrator, high = slow.
    pub fn from_depths(tx_depths: &[u64]) -> Self {
        if tx_depths.len() < 2 {
            return TemporalSignature(0.0);
        }

        let mut sorted = tx_depths.to_vec();
        sorted.sort_unstable();

        let gaps: Vec<f64> = sorted.windows(2).map(|w| (w[1] - w[0]) as f64).collect();

        let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
        TemporalSignature(mean)
    }
}

impl LevelTemporality {
    /// Compute the gap between two level-temporality measurements.
    /// Returns (level_gap, temporal_gap) — both non-negative.
    pub fn gap(&self, other: &LevelTemporality) -> (u32, f64) {
        let level_gap = self.level.0.abs_diff(other.level.0);
        let temporal_gap = (self.temporality.0 - other.temporality.0).abs();
        (level_gap, temporal_gap)
    }
}
