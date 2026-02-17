//! Reputation bucket system for ZK-compatible mass computation.
//!
//! Reputation values are discretized into buckets to bridge the gap between
//! ZK proofs (which prove predicates like "I'm in bucket 3") and mass computation
//! (which requires numeric values).
//!
//! Each bucket has a fixed weight that consensus uses for mass calculation.

/// Fixed-point type matching disentangle-dag (avoids circular dependency)
pub type FixedPoint = i32;

/// Fixed-point scale factor (2^16)
pub const SCALE: i32 = 65536;

/// Number of reputation buckets
pub const NUM_BUCKETS: usize = 6;

/// Reputation bucket boundaries (exclusive upper bound)
/// Bucket 0: [0, 10)
/// Bucket 1: [10, 50)
/// Bucket 2: [50, 100)
/// Bucket 3: [100, 500)
/// Bucket 4: [500, 1000)
/// Bucket 5: [1000, ∞)
pub const BUCKET_BOUNDS: [u64; NUM_BUCKETS] = [10, 50, 100, 500, 1000, u64::MAX];

/// Bucket weights for mass computation (in fixed-point, SCALE = 1.0)
/// These are tuned to provide meaningful differentiation while
/// preventing excessive concentration of influence.
///
/// | Bucket | Weight | Interpretation |
/// |--------|--------|----------------|
/// | 0 | 1.0 | Baseline (new accounts) |
/// | 1 | 1.3 | Established accounts |
/// | 2 | 1.5 | Active participants |
/// | 3 | 1.8 | Significant contributors |
/// | 4 | 2.0 | Heavy participants |
/// | 5 | 2.2 | Maximum influence cap |
pub const BUCKET_WEIGHTS: [FixedPoint; NUM_BUCKETS] = [
    SCALE,                      // 1.0
    SCALE + SCALE * 3 / 10,     // 1.3
    SCALE + SCALE / 2,          // 1.5
    SCALE + SCALE * 8 / 10,     // 1.8
    SCALE * 2,                  // 2.0
    SCALE * 2 + SCALE * 2 / 10, // 2.2
];

/// Reputation bucket identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReputationBucket(pub u8);

impl ReputationBucket {
    /// Create a new reputation bucket (clamped to valid range)
    pub fn new(bucket: u8) -> Self {
        Self(bucket.min((NUM_BUCKETS - 1) as u8))
    }

    /// Get the bucket index
    pub fn index(&self) -> usize {
        self.0 as usize
    }

    /// Get the weight for this bucket (in fixed-point)
    pub fn weight(&self) -> FixedPoint {
        BUCKET_WEIGHTS[self.index()]
    }

    /// Get the minimum reputation for this bucket
    pub fn min_reputation(&self) -> u64 {
        if self.0 == 0 {
            0
        } else {
            BUCKET_BOUNDS[self.0 as usize - 1]
        }
    }

    /// Get the maximum reputation for this bucket (exclusive)
    pub fn max_reputation(&self) -> u64 {
        BUCKET_BOUNDS[self.0 as usize]
    }

    /// Check if a reputation value falls within this bucket
    pub fn contains(&self, reputation: u64) -> bool {
        reputation >= self.min_reputation() && reputation < self.max_reputation()
    }
}

/// Convert a numeric reputation to its bucket
pub fn reputation_to_bucket(reputation: u64) -> ReputationBucket {
    for (i, &bound) in BUCKET_BOUNDS.iter().enumerate() {
        if reputation < bound {
            return ReputationBucket(i as u8);
        }
    }
    ReputationBucket((NUM_BUCKETS - 1) as u8)
}

/// Get the weight for a reputation value (via bucket lookup)
pub fn bucket_weight(reputation: u64) -> FixedPoint {
    reputation_to_bucket(reputation).weight()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_boundaries() {
        // Bucket 0: [0, 10)
        assert_eq!(reputation_to_bucket(0).0, 0);
        assert_eq!(reputation_to_bucket(9).0, 0);

        // Bucket 1: [10, 50)
        assert_eq!(reputation_to_bucket(10).0, 1);
        assert_eq!(reputation_to_bucket(49).0, 1);

        // Bucket 2: [50, 100)
        assert_eq!(reputation_to_bucket(50).0, 2);
        assert_eq!(reputation_to_bucket(99).0, 2);

        // Bucket 3: [100, 500)
        assert_eq!(reputation_to_bucket(100).0, 3);
        assert_eq!(reputation_to_bucket(499).0, 3);

        // Bucket 4: [500, 1000)
        assert_eq!(reputation_to_bucket(500).0, 4);
        assert_eq!(reputation_to_bucket(999).0, 4);

        // Bucket 5: [1000, ∞)
        assert_eq!(reputation_to_bucket(1000).0, 5);
        assert_eq!(reputation_to_bucket(1_000_000).0, 5);
    }

    #[test]
    fn test_bucket_weights_ascending() {
        for i in 1..NUM_BUCKETS {
            assert!(
                BUCKET_WEIGHTS[i] >= BUCKET_WEIGHTS[i - 1],
                "Bucket weights should be non-decreasing"
            );
        }
    }

    #[test]
    fn test_bucket_weight_lookup() {
        // Low reputation gets baseline weight
        assert_eq!(bucket_weight(5), SCALE);

        // High reputation gets capped weight
        let max_weight = bucket_weight(10_000);
        assert_eq!(max_weight, BUCKET_WEIGHTS[NUM_BUCKETS - 1]);
    }

    #[test]
    fn test_bucket_contains() {
        let bucket = ReputationBucket::new(2);
        assert!(!bucket.contains(49));
        assert!(bucket.contains(50));
        assert!(bucket.contains(99));
        assert!(!bucket.contains(100));
    }
}
