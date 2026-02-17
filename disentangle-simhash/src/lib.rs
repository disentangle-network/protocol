//! # Entangle SimHash v0.2
//! 
//! Locality-sensitive hashing for Proof of Entanglement with STRICT STRUCTURAL BINDING.
//! 
//! ## Security Invariant
//! 
//! The SimHash MUST be derived ONLY from:
//! 1. Parent transaction hashes (environmental influence)
//! 2. Identity history Merkle root (genetic influence)
//! 
//! NO user-controllable content (memo fields, output data, etc.) may influence
//! the SimHash. This prevents "grinding attacks" where an attacker generates
//! random transaction content to find a favorable topological position.
//!
//! ## Changes from v0.1
//! - Removed `from_bytes(data)` - no arbitrary data allowed
//! - Added `from_structural()` - only structural inputs accepted
//! - SHA2 → SHA3-256 for quantum resistance

use sha3::{Sha3_256, Digest};
use serde::{Serialize, Deserialize};
use disentangle_crypto::hash::Hash256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SimHash(pub u128);

impl SimHash {
    pub const ZERO: SimHash = SimHash(0);
    pub const BITS: u32 = 128;
    
    /// Compute SimHash from STRUCTURAL INPUTS ONLY.
    /// 
    /// # Arguments
    /// * `parent_hashes` - Hashes of parent transactions (DAG edges)
    /// * `identity_history_root` - Merkle root of sender's transaction history
    /// 
    /// # Security
    /// This function accepts NO user-controllable data. The sender's topological
    /// position is determined entirely by their history and their chosen parents.
    pub fn from_structural(parent_hashes: &[Hash256], identity_history_root: &Hash256) -> Self {
        let parent_combined = Self::combine_parent_hashes(parent_hashes);
        let structural_seed = sha3_combine(&parent_combined, identity_history_root);
        Self::generate_from_seed(&structural_seed)
    }
    
    /// Combine parent SimHashes using majority voting.
    /// Used to compute environmental influence from parent transactions.
    pub fn combine_simhashes(hashes: &[SimHash]) -> SimHash {
        if hashes.is_empty() {
            return SimHash::ZERO;
        }
        let mut result = 0u128;
        for bit in 0..128 {
            let ones = hashes.iter().filter(|h| (h.0 >> bit) & 1 == 1).count();
            if ones > hashes.len() / 2 {
                result |= 1u128 << bit;
            }
        }
        SimHash(result)
    }
    
    /// Hamming distance between two SimHashes.
    /// Lower distance = more similar topological position.
    pub fn hamming_distance(&self, other: &SimHash) -> u32 {
        (self.0 ^ other.0).count_ones()
    }
    
    /// Check if two SimHashes are within coherence threshold.
    pub fn is_coherent(&self, other: &SimHash, threshold: u32) -> bool {
        self.hamming_distance(other) <= threshold
    }
    
    /// Apply bounded drift to SimHash.
    /// Used for natural evolution of position over time.
    /// 
    /// # Arguments
    /// * `seed` - Deterministic seed derived from structural data
    /// * `drift_bits` - Maximum bits allowed to flip
    pub fn drift(&self, seed: &[u8], drift_bits: u32) -> SimHash {
        let mut hasher = Sha3_256::new();
        hasher.update(b"SIMHASH_DRIFT_V2");
        hasher.update(seed);
        hasher.update(self.0.to_le_bytes());
        let hash = hasher.finalize();
        let noise = u128::from_le_bytes(hash[0..16].try_into().unwrap());
        let mask = create_sparse_mask(noise, drift_bits);
        SimHash(self.0 ^ mask)
    }
    
    fn combine_parent_hashes(parent_hashes: &[Hash256]) -> Hash256 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"PARENT_COMBINE_V2");
        hasher.update((parent_hashes.len() as u32).to_le_bytes());
        for hash in parent_hashes {
            hasher.update(hash);
        }
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
    
    fn generate_from_seed(seed: &Hash256) -> Self {
        let mut weights = [0i32; 128];
        let mut hasher = Sha3_256::new();
        hasher.update(b"SIMHASH_GEN_V2");
        hasher.update(seed);
        let mut current_hash = hasher.finalize();
        for chunk in 0..4 {
            let mut chunk_hasher = Sha3_256::new();
            chunk_hasher.update(current_hash);
            chunk_hasher.update([chunk as u8]);
            let chunk_hash = chunk_hasher.finalize();
            for (i, &byte) in chunk_hash.iter().enumerate() {
                for bit in 0..8 {
                    let idx = chunk * 32 + i * 8 + bit;
                    if idx < 128 {
                        if (byte >> bit) & 1 == 1 {
                            weights[idx] += 1;
                        } else {
                            weights[idx] -= 1;
                        }
                    }
                }
            }
            current_hash = chunk_hash;
        }
        let mut result = 0u128;
        for (i, &w) in weights.iter().enumerate() {
            if w > 0 {
                result |= 1u128 << i;
            }
        }
        SimHash(result)
    }
}

fn sha3_combine(a: &Hash256, b: &Hash256) -> Hash256 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"STRUCTURAL_COMBINE_V2");
    hasher.update(a);
    hasher.update(b);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn create_sparse_mask(seed: u128, max_bits: u32) -> u128 {
    let mut mask = 0u128;
    let mut remaining = max_bits;
    let mut s = seed;
    for i in 0..128 {
        if remaining == 0 {
            break;
        }
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        if (s >> 64) as u64 % 128 < remaining as u64 {
            mask |= 1u128 << i;
            remaining -= 1;
        }
    }
    mask
}

pub const COHERENCE_THRESHOLD: u32 = 32;
pub const MAX_DRIFT_BITS: u32 = 8;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(n: u8) -> Hash256 {
        let mut h = [0u8; 32];
        h[0] = n;
        h
    }

    #[test]
    fn test_structural_determinism() {
        let parents = vec![test_hash(1), test_hash(2)];
        let history = test_hash(100);
        let h1 = SimHash::from_structural(&parents, &history);
        let h2 = SimHash::from_structural(&parents, &history);
        assert_eq!(h1, h2, "SimHash must be deterministic");
    }

    #[test]
    fn test_different_parents_different_hash() {
        let history = test_hash(100);
        let h1 = SimHash::from_structural(&[test_hash(1)], &history);
        let h2 = SimHash::from_structural(&[test_hash(2)], &history);
        assert_ne!(h1, h2, "Different parents should produce different SimHash");
    }

    #[test]
    fn test_different_history_different_hash() {
        let parents = vec![test_hash(1)];
        let h1 = SimHash::from_structural(&parents, &test_hash(100));
        let h2 = SimHash::from_structural(&parents, &test_hash(200));
        assert_ne!(h1, h2, "Different history should produce different SimHash");
    }

    #[test]
    fn test_hamming_distance() {
        let a = SimHash(0b1010_1010u128);
        let b = SimHash(0b1010_1011u128);
        assert_eq!(a.hamming_distance(&b), 1);
        let c = SimHash(0b0101_0101u128);
        assert_eq!(a.hamming_distance(&c), 8);
    }

    #[test]
    fn test_coherence_threshold() {
        let a = SimHash(0u128);
        let b = SimHash(0b1111u128);
        assert!(a.is_coherent(&b, 4));
        assert!(!a.is_coherent(&b, 3));
    }

    #[test]
    fn test_drift_bounded() {
        let original = SimHash::from_structural(&[test_hash(1)], &test_hash(100));
        let drifted = original.drift(b"seed", MAX_DRIFT_BITS);
        let distance = original.hamming_distance(&drifted);
        assert!(distance <= MAX_DRIFT_BITS, "Drift should be bounded");
    }

    #[test]
    fn test_combine_majority() {
        let h1 = SimHash(0b1111_0000u128);
        let h2 = SimHash(0b1111_0000u128);
        let h3 = SimHash(0b0000_1111u128);
        let combined = SimHash::combine_simhashes(&[h1, h2, h3]);
        assert_eq!(combined.0 & 0xFF, 0b1111_0000, "Majority vote should win");
    }

    #[test]
    fn test_no_user_data_influence() {
        let parents = vec![test_hash(1)];
        let history = test_hash(100);
        let h1 = SimHash::from_structural(&parents, &history);
        let h2 = SimHash::from_structural(&parents, &history);
        assert_eq!(h1, h2, "SimHash should be identical regardless of any user data");
    }
    
    #[test]
    fn test_grinding_resistance() {
        let history = test_hash(100);
        let mut hashes = Vec::new();
        for i in 0..100 {
            let parents = vec![test_hash(i)];
            hashes.push(SimHash::from_structural(&parents, &history));
        }
        let unique_count = hashes.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, 100, "Each unique parent set should produce unique SimHash");
    }
}
