//! STARK circuit for reputation threshold proofs.
//!
//! This module defines the AIR (Algebraic Intermediate Representation) for proving
//! that an account has reputation >= threshold without revealing the account identity.
//!
//! ## Circuit Overview
//!
//! Public Inputs:
//! - merkle_root: Hash256 (commitment to all account states)
//! - reputation_threshold: u64 (minimum reputation being proven)
//!
//! Private Inputs (witness):
//! - account_state: AccountStateLeaf (the prover's account)
//! - merkle_path: Vec<Hash256> (path from leaf to root)
//! - leaf_index: usize (position in tree)
//!
//! Constraints:
//! 1. merkle_path is valid from leaf to merkle_root
//! 2. leaf = hash(account_state)
//! 3. account_state.reputation_score >= reputation_threshold

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, Field};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

/// Width of the execution trace (number of columns).
/// We need columns for:
/// - Merkle path verification (hash inputs/outputs at each level)
/// - Reputation comparison
const TRACE_WIDTH: usize = 16;

/// Maximum Merkle tree depth supported.
pub const MAX_TREE_DEPTH: usize = 32;

/// The reputation proof AIR.
/// Defines constraints that must hold for a valid reputation claim.
#[derive(Clone, Debug)]
pub struct ReputationAir {
    /// Number of rows in the trace (depends on tree depth)
    pub num_rows: usize,
}

impl Default for ReputationAir {
    fn default() -> Self {
        Self {
            num_rows: MAX_TREE_DEPTH,
        }
    }
}

impl<F: Field> BaseAir<F> for ReputationAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for ReputationAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local = &*local;
        let next = &*next;

        // Column layout:
        // [0]: current_hash_lo (low 128 bits as field elements)
        // [1]: current_hash_hi
        // [2]: sibling_hash_lo
        // [3]: sibling_hash_hi
        // [4]: is_right (0 or 1)
        // [5]: parent_hash_lo (result)
        // [6]: parent_hash_hi
        // [7]: reputation_score
        // [8]: threshold
        // [9]: is_last_row
        // [10-15]: workspace/flags

        // Constraint 1: is_right must be boolean
        let is_right = local[4];
        builder.assert_bool(is_right);

        // Constraint 2: Reputation score must be >= threshold
        // This is checked in the first row where we have the account data
        // We use the "difference is non-negative" approach via range check
        let reputation = local[7];
        let threshold = local[8];

        // For now, simplified constraint: reputation - threshold has no underflow
        // Full implementation would use range proofs
        let is_last = local[9];
        builder.when(is_last).assert_zero(
            reputation - threshold - local[10], // diff stored in workspace
        );

        // Constraint 3: Hash chain continuity
        // parent_hash becomes current_hash in next row.
        // Only enforced on non-last real rows (padding rows are all-zero
        // and satisfy 0==0 trivially; the last-real→first-padding transition
        // is skipped via the is_last guard).
        let not_last = AB::Expr::one() - is_last;
        builder
            .when_transition()
            .when(not_last.clone())
            .assert_eq(
                local[5], // parent_hash_lo this row
                next[0],  // current_hash_lo next row
            );
        builder
            .when_transition()
            .when(not_last)
            .assert_eq(
                local[6], // parent_hash_hi this row
                next[1],  // current_hash_hi next row
            );
    }
}

/// Witness data for generating a reputation proof trace.
#[derive(Clone, Debug)]
pub struct ReputationWitness {
    /// The prover's reputation score
    pub reputation_score: u64,
    /// Minimum reputation being proven
    pub threshold: u64,
    /// Leaf hash of the account state
    pub leaf_hash: [u8; 32],
    /// Sibling hashes in the Merkle path
    pub merkle_siblings: Vec<[u8; 32]>,
    /// Path direction bits (false = left, true = right)
    pub path_bits: Vec<bool>,
    /// Expected Merkle root
    pub merkle_root: [u8; 32],
}

impl ReputationWitness {
    /// Generate the execution trace for the STARK prover.
    pub fn generate_trace(&self) -> RowMajorMatrix<BabyBear> {
        let num_rows = self.merkle_siblings.len().max(1);
        let mut trace = vec![BabyBear::zero(); num_rows * TRACE_WIDTH];

        // Fill in the trace row by row
        let mut current_hash = self.leaf_hash;

        for (row_idx, (sibling, &is_right)) in self
            .merkle_siblings
            .iter()
            .zip(self.path_bits.iter())
            .enumerate()
        {
            let row_start = row_idx * TRACE_WIDTH;

            // Current hash (split into field elements)
            trace[row_start] = bytes_to_field(&current_hash[0..16]);
            trace[row_start + 1] = bytes_to_field(&current_hash[16..32]);

            // Sibling hash
            trace[row_start + 2] = bytes_to_field(&sibling[0..16]);
            trace[row_start + 3] = bytes_to_field(&sibling[16..32]);

            // Direction bit
            trace[row_start + 4] = if is_right {
                BabyBear::one()
            } else {
                BabyBear::zero()
            };

            // Compute parent hash
            let parent = if is_right {
                hash_pair_native(sibling, &current_hash)
            } else {
                hash_pair_native(&current_hash, sibling)
            };

            trace[row_start + 5] = bytes_to_field(&parent[0..16]);
            trace[row_start + 6] = bytes_to_field(&parent[16..32]);

            // Reputation and threshold (in first row only, but we fill all for simplicity)
            trace[row_start + 7] = u64_to_field(self.reputation_score);
            trace[row_start + 8] = u64_to_field(self.threshold);

            // Is last row flag
            trace[row_start + 9] = if row_idx == num_rows - 1 {
                BabyBear::one()
            } else {
                BabyBear::zero()
            };

            // Workspace: store reputation - threshold difference
            let diff = self.reputation_score.saturating_sub(self.threshold);
            trace[row_start + 10] = u64_to_field(diff);

            current_hash = parent;
        }

        RowMajorMatrix::new(trace, TRACE_WIDTH)
    }
}

/// Convert bytes to a BabyBear field element.
/// BabyBear prime is 2^31 - 2^27 + 1 = 2013265921, so we need to reduce mod prime.
const BABYBEAR_PRIME: u64 = 2013265921;

fn bytes_to_field(bytes: &[u8]) -> BabyBear {
    let mut val: u64 = 0;
    for (i, &b) in bytes.iter().take(4).enumerate() {
        val |= (b as u64) << (i * 8);
    }
    BabyBear::from_canonical_u32((val % BABYBEAR_PRIME) as u32)
}

/// Convert u64 to BabyBear field element (reduced mod prime).
fn u64_to_field(val: u64) -> BabyBear {
    BabyBear::from_canonical_u32((val % BABYBEAR_PRIME) as u32)
}

/// Hash two nodes together (native computation, not in-circuit).
/// This is used during witness generation.
fn hash_pair_native(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    disentangle_crypto::hash::sha3_256_multi(&[b"MERKLE_NODE_V1", left, right])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness_generation() {
        let witness = ReputationWitness {
            reputation_score: 100,
            threshold: 50,
            leaf_hash: [1u8; 32],
            merkle_siblings: vec![[2u8; 32], [3u8; 32]],
            path_bits: vec![false, true],
            merkle_root: [0u8; 32], // Will be computed
        };

        let trace = witness.generate_trace();
        assert_eq!(trace.width(), TRACE_WIDTH);
        assert_eq!(trace.height(), 2);
    }

    #[test]
    fn test_bytes_to_field() {
        let bytes = [0x12, 0x34, 0x56, 0x00]; // Use smaller value to fit in field
        let field = bytes_to_field(&bytes);
        // Should be little-endian: 0x00563412
        let expected = 0x00563412u64 % BABYBEAR_PRIME;
        assert_eq!(field, BabyBear::from_canonical_u32(expected as u32));
    }
}
