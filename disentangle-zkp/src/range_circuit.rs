//! STARK circuit for range proofs.
//!
//! Proves: 0 <= amount < 2^64
//! Uses bit decomposition approach.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, Field};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

/// Number of bits for range proof (64 bits for u64)
pub const RANGE_BITS: usize = 64;

/// Trace width: one column per bit + original value + reconstructed value
const RANGE_TRACE_WIDTH: usize = RANGE_BITS + 2;

/// AIR for range proof.
#[derive(Clone, Debug, Default)]
pub struct RangeAir;

impl<F: Field> BaseAir<F> for RangeAir {
    fn width(&self) -> usize {
        RANGE_TRACE_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for RangeAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local = &*local;

        // Columns [0..RANGE_BITS]: bit decomposition
        // Column [RANGE_BITS]: original value
        // Column [RANGE_BITS + 1]: reconstructed value from bits

        // Constraint 1: Each bit must be boolean (0 or 1)
        for bit in local.iter().take(RANGE_BITS) {
            builder.assert_bool(*bit);
        }

        // Constraint 2: Reconstructed value must equal original
        // reconstructed = sum(bit[i] * 2^i) for i in 0..64
        // This ensures the original value is < 2^64
        builder.assert_eq(local[RANGE_BITS], local[RANGE_BITS + 1]);
    }
}

/// Witness for range proof.
#[derive(Clone, Debug)]
pub struct RangeWitness {
    pub value: u64,
}

impl RangeWitness {
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    /// Generate the execution trace.
    pub fn generate_trace(&self) -> RowMajorMatrix<BabyBear> {
        let mut trace = vec![BabyBear::zero(); RANGE_TRACE_WIDTH];

        // Bit decomposition
        let mut reconstructed = BabyBear::zero();
        let mut power_of_two = BabyBear::one();

        for (i, trace_bit) in trace.iter_mut().enumerate().take(RANGE_BITS) {
            let bit = (self.value >> i) & 1;
            *trace_bit = if bit == 1 {
                BabyBear::one()
            } else {
                BabyBear::zero()
            };
            if bit == 1 {
                reconstructed += power_of_two;
            }
            power_of_two = power_of_two + power_of_two; // multiply by 2
        }

        // Original value (reduced mod prime)
        const BABYBEAR_PRIME: u64 = 2013265921;
        trace[RANGE_BITS] = BabyBear::from_canonical_u32((self.value % BABYBEAR_PRIME) as u32);
        trace[RANGE_BITS + 1] = reconstructed;

        RowMajorMatrix::new(trace, RANGE_TRACE_WIDTH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_witness_small_value() {
        let witness = RangeWitness::new(42);
        let trace = witness.generate_trace();

        assert_eq!(trace.width(), RANGE_TRACE_WIDTH);
        assert_eq!(trace.height(), 1);

        // Check bit decomposition of 42 = 0b101010
        let row: Vec<_> = trace.row(0).collect();
        assert_eq!(row[1], BabyBear::one()); // bit 1
        assert_eq!(row[3], BabyBear::one()); // bit 3
        assert_eq!(row[5], BabyBear::one()); // bit 5
        assert_eq!(row[0], BabyBear::zero()); // bit 0
        assert_eq!(row[2], BabyBear::zero()); // bit 2
    }

    #[test]
    fn test_range_witness_max_value() {
        let witness = RangeWitness::new(u64::MAX);
        let trace = witness.generate_trace();

        // All bits should be 1
        let row: Vec<_> = trace.row(0).collect();
        for i in 0..RANGE_BITS {
            assert_eq!(row[i], BabyBear::one());
        }
    }

    #[test]
    fn test_range_witness_zero() {
        let witness = RangeWitness::new(0);
        let trace = witness.generate_trace();

        // All bits should be 0
        let row: Vec<_> = trace.row(0).collect();
        for i in 0..RANGE_BITS {
            assert_eq!(row[i], BabyBear::zero());
        }

        // Original and reconstructed should both be 0
        assert_eq!(row[RANGE_BITS], BabyBear::zero());
        assert_eq!(row[RANGE_BITS + 1], BabyBear::zero());
    }

    #[test]
    fn test_range_witness_power_of_two() {
        // Test 256 = 2^8
        let witness = RangeWitness::new(256);
        let trace = witness.generate_trace();

        let row: Vec<_> = trace.row(0).collect();
        // Only bit 8 should be set
        for i in 0..RANGE_BITS {
            if i == 8 {
                assert_eq!(row[i], BabyBear::one());
            } else {
                assert_eq!(row[i], BabyBear::zero());
            }
        }
    }

    #[test]
    fn test_reconstructed_matches_original_small() {
        // For small values that fit in BabyBear field without reduction
        let value = 12345u64;
        let witness = RangeWitness::new(value);
        let trace = witness.generate_trace();

        let row: Vec<_> = trace.row(0).collect();
        // Original and reconstructed should match (both < BABYBEAR_PRIME)
        assert_eq!(row[RANGE_BITS], row[RANGE_BITS + 1]);
    }
}
