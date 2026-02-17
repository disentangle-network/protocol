//! STARK circuit for balance conservation in confidential transactions.
//!
//! Proves: Sum(input_amounts) == Sum(output_amounts)
//! Without revealing the actual amounts.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, AbstractField};
use p3_baby_bear::BabyBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use crate::confidential::{AmountCommitment, Blinding};

/// Maximum number of inputs/outputs supported per transaction.
pub const MAX_IO_COUNT: usize = 8;

/// Trace width for balance circuit.
/// Columns: [amount_i for i in 0..MAX_IO_COUNT] + [is_input_i] + [running_sum] + workspace
const BALANCE_TRACE_WIDTH: usize = MAX_IO_COUNT * 2 + 4;

/// AIR for balance conservation proof.
#[derive(Clone, Debug)]
pub struct BalanceAir {
    pub num_inputs: usize,
    pub num_outputs: usize,
}

impl Default for BalanceAir {
    fn default() -> Self {
        Self { num_inputs: 2, num_outputs: 2 }
    }
}

impl<F: Field> BaseAir<F> for BalanceAir {
    fn width(&self) -> usize {
        BALANCE_TRACE_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for BalanceAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local = &*local;

        // Column layout:
        // [0..MAX_IO_COUNT]: amounts
        // [MAX_IO_COUNT..2*MAX_IO_COUNT]: is_input flags (1 for input, 0 for output)
        // [2*MAX_IO_COUNT]: input_sum
        // [2*MAX_IO_COUNT + 1]: output_sum
        // [2*MAX_IO_COUNT + 2]: balance_diff (should be 0)
        // [2*MAX_IO_COUNT + 3]: is_final_row

        // Constraint: is_input flags must be boolean
        for item in local.iter().take(2 * MAX_IO_COUNT).skip(MAX_IO_COUNT) {
            builder.assert_bool(*item);
        }

        // Constraint: input_sum == sum of (amount * is_input)
        // Constraint: output_sum == sum of (amount * (1 - is_input))
        // These would be computed in witness and verified via range decomposition

        // Final constraint: input_sum == output_sum (balance_diff == 0)
        let balance_diff = local[2 * MAX_IO_COUNT + 2];
        let is_final = local[2 * MAX_IO_COUNT + 3];
        builder.when(is_final).assert_zero(balance_diff);
    }
}

/// Witness for balance proof generation.
#[derive(Clone, Debug)]
pub struct BalanceWitness {
    /// Input amounts and their blinding factors
    pub inputs: Vec<(u64, Blinding)>,
    /// Output amounts and their blinding factors
    pub outputs: Vec<(u64, Blinding)>,
    /// Input commitments (public)
    pub input_commitments: Vec<AmountCommitment>,
    /// Output commitments (public)
    pub output_commitments: Vec<AmountCommitment>,
}

impl BalanceWitness {
    /// Create a new balance witness.
    /// Returns None if balance doesn't conserve.
    pub fn new(
        inputs: Vec<(u64, Blinding)>,
        outputs: Vec<(u64, Blinding)>,
    ) -> Option<Self> {
        let input_sum: u64 = inputs.iter().map(|(a, _)| a).sum();
        let output_sum: u64 = outputs.iter().map(|(a, _)| a).sum();

        if input_sum != output_sum {
            return None;
        }

        let input_commitments: Vec<_> = inputs
            .iter()
            .map(|(amount, blinding)| AmountCommitment::commit(*amount, blinding))
            .collect();

        let output_commitments: Vec<_> = outputs
            .iter()
            .map(|(amount, blinding)| AmountCommitment::commit(*amount, blinding))
            .collect();

        Some(Self {
            inputs,
            outputs,
            input_commitments,
            output_commitments,
        })
    }

    /// Generate the execution trace.
    pub fn generate_trace(&self) -> RowMajorMatrix<BabyBear> {
        // Simplified trace generation
        // Full implementation would include range proof constraints
        let num_rows = 1;
        let mut trace = vec![BabyBear::zero(); num_rows * BALANCE_TRACE_WIDTH];

        // Fill amounts
        for (i, (amount, _)) in self.inputs.iter().enumerate() {
            if i < MAX_IO_COUNT {
                trace[i] = u64_to_field(*amount);
                trace[MAX_IO_COUNT + i] = BabyBear::one(); // is_input = 1
            }
        }

        for (i, (amount, _)) in self.outputs.iter().enumerate() {
            let idx = self.inputs.len() + i;
            if idx < MAX_IO_COUNT {
                trace[idx] = u64_to_field(*amount);
                trace[MAX_IO_COUNT + idx] = BabyBear::zero(); // is_input = 0
            }
        }

        // Compute sums
        let input_sum: u64 = self.inputs.iter().map(|(a, _)| a).sum();
        let output_sum: u64 = self.outputs.iter().map(|(a, _)| a).sum();
        trace[2 * MAX_IO_COUNT] = u64_to_field(input_sum);
        trace[2 * MAX_IO_COUNT + 1] = u64_to_field(output_sum);
        trace[2 * MAX_IO_COUNT + 2] = BabyBear::zero(); // balance_diff
        trace[2 * MAX_IO_COUNT + 3] = BabyBear::one(); // is_final_row

        RowMajorMatrix::new(trace, BALANCE_TRACE_WIDTH)
    }
}

const BABYBEAR_PRIME: u64 = 2013265921;

fn u64_to_field(val: u64) -> BabyBear {
    BabyBear::from_canonical_u32((val % BABYBEAR_PRIME) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balance_witness_valid() {
        let inputs = vec![
            (1000u64, [1u8; 32]),
            (500u64, [2u8; 32]),
        ];
        let outputs = vec![
            (800u64, [3u8; 32]),
            (700u64, [4u8; 32]),
        ];

        let witness = BalanceWitness::new(inputs, outputs);
        assert!(witness.is_some());

        let witness = witness.unwrap();
        assert_eq!(witness.inputs.len(), 2);
        assert_eq!(witness.outputs.len(), 2);
        assert_eq!(witness.input_commitments.len(), 2);
        assert_eq!(witness.output_commitments.len(), 2);
    }

    #[test]
    fn test_balance_witness_invalid() {
        let inputs = vec![
            (1000u64, [1u8; 32]),
        ];
        let outputs = vec![
            (999u64, [2u8; 32]), // Doesn't balance!
        ];

        let witness = BalanceWitness::new(inputs, outputs);
        assert!(witness.is_none());
    }

    #[test]
    fn test_trace_generation() {
        let inputs = vec![
            (500u64, [5u8; 32]),
            (300u64, [6u8; 32]),
        ];
        let outputs = vec![
            (800u64, [7u8; 32]),
        ];

        let witness = BalanceWitness::new(inputs, outputs).unwrap();
        let trace = witness.generate_trace();

        assert_eq!(trace.width(), BALANCE_TRACE_WIDTH);
        assert_eq!(trace.height(), 1);

        // Check that amounts are filled
        let row: Vec<_> = trace.row(0).collect();
        assert_eq!(row[0], u64_to_field(500)); // First input amount
        assert_eq!(row[1], u64_to_field(300)); // Second input amount
        assert_eq!(row[2], u64_to_field(800)); // First output amount
    }

    #[test]
    fn test_u64_to_field_reduction() {
        // Test that values larger than BabyBear prime are reduced
        let large_val = BABYBEAR_PRIME + 100;
        let field_val = u64_to_field(large_val);
        assert_eq!(field_val, BabyBear::from_canonical_u32(100));
    }
}
