//! Hash-based amount commitments for confidential transactions.
//!
//! Uses SHA3-256 for post-quantum security (collision-resistant binding).

use disentangle_crypto::hash::{sha3_256_multi, Hash256};
use serde::{Serialize, Deserialize};

pub const BLINDING_BYTES: usize = 32;
pub type Blinding = [u8; BLINDING_BYTES];

/// A hash-based commitment to an amount.
/// Commitment = SHA3-256("AMOUNT_COMMIT_V1" || amount_le_bytes || blinding)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AmountCommitment(pub Hash256);

impl AmountCommitment {
    /// Create a new commitment to an amount.
    ///
    /// # Arguments
    /// * `amount` - The amount being committed (in smallest units)
    /// * `blinding` - 32-byte random blinding factor (must be kept secret)
    pub fn commit(amount: u64, blinding: &Blinding) -> Self {
        let hash = sha3_256_multi(&[
            b"AMOUNT_COMMIT_V1",
            &amount.to_le_bytes(),
            blinding,
        ]);
        Self(hash)
    }

    /// Verify that a commitment opens to the given amount and blinding.
    pub fn verify_opening(&self, amount: u64, blinding: &Blinding) -> bool {
        let expected = Self::commit(amount, blinding);
        self.0 == expected.0
    }

    /// Get the commitment as bytes.
    pub fn as_bytes(&self) -> &Hash256 {
        &self.0
    }
}

/// A confidential amount with its commitment and encrypted value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialAmount {
    /// The commitment hiding the actual amount
    pub commitment: AmountCommitment,
    /// The blinding factor (private, only known to creator)
    #[serde(skip)]
    pub blinding: Option<Blinding>,
}

impl ConfidentialAmount {
    /// Create a new confidential amount.
    pub fn new(amount: u64, blinding: Blinding) -> Self {
        Self {
            commitment: AmountCommitment::commit(amount, &blinding),
            blinding: Some(blinding),
        }
    }

    /// Create from just a commitment (no blinding known).
    pub fn from_commitment(commitment: AmountCommitment) -> Self {
        Self {
            commitment,
            blinding: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_creation() {
        let amount = 1000u64;
        let blinding = [42u8; 32];
        let commitment = AmountCommitment::commit(amount, &blinding);
        assert!(commitment.verify_opening(amount, &blinding));
    }

    #[test]
    fn test_commitment_determinism() {
        let amount = 500u64;
        let blinding = [1u8; 32];
        let c1 = AmountCommitment::commit(amount, &blinding);
        let c2 = AmountCommitment::commit(amount, &blinding);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_commitment_wrong_opening() {
        let amount = 1000u64;
        let blinding = [42u8; 32];
        let commitment = AmountCommitment::commit(amount, &blinding);

        // Wrong amount
        assert!(!commitment.verify_opening(999, &blinding));

        // Wrong blinding
        let wrong_blinding = [43u8; 32];
        assert!(!commitment.verify_opening(amount, &wrong_blinding));
    }

    #[test]
    fn test_confidential_amount() {
        let amount = 1500u64;
        let blinding = [7u8; 32];
        let conf_amount = ConfidentialAmount::new(amount, blinding);

        assert!(conf_amount.commitment.verify_opening(amount, &blinding));
        assert_eq!(conf_amount.blinding, Some(blinding));
    }

    #[test]
    fn test_confidential_amount_from_commitment() {
        let commitment = AmountCommitment::commit(2000, &[9u8; 32]);
        let conf_amount = ConfidentialAmount::from_commitment(commitment);

        assert_eq!(conf_amount.commitment, commitment);
        assert_eq!(conf_amount.blinding, None);
    }
}
