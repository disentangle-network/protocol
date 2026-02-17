//! Stealth addresses using Kyber1024 KEM.
//!
//! Allows sending to recipients without revealing their public key on-chain.

use disentangle_crypto::kem::{
    EncapsulationKey, DecapsulationKey, Ciphertext, SharedSecret,
    encapsulate, decapsulate,
};
use disentangle_crypto::hash::{sha3_256_multi, Hash256};
use serde::{Serialize, Deserialize};
use crate::confidential::AmountCommitment;

/// A stealth address derived from a KEM shared secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthAddress(pub Hash256);

impl StealthAddress {
    /// Derive a stealth address from a shared secret.
    fn from_shared_secret(shared_secret: &SharedSecret, domain: &[u8]) -> Self {
        let hash = sha3_256_multi(&[
            b"STEALTH_ADDR_V1",
            domain,
            shared_secret.as_bytes(),
        ]);
        Self(hash)
    }

    /// Check if this stealth address matches the expected one.
    pub fn matches(&self, other: &StealthAddress) -> bool {
        self.0 == other.0
    }

    pub fn as_bytes(&self) -> &Hash256 {
        &self.0
    }
}

/// Generate a stealth address for a recipient.
///
/// # Returns
/// * `StealthAddress` - The stealth address to use in the output
/// * `Ciphertext` - The ephemeral ciphertext (stored on-chain for recipient to decode)
/// * `SharedSecret` - The shared secret (used to encrypt amount, then discarded)
pub fn generate_stealth_address(
    recipient_ek: &EncapsulationKey,
) -> (StealthAddress, Ciphertext, SharedSecret) {
    let (ciphertext, shared_secret) = encapsulate(recipient_ek);
    let stealth_addr = StealthAddress::from_shared_secret(&shared_secret, b"");
    (stealth_addr, ciphertext, shared_secret)
}

/// Recover a stealth address from the recipient's perspective.
///
/// # Arguments
/// * `recipient_dk` - Recipient's decapsulation key
/// * `ciphertext` - The ephemeral ciphertext from the transaction
pub fn recover_stealth_address(
    recipient_dk: &DecapsulationKey,
    ciphertext: &Ciphertext,
) -> Result<(StealthAddress, SharedSecret), StealthError> {
    let shared_secret = decapsulate(recipient_dk, ciphertext)
        .map_err(|_| StealthError::DecapsulationFailed)?;
    let stealth_addr = StealthAddress::from_shared_secret(&shared_secret, b"");
    Ok((stealth_addr, shared_secret))
}

/// A confidential output that can be sent to a stealth address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialOutput {
    /// Commitment to the amount
    pub commitment: AmountCommitment,
    /// Stealth address for the recipient
    pub stealth_address: StealthAddress,
    /// Encrypted amount (ChaCha20-Poly1305 with key derived from shared secret)
    pub encrypted_amount: Vec<u8>,
    /// Ephemeral ciphertext for recipient to derive shared secret
    pub ephemeral_ciphertext: Ciphertext,
}

impl ConfidentialOutput {
    /// Create a new confidential output.
    ///
    /// # Arguments
    /// * `amount` - The amount to send
    /// * `blinding` - Random blinding factor for commitment
    /// * `recipient_ek` - Recipient's encapsulation key
    pub fn new(
        amount: u64,
        blinding: [u8; 32],
        recipient_ek: &EncapsulationKey,
    ) -> Self {
        let commitment = AmountCommitment::commit(amount, &blinding);
        let (stealth_address, ephemeral_ciphertext, shared_secret) =
            generate_stealth_address(recipient_ek);

        // Encrypt amount using shared secret as key
        // Using simple XOR for now (should use ChaCha20-Poly1305 in production)
        let encrypted_amount = encrypt_amount(amount, &blinding, shared_secret.as_bytes());

        Self {
            commitment,
            stealth_address,
            encrypted_amount,
            ephemeral_ciphertext,
        }
    }

    /// Try to decrypt this output using a decapsulation key.
    /// Returns (amount, blinding) if successful.
    pub fn try_decrypt(
        &self,
        recipient_dk: &DecapsulationKey,
    ) -> Result<(u64, [u8; 32]), StealthError> {
        let (recovered_addr, shared_secret) =
            recover_stealth_address(recipient_dk, &self.ephemeral_ciphertext)?;

        if !self.stealth_address.matches(&recovered_addr) {
            return Err(StealthError::NotForRecipient);
        }

        let (amount, blinding) = decrypt_amount(&self.encrypted_amount, shared_secret.as_bytes())?;

        // Verify the commitment
        if !self.commitment.verify_opening(amount, &blinding) {
            return Err(StealthError::CommitmentMismatch);
        }

        Ok((amount, blinding))
    }
}

/// Encrypt amount and blinding factor.
/// In production, use ChaCha20-Poly1305.
fn encrypt_amount(amount: u64, blinding: &[u8; 32], key: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(blinding);

    // Simple XOR encryption (replace with ChaCha20-Poly1305)
    let key_stream = sha3_256_multi(&[b"ENCRYPT_STREAM", key]);
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key_stream[i % 32];
    }

    data
}

/// Decrypt amount and blinding factor.
fn decrypt_amount(encrypted: &[u8], key: &[u8; 32]) -> Result<(u64, [u8; 32]), StealthError> {
    if encrypted.len() != 40 {
        return Err(StealthError::InvalidEncryptedData);
    }

    let mut data = encrypted.to_vec();

    // XOR decryption
    let key_stream = sha3_256_multi(&[b"ENCRYPT_STREAM", key]);
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key_stream[i % 32];
    }

    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let mut blinding = [0u8; 32];
    blinding.copy_from_slice(&data[8..40]);

    Ok((amount, blinding))
}

#[derive(Debug, thiserror::Error)]
pub enum StealthError {
    #[error("decapsulation failed")]
    DecapsulationFailed,
    #[error("output not for this recipient")]
    NotForRecipient,
    #[error("commitment does not match decrypted amount")]
    CommitmentMismatch,
    #[error("invalid encrypted data length")]
    InvalidEncryptedData,
}

#[cfg(test)]
mod tests {
    use super::*;
    use disentangle_crypto::kem::generate_kem_keypair;

    #[test]
    fn test_stealth_address_generation() {
        let (ek, _) = generate_kem_keypair();
        let (addr1, ct1, ss1) = generate_stealth_address(&ek);
        let (addr2, ct2, ss2) = generate_stealth_address(&ek);

        // Different invocations should produce different addresses
        assert_ne!(addr1, addr2);
        assert_ne!(ct1, ct2);
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_stealth_address_recovery() {
        let (ek, dk) = generate_kem_keypair();
        let (original_addr, ciphertext, _) = generate_stealth_address(&ek);

        let (recovered_addr, _) = recover_stealth_address(&dk, &ciphertext).unwrap();
        assert_eq!(original_addr, recovered_addr);
    }

    #[test]
    fn test_stealth_address_wrong_key() {
        let (ek1, _) = generate_kem_keypair();
        let (_, dk2) = generate_kem_keypair();

        let (original_addr, ciphertext, _) = generate_stealth_address(&ek1);
        let (recovered_addr, _) = recover_stealth_address(&dk2, &ciphertext).unwrap();

        // Different key should produce different address
        assert_ne!(original_addr, recovered_addr);
    }

    #[test]
    fn test_confidential_output_roundtrip() {
        let (ek, dk) = generate_kem_keypair();
        let amount = 5000u64;
        let blinding = [13u8; 32];

        let output = ConfidentialOutput::new(amount, blinding, &ek);
        let (decrypted_amount, decrypted_blinding) = output.try_decrypt(&dk).unwrap();

        assert_eq!(amount, decrypted_amount);
        assert_eq!(blinding, decrypted_blinding);
    }

    #[test]
    fn test_confidential_output_wrong_recipient() {
        let (ek1, _) = generate_kem_keypair();
        let (_, dk2) = generate_kem_keypair();

        let output = ConfidentialOutput::new(1000, [7u8; 32], &ek1);
        let result = output.try_decrypt(&dk2);

        assert!(result.is_err());
        match result {
            Err(StealthError::NotForRecipient) => {},
            _ => panic!("Expected NotForRecipient error"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let amount = 9999u64;
        let blinding = [99u8; 32];
        let key = [42u8; 32];

        let encrypted = encrypt_amount(amount, &blinding, &key);
        let (dec_amount, dec_blinding) = decrypt_amount(&encrypted, &key).unwrap();

        assert_eq!(amount, dec_amount);
        assert_eq!(blinding, dec_blinding);
    }

    #[test]
    fn test_decrypt_wrong_length() {
        let key = [1u8; 32];
        let wrong_data = vec![0u8; 30]; // Wrong length

        let result = decrypt_amount(&wrong_data, &key);
        assert!(result.is_err());
        match result {
            Err(StealthError::InvalidEncryptedData) => {},
            _ => panic!("Expected InvalidEncryptedData error"),
        }
    }
}
