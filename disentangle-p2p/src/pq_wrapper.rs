//! Post-Quantum Encrypted Stream Wrapper
//!
//! Wraps an existing transport stream with ChaCha20-Poly1305 AEAD encryption
//! using post-quantum derived session keys.

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use thiserror::Error;

/// Errors that can occur during PQ encryption/decryption
#[derive(Debug, Error)]
pub enum PqEncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Nonce overflow")]
    NonceOverflow,
    #[error("Invalid message format")]
    InvalidFormat,
}

/// Post-quantum encrypted stream wrapper
///
/// Uses ChaCha20-Poly1305 AEAD with PQ-derived keys for encryption.
/// Maintains separate nonce counters for send and receive directions.
pub struct PqEncryptedStream {
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
    send_nonce: u64,
    recv_nonce: u64,
}

impl PqEncryptedStream {
    /// Create a new PQ encrypted stream with session keys
    ///
    /// # Arguments
    /// * `send_key` - 32-byte key for encrypting outgoing messages
    /// * `recv_key` - 32-byte key for decrypting incoming messages
    pub fn new(send_key: &[u8; 32], recv_key: &[u8; 32]) -> Self {
        let send_cipher = ChaCha20Poly1305::new(GenericArray::from_slice(send_key));
        let recv_cipher = ChaCha20Poly1305::new(GenericArray::from_slice(recv_key));

        Self {
            send_cipher,
            recv_cipher,
            send_nonce: 0,
            recv_nonce: 0,
        }
    }

    /// Encrypt a message for sending
    ///
    /// Returns: encrypted message with authentication tag
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PqEncryptionError> {
        // Check for nonce overflow
        if self.send_nonce == u64::MAX {
            return Err(PqEncryptionError::NonceOverflow);
        }

        // Create 12-byte nonce from counter (96 bits)
        let nonce = self.create_nonce(self.send_nonce);

        // Encrypt with AEAD
        let ciphertext = self
            .send_cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| PqEncryptionError::EncryptionFailed)?;

        // Increment nonce counter
        self.send_nonce += 1;

        Ok(ciphertext)
    }

    /// Decrypt a received message
    ///
    /// Returns: decrypted plaintext
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, PqEncryptionError> {
        // Check for nonce overflow
        if self.recv_nonce == u64::MAX {
            return Err(PqEncryptionError::NonceOverflow);
        }

        // Create 12-byte nonce from counter
        let nonce = self.create_nonce(self.recv_nonce);

        // Decrypt with AEAD
        let plaintext = self
            .recv_cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| PqEncryptionError::DecryptionFailed)?;

        // Increment nonce counter
        self.recv_nonce += 1;

        Ok(plaintext)
    }

    /// Create a 12-byte nonce from a counter value
    ///
    /// ChaCha20-Poly1305 uses 96-bit (12-byte) nonces.
    /// We use the counter as an 8-byte value followed by 4 zero bytes.
    fn create_nonce(&self, counter: u64) -> GenericArray<u8, chacha20poly1305::aead::consts::U12> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&counter.to_le_bytes());
        *GenericArray::from_slice(&nonce_bytes)
    }

    /// Get current send nonce (for debugging/monitoring)
    pub fn send_nonce(&self) -> u64 {
        self.send_nonce
    }

    /// Get current receive nonce (for debugging/monitoring)
    pub fn recv_nonce(&self) -> u64 {
        self.recv_nonce
    }
}

/// Encrypt a single message (stateless version)
pub fn encrypt_message(
    key: &[u8; 32],
    nonce_counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, PqEncryptionError> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..8].copy_from_slice(&nonce_counter.to_le_bytes());
    let nonce = GenericArray::from_slice(&nonce_bytes);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| PqEncryptionError::EncryptionFailed)
}

/// Decrypt a single message (stateless version)
pub fn decrypt_message(
    key: &[u8; 32],
    nonce_counter: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, PqEncryptionError> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..8].copy_from_slice(&nonce_counter.to_le_bytes());
    let nonce = GenericArray::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| PqEncryptionError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let send_key = [1u8; 32];
        let recv_key = [2u8; 32];

        let mut sender = PqEncryptedStream::new(&send_key, &recv_key);
        let mut receiver = PqEncryptedStream::new(&recv_key, &send_key);

        let plaintext = b"Hello, quantum-resistant world!";

        // Encrypt with sender
        let ciphertext = sender.encrypt_message(plaintext).unwrap();

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

        // Decrypt with receiver
        let decrypted = receiver.decrypt_message(&ciphertext).unwrap();

        // Verify plaintext matches
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_multiple_messages() {
        let send_key = [3u8; 32];
        let recv_key = [4u8; 32];

        let mut sender = PqEncryptedStream::new(&send_key, &recv_key);
        let mut receiver = PqEncryptedStream::new(&recv_key, &send_key);

        let messages = [
            b"Message 1".to_vec(),
            b"Message 2".to_vec(),
            b"Message 3".to_vec(),
        ];

        for (i, msg) in messages.iter().enumerate() {
            let ciphertext = sender.encrypt_message(msg).unwrap();
            let decrypted = receiver.decrypt_message(&ciphertext).unwrap();
            assert_eq!(&decrypted, msg);
            assert_eq!(sender.send_nonce(), (i + 1) as u64);
            assert_eq!(receiver.recv_nonce(), (i + 1) as u64);
        }
    }

    #[test]
    fn test_nonce_increments() {
        let key = [5u8; 32];
        let mut stream = PqEncryptedStream::new(&key, &key);

        assert_eq!(stream.send_nonce(), 0);
        stream.encrypt_message(b"test").unwrap();
        assert_eq!(stream.send_nonce(), 1);
        stream.encrypt_message(b"test").unwrap();
        assert_eq!(stream.send_nonce(), 2);
    }

    #[test]
    fn test_different_keys_fail() {
        let send_key = [6u8; 32];
        let wrong_key = [7u8; 32];

        let mut sender = PqEncryptedStream::new(&send_key, &wrong_key);
        let mut receiver = PqEncryptedStream::new(&wrong_key, &wrong_key);

        let plaintext = b"Secret message";
        let ciphertext = sender.encrypt_message(plaintext).unwrap();

        // Decryption should fail with wrong key
        let result = receiver.decrypt_message(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_nonce_order_fails() {
        let key = [8u8; 32];
        let mut sender = PqEncryptedStream::new(&key, &key);

        let msg1 = b"First message";
        let msg2 = b"Second message";

        let ct1 = sender.encrypt_message(msg1).unwrap();
        let ct2 = sender.encrypt_message(msg2).unwrap();

        // Receiver expecting messages in order
        let mut receiver = PqEncryptedStream::new(&key, &key);

        // Try to decrypt second message first (wrong nonce)
        let result = receiver.decrypt_message(&ct2);
        assert!(result.is_err());

        // First message should work
        let decrypted = receiver.decrypt_message(&ct1).unwrap();
        assert_eq!(&decrypted, msg1);
    }

    #[test]
    fn test_stateless_encrypt_decrypt() {
        let key = [9u8; 32];
        let plaintext = b"Stateless test";
        let nonce = 42u64;

        let ciphertext = encrypt_message(&key, nonce, plaintext).unwrap();
        let decrypted = decrypt_message(&key, nonce, &ciphertext).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_stateless_different_nonces() {
        let key = [10u8; 32];
        let plaintext = b"Same message";

        let ct1 = encrypt_message(&key, 1, plaintext).unwrap();
        let ct2 = encrypt_message(&key, 2, plaintext).unwrap();

        // Different nonces produce different ciphertexts
        assert_ne!(ct1, ct2);

        // Each decrypts correctly with matching nonce
        let pt1 = decrypt_message(&key, 1, &ct1).unwrap();
        let pt2 = decrypt_message(&key, 2, &ct2).unwrap();

        assert_eq!(&pt1, plaintext);
        assert_eq!(&pt2, plaintext);

        // Wrong nonce fails
        assert!(decrypt_message(&key, 2, &ct1).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [11u8; 32];
        let plaintext = b"Authenticated message";

        let mut ciphertext = encrypt_message(&key, 0, plaintext).unwrap();

        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        // Decryption should fail due to authentication tag mismatch
        let result = decrypt_message(&key, 0, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_message() {
        let key = [12u8; 32];
        let plaintext = b"";

        let mut stream = PqEncryptedStream::new(&key, &key);
        let ciphertext = stream.encrypt_message(plaintext).unwrap();

        // Even empty messages have authentication tags
        assert!(!ciphertext.is_empty());

        let mut receiver = PqEncryptedStream::new(&key, &key);
        let decrypted = receiver.decrypt_message(&ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_large_message() {
        let key = [13u8; 32];
        let plaintext = vec![0x42u8; 10_000];

        let mut stream = PqEncryptedStream::new(&key, &key);
        let ciphertext = stream.encrypt_message(&plaintext).unwrap();

        let mut receiver = PqEncryptedStream::new(&key, &key);
        let decrypted = receiver.decrypt_message(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
