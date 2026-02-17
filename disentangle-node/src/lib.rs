//! # Disentangle Node v0.2
//!
//! Network node implementation for the Disentangle protocol.
//!
//! ## Changes from v0.1
//! - SHA2 → SHA3-256 for PoW
//! - Added coherence validation using structural SimHash

use sha3::{Sha3_256, Digest};
use disentangle_dag::{Transaction, NodeId};
use disentangle_crypto::hash::Hash256;
use disentangle_simhash::SimHash;

pub mod identity_state;
pub mod identity_rpc;

pub struct HelloWorldPoW {
    pub target: [u8; 32],
}

impl HelloWorldPoW {
    pub fn new(leading_zero_bits: u8) -> Self {
        let mut target = [0xFF; 32];
        let full_bytes = (leading_zero_bits / 8) as usize;
        let remaining_bits = leading_zero_bits % 8;
        for byte in target.iter_mut().take(full_bytes) {
            *byte = 0x00;
        }
        if remaining_bits > 0 && full_bytes < 32 {
            target[full_bytes] = 0xFF >> remaining_bits;
        }
        Self { target }
    }

    pub fn validate(&self, tx_header: &[u8], nonce: u64) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(tx_header);
        hasher.update(nonce.to_le_bytes());
        let hash = hasher.finalize();
        for (i, &target_byte) in self.target.iter().enumerate() {
            if hash[i] > target_byte {
                return false;
            }
            if hash[i] < target_byte {
                return true;
            }
        }
        true
    }

    pub fn mine(&self, tx_header: &[u8]) -> u64 {
        let mut nonce = 0u64;
        loop {
            if self.validate(tx_header, nonce) {
                return nonce;
            }
            nonce = nonce.wrapping_add(1);
        }
    }
}

pub struct MempoolEntry {
    pub tx: Transaction,
    pub received_at: u64,
    pub pow_valid: bool,
    pub coherent: bool,
    pub simhash_valid: bool,
}

pub struct Mempool {
    entries: std::collections::HashMap<NodeId, MempoolEntry>,
    pow: HelloWorldPoW,
}

impl Mempool {
    pub fn new(pow_difficulty: u8) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            pow: HelloWorldPoW::new(pow_difficulty),
        }
    }

    pub fn validate_and_insert(
        &mut self,
        tx: Transaction,
        nonce: u64,
        now: u64,
        _parent_simhashes: &[SimHash],  // Reserved: for future SimHash chain validation
        expected_history_root: &Hash256,
    ) -> Result<(), MempoolError> {
        let tx_header = self.serialize_header(&tx);
        if !self.pow.validate(&tx_header, nonce) {
            return Err(MempoolError::InvalidPoW);
        }
        let expected_simhash = SimHash::from_structural(
            &tx.parents.to_vec(),
            expected_history_root,
        );
        let simhash_valid = tx.simhash.is_coherent(&expected_simhash, disentangle_simhash::COHERENCE_THRESHOLD);
        let entry = MempoolEntry {
            tx: tx.clone(),
            received_at: now,
            pow_valid: true,
            coherent: true,
            simhash_valid,
        };
        self.entries.insert(tx.id, entry);
        Ok(())
    }

    fn serialize_header(&self, tx: &Transaction) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&tx.ephemeral_pk.to_bytes());
        for parent in &tx.parents {
            header.extend_from_slice(parent);
        }
        // No block field - transactions are purely topological now
        header.extend_from_slice(tx.nullifier.as_bytes());
        header
    }

    pub fn get_coherent_transactions(&self) -> Vec<&Transaction> {
        self.entries
            .values()
            .filter(|e| e.pow_valid && e.coherent && e.simhash_valid)
            .map(|e| &e.tx)
            .collect()
    }
    
    pub fn remove(&mut self, id: &NodeId) -> Option<MempoolEntry> {
        self.entries.remove(id)
    }
    
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("invalid proof of work")]
    InvalidPoW,
    #[error("invalid simhash - potential grinding attack")]
    InvalidSimHash,
    #[error("transaction already in mempool")]
    Duplicate,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_validation() {
        let pow = HelloWorldPoW::new(8);
        let header = b"test transaction header";
        let nonce = pow.mine(header);
        assert!(pow.validate(header, nonce));
        assert!(!pow.validate(header, nonce.wrapping_add(1)));
    }

    #[test]
    fn test_pow_difficulty_scaling() {
        let easy_pow = HelloWorldPoW::new(4);
        let hard_pow = HelloWorldPoW::new(16);
        let header = b"test";
        let easy_nonce = easy_pow.mine(header);
        let hard_nonce = hard_pow.mine(header);
        assert!(easy_pow.validate(header, easy_nonce));
        assert!(hard_pow.validate(header, hard_nonce));
    }
}
