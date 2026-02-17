//! SHA3-256 Hashing for Entangle Protocol v0.2
//!
//! SHA3-256 provides:
//! - Output: 32 bytes (256 bits)
//! - Collision resistance: 128-bit (quantum), 256-bit (classical)
//! - NIST standardized (FIPS 202)
//!
//! Used for:
//! - Transaction IDs
//! - Merkle tree nodes
//! - SimHash seed derivation
//! - Nullifier computation

use sha3::{Sha3_256, Digest};
use serde::{Serialize, Deserialize};

pub const HASH_BYTES: usize = 32;

pub type Hash256 = [u8; HASH_BYTES];

pub fn sha3_256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; HASH_BYTES];
    hash.copy_from_slice(&result);
    hash
}

pub fn sha3_256_multi(parts: &[&[u8]]) -> Hash256 {
    let mut hasher = Sha3_256::new();
    for part in parts {
        hasher.update(part);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; HASH_BYTES];
    hash.copy_from_slice(&result);
    hash
}

pub fn sha3_256_domain(domain: &[u8], data: &[u8]) -> Hash256 {
    sha3_256_multi(&[domain, data])
}

pub fn compute_nullifier(secret_key_hash: &Hash256, epoch: u64, nonce: &[u8]) -> Hash256 {
    sha3_256_multi(&[
        b"NULLIFIER_V2",
        secret_key_hash,
        &epoch.to_le_bytes(),
        nonce,
    ])
}

pub fn compute_identity_leaf(public_key: &[u8], reputation_score: u64, tx_count: u64) -> Hash256 {
    sha3_256_multi(&[
        b"IDENTITY_LEAF_V2",
        public_key,
        &reputation_score.to_le_bytes(),
        &tx_count.to_le_bytes(),
    ])
}

pub fn merkle_parent(left: &Hash256, right: &Hash256) -> Hash256 {
    sha3_256_multi(&[b"MERKLE_NODE", left, right])
}

pub fn merkle_leaf(data: &[u8]) -> Hash256 {
    sha3_256_multi(&[b"MERKLE_LEAF", data])
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashDigest(pub Hash256);

impl HashDigest {
    pub fn new(data: &[u8]) -> Self {
        Self(sha3_256(data))
    }

    pub fn as_bytes(&self) -> &Hash256 {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != HASH_BYTES {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; HASH_BYTES];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Debug for HashDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash({})", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for HashDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for HashDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Hash256> for HashDigest {
    fn from(arr: Hash256) -> Self {
        Self(arr)
    }
}

impl From<HashDigest> for Hash256 {
    fn from(digest: HashDigest) -> Self {
        digest.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_determinism() {
        let data = b"test data for hashing";
        let h1 = sha3_256(data);
        let h2 = sha3_256(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha3_different_inputs() {
        let h1 = sha3_256(b"input 1");
        let h2 = sha3_256(b"input 2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_sha3_multi_equivalent() {
        let part1 = b"hello ";
        let part2 = b"world";
        let combined = b"hello world";
        let h_multi = sha3_256_multi(&[part1, part2]);
        let h_single = sha3_256(combined);
        assert_eq!(h_multi, h_single);
    }

    #[test]
    fn test_nullifier_derivation() {
        let sk_hash = sha3_256(b"secret key");
        let epoch = 100u64;
        let nonce = b"random nonce";
        let n1 = compute_nullifier(&sk_hash, epoch, nonce);
        let n2 = compute_nullifier(&sk_hash, epoch, nonce);
        assert_eq!(n1, n2);
        let n3 = compute_nullifier(&sk_hash, epoch + 1, nonce);
        assert_ne!(n1, n3);
    }

    #[test]
    fn test_merkle_operations() {
        let leaf1 = merkle_leaf(b"data1");
        let leaf2 = merkle_leaf(b"data2");
        let parent = merkle_parent(&leaf1, &leaf2);
        assert_ne!(leaf1, parent);
        assert_ne!(leaf2, parent);
        let parent_reversed = merkle_parent(&leaf2, &leaf1);
        assert_ne!(parent, parent_reversed);
    }

    #[test]
    fn test_hash_digest_hex_roundtrip() {
        let digest = HashDigest::new(b"test");
        let hex = digest.to_hex();
        let restored = HashDigest::from_hex(&hex).unwrap();
        assert_eq!(digest, restored);
    }
}
