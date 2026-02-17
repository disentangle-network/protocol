//! Merkle tree for account state commitments.
//!
//! Uses SHA3-256 for consistency with the rest of the Entangle protocol.
//! The tree commits to all account states, allowing ZK proofs of membership
//! and reputation claims.

use crate::types::AccountStateLeaf;
use crate::ZkpError;
use disentangle_crypto::hash::{sha3_256_multi, Hash256};
use serde::{Deserialize, Serialize};

/// A Merkle proof of membership for an account state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The leaf being proven
    pub leaf_hash: Hash256,
    /// Index of the leaf in the tree
    pub leaf_index: usize,
    /// Sibling hashes along the path to root (bottom to top)
    pub siblings: Vec<Hash256>,
    /// Direction bits: false = left, true = right
    pub path_bits: Vec<bool>,
}

impl MerkleProof {
    /// Verify this proof against a root.
    pub fn verify(&self, root: &Hash256) -> bool {
        let mut current = self.leaf_hash;

        for (sibling, &is_right) in self.siblings.iter().zip(self.path_bits.iter()) {
            current = if is_right {
                // Current node is on the right, sibling on left
                hash_pair(sibling, &current)
            } else {
                // Current node is on the left, sibling on right
                hash_pair(&current, sibling)
            };
        }

        current == *root
    }
}

/// Hash two nodes together with domain separation.
fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    sha3_256_multi(&[b"MERKLE_NODE_V1", left, right])
}

/// Hash a single node (for padding).
#[allow(dead_code)]
fn hash_leaf(data: &Hash256) -> Hash256 {
    sha3_256_multi(&[b"MERKLE_LEAF_V1", data])
}

/// Merkle tree of account states.
#[derive(Debug, Clone)]
pub struct AccountMerkleTree {
    /// Original leaves (hashed account states)
    leaves: Vec<Hash256>,
    /// All nodes in the tree, organized by level
    /// Level 0 = leaves, Level N = root
    levels: Vec<Vec<Hash256>>,
}

impl AccountMerkleTree {
    /// Build a new Merkle tree from account state leaves.
    /// Pads to next power of 2 with zero hashes.
    pub fn new(accounts: &[AccountStateLeaf]) -> Self {
        if accounts.is_empty() {
            return Self {
                leaves: vec![[0u8; 32]],
                levels: vec![vec![[0u8; 32]]],
            };
        }

        // Hash all account states to get leaves
        let mut leaves: Vec<Hash256> = accounts.iter().map(|a| a.hash()).collect();

        // Pad to next power of 2
        let target_len = leaves.len().next_power_of_two();
        let zero_leaf = [0u8; 32];
        while leaves.len() < target_len {
            leaves.push(zero_leaf);
        }

        // Build tree levels bottom-up
        let mut levels = vec![leaves.clone()];
        let mut current_level = leaves.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for chunk in current_level.chunks(2) {
                let parent = hash_pair(&chunk[0], &chunk[1]);
                next_level.push(parent);
            }
            levels.push(next_level.clone());
            current_level = next_level;
        }

        Self { leaves, levels }
    }

    /// Get the Merkle root.
    pub fn root(&self) -> Hash256 {
        self.levels
            .last()
            .and_then(|level| level.first().copied())
            .unwrap_or([0u8; 32])
    }

    /// Get the number of accounts in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Generate a membership proof for the account at given index.
    pub fn prove_membership(&self, index: usize) -> Result<MerkleProof, ZkpError> {
        if index >= self.leaves.len() {
            return Err(ZkpError::InvalidMerkleProof);
        }

        let mut siblings = Vec::new();
        let mut path_bits = Vec::new();
        let mut current_index = index;

        // Walk up the tree, collecting sibling nodes
        for level in 0..self.levels.len() - 1 {
            let is_right = current_index % 2 == 1;
            let sibling_index = if is_right {
                current_index - 1
            } else {
                current_index + 1
            };

            if sibling_index < self.levels[level].len() {
                siblings.push(self.levels[level][sibling_index]);
            } else {
                siblings.push([0u8; 32]); // Padding node
            }

            path_bits.push(is_right);
            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf_hash: self.leaves[index],
            leaf_index: index,
            siblings,
            path_bits,
        })
    }

    /// Verify a proof against this tree's root.
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        proof.verify(&self.root())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_account(id: u8, reputation: u64) -> AccountStateLeaf {
        AccountStateLeaf::new([id; 32], reputation, 10, 100)
    }

    #[test]
    fn test_empty_tree() {
        let tree = AccountMerkleTree::new(&[]);
        assert_eq!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_single_account() {
        let accounts = vec![make_test_account(1, 100)];
        let tree = AccountMerkleTree::new(&accounts);
        assert_ne!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_merkle_proof_valid() {
        let accounts = vec![
            make_test_account(1, 100),
            make_test_account(2, 200),
            make_test_account(3, 300),
            make_test_account(4, 400),
        ];
        let tree = AccountMerkleTree::new(&accounts);

        for i in 0..accounts.len() {
            let proof = tree.prove_membership(i).unwrap();
            assert!(tree.verify_proof(&proof), "Proof for index {} failed", i);
        }
    }

    #[test]
    fn test_merkle_proof_invalid_root() {
        let accounts = vec![make_test_account(1, 100), make_test_account(2, 200)];
        let tree = AccountMerkleTree::new(&accounts);
        let proof = tree.prove_membership(0).unwrap();

        // Verify against wrong root should fail
        let wrong_root = [0xFFu8; 32];
        assert!(!proof.verify(&wrong_root));
    }

    #[test]
    fn test_merkle_root_determinism() {
        let accounts = vec![make_test_account(1, 100), make_test_account(2, 200)];
        let tree1 = AccountMerkleTree::new(&accounts);
        let tree2 = AccountMerkleTree::new(&accounts);
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_merkle_root_changes_with_data() {
        let accounts1 = vec![make_test_account(1, 100)];
        let accounts2 = vec![make_test_account(1, 101)]; // Different reputation
        let tree1 = AccountMerkleTree::new(&accounts1);
        let tree2 = AccountMerkleTree::new(&accounts2);
        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_power_of_two_padding() {
        // 3 accounts should be padded to 4
        let accounts = vec![
            make_test_account(1, 100),
            make_test_account(2, 200),
            make_test_account(3, 300),
        ];
        let tree = AccountMerkleTree::new(&accounts);
        assert_eq!(tree.len(), 4); // Padded to power of 2

        // All original accounts should have valid proofs
        for i in 0..3 {
            let proof = tree.prove_membership(i).unwrap();
            assert!(tree.verify_proof(&proof));
        }
    }
}
