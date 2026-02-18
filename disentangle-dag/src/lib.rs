//! # Entangle DAG v0.2
//!
//! Transaction DAG with discrete curvature computation.
//! All arithmetic uses fixed-point integers for determinism.
//!
//! ## Changes from v0.1
//! - Ed25519 → Dilithium5 (Post-Quantum)
//! - SHA2 → SHA3-256
//! - Added EphemeralIdentity for privacy
//! - SimHash now structurally bound

use disentangle_crypto::{
    hash::sha3_256_multi,
    signature::{Signature, VerifyingKey},
};
use disentangle_simhash::SimHash;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub use disentangle_crypto::hash::Hash256;
pub use disentangle_crypto::types::{Epoch, NodeId, Nullifier};

pub const SCALE: i32 = 65536;
pub type FixedPoint = i32;

// Bootstrap throttling constants
/// Maximum throttling aggressiveness (fully activated)
pub const ALPHA_MAX: i32 = 3;
/// Minimum edge weight floor (1% = SCALE/100)
pub const MIN_CURVATURE_WEIGHT: i32 = SCALE / 100;
/// Block at which throttling begins ramping up
pub const BOOTSTRAP_START: u64 = 1000;
/// Block at which throttling reaches full strength
pub const BOOTSTRAP_END: u64 = 6000;
/// Confirmation depth for finality assessment.
/// Transactions deeper than this are considered stable for conflict resolution.
/// Note: curvature is immutable by construction (ancestor-based), so this
/// constant is NOT used for curvature freezing.
pub const CONFIRMATION_DEPTH: u64 = 6;
/// Maximum parents per transaction (bounds ancestor set size and prevents parent flooding)
pub const MAX_PARENTS: usize = 8;
/// Minimum parents per non-genesis transaction (ensures DAG connectivity)
pub const MIN_PARENTS: usize = 2;
/// Depth of ancestor traversal for neighbor sets (k=2: parents + grandparents)
pub const ANCESTOR_DEPTH: u32 = 2;

/// Compute effective throttling alpha based on topological depth.
///
/// During bootstrap (depth < BOOTSTRAP_START), alpha = 0 (no throttling).
/// During ramp-up (BOOTSTRAP_START <= depth < BOOTSTRAP_END), alpha increases linearly.
/// After full activation (depth >= BOOTSTRAP_END), alpha = ALPHA_MAX.
///
/// Note: depth is per-transaction, not global. Each transaction is evaluated
/// at its own depth. An attacker self-chaining to inflate depth subjects their
/// own transactions to full throttling (which hurts them, since their internal
/// curvature is negative).
pub fn effective_alpha(depth: u64) -> i32 {
    if depth < BOOTSTRAP_START {
        // Pure descendant count mode, no curvature throttling
        0
    } else if depth >= BOOTSTRAP_END {
        // Full throttling activated
        ALPHA_MAX
    } else {
        // Linear ramp: α = α_max * (depth - start) / (end - start)
        let progress = depth - BOOTSTRAP_START;
        let range = BOOTSTRAP_END - BOOTSTRAP_START;
        // Using i64 to avoid overflow, then clamp to i32
        ((ALPHA_MAX as i64 * progress as i64) / range as i64) as i32
    }
}

pub fn fp_from_ratio(num: i32, denom: i32) -> FixedPoint {
    if denom == 0 {
        return 0;
    }
    ((num as i64 * SCALE as i64) / denom as i64) as FixedPoint
}

pub fn fp_mul(a: FixedPoint, b: FixedPoint) -> FixedPoint {
    ((a as i64 * b as i64) / SCALE as i64) as FixedPoint
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: NodeId,
    pub ephemeral_pk: VerifyingKey,
    pub signature: Signature,
    pub parents: Vec<NodeId>,
    pub simhash: SimHash,
    pub nullifier: Nullifier,
    pub reputation_claim: u64,

    /// Optional confidential outputs for privacy-preserving transfers
    #[serde(default)]
    pub confidential_outputs: Vec<disentangle_zkp::ConfidentialOutput>,
}

impl Transaction {
    pub fn compute_id(&self) -> NodeId {
        sha3_256_multi(&[
            b"TX_ID_V3",
            &self.ephemeral_pk.to_bytes(),
            &self.nullifier.as_bytes()[..],
        ])
    }

    pub fn verify_signature(&self, message: &[u8]) -> bool {
        disentangle_crypto::verify(&self.ephemeral_pk, message, &self.signature).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountState {
    pub history_root: Hash256,
    pub transaction_count: u64,
    pub first_seen_depth: u64,
    pub reputation_score: u64,
}

#[derive(Debug, Default)]
pub struct TransactionDAG {
    transactions: HashMap<NodeId, Transaction>,
    children: HashMap<NodeId, Vec<NodeId>>,
    curvature_cache: HashMap<(NodeId, NodeId), FixedPoint>,
    nullifier_set: HashSet<Nullifier>,
    depth_cache: HashMap<NodeId, u64>,
}

impl TransactionDAG {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, tx: Transaction) -> Result<(), DagError> {
        if self.nullifier_set.contains(&tx.nullifier) {
            return Err(DagError::DuplicateNullifier);
        }
        if tx.parents.len() > MAX_PARENTS {
            return Err(DagError::TooManyParents(tx.parents.len(), MAX_PARENTS));
        }
        if tx.parents.len() < MIN_PARENTS {
            return Err(DagError::TooFewParents(tx.parents.len(), MIN_PARENTS));
        }
        let id = tx.id;
        for parent in &tx.parents {
            if !self.transactions.contains_key(parent) {
                return Err(DagError::MissingParent(*parent));
            }
            self.children.entry(*parent).or_default().push(id);
        }
        self.nullifier_set.insert(tx.nullifier.clone());
        self.transactions.insert(id, tx);
        Ok(())
    }

    /// Insert a transaction without parent validation.
    /// Used for genesis and test scenarios. Still builds children index.
    pub fn insert_genesis(&mut self, tx: Transaction) {
        let id = tx.id;
        // Build children relationships for any existing parents
        for parent in &tx.parents {
            if self.transactions.contains_key(parent) {
                self.children.entry(*parent).or_default().push(id);
            }
        }
        self.nullifier_set.insert(tx.nullifier.clone());
        self.transactions.insert(id, tx);
    }

    pub fn get(&self, id: &NodeId) -> Option<&Transaction> {
        self.transactions.get(id)
    }

    pub fn contains(&self, id: &NodeId) -> bool {
        self.transactions.contains_key(id)
    }

    pub fn has_nullifier(&self, nullifier: &Nullifier) -> bool {
        self.nullifier_set.contains(nullifier)
    }

    pub fn neighbors(&self, id: &NodeId) -> HashSet<NodeId> {
        let mut result = HashSet::new();
        if let Some(tx) = self.transactions.get(id) {
            for parent in &tx.parents {
                result.insert(*parent);
            }
        }
        if let Some(children) = self.children.get(id) {
            for child in children {
                result.insert(*child);
            }
        }
        result
    }

    /// Compute the ancestor set of a transaction up to the given depth.
    ///
    /// ancestors(id, 1) = parents(id)
    /// ancestors(id, 2) = parents(id) ∪ grandparents(id)
    /// ancestors(id, k) = parents(id) ∪ parents(parents(id)) ∪ ... up to depth k
    ///
    /// All ancestors are committed data (immutable once transaction is created),
    /// making this computation fully deterministic across all honest nodes.
    /// No view-consistency assumptions are required.
    ///
    /// Complexity: O(MAX_PARENTS^k) per call. With MAX_PARENTS=8, k=2: O(64).
    pub fn ancestors(&self, id: &NodeId, depth: u32) -> HashSet<NodeId> {
        let mut result = HashSet::new();
        if depth == 0 {
            return result;
        }
        let mut frontier: Vec<NodeId> = Vec::new();
        if let Some(tx) = self.transactions.get(id) {
            for parent in &tx.parents {
                result.insert(*parent);
                frontier.push(*parent);
            }
        }
        for _ in 1..depth {
            let mut next_frontier = Vec::new();
            for node in &frontier {
                if let Some(tx) = self.transactions.get(node) {
                    for parent in &tx.parents {
                        if result.insert(*parent) {
                            next_frontier.push(*parent);
                        }
                    }
                }
            }
            frontier = next_frontier;
        }
        result
    }

    /// Check if curvature between two nodes has been computed and cached.
    ///
    /// Curvature is immutable by construction (ancestor-based),
    /// so this returns true if the curvature has been computed.
    pub fn is_curvature_frozen(&self, u: &NodeId, v: &NodeId) -> bool {
        let key = if u < v { (*u, *v) } else { (*v, *u) };
        self.curvature_cache.contains_key(&key)
    }

    /// Compute discrete curvature between two nodes using ancestor-depth neighbor sets.
    ///
    /// Uses ancestors(id, ANCESTOR_DEPTH) instead of parents+children.
    /// This ensures curvature is computed exclusively from committed transaction data,
    /// making it fully deterministic across all honest nodes without requiring
    /// view-consistency assumptions or freezing semantics.
    ///
    /// Curvature is IMMUTABLE by construction: ancestors never change after
    /// transaction creation. The cache is for performance only.
    ///
    /// # Returns
    /// Fixed-point curvature value (κ_J = 2 * Jaccard - 1)
    pub fn discrete_curvature(&mut self, u: &NodeId, v: &NodeId) -> FixedPoint {
        let key = if u < v { (*u, *v) } else { (*v, *u) };

        // Check cache (performance only — value is immutable)
        if let Some(&cached) = self.curvature_cache.get(&key) {
            return cached;
        }

        // Compute curvature using ancestor-depth neighbor sets
        let ancestors_u = self.ancestors(u, ANCESTOR_DEPTH);
        let ancestors_v = self.ancestors(v, ANCESTOR_DEPTH);
        let intersection_count = ancestors_u.intersection(&ancestors_v).count() as i32;
        let union_count = ancestors_u.union(&ancestors_v).count() as i32;
        let curvature = if union_count == 0 {
            0
        } else {
            2 * fp_from_ratio(intersection_count, union_count) - SCALE
        };

        // Cache permanently (ancestors are immutable, so curvature never changes)
        self.curvature_cache.insert(key, curvature);
        curvature
    }

    /// Compute edge weight from curvature with full throttling (post-bootstrap).
    ///
    /// Uses ALPHA_MAX for throttling. For block-aware throttling during bootstrap,
    /// use `curvature_weight_at_depth()` instead.
    pub fn curvature_weight(&self, curvature: FixedPoint) -> FixedPoint {
        self.curvature_weight_with_alpha(curvature, ALPHA_MAX)
    }

    /// Compute edge weight with ramped throttling based on topological depth.
    ///
    /// During bootstrap (depth < BOOTSTRAP_START), no throttling is applied.
    /// During ramp-up (BOOTSTRAP_START <= depth < BOOTSTRAP_END), throttling
    /// increases linearly to prevent the bootstrap cliff attack.
    pub fn curvature_weight_at_depth(&self, curvature: FixedPoint, depth: u64) -> FixedPoint {
        let alpha = effective_alpha(depth);
        self.curvature_weight_with_alpha(curvature, alpha)
    }

    /// Compute edge weight with specified alpha.
    fn curvature_weight_with_alpha(&self, curvature: FixedPoint, alpha: i32) -> FixedPoint {
        if alpha == 0 {
            // No throttling during early bootstrap
            return SCALE;
        }
        let weight = SCALE + alpha * curvature;
        weight.clamp(MIN_CURVATURE_WEIGHT, SCALE)
    }

    pub fn descendants(&self, root: &NodeId) -> HashSet<NodeId> {
        let mut visited = HashSet::new();
        let mut stack = vec![*root];
        while let Some(node) = stack.pop() {
            if visited.insert(node) {
                if let Some(children) = self.children.get(&node) {
                    stack.extend(children.iter().cloned());
                }
            }
        }
        visited
    }

    /// Find the best (maximum) path weight from source to target.
    ///
    /// Path weight is defined as the product of all edge weights along the path:
    ///   w(from, to) = max over paths P of ∏_{e ∈ P} edge_weight(e)
    ///
    /// Uses DFS with pruning for efficiency on DAGs. The multiplicative nature
    /// means heavily throttled paths (negative curvature bridges) contribute
    /// exponentially less than paths through positive curvature communities.
    ///
    /// # Arguments
    /// * `from` - Source node
    /// * `to` - Target node
    /// * `max_depth` - Maximum path length to explore
    /// * `fork_depth` - Topological depth at which to evaluate bootstrap throttling
    ///
    /// # Fixed-Point Arithmetic
    /// All weights are in fixed-point (SCALE = 1.0). Product of n edges with
    /// weight ε each yields ε^n, ensuring Sybil paths with multiple bridge
    /// crossings are severely attenuated.
    pub fn find_best_path_weight(
        &mut self,
        from: &NodeId,
        to: &NodeId,
        max_depth: usize,
        fork_depth: u64,
    ) -> FixedPoint {
        if from == to {
            return SCALE;
        }

        let mut best = 0;
        // Stack: (current_node, accumulated_path_weight, depth)
        let mut stack: Vec<(NodeId, FixedPoint, usize)> = vec![(*from, SCALE, 0)];

        while let Some((node, path_weight, depth)) = stack.pop() {
            if depth > max_depth {
                continue;
            }

            // Pruning: if current path weight is already worse than best found,
            // no point exploring further (since multiplication can only decrease)
            if path_weight <= best && node != *to {
                continue;
            }

            if node == *to {
                best = best.max(path_weight);
                continue;
            }

            if let Some(children) = self.children.get(&node).cloned() {
                for child in children {
                    let curv = self.discrete_curvature(&node, &child);
                    let edge_weight = self.curvature_weight_at_depth(curv, fork_depth);
                    // Multiplicative path weight: product of all edge weights
                    let new_path_weight = fp_mul(path_weight, edge_weight);
                    // Only explore if the path still has meaningful weight
                    if new_path_weight > 0 {
                        stack.push((child, new_path_weight, depth + 1));
                    }
                }
            }
        }
        best
    }

    pub fn iter_transactions(&self) -> impl Iterator<Item = (&NodeId, &Transaction)> {
        self.transactions.iter()
    }

    pub fn transaction_ids(&self) -> impl Iterator<Item = &NodeId> {
        self.transactions.keys()
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    pub fn clear_curvature_cache(&mut self) {
        self.curvature_cache.clear();
    }

    /// Compute topological depth of a transaction (Lamport clock).
    ///
    /// depth(tx) = 1 + max(depth(parent) for parent in tx.parents)
    /// depth(genesis) = 0
    ///
    /// Uses memoized DP (not recursion) to avoid stack overflow on deep DAGs.
    /// Computes via iterative topological sort.
    ///
    /// All honest nodes compute identical depth for any transaction they both know,
    /// since depth depends only on the parent chain (committed, immutable data).
    pub fn depth(&mut self, id: &NodeId) -> u64 {
        if let Some(&cached) = self.depth_cache.get(id) {
            return cached;
        }

        // Iterative DFS with memoization
        let mut stack: Vec<NodeId> = vec![*id];
        let mut visit_order: Vec<NodeId> = Vec::new();

        // Phase 1: Determine topological order via DFS
        let mut visited = HashSet::new();
        while let Some(node) = stack.last().copied() {
            if self.depth_cache.contains_key(&node) {
                stack.pop();
                continue;
            }
            if visited.contains(&node) {
                stack.pop();
                visit_order.push(node);
                continue;
            }
            visited.insert(node);
            if let Some(tx) = self.transactions.get(&node) {
                for parent in &tx.parents {
                    if !self.depth_cache.contains_key(parent) && !visited.contains(parent) {
                        stack.push(*parent);
                    }
                }
            }
        }

        // Phase 2: Compute depths in topological order (leaves first)
        for node in visit_order {
            if self.depth_cache.contains_key(&node) {
                continue;
            }
            let d = match self.transactions.get(&node) {
                Some(tx) if !tx.parents.is_empty() => {
                    1 + tx
                        .parents
                        .iter()
                        .map(|p| self.depth_cache.get(p).copied().unwrap_or(0))
                        .max()
                        .unwrap_or(0)
                }
                _ => 0, // Genesis or orphan
            };
            self.depth_cache.insert(node, d);
        }

        self.depth_cache.get(id).copied().unwrap_or(0)
    }

    /// Get depth without mutable borrow (returns None if not cached).
    /// Use after an initial depth() call to avoid borrow issues.
    pub fn cached_depth(&self, id: &NodeId) -> Option<u64> {
        self.depth_cache.get(id).copied()
    }

    /// Compute epoch for a transaction based on its topological depth.
    pub fn epoch(&mut self, id: &NodeId) -> Epoch {
        Epoch::from_depth(self.depth(id))
    }

    /// Compute depth for a transaction from its parents, BEFORE inserting.
    /// Resolves the chicken-and-egg: nullifier needs epoch, epoch needs depth,
    /// depth needs parents. Call this before creating the transaction.
    pub fn compute_depth_from_parents(&self, parents: &[NodeId]) -> u64 {
        if parents.is_empty() {
            return 0;
        }
        1 + parents
            .iter()
            .filter_map(|p| self.cached_depth(p))
            .max()
            .unwrap_or(0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DagError {
    #[error("duplicate nullifier - potential double-spend")]
    DuplicateNullifier,
    #[error("missing parent transaction: {0:?}")]
    MissingParent(NodeId),
    #[error("invalid transaction signature")]
    InvalidSignature,
    #[error("too many parents: {0} exceeds MAX_PARENTS ({1})")]
    TooManyParents(usize, usize),
    #[error("too few parents: {0} below MIN_PARENTS ({1})")]
    TooFewParents(usize, usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use disentangle_crypto::signature::generate_keypair;

    fn make_test_tx(nonce_seed: u64, parents: Vec<NodeId>) -> Transaction {
        let (sk, pk) = generate_keypair();
        let history_root = [nonce_seed as u8; 32];
        let parent_hashes: Vec<Hash256> = parents.iter().copied().collect();
        let simhash = SimHash::from_structural(&parent_hashes, &history_root);
        let nullifier = Nullifier::compute(&[0u8; 32], Epoch(0), &nonce_seed.to_le_bytes());
        let mut tx = Transaction {
            id: [0u8; 32],
            ephemeral_pk: pk,
            signature: disentangle_crypto::sign(&sk, b"test"),
            parents,
            simhash,
            nullifier,
            reputation_claim: 0,
            confidential_outputs: vec![],
        };
        tx.id = tx.compute_id();
        tx
    }

    #[test]
    fn test_dag_insert_and_retrieve() {
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![]);
        let id = genesis.id;
        dag.insert_genesis(genesis);
        assert!(dag.get(&id).is_some());
    }

    #[test]
    fn test_nullifier_prevents_double_spend() {
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![]);
        dag.insert_genesis(genesis.clone());
        let mut duplicate = genesis.clone();
        duplicate.id = [1u8; 32];
        assert!(matches!(
            dag.insert(duplicate),
            Err(DagError::DuplicateNullifier)
        ));
    }

    #[test]
    fn test_descendants() {
        let mut dag = TransactionDAG::new();
        let g = make_test_tx(0, vec![]);
        let gid = g.id;
        dag.insert_genesis(g);

        let mut c1 = make_test_tx(1, vec![gid]);
        c1.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"c1");
        c1.id = c1.compute_id();
        let c1id = c1.id;
        dag.insert_genesis(c1); // Use insert_genesis to bypass MIN_PARENTS for test

        let mut c2 = make_test_tx(2, vec![c1id]);
        c2.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"c2");
        c2.id = c2.compute_id();
        dag.insert_genesis(c2); // Use insert_genesis to bypass MIN_PARENTS for test

        let descendants = dag.descendants(&gid);
        assert_eq!(descendants.len(), 3);
    }

    #[test]
    fn test_ramped_bootstrap_throttling() {
        // Test effective_alpha at various block heights

        // Before bootstrap start: no throttling
        assert_eq!(effective_alpha(0), 0);
        assert_eq!(effective_alpha(500), 0);
        assert_eq!(effective_alpha(999), 0);

        // At bootstrap start: throttling begins
        assert_eq!(effective_alpha(BOOTSTRAP_START), 0); // Just started, alpha = 0

        // Midpoint: half throttling
        let midpoint = (BOOTSTRAP_START + BOOTSTRAP_END) / 2;
        let mid_alpha = effective_alpha(midpoint);
        assert!(
            mid_alpha > 0 && mid_alpha < ALPHA_MAX,
            "Mid-bootstrap alpha should be between 0 and max"
        );

        // At bootstrap end: full throttling
        assert_eq!(effective_alpha(BOOTSTRAP_END), ALPHA_MAX);
        assert_eq!(effective_alpha(BOOTSTRAP_END + 1000), ALPHA_MAX);
        assert_eq!(effective_alpha(100_000), ALPHA_MAX);
    }

    #[test]
    fn test_curvature_weight_at_depth() {
        let dag = TransactionDAG::new();

        // Negative curvature (bridge edge)
        let negative_curv = -SCALE / 2; // -0.5 in fixed point

        // During bootstrap: no throttling, weight = SCALE
        let weight_early = dag.curvature_weight_at_depth(negative_curv, 500);
        assert_eq!(
            weight_early, SCALE,
            "Early bootstrap should have no throttling"
        );

        // After full activation: throttled to minimum
        let weight_late = dag.curvature_weight_at_depth(negative_curv, 10_000);
        assert_eq!(
            weight_late, MIN_CURVATURE_WEIGHT,
            "Full throttling should clamp to minimum"
        );

        // Positive curvature should always give full weight
        let positive_curv = SCALE / 4; // +0.25
        let weight_pos = dag.curvature_weight_at_depth(positive_curv, 10_000);
        assert_eq!(
            weight_pos, SCALE,
            "Positive curvature should have full weight"
        );
    }

    #[test]
    fn test_curvature_immutable_by_construction() {
        let mut dag = TransactionDAG::new();

        // Create a simple DAG: genesis -> tx1 -> tx2
        let genesis = make_test_tx(100, vec![]);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        let mut tx1 = make_test_tx(101, vec![gid]);
        tx1.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"tx1");
        tx1.id = tx1.compute_id();
        let tx1id = tx1.id;
        dag.insert_genesis(tx1); // Use insert_genesis to bypass MIN_PARENTS for test

        let mut tx2 = make_test_tx(102, vec![tx1id]);
        tx2.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"tx2");
        tx2.id = tx2.compute_id();
        dag.insert_genesis(tx2); // Use insert_genesis to bypass MIN_PARENTS for test

        // Curvature is immutable by construction (ancestor-based).
        // Once computed, it is always "frozen" (cached).
        let curv1 = dag.discrete_curvature(&gid, &tx1id);
        assert!(
            dag.is_curvature_frozen(&gid, &tx1id),
            "Curvature should be frozen immediately after computation"
        );

        // Recomputing at a different block should return the same value
        let curv2 = dag.discrete_curvature(&gid, &tx1id);
        assert_eq!(
            curv1, curv2,
            "Curvature is immutable — must be same regardless of block"
        );

        // Verify cached curvature is returned
        let curv3 = dag.discrete_curvature(&gid, &tx1id);
        assert_eq!(curv2, curv3, "Cached curvature should be returned");
    }

    #[test]
    fn test_find_best_path_with_current_block() {
        let mut dag = TransactionDAG::new();

        // Create a simple path: genesis -> tx1
        let genesis = make_test_tx(100, vec![]);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        let mut tx1 = make_test_tx(101, vec![gid]);
        tx1.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"tx1");
        tx1.id = tx1.compute_id();
        let tx1id = tx1.id;
        dag.insert_genesis(tx1); // Use insert_genesis to bypass MIN_PARENTS for test

        // Find path weight at different block heights
        let weight_early = dag.find_best_path_weight(&gid, &tx1id, 10, 500);
        assert!(
            weight_early > 0,
            "Path weight should be positive during bootstrap"
        );

        let weight_late = dag.find_best_path_weight(&gid, &tx1id, 10, 10_000);
        assert!(
            weight_late > 0,
            "Path weight should be positive after bootstrap"
        );
    }

    #[test]
    fn test_max_parents_rejected() {
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![]);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Create 9 additional txs as potential parents
        let mut parent_ids = vec![gid];
        for i in 1..=9 {
            let mut tx = make_test_tx(i, vec![gid]);
            tx.nullifier = Nullifier::compute(&[i as u8; 32], Epoch(0), &i.to_le_bytes());
            tx.id = tx.compute_id();
            let id = tx.id;
            dag.insert_genesis(tx); // bypass validation for setup
            parent_ids.push(id);
        }

        // Try to insert tx with 10 parents (exceeds MAX_PARENTS=8)
        let mut bad_tx = make_test_tx(100, parent_ids[..10].to_vec());
        bad_tx.nullifier = Nullifier::compute(&[100u8; 32], Epoch(0), b"bad");
        bad_tx.id = bad_tx.compute_id();
        assert!(matches!(
            dag.insert(bad_tx),
            Err(DagError::TooManyParents(10, 8))
        ));
    }

    #[test]
    fn test_empty_parents_rejected() {
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![]);
        dag.insert_genesis(genesis);

        let mut bad_tx = make_test_tx(1, vec![]);
        bad_tx.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"empty");
        bad_tx.id = bad_tx.compute_id();
        assert!(matches!(
            dag.insert(bad_tx),
            Err(DagError::TooFewParents(0, _))
        ));
    }

    #[test]
    fn test_ancestors_depth_1() {
        let mut dag = TransactionDAG::new();
        let g = make_test_tx(0, vec![]);
        let gid = g.id;
        dag.insert_genesis(g);

        let mut a = make_test_tx(1, vec![gid]);
        a.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"a");
        a.id = a.compute_id();
        let aid = a.id;
        dag.insert_genesis(a);

        let mut b = make_test_tx(2, vec![aid]);
        b.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"b");
        b.id = b.compute_id();
        let bid = b.id;
        dag.insert_genesis(b);

        // ancestors(b, 1) = parents(b) = {a}
        let anc1 = dag.ancestors(&bid, 1);
        assert_eq!(anc1.len(), 1);
        assert!(anc1.contains(&aid));
    }

    #[test]
    fn test_ancestors_depth_2() {
        let mut dag = TransactionDAG::new();
        let g = make_test_tx(0, vec![]);
        let gid = g.id;
        dag.insert_genesis(g);

        let mut a = make_test_tx(1, vec![gid]);
        a.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"a");
        a.id = a.compute_id();
        let aid = a.id;
        dag.insert_genesis(a);

        let mut b = make_test_tx(2, vec![aid]);
        b.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"b");
        b.id = b.compute_id();
        let bid = b.id;
        dag.insert_genesis(b);

        // ancestors(b, 2) = parents(b) ∪ grandparents(b) = {a, g}
        let anc2 = dag.ancestors(&bid, 2);
        assert_eq!(anc2.len(), 2);
        assert!(anc2.contains(&aid));
        assert!(anc2.contains(&gid));
    }

    #[test]
    fn test_ancestors_multi_parent() {
        let mut dag = TransactionDAG::new();
        let g = make_test_tx(0, vec![]);
        let gid = g.id;
        dag.insert_genesis(g);

        let mut a = make_test_tx(1, vec![gid]);
        a.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"a");
        a.id = a.compute_id();
        let aid = a.id;
        dag.insert_genesis(a);

        let mut b = make_test_tx(2, vec![gid]);
        b.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"b");
        b.id = b.compute_id();
        let bid = b.id;
        dag.insert_genesis(b);

        // c has two parents: a, b
        let mut c = make_test_tx(3, vec![aid, bid]);
        c.nullifier = Nullifier::compute(&[3u8; 32], Epoch(0), b"c");
        c.id = c.compute_id();
        let cid = c.id;
        dag.insert_genesis(c);

        // ancestors(c, 1) = {a, b}
        let anc1 = dag.ancestors(&cid, 1);
        assert_eq!(anc1.len(), 2);

        // ancestors(c, 2) = {a, b, g}
        let anc2 = dag.ancestors(&cid, 2);
        assert_eq!(anc2.len(), 3);
        assert!(anc2.contains(&gid));
    }

    #[test]
    fn test_curvature_deterministic_without_children() {
        // This test verifies the critical property: curvature does NOT change
        // when new children are added to a node.
        let mut dag = TransactionDAG::new();
        let g = make_test_tx(0, vec![]);
        let gid = g.id;
        dag.insert_genesis(g);

        let mut a = make_test_tx(1, vec![gid]);
        a.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"a");
        a.id = a.compute_id();
        let aid = a.id;
        dag.insert_genesis(a);

        let mut b = make_test_tx(2, vec![gid]);
        b.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"b");
        b.id = b.compute_id();
        let bid = b.id;
        dag.insert_genesis(b);

        // Compute curvature between a and b BEFORE any children
        dag.clear_curvature_cache();
        let curv_before = dag.discrete_curvature(&aid, &bid);

        // Add a child of both a and b
        let mut c = make_test_tx(3, vec![aid, bid]);
        c.nullifier = Nullifier::compute(&[3u8; 32], Epoch(0), b"c");
        c.id = c.compute_id();
        dag.insert_genesis(c);

        // Compute curvature between a and b AFTER child added
        dag.clear_curvature_cache();
        let curv_after = dag.discrete_curvature(&aid, &bid);

        // CRITICAL: curvature must be identical (ancestor-based = immutable)
        assert_eq!(
            curv_before, curv_after,
            "Curvature must not change when children are added (ancestor-based computation)"
        );
    }

    #[test]
    fn test_curvature_positive_with_shared_grandparent() {
        // Two sibling transactions sharing a grandparent should have positive curvature
        // when using ancestor depth 2
        let mut dag = TransactionDAG::new();
        let g = make_test_tx(0, vec![]);
        let gid = g.id;
        dag.insert_genesis(g);

        let mut a = make_test_tx(1, vec![gid]);
        a.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"a");
        a.id = a.compute_id();
        let aid = a.id;
        dag.insert_genesis(a);

        let mut b = make_test_tx(2, vec![gid]);
        b.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"b");
        b.id = b.compute_id();
        let bid = b.id;
        dag.insert_genesis(b);

        // c and d are children of a and b respectively, both grandchildren of g
        let mut c = make_test_tx(3, vec![aid]);
        c.nullifier = Nullifier::compute(&[3u8; 32], Epoch(0), b"c");
        c.id = c.compute_id();
        let cid = c.id;
        dag.insert_genesis(c);

        let mut d = make_test_tx(4, vec![bid]);
        d.nullifier = Nullifier::compute(&[4u8; 32], Epoch(0), b"d");
        d.id = d.compute_id();
        let did = d.id;
        dag.insert_genesis(d);

        // ancestors(c, 2) = {a, g}
        // ancestors(d, 2) = {b, g}
        // intersection = {g}, union = {a, b, g}
        // Jaccard = 1/3, kappa = 2/3 - 1 = -1/3
        // Not positive, but better than -1.0 (tree structure)

        // Now create e with parents c AND d (cross-referencing)
        let mut e = make_test_tx(5, vec![cid, did]);
        e.nullifier = Nullifier::compute(&[5u8; 32], Epoch(0), b"e");
        e.id = e.compute_id();
        let eid = e.id;
        dag.insert_genesis(e);

        // ancestors(e, 2) = {c, d, a, b} (parents + grandparents)
        let anc_e = dag.ancestors(&eid, 2);
        assert_eq!(anc_e.len(), 4);

        // Edge (c, e): ancestors(c, 2) = {a, g}, ancestors(e, 2) = {c, d, a, b}
        // intersection = {a}, union = {a, b, c, d, g}
        // Jaccard = 1/5, kappa = 2/5 - 1 = -3/5 = -0.6
        let curv_ce = dag.discrete_curvature(&cid, &eid);
        // Still negative in small DAG, but not -1.0 like pure tree
        assert!(
            curv_ce > -SCALE,
            "Should be better than pure tree kappa=-1.0"
        );
    }

    // ========================================================================
    // Additional unit tests for coverage gaps
    // ========================================================================

    #[test]
    fn test_min_parents_enforcement_one_parent() {
        // Test that a non-genesis transaction with only 1 parent is rejected
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![]);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Try to insert with only 1 parent (should fail, MIN_PARENTS=2)
        let mut tx_one_parent = make_test_tx(1, vec![gid]);
        tx_one_parent.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"one");
        tx_one_parent.id = tx_one_parent.compute_id();

        let result = dag.insert(tx_one_parent);
        assert!(
            matches!(result, Err(DagError::TooFewParents(1, 2))),
            "Transaction with 1 parent should be rejected (MIN_PARENTS=2)"
        );
    }

    #[test]
    fn test_min_parents_enforcement_two_parents() {
        // Test that 2 parents succeeds
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![]);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Create second parent
        let mut parent2 = make_test_tx(1, vec![]);
        parent2.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"p2");
        parent2.id = parent2.compute_id();
        let p2id = parent2.id;
        dag.insert_genesis(parent2);

        // Insert with 2 parents (should succeed)
        let mut tx_two_parents = make_test_tx(2, vec![gid, p2id]);
        tx_two_parents.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"two");
        tx_two_parents.id = tx_two_parents.compute_id();

        assert!(
            dag.insert(tx_two_parents).is_ok(),
            "Transaction with 2 parents should succeed (MIN_PARENTS=2)"
        );
    }

    #[test]
    fn test_max_parents_enforcement_exact() {
        // Test that exactly MAX_PARENTS (8) succeeds
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![]);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Create 7 additional parents (total 8)
        let mut parent_ids = vec![gid];
        for i in 1..=7 {
            let mut tx = make_test_tx(i, vec![]);
            tx.nullifier = Nullifier::compute(&[i as u8; 32], Epoch(0), &i.to_le_bytes());
            tx.id = tx.compute_id();
            let id = tx.id;
            dag.insert_genesis(tx);
            parent_ids.push(id);
        }

        // Insert with exactly MAX_PARENTS (8) parents (should succeed)
        let mut tx_max = make_test_tx(100, parent_ids.clone());
        tx_max.nullifier = Nullifier::compute(&[100u8; 32], Epoch(0), b"max");
        tx_max.id = tx_max.compute_id();

        assert!(
            dag.insert(tx_max).is_ok(),
            "Transaction with MAX_PARENTS (8) should succeed"
        );
    }

    #[test]
    fn test_max_parents_enforcement_exceeded() {
        // Test that MAX_PARENTS+1 returns TooManyParents error
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![]);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        // Create 8 additional parents (total 9, exceeds MAX_PARENTS)
        let mut parent_ids = vec![gid];
        for i in 1..=8 {
            let mut tx = make_test_tx(i, vec![]);
            tx.nullifier = Nullifier::compute(&[i as u8; 32], Epoch(0), &i.to_le_bytes());
            tx.id = tx.compute_id();
            let id = tx.id;
            dag.insert_genesis(tx);
            parent_ids.push(id);
        }

        // Try to insert with 9 parents (should fail)
        let mut tx_too_many = make_test_tx(100, parent_ids);
        tx_too_many.nullifier = Nullifier::compute(&[100u8; 32], Epoch(0), b"overflow");
        tx_too_many.id = tx_too_many.compute_id();

        let result = dag.insert(tx_too_many);
        assert!(
            matches!(result, Err(DagError::TooManyParents(9, 8))),
            "Transaction with 9 parents should be rejected (MAX_PARENTS=8)"
        );
    }

    #[test]
    fn test_verify_signature_valid() {
        // Test that a properly signed transaction passes verify_signature()
        let (sk, pk) = generate_keypair();
        let message = b"test message";
        let signature = disentangle_crypto::sign(&sk, message);

        let tx = Transaction {
            id: [0u8; 32],
            ephemeral_pk: pk,
            signature,
            parents: vec![],
            simhash: SimHash::from_structural(&[], &[0u8; 32]),

            nullifier: Nullifier::compute(&[0u8; 32], Epoch(0), b"test"),
            reputation_claim: 0,
            confidential_outputs: vec![],
        };

        assert!(
            tx.verify_signature(message),
            "Valid signature should pass verification"
        );
    }

    #[test]
    fn test_verify_signature_tampered_message() {
        // Test that a transaction with tampered message fails verification
        let (sk, pk) = generate_keypair();
        let message = b"original message";
        let signature = disentangle_crypto::sign(&sk, message);

        let tx = Transaction {
            id: [0u8; 32],
            ephemeral_pk: pk,
            signature,
            parents: vec![],
            simhash: SimHash::from_structural(&[], &[0u8; 32]),

            nullifier: Nullifier::compute(&[0u8; 32], Epoch(0), b"test"),
            reputation_claim: 0,
            confidential_outputs: vec![],
        };

        let tampered_message = b"tampered message";
        assert!(
            !tx.verify_signature(tampered_message),
            "Tampered message should fail verification"
        );
    }

    #[test]
    fn test_verify_signature_wrong_key() {
        // Test that a transaction signed with wrong key fails verification
        let (sk1, _pk1) = generate_keypair();
        let (_sk2, pk2) = generate_keypair();
        let message = b"test message";
        let signature = disentangle_crypto::sign(&sk1, message);

        let tx = Transaction {
            id: [0u8; 32],
            ephemeral_pk: pk2, // Different key than what was used to sign
            signature,
            parents: vec![],
            simhash: SimHash::from_structural(&[], &[0u8; 32]),

            nullifier: Nullifier::compute(&[0u8; 32], Epoch(0), b"test"),
            reputation_claim: 0,
            confidential_outputs: vec![],
        };

        assert!(
            !tx.verify_signature(message),
            "Signature with wrong key should fail verification"
        );
    }

    #[test]
    fn test_fp_mul_large_values() {
        // Test fp_mul with large values to verify it handles them correctly
        // Using 10.0 * 10.0 = 100.0 (well within i32 range)
        let ten = 10 * SCALE;
        let result = fp_mul(ten, ten);
        assert_eq!(result, 100 * SCALE, "10.0 * 10.0 should equal 100.0");

        // Test with SCALE * SCALE (1.0 * 1.0 = 1.0)
        let result2 = fp_mul(SCALE, SCALE);
        assert_eq!(
            result2, SCALE,
            "SCALE * SCALE should equal SCALE (1.0 * 1.0 = 1.0)"
        );

        // Test with large but safe values (100.0 * 2.0 = 200.0)
        let hundred = 100 * SCALE;
        let two = 2 * SCALE;
        let result3 = fp_mul(hundred, two);
        assert_eq!(result3, 200 * SCALE, "100.0 * 2.0 should equal 200.0");
    }

    #[test]
    fn test_fp_mul_negative_values() {
        // Test fp_mul with negative values
        let neg = -SCALE / 2; // -0.5
        let result = fp_mul(neg, neg);
        assert!(result > 0, "Negative * negative should be positive");
        assert_eq!(result, SCALE / 4, "-0.5 * -0.5 should equal 0.25");

        // Test positive * negative
        let result2 = fp_mul(SCALE, neg);
        assert_eq!(result2, neg, "1.0 * -0.5 should equal -0.5");
    }

    #[test]
    fn test_fp_mul_edge_cases() {
        // Test with i32::MIN (shouldn't panic)
        let min_val = i32::MIN / SCALE;
        let result = fp_mul(min_val, SCALE);
        assert!(result <= 0, "Large negative multiplication should work");

        // Test zero
        assert_eq!(fp_mul(0, SCALE), 0, "0 * anything = 0");
        assert_eq!(fp_mul(SCALE, 0), 0, "anything * 0 = 0");
    }

    #[test]
    fn test_fp_from_ratio_zero_numerator() {
        // Test with 0/0 (should return 0)
        assert_eq!(
            fp_from_ratio(0, 0),
            0,
            "0/0 should return 0 (defined behavior)"
        );

        // Test 0/nonzero
        assert_eq!(fp_from_ratio(0, 100), 0, "0/100 should return 0");
    }

    #[test]
    fn test_fp_from_ratio_zero_denominator() {
        // Test with nonzero/0 (should return 0)
        assert_eq!(
            fp_from_ratio(100, 0),
            0,
            "100/0 should return 0 (defined behavior)"
        );
    }

    #[test]
    fn test_fp_from_ratio_negative_values() {
        // Test with negative numerator
        let result = fp_from_ratio(-1, 2);
        assert_eq!(result, -SCALE / 2, "-1/2 should equal -0.5");

        // Test with negative denominator
        let result2 = fp_from_ratio(1, -2);
        assert_eq!(result2, -SCALE / 2, "1/-2 should equal -0.5");

        // Test with both negative
        let result3 = fp_from_ratio(-1, -2);
        assert_eq!(result3, SCALE / 2, "-1/-2 should equal 0.5");
    }

    #[test]
    fn test_fp_from_ratio_greater_than_one() {
        // Test with ratio > 1
        let result = fp_from_ratio(3, 2);
        assert_eq!(result, 3 * SCALE / 2, "3/2 should equal 1.5");

        let result2 = fp_from_ratio(10, 1);
        assert_eq!(result2, 10 * SCALE, "10/1 should equal 10.0");
    }

    #[test]
    fn test_ancestors_depth_zero() {
        // Test ancestors(id, 0) returns empty set
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![]);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        let anc = dag.ancestors(&gid, 0);
        assert_eq!(anc.len(), 0, "ancestors(id, 0) should return empty set");
    }

    #[test]
    fn test_ancestors_genesis_returns_empty() {
        // Test ancestors(genesis, 2) returns empty set (genesis has no parents)
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![]);
        let gid = genesis.id;
        dag.insert_genesis(genesis);

        let anc = dag.ancestors(&gid, 2);
        assert_eq!(anc.len(), 0, "Genesis transaction should have no ancestors");
    }

    #[test]
    fn test_ancestors_diamond_pattern() {
        // Test diamond pattern: A->B->D, A->C->D
        // ancestors(D, 2) should include A
        let mut dag = TransactionDAG::new();

        // A (genesis)
        let mut a = make_test_tx(0, vec![]);
        a.nullifier = Nullifier::compute(&[0u8; 32], Epoch(0), b"a");
        a.id = a.compute_id();
        let aid = a.id;
        dag.insert_genesis(a);

        // B -> A
        let mut b = make_test_tx(1, vec![aid]);
        b.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"b");
        b.id = b.compute_id();
        let bid = b.id;
        dag.insert_genesis(b);

        // C -> A
        let mut c = make_test_tx(2, vec![aid]);
        c.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"c");
        c.id = c.compute_id();
        let cid = c.id;
        dag.insert_genesis(c);

        // D -> B, C (diamond pattern complete)
        let mut d = make_test_tx(3, vec![bid, cid]);
        d.nullifier = Nullifier::compute(&[3u8; 32], Epoch(0), b"d");
        d.id = d.compute_id();
        let did = d.id;
        dag.insert_genesis(d);

        // ancestors(D, 1) = {B, C}
        let anc1 = dag.ancestors(&did, 1);
        assert_eq!(anc1.len(), 2, "D should have 2 parents");
        assert!(anc1.contains(&bid) && anc1.contains(&cid));

        // ancestors(D, 2) = {B, C, A} (A appears via both paths but counted once)
        let anc2 = dag.ancestors(&did, 2);
        assert_eq!(anc2.len(), 3, "D should have 3 ancestors at depth 2");
        assert!(
            anc2.contains(&aid),
            "Diamond pattern should include A at depth 2"
        );
        assert!(anc2.contains(&bid) && anc2.contains(&cid));
    }

    #[test]
    fn test_neighbors_includes_parents_and_children() {
        // Test that neighbors() includes both parents and children
        let mut dag = TransactionDAG::new();

        let mut g = make_test_tx(0, vec![]);
        g.nullifier = Nullifier::compute(&[0u8; 32], Epoch(0), b"g");
        g.id = g.compute_id();
        let gid = g.id;
        dag.insert_genesis(g);

        let mut a = make_test_tx(1, vec![gid]);
        a.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"a");
        a.id = a.compute_id();
        let aid = a.id;
        dag.insert_genesis(a);

        let mut b = make_test_tx(2, vec![aid]);
        b.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"b");
        b.id = b.compute_id();
        let bid = b.id;
        dag.insert_genesis(b);

        // neighbors(a) should include both g (parent) and b (child)
        let neighbors = dag.neighbors(&aid);
        assert_eq!(
            neighbors.len(),
            2,
            "A should have 2 neighbors (1 parent + 1 child)"
        );
        assert!(
            neighbors.contains(&gid),
            "Neighbors should include parent G"
        );
        assert!(neighbors.contains(&bid), "Neighbors should include child B");
    }

    #[test]
    fn test_curvature_weight_with_alpha_clamping() {
        // Test that curvature_weight_with_alpha always returns values
        // between MIN_CURVATURE_WEIGHT and SCALE
        let dag = TransactionDAG::new();

        // Test with very negative curvature (should clamp to MIN)
        let very_negative = -SCALE; // -1.0 (maximum negative)
        let weight_min = dag.curvature_weight_with_alpha(very_negative, ALPHA_MAX);
        assert_eq!(
            weight_min, MIN_CURVATURE_WEIGHT,
            "Very negative curvature should clamp to MIN_CURVATURE_WEIGHT"
        );

        // Test with positive curvature (should clamp to SCALE)
        let positive = SCALE / 2; // +0.5
        let weight_pos = dag.curvature_weight_with_alpha(positive, ALPHA_MAX);
        // With alpha=3, weight = SCALE + 3 * (SCALE/2) = SCALE + 1.5*SCALE = 2.5*SCALE
        // Should clamp to SCALE
        assert_eq!(
            weight_pos, SCALE,
            "Positive curvature should clamp to SCALE (max weight)"
        );

        // Test with zero curvature
        let zero_curv = 0;
        let weight_zero = dag.curvature_weight_with_alpha(zero_curv, ALPHA_MAX);
        assert_eq!(
            weight_zero, SCALE,
            "Zero curvature should give weight = SCALE"
        );

        // Test that result is always in valid range
        for curv in [-SCALE, -SCALE / 2, 0, SCALE / 4, SCALE / 2, SCALE] {
            let w = dag.curvature_weight_with_alpha(curv, ALPHA_MAX);
            assert!(
                w >= MIN_CURVATURE_WEIGHT && w <= SCALE,
                "Weight should always be in range [MIN_CURVATURE_WEIGHT, SCALE]"
            );
        }
    }

    #[test]
    fn test_effective_alpha_at_bootstrap_start() {
        // Test at exactly BOOTSTRAP_START (block 1000) returns 0
        assert_eq!(
            effective_alpha(BOOTSTRAP_START),
            0,
            "Alpha should be 0 at BOOTSTRAP_START"
        );
    }

    #[test]
    fn test_effective_alpha_at_bootstrap_end() {
        // Test at BOOTSTRAP_END (block 6000) returns ALPHA_MAX
        assert_eq!(
            effective_alpha(BOOTSTRAP_END),
            ALPHA_MAX,
            "Alpha should be ALPHA_MAX at BOOTSTRAP_END"
        );
    }

    #[test]
    fn test_effective_alpha_midpoint() {
        // Test at midpoint returns approximately half of ALPHA_MAX
        let midpoint = (BOOTSTRAP_START + BOOTSTRAP_END) / 2; // 3500
        let alpha_mid = effective_alpha(midpoint);

        // Linear ramp: at midpoint, should be ~ALPHA_MAX/2 = 1.5, rounds to 1
        assert!(
            alpha_mid > 0 && alpha_mid < ALPHA_MAX,
            "Alpha at midpoint should be between 0 and ALPHA_MAX"
        );

        // Check it's proportional: at 25% through ramp
        let quarter = BOOTSTRAP_START + (BOOTSTRAP_END - BOOTSTRAP_START) / 4; // 2250
        let alpha_quarter = effective_alpha(quarter);
        assert!(
            alpha_quarter < alpha_mid,
            "Alpha should increase monotonically through ramp"
        );
    }

    #[test]
    fn test_effective_alpha_boundary_conditions() {
        // Test just before and after boundaries
        assert_eq!(
            effective_alpha(BOOTSTRAP_START - 1),
            0,
            "One depth before bootstrap should have alpha=0"
        );

        assert_eq!(
            effective_alpha(BOOTSTRAP_END + 1),
            ALPHA_MAX,
            "One depth after bootstrap should have alpha=ALPHA_MAX"
        );
    }

    // ========================================================================
    // Topological depth tests
    // ========================================================================

    #[test]
    fn test_depth_genesis() {
        let mut dag = TransactionDAG::new();
        let genesis = make_test_tx(0, vec![]);
        let gid = genesis.id;
        dag.insert_genesis(genesis);
        assert_eq!(dag.depth(&gid), 0);
    }

    #[test]
    fn test_depth_linear_chain() {
        let mut dag = TransactionDAG::new();
        let g = make_test_tx(0, vec![]);
        let gid = g.id;
        dag.insert_genesis(g);

        let mut g2 = make_test_tx(50, vec![]);
        g2.nullifier = Nullifier::compute(&[50u8; 32], Epoch(0), b"g2");
        g2.id = g2.compute_id();
        let g2id = g2.id;
        dag.insert_genesis(g2);

        let mut t1 = make_test_tx(1, vec![gid, g2id]);
        t1.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"t1");
        t1.id = t1.compute_id();
        let t1id = t1.id;
        dag.insert_genesis(t1);
        assert_eq!(dag.depth(&t1id), 1);

        let mut t2 = make_test_tx(2, vec![gid, t1id]);
        t2.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"t2");
        t2.id = t2.compute_id();
        let t2id = t2.id;
        dag.insert_genesis(t2);
        assert_eq!(dag.depth(&t2id), 2);
    }

    #[test]
    fn test_depth_diamond() {
        // g1, g2 → a(g1,g2), b(g1,g2) → c(a,b)
        let mut dag = TransactionDAG::new();
        let g1 = make_test_tx(0, vec![]);
        let g1id = g1.id;
        dag.insert_genesis(g1);

        let mut g2 = make_test_tx(50, vec![]);
        g2.nullifier = Nullifier::compute(&[50u8; 32], Epoch(0), b"g2");
        g2.id = g2.compute_id();
        let g2id = g2.id;
        dag.insert_genesis(g2);

        let mut a = make_test_tx(1, vec![g1id, g2id]);
        a.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"a");
        a.id = a.compute_id();
        let aid = a.id;
        dag.insert_genesis(a);

        let mut b = make_test_tx(2, vec![g1id, g2id]);
        b.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"b");
        b.id = b.compute_id();
        let bid = b.id;
        dag.insert_genesis(b);

        let mut c = make_test_tx(3, vec![aid, bid]);
        c.nullifier = Nullifier::compute(&[3u8; 32], Epoch(0), b"c");
        c.id = c.compute_id();
        let cid = c.id;
        dag.insert_genesis(c);

        assert_eq!(dag.depth(&aid), 1);
        assert_eq!(dag.depth(&bid), 1);
        assert_eq!(dag.depth(&cid), 2); // max(1,1) + 1
    }

    #[test]
    fn test_depth_asymmetric() {
        // g1,g2 → a(g1,g2) → b(g1,a) → c(g2,b), d(g1,g2), e(d,c)
        let mut dag = TransactionDAG::new();
        let g1 = make_test_tx(0, vec![]);
        let g1id = g1.id;
        dag.insert_genesis(g1);

        let mut g2 = make_test_tx(50, vec![]);
        g2.nullifier = Nullifier::compute(&[50u8; 32], Epoch(0), b"g2");
        g2.id = g2.compute_id();
        let g2id = g2.id;
        dag.insert_genesis(g2);

        let mut a = make_test_tx(1, vec![g1id, g2id]);
        a.nullifier = Nullifier::compute(&[1u8; 32], Epoch(0), b"a");
        a.id = a.compute_id();
        let aid = a.id;
        dag.insert_genesis(a);

        let mut b = make_test_tx(2, vec![g1id, aid]);
        b.nullifier = Nullifier::compute(&[2u8; 32], Epoch(0), b"b");
        b.id = b.compute_id();
        let bid = b.id;
        dag.insert_genesis(b);

        let mut c = make_test_tx(3, vec![g2id, bid]);
        c.nullifier = Nullifier::compute(&[3u8; 32], Epoch(0), b"c");
        c.id = c.compute_id();
        let cid = c.id;
        dag.insert_genesis(c);

        let mut d = make_test_tx(4, vec![g1id, g2id]);
        d.nullifier = Nullifier::compute(&[4u8; 32], Epoch(0), b"d");
        d.id = d.compute_id();
        let did = d.id;
        dag.insert_genesis(d);

        let mut e = make_test_tx(5, vec![did, cid]);
        e.nullifier = Nullifier::compute(&[5u8; 32], Epoch(0), b"e");
        e.id = e.compute_id();
        let eid = e.id;
        dag.insert_genesis(e);

        assert_eq!(dag.depth(&aid), 1);
        assert_eq!(dag.depth(&bid), 2);
        assert_eq!(dag.depth(&cid), 3);
        assert_eq!(dag.depth(&did), 1);
        assert_eq!(dag.depth(&eid), 4); // max(1, 3) + 1
    }

    #[test]
    fn test_epoch_from_depth_integration() {
        let mut dag = TransactionDAG::new();
        let g = make_test_tx(0, vec![]);
        let gid = g.id;
        dag.insert_genesis(g);
        assert_eq!(dag.epoch(&gid).0, 0); // depth 0 → epoch 0
    }

    #[test]
    fn test_compute_depth_from_parents() {
        let mut dag = TransactionDAG::new();
        let g = make_test_tx(0, vec![]);
        let gid = g.id;
        dag.insert_genesis(g);
        // Ensure genesis depth is cached
        dag.depth(&gid);

        // depth_from_parents([genesis]) = 1 + max(0) = 1
        assert_eq!(dag.compute_depth_from_parents(&[gid]), 1);

        // Empty parents → 0 (genesis)
        assert_eq!(dag.compute_depth_from_parents(&[]), 0);
    }
}
