//! Graph synchronization logic.
//!
//! Implements "Recursive Pull" - when we receive a Tx but don't have
//! its parents, we buffer the Tx and request the parents immediately.

use crate::wire::WireTransaction;
use disentangle_dag::{NodeId, Transaction, TransactionDAG};
use disentangle_node::HelloWorldPoW;
use std::collections::{HashMap, HashSet, VecDeque};
use tracing::{debug, info, warn};

pub const MAX_PENDING_DEPTH: usize = 10;
pub const MAX_PENDING_TXS: usize = 10000;
pub const MAX_REQUESTS_PER_PARENT: usize = 3;

pub struct SyncState {
    dag: TransactionDAG,
    pending: HashMap<NodeId, PendingTx>,
    waiting_for: HashMap<NodeId, HashSet<NodeId>>,
    request_counts: HashMap<NodeId, usize>,
    tips: HashSet<NodeId>,
    pow: HelloWorldPoW,
    /// Cache of PoW nonces so get_transaction can serve the original nonce.
    /// Without this, syncing peers would receive nonce=0 and fail PoW validation
    /// for non-genesis transactions.
    nonce_cache: HashMap<NodeId, u64>,
}

struct PendingTx {
    wire_tx: WireTransaction,
    missing_parents: HashSet<NodeId>,
    depth: usize,
}

impl SyncState {
    pub fn new(pow_difficulty: u8) -> Self {
        Self {
            dag: TransactionDAG::new(),
            pending: HashMap::new(),
            waiting_for: HashMap::new(),
            request_counts: HashMap::new(),
            tips: HashSet::new(),
            pow: HelloWorldPoW::new(pow_difficulty),
            nonce_cache: HashMap::new(),
        }
    }

    pub fn dag(&self) -> &TransactionDAG {
        &self.dag
    }

    pub fn dag_mut(&mut self) -> &mut TransactionDAG {
        &mut self.dag
    }

    pub fn tips(&self) -> Vec<NodeId> {
        self.tips.iter().cloned().collect()
    }

    pub fn has_transaction(&self, id: &NodeId) -> bool {
        self.dag.get(id).is_some() || self.pending.contains_key(id)
    }

    pub fn receive_transaction(&mut self, wire_tx: WireTransaction) -> SyncResult {
        let tx = &wire_tx.tx;
        let tx_id = tx.id;
        if self.dag.get(&tx_id).is_some() {
            return SyncResult::AlreadyHave;
        }
        if self.pending.contains_key(&tx_id) {
            return SyncResult::AlreadyPending;
        }
        // Validate PoW for all non-genesis transactions
        if !tx.parents.is_empty() {
            let tx_header = self.serialize_tx_header(tx);
            if !self.pow.validate(&tx_header, wire_tx.nonce) {
                warn!("Invalid PoW for tx {:?}", &tx_id[..4]);
                return SyncResult::InvalidPoW;
            }
        }
        // Cache the nonce so get_transaction can return the original value
        self.nonce_cache.insert(tx_id, wire_tx.nonce);
        let mut missing: HashSet<NodeId> = HashSet::new();
        for parent in &tx.parents {
            if self.dag.get(parent).is_none() && !self.pending.contains_key(parent) {
                missing.insert(*parent);
            }
        }
        if missing.is_empty() {
            self.insert_and_propagate(wire_tx);
            SyncResult::Inserted
        } else {
            if self.pending.len() >= MAX_PENDING_TXS {
                warn!("Pending buffer full, dropping tx {:?}", &tx_id[..4]);
                return SyncResult::BufferFull;
            }
            let parents_to_request: Vec<NodeId> = missing
                .iter()
                .filter(|p| {
                    let count = self.request_counts.get(*p).unwrap_or(&0);
                    *count < MAX_REQUESTS_PER_PARENT
                })
                .cloned()
                .collect();
            for parent in &parents_to_request {
                *self.request_counts.entry(*parent).or_insert(0) += 1;
                self.waiting_for.entry(*parent).or_default().insert(tx_id);
            }
            debug!("Tx {:?} waiting for {} parents", &tx_id[..4], missing.len());
            self.pending.insert(
                tx_id,
                PendingTx {
                    wire_tx,
                    missing_parents: missing,
                    depth: 0,
                },
            );
            SyncResult::NeedParents(parents_to_request)
        }
    }

    fn insert_and_propagate(&mut self, wire_tx: WireTransaction) {
        let tx_id = wire_tx.tx.id;
        for parent in &wire_tx.tx.parents {
            self.tips.remove(parent);
        }
        self.tips.insert(tx_id);
        // Genesis transactions (no parents) bypass parent validation
        if wire_tx.tx.parents.is_empty() {
            self.dag.insert_genesis(wire_tx.tx);
        } else if let Err(e) = self.dag.insert(wire_tx.tx) {
            warn!("Failed to insert tx {:?}: {}", &tx_id[..4], e);
            return;
        }
        self.request_counts.remove(&tx_id);
        info!("Inserted tx {:?}", &tx_id[..4]);
        if let Some(waiters) = self.waiting_for.remove(&tx_id) {
            let mut ready: VecDeque<NodeId> = VecDeque::new();
            for waiter_id in waiters {
                if let Some(pending) = self.pending.get_mut(&waiter_id) {
                    pending.missing_parents.remove(&tx_id);
                    if pending.missing_parents.is_empty() {
                        ready.push_back(waiter_id);
                    }
                }
            }
            while let Some(ready_id) = ready.pop_front() {
                if let Some(pending) = self.pending.remove(&ready_id) {
                    let child_tx_id = pending.wire_tx.tx.id;
                    for parent in &pending.wire_tx.tx.parents {
                        self.tips.remove(parent);
                    }
                    self.tips.insert(child_tx_id);
                    if let Err(e) = self.dag.insert(pending.wire_tx.tx) {
                        warn!("Failed to insert pending tx {:?}: {}", &child_tx_id[..4], e);
                        continue;
                    }
                    self.request_counts.remove(&child_tx_id);
                    info!("Inserted pending tx {:?}", &child_tx_id[..4]);
                    if let Some(child_waiters) = self.waiting_for.remove(&child_tx_id) {
                        for w in child_waiters {
                            if let Some(p) = self.pending.get_mut(&w) {
                                p.missing_parents.remove(&child_tx_id);
                                if p.missing_parents.is_empty() {
                                    ready.push_back(w);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn get_transaction(&self, id: &NodeId) -> Option<WireTransaction> {
        self.dag.get(id).map(|tx| {
            let nonce = self.nonce_cache.get(id).copied().unwrap_or(0);
            WireTransaction::new(tx.clone(), nonce)
        })
    }

    pub fn parent_not_found(&mut self, parent_id: &NodeId) {
        if let Some(waiters) = self.waiting_for.remove(parent_id) {
            for waiter_id in waiters {
                if let Some(pending) = self.pending.get(&waiter_id) {
                    if pending.depth >= MAX_PENDING_DEPTH {
                        warn!("Dropping tx {:?}: max depth exceeded", &waiter_id[..4]);
                        self.pending.remove(&waiter_id);
                    }
                }
            }
        }
        self.request_counts.remove(parent_id);
    }

    fn serialize_tx_header(&self, tx: &Transaction) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&tx.ephemeral_pk.to_bytes());
        for parent in &tx.parents {
            header.extend_from_slice(parent);
        }
        // v0.3: No block field - temporal properties derive from topological depth
        header.extend_from_slice(tx.nullifier.as_bytes());
        header
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn transaction_count(&self) -> usize {
        self.dag.transaction_ids().count()
    }
}

#[derive(Debug, Clone)]
pub enum SyncResult {
    Inserted,
    AlreadyHave,
    AlreadyPending,
    InvalidPoW,
    BufferFull,
    NeedParents(Vec<NodeId>),
}
