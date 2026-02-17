//! Identity Subgraph
//!
//! Tracks introductions, delegations, and computes identity curvature.

use crate::capability::{CapabilityId, DelegationRecord, RevocationScope};
use crate::did::DID;
use crate::petname::IntroductionStep;
use crate::transactions::{IntroductionContext, IntroductionTransaction};
use disentangle_crypto::hash::Hash256;
use disentangle_dag::{fp_from_ratio, FixedPoint, SCALE};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Default)]
pub struct IdentityGraph {
    introductions: HashMap<(DID, DID), Vec<IntroductionRecord>>,
    delegations: HashMap<CapabilityId, Vec<DelegationRecord>>,
    revocations: HashSet<CapabilityId>,
    did_neighbors: HashMap<DID, HashSet<DID>>,
}

#[derive(Debug, Clone)]
struct IntroductionRecord {
    edge_name: String,
    #[allow(dead_code)] // Stored for future use (audit trails, context-aware filtering)
    context: IntroductionContext,
    depth: u64,
    tx_id: Hash256,
}

impl IdentityGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an introduction transaction
    pub fn record_introduction(&mut self, tx: &IntroductionTransaction) {
        let record = IntroductionRecord {
            edge_name: tx.edge_name.clone(),
            context: tx.context.clone(),
            depth: tx.depth,
            tx_id: tx.compute_id(),
        };

        let key = (tx.introducer_did.clone(), tx.introduced_did.clone());
        self.introductions.entry(key).or_default().push(record);

        // Update neighbors
        self.did_neighbors
            .entry(tx.introducer_did.clone())
            .or_default()
            .insert(tx.introduced_did.clone());

        self.did_neighbors
            .entry(tx.introduced_did.clone())
            .or_default()
            .insert(tx.introducer_did.clone());
    }

    /// Record a capability delegation
    pub fn record_delegation(&mut self, record: &DelegationRecord) {
        self.delegations
            .entry(record.capability_id)
            .or_default()
            .push(record.clone());

        // Update neighbors based on delegation
        self.did_neighbors
            .entry(record.delegator.clone())
            .or_default()
            .insert(record.delegatee.clone());

        self.did_neighbors
            .entry(record.delegatee.clone())
            .or_default()
            .insert(record.delegator.clone());
    }

    /// Record a capability revocation
    pub fn record_revocation(&mut self, cap_id: &CapabilityId, scope: RevocationScope) {
        match scope {
            RevocationScope::Single | RevocationScope::Subtree | RevocationScope::All => {
                self.revocations.insert(*cap_id);
            }
        }
    }

    /// Check if a capability is revoked
    pub fn is_revoked(&self, cap_id: &CapabilityId) -> bool {
        self.revocations.contains(cap_id)
    }

    /// Get neighbors of a DID in the identity graph
    pub fn neighbors(&self, did: &DID) -> HashSet<DID> {
        self.did_neighbors.get(did).cloned().unwrap_or_default()
    }

    /// Compute identity curvature between two DIDs using Jaccard formula
    ///
    /// κ_J(a,b) = 2 * |N(a) ∩ N(b)| / |N(a) ∪ N(b)| - 1
    ///
    /// This is the same formula used for transaction DAG curvature.
    pub fn identity_curvature(&self, a: &DID, b: &DID) -> FixedPoint {
        let neighbors_a = self.neighbors(a);
        let neighbors_b = self.neighbors(b);

        let intersection_count = neighbors_a.intersection(&neighbors_b).count() as i32;
        let union_count = neighbors_a.union(&neighbors_b).count() as i32;

        if union_count == 0 {
            return 0;
        }

        // Jaccard curvature: κ_J = 2 * J(A,B) - 1
        2 * fp_from_ratio(intersection_count, union_count) - SCALE
    }

    /// Find the introduction chain from one DID to another
    pub fn introduction_chain(&self, from: &DID, to: &DID) -> Option<Vec<IntroductionStep>> {
        // BFS to find shortest introduction path
        let mut queue = std::collections::VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent_map: HashMap<DID, (DID, IntroductionStep)> = HashMap::new();

        queue.push_back(from.clone());
        visited.insert(from.clone());

        while let Some(current) = queue.pop_front() {
            if &current == to {
                // Reconstruct path
                let mut path = Vec::new();
                let mut node = to.clone();

                while let Some((prev, step)) = parent_map.get(&node) {
                    path.push(step.clone());
                    node = prev.clone();
                    if &node == from {
                        break;
                    }
                }

                path.reverse();
                return Some(path);
            }

            // Explore neighbors
            if let Some(neighbors) = self.did_neighbors.get(&current) {
                for neighbor in neighbors {
                    if visited.insert(neighbor.clone()) {
                        // Find the introduction record
                        let key = (current.clone(), neighbor.clone());
                        if let Some(records) = self.introductions.get(&key) {
                            if let Some(record) = records.first() {
                                let step = IntroductionStep {
                                    introducer: current.clone(),
                                    edge_name: record.edge_name.clone(),
                                    depth: record.depth,
                                    introduction_tx: record.tx_id,
                                };

                                parent_map.insert(neighbor.clone(), (current.clone(), step));
                                queue.push_back(neighbor.clone());
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Get the delegation chain for a capability
    pub fn delegation_chain(&self, cap: &CapabilityId) -> Vec<&DelegationRecord> {
        self.delegations
            .get(cap)
            .map(|records| records.iter().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use disentangle_crypto::signature::generate_keypair;

    #[test]
    fn test_record_introduction() {
        let mut graph = IdentityGraph::new();

        let (sk, pk) = generate_keypair();
        let did1 = DID::new(&pk, false);

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let tx = IntroductionTransaction {
            introducer_did: did1.clone(),
            introduced_did: did2.clone(),
            edge_name: "Friend".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk, b"test"),
            parents: vec![],
            depth: 100,
        };

        graph.record_introduction(&tx);

        assert!(graph.neighbors(&did1).contains(&did2));
        assert!(graph.neighbors(&did2).contains(&did1));
    }

    #[test]
    fn test_identity_curvature_empty() {
        let graph = IdentityGraph::new();

        let (_, pk1) = generate_keypair();
        let did1 = DID::new(&pk1, false);

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        // No neighbors, curvature should be 0
        let curvature = graph.identity_curvature(&did1, &did2);
        assert_eq!(curvature, 0);
    }

    #[test]
    fn test_identity_curvature_with_neighbors() {
        let mut graph = IdentityGraph::new();

        let (sk1, pk1) = generate_keypair();
        let did1 = DID::new(&pk1, false);

        let (sk2, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let (_, pk3) = generate_keypair();
        let did3 = DID::new(&pk3, false);

        // Create introductions: did1 <-> did3, did2 <-> did3
        let tx1 = IntroductionTransaction {
            introducer_did: did1.clone(),
            introduced_did: did3.clone(),
            edge_name: "Shared".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk1, b"test"),
            parents: vec![],
            depth: 100,
        };

        let tx2 = IntroductionTransaction {
            introducer_did: did2.clone(),
            introduced_did: did3.clone(),
            edge_name: "Shared".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk2, b"test"),
            parents: vec![],
            depth: 101,
        };

        graph.record_introduction(&tx1);
        graph.record_introduction(&tx2);

        // did1 and did2 share did3 as a neighbor
        let curvature = graph.identity_curvature(&did1, &did2);
        assert!(curvature > 0); // Should have positive curvature due to shared neighbor
    }

    #[test]
    fn test_introduction_chain() {
        let mut graph = IdentityGraph::new();

        let (sk1, pk1) = generate_keypair();
        let did1 = DID::new(&pk1, false);

        let (sk2, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let (_, pk3) = generate_keypair();
        let did3 = DID::new(&pk3, false);

        // Create chain: did1 -> did2 -> did3
        let tx1 = IntroductionTransaction {
            introducer_did: did1.clone(),
            introduced_did: did2.clone(),
            edge_name: "Friend".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk1, b"test"),
            parents: vec![],
            depth: 100,
        };

        let tx2 = IntroductionTransaction {
            introducer_did: did2.clone(),
            introduced_did: did3.clone(),
            edge_name: "FriendOfFriend".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk2, b"test"),
            parents: vec![],
            depth: 101,
        };

        graph.record_introduction(&tx1);
        graph.record_introduction(&tx2);

        let chain = graph.introduction_chain(&did1, &did3);
        assert!(chain.is_some());

        let chain = chain.unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].edge_name, "Friend");
        assert_eq!(chain[1].edge_name, "FriendOfFriend");
    }

    #[test]
    fn test_revocation() {
        let mut graph = IdentityGraph::new();
        let cap_id = [1u8; 32];

        assert!(!graph.is_revoked(&cap_id));

        graph.record_revocation(&cap_id, RevocationScope::Single);
        assert!(graph.is_revoked(&cap_id));
    }
}
