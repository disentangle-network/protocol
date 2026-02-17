//! Petname Database
//!
//! Local-first naming with edge names and proposed names.

use crate::did::DID;
use crate::graph::IdentityGraph;
use crate::IdentityError;
use disentangle_crypto::hash::Hash256;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetnameEntry {
    pub local_name: String,
    pub did: DID,
    pub trust_path: Vec<IntroductionStep>,
    pub first_bound_depth: u64,
    pub last_verified_depth: u64,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroductionStep {
    pub introducer: DID,
    pub edge_name: String,
    pub depth: u64,
    pub introduction_tx: Hash256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedName {
    pub name: String,
    pub source: DID,
    pub disambiguation: Option<u32>,
}

#[derive(Debug, Default)]
pub struct PetnameDB {
    petnames: HashMap<String, PetnameEntry>,
    did_to_petname: HashMap<DID, String>,
    edge_name_cache: HashMap<DID, HashMap<String, DID>>,
    proposed_names: HashMap<DID, Vec<ProposedName>>,
    proposed_name_counts: HashMap<String, u32>,
}

impl PetnameDB {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a petname to a DID with a trust path
    pub fn bind(&mut self, name: &str, did: &DID, trust_path: Vec<IntroductionStep>, depth: u64) -> Result<(), IdentityError> {
        // Check if name is already bound
        if self.petnames.contains_key(name) {
            return Err(IdentityError::PetnameAlreadyBound(name.to_string()));
        }

        let entry = PetnameEntry {
            local_name: name.to_string(),
            did: did.clone(),
            trust_path,
            first_bound_depth: depth,
            last_verified_depth: depth,
            notes: None,
        };

        self.petnames.insert(name.to_string(), entry);
        self.did_to_petname.insert(did.clone(), name.to_string());

        Ok(())
    }

    /// Unbind a petname
    pub fn unbind(&mut self, name: &str) -> Result<(), IdentityError> {
        if let Some(entry) = self.petnames.remove(name) {
            self.did_to_petname.remove(&entry.did);
            Ok(())
        } else {
            Err(IdentityError::DIDNotFound(format!("Petname not found: {}", name)))
        }
    }

    /// Resolve a petname to a DID
    pub fn resolve_name(&self, name: &str) -> Option<&DID> {
        self.petnames.get(name).map(|entry| &entry.did)
    }

    /// Resolve a DID to its petname (reverse lookup)
    pub fn resolve_did(&self, did: &DID) -> Option<&str> {
        self.did_to_petname.get(did).map(|s| s.as_str())
    }

    /// Resolve an edge path like "Barton => TopoCAT"
    ///
    /// If an IdentityGraph is provided, edges with negative curvature are
    /// skipped during resolution (curvature gate per CCIP spec). This
    /// prevents Sybil entities from polluting the namespace.
    pub fn resolve_edge_path(&self, path: &str, identity_graph: Option<&IdentityGraph>) -> Option<&DID> {
        let parts: Vec<&str> = path.split("=>").map(|s| s.trim()).collect();

        if parts.len() < 2 {
            return None;
        }

        let source_did = self.resolve_name(parts[0])?;

        let mut current_did = source_did;
        for edge_name in &parts[1..] {
            let edge_names = self.edge_name_cache.get(current_did)?;
            let next_did = edge_names.get(*edge_name)?;

            if let Some(graph) = identity_graph {
                let curv = graph.identity_curvature(current_did, next_did);
                if curv < 0 {
                    return None;
                }
            }

            current_did = next_did;
        }

        Some(current_did)
    }

    /// Add edge names published by a DID
    pub fn add_edge_names(&mut self, source: &DID, names: HashMap<String, DID>) {
        self.edge_name_cache.insert(source.clone(), names);
    }

    /// Add a proposed name with auto-disambiguation
    pub fn add_proposed_name(&mut self, did: &DID, name: &str) {
        let count = self.proposed_name_counts.entry(name.to_string()).or_insert(0);
        *count += 1;

        let disambiguation = if *count > 1 {
            Some(*count)
        } else {
            None
        };

        let proposed = ProposedName {
            name: name.to_string(),
            source: did.clone(),
            disambiguation,
        };

        self.proposed_names.entry(did.clone()).or_default().push(proposed);
    }

    /// Get a display name for a DID (priority: petname > edge name > proposed > truncated DID)
    pub fn display_name(&self, did: &DID) -> String {
        // 1. Check for petname
        if let Some(petname) = self.resolve_did(did) {
            return petname.to_string();
        }

        // 2. Check for edge name from any known source
        for (source, edge_names) in &self.edge_name_cache {
            for (edge_name, target) in edge_names {
                if target == did {
                    if let Some(source_petname) = self.resolve_did(source) {
                        return format!("{} => {}", source_petname, edge_name);
                    }
                }
            }
        }

        // 3. Check for proposed name
        if let Some(proposals) = self.proposed_names.get(did) {
            if let Some(proposed) = proposals.first() {
                return if let Some(num) = proposed.disambiguation {
                    if num > 9 {
                        format!("{}…", proposed.name)
                    } else {
                        format!("{}.{}", proposed.name, num)
                    }
                } else {
                    proposed.name.clone()
                };
            }
        }

        // 4. Truncated DID
        let method_id = did.method_specific_id();
        if method_id.len() > 16 {
            format!("{}…{}", &method_id[..8], &method_id[method_id.len()-4..])
        } else {
            method_id.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use disentangle_crypto::signature::generate_keypair;

    #[test]
    fn test_bind_and_resolve() {
        let mut db = PetnameDB::new();
        let (_, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        db.bind("Alice", &did, vec![], 100).unwrap();

        assert_eq!(db.resolve_name("Alice"), Some(&did));
        assert_eq!(db.resolve_did(&did), Some("Alice"));
    }

    #[test]
    fn test_duplicate_bind_fails() {
        let mut db = PetnameDB::new();
        let (_, pk1) = generate_keypair();
        let did1 = DID::new(&pk1, false);

        db.bind("Alice", &did1, vec![], 100).unwrap();

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let result = db.bind("Alice", &did2, vec![], 101);
        assert!(result.is_err());
    }

    #[test]
    fn test_unbind() {
        let mut db = PetnameDB::new();
        let (_, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        db.bind("Alice", &did, vec![], 100).unwrap();
        db.unbind("Alice").unwrap();

        assert_eq!(db.resolve_name("Alice"), None);
        assert_eq!(db.resolve_did(&did), None);
    }

    #[test]
    fn test_edge_name_resolution() {
        let mut db = PetnameDB::new();

        let (_, pk1) = generate_keypair();
        let did1 = DID::new(&pk1, false);
        db.bind("Barton", &did1, vec![], 100).unwrap();

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let mut edge_names = HashMap::new();
        edge_names.insert("TopoCAT".to_string(), did2.clone());
        db.add_edge_names(&did1, edge_names);

        let resolved = db.resolve_edge_path("Barton => TopoCAT", None);
        assert_eq!(resolved, Some(&did2));
    }

    #[test]
    fn test_proposed_name_disambiguation() {
        let mut db = PetnameDB::new();

        let (_, pk1) = generate_keypair();
        let did1 = DID::new(&pk1, false);
        db.add_proposed_name(&did1, "Guardian");

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);
        db.add_proposed_name(&did2, "Guardian");

        let display1 = db.display_name(&did1);
        let display2 = db.display_name(&did2);

        // First should not have disambiguation, second should
        assert_eq!(display1, "Guardian");
        assert!(display2.starts_with("Guardian."));
    }

    #[test]
    fn test_display_name_priority() {
        let mut db = PetnameDB::new();
        let (_, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        // Initially, should show truncated DID
        let display = db.display_name(&did);
        assert!(display.contains("…"));

        // Add proposed name
        db.add_proposed_name(&did, "Guardian");
        let display = db.display_name(&did);
        assert_eq!(display, "Guardian");

        // Bind petname (should override proposed)
        db.bind("MyGuardian", &did, vec![], 100).unwrap();
        let display = db.display_name(&did);
        assert_eq!(display, "MyGuardian");
    }

    #[test]
    fn test_edge_path_curvature_gate() {
        use crate::graph::IdentityGraph;
        use crate::did::DID;
        use crate::transactions::{IntroductionTransaction, IntroductionContext};
        use disentangle_crypto::signature::generate_keypair;

        let mut db = PetnameDB::new();

        // Create keypairs for signing
        let (sk_alice, pk_alice) = generate_keypair();
        let alice = DID::new(&pk_alice, false);
        let (sk_bob, pk_bob) = generate_keypair();
        let bob = DID::new(&pk_bob, false);
        let (_, pk_sybil) = generate_keypair();
        let sybil = DID::new(&pk_sybil, false);

        db.bind("Alice", &alice, vec![], 100).unwrap();
        let mut edge_names = std::collections::HashMap::new();
        edge_names.insert("Bob".to_string(), bob.clone());
        edge_names.insert("Sybil".to_string(), sybil.clone());
        db.add_edge_names(&alice, edge_names);

        // Without graph, both resolve
        assert!(db.resolve_edge_path("Alice => Bob", None).is_some());
        assert!(db.resolve_edge_path("Alice => Sybil", None).is_some());

        // Build graph where alice->bob has positive curvature (shared neighbors)
        // but alice->sybil has negative curvature (no shared neighbors)
        let mut graph = IdentityGraph::new();

        let (_, pk_carol) = generate_keypair();
        let carol = DID::new(&pk_carol, false);
        let (_, pk_dave) = generate_keypair();
        let dave = DID::new(&pk_dave, false);

        // Alice and Bob both know Carol and Dave (but not each other directly)
        // This creates positive curvature between alice and bob
        let tx_alice_carol = IntroductionTransaction {
            introducer_did: alice.clone(),
            introduced_did: carol.clone(),
            edge_name: "Carol".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk_alice, b"alice_carol"),
            parents: vec![],
            depth: 100,
        };

        let tx_bob_carol = IntroductionTransaction {
            introducer_did: bob.clone(),
            introduced_did: carol.clone(),
            edge_name: "Carol".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk_bob, b"bob_carol"),
            parents: vec![],
            depth: 101,
        };

        let tx_alice_dave = IntroductionTransaction {
            introducer_did: alice.clone(),
            introduced_did: dave.clone(),
            edge_name: "Dave".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk_alice, b"alice_dave"),
            parents: vec![],
            depth: 102,
        };

        let tx_bob_dave = IntroductionTransaction {
            introducer_did: bob.clone(),
            introduced_did: dave.clone(),
            edge_name: "Dave".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk_bob, b"bob_dave"),
            parents: vec![],
            depth: 103,
        };

        // Alice knows Sybil, but Sybil has no other connections
        // This creates negative curvature between alice and sybil
        let tx_alice_sybil = IntroductionTransaction {
            introducer_did: alice.clone(),
            introduced_did: sybil.clone(),
            edge_name: "Sybil".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk_alice, b"alice_sybil"),
            parents: vec![],
            depth: 104,
        };

        graph.record_introduction(&tx_alice_carol);
        graph.record_introduction(&tx_bob_carol);
        graph.record_introduction(&tx_alice_dave);
        graph.record_introduction(&tx_bob_dave);
        graph.record_introduction(&tx_alice_sybil);

        // alice neighbors: {carol, dave, sybil}
        // bob neighbors: {carol, dave}
        // Intersection: {carol, dave} = 2
        // Union: {carol, dave, sybil} = 3
        // Jaccard = 2/3, κ_J = 2*(2/3) - 1 = 1/3 > 0 ✓

        // alice neighbors: {carol, dave, sybil}
        // sybil neighbors: {alice}
        // Intersection: {} = 0 (they don't share any neighbors besides each other)
        // Union: {alice, carol, dave, sybil} = 4
        // Jaccard = 0/4 = 0, κ_J = 2*0 - 1 = -1 < 0 ✓

        let curv_bob = graph.identity_curvature(&alice, &bob);
        let curv_sybil = graph.identity_curvature(&alice, &sybil);
        assert!(curv_bob >= 0, "alice->bob should have non-negative curvature, got {}", curv_bob);
        assert!(curv_sybil < 0, "alice->sybil should have negative curvature, got {}", curv_sybil);

        // With curvature gate, sybil path should fail
        assert!(db.resolve_edge_path("Alice => Bob", Some(&graph)).is_some());
        assert!(db.resolve_edge_path("Alice => Sybil", Some(&graph)).is_none());
    }
}
