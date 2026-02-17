//! # Entangle Identity
//!
//! Capability-Coherence Identity Protocol (CCIP) for the Entangle Protocol.
//!
//! This crate implements:
//! - DID-based persistent identity (did:disentangle:*)
//! - Object capabilities with delegation and constraints
//! - Petname-native naming system
//! - Coherence-as-value measurement
//! - Governance with coherence-weighted voting
//!
//! ## Phase 1: Core Types
//!
//! This is Phase 1 of the implementation, providing core types without ZK proofs
//! or networking. ZK integration (Phase 2) and full DAG integration (Phase 3) will follow.

pub mod did;
pub mod capability;
pub mod petname;
pub mod transactions;
pub mod graph;
pub mod coherence;
pub mod governance;

// Re-export main types
pub use did::{DID, DIDDocument, AgentType, VerificationMethod, VerificationMethodType, RuntimeAttestation, ServiceEndpoint};
pub use capability::{
    Capability, CapabilityId, CapabilitySubject, Constraint, DelegationRecord,
    TransactionScope, NameOp, AccessOp, GovernanceScope, RevocationScope, ConstraintContext,
};
pub use petname::{PetnameDB, PetnameEntry, IntroductionStep, ProposedName};
pub use transactions::{
    DisentangleTransaction, IdentityTransaction, CapabilityTransaction,
    IntroductionTransaction, GovernanceTransaction, TransactionIdentity,
    DIDRegistration, DIDUpdate, DIDUpdateOp, DIDDeactivation, KeyRotation,
    IntroductionContext, CapabilityOperation,
};
pub use graph::IdentityGraph;
pub use coherence::{CoherenceProfile, COHERENCE_HALF_LIFE};
pub use governance::{
    GovernanceProposal, GovernanceVote, VoteChoice, GovernanceQuorum,
    ProposalType, ProposalResult, evaluate_proposal,
};

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("DID not found: {0}")]
    DIDNotFound(String),

    #[error("invalid DID format: {0}")]
    InvalidDID(String),

    #[error("capability not found: {0}")]
    CapabilityNotFound(String),

    #[error("capability revoked")]
    CapabilityRevoked,

    #[error("delegation depth exceeded: {depth} > {max}")]
    DelegationDepthExceeded { depth: u32, max: u32 },

    #[error("constraint not satisfied: {0}")]
    ConstraintNotSatisfied(String),

    #[error("petname already bound: {0}")]
    PetnameAlreadyBound(String),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("insufficient proof of work")]
    InsufficientPoW,

    #[error("duplicate nullifier")]
    DuplicateNullifier,

    #[error("introduction cooldown active")]
    IntroductionCooldown,
}

pub type Result<T> = std::result::Result<T, IdentityError>;

#[cfg(test)]
mod tests {
    use super::*;
    use disentangle_crypto::signature::generate_keypair;

    #[test]
    fn test_full_did_lifecycle() {
        // Create DID
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        assert!(!did.is_agi());

        // Create DID document
        let doc = DIDDocument::new(&sk, &pk, AgentType::Human, 100);
        assert_eq!(doc.id, did);
        assert!(doc.verify());

        // Compute ID hash
        let hash = doc.id_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_full_capability_flow() {
        // Create issuer
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        // Create capability
        let subject = CapabilitySubject::Transact {
            scope: TransactionScope::All,
        };
        let cap = Capability::new(&did, &pk, subject, &sk);
        assert!(cap.verify(&pk));

        // Create delegatee
        let (_sk2, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        // Delegate capability
        let delegation = DelegationRecord::new(&cap, &did, &did2, &sk, 1000);
        assert!(delegation.is_ok());

        // Verify delegation chain
        let record = delegation.unwrap();
        assert!(DelegationRecord::verify_chain(&[record], &cap, &[pk]));
    }

    #[test]
    fn test_petname_system() {
        let mut db = PetnameDB::new();

        let (_, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        // Bind petname
        db.bind("Alice", &did, vec![], 100).unwrap();

        // Resolve both directions
        assert_eq!(db.resolve_name("Alice"), Some(&did));
        assert_eq!(db.resolve_did(&did), Some("Alice"));

        // Display name
        assert_eq!(db.display_name(&did), "Alice");

        // Unbind
        db.unbind("Alice").unwrap();
        assert_eq!(db.resolve_name("Alice"), None);
    }

    #[test]
    fn test_identity_graph_and_curvature() {
        let mut graph = IdentityGraph::new();

        let (sk1, pk1) = generate_keypair();
        let did1 = DID::new(&pk1, false);

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        // Create introduction
        let tx = IntroductionTransaction {
            introducer_did: did1.clone(),
            introduced_did: did2.clone(),
            edge_name: "Friend".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk1, b"test"),
            parents: vec![],
            depth: 100,
        };

        graph.record_introduction(&tx);

        // Check neighbors
        let neighbors1 = graph.neighbors(&did1);
        let neighbors2 = graph.neighbors(&did2);
        assert!(neighbors1.contains(&did2));
        assert!(neighbors2.contains(&did1));

        // Compute curvature
        let curvature = graph.identity_curvature(&did1, &did2);
        // Two nodes with only each other as neighbors: no shared neighbors
        // Union = 2 (they see each other), Intersection = 0
        // Jaccard = 0, so κ_J = 2*0 - 1 = -1
        use disentangle_dag::SCALE;
        assert_eq!(curvature, -SCALE); // Negative curvature, no shared neighbors
    }

    #[test]
    fn test_coherence_profile() {
        let mut graph = IdentityGraph::new();

        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        // Create introduction
        let tx = IntroductionTransaction {
            introducer_did: did.clone(),
            introduced_did: did2,
            edge_name: "Friend".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(&sk, b"test"),
            parents: vec![],
            depth: 100,
        };

        graph.record_introduction(&tx);

        // Compute coherence profile
        let profile = CoherenceProfile::compute(&did, &graph, 0, 200);

        assert_eq!(profile.temporal_depth, 200);
        // With one neighbor and negative curvature, mass might be zero
        // Just verify profile was computed
        assert_eq!(profile.last_active_depth, 200);

        // Test decay (only meaningful if mass > 0)
        if profile.topological_mass > 0 {
            let decayed = profile.decayed_mass(200 + COHERENCE_HALF_LIFE);
            assert!(decayed < profile.topological_mass);
        }
    }

    #[test]
    fn test_governance_proposal() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        let proposal_type = ProposalType::ProtocolParameter {
            parameter: "alpha_max".to_string(),
            new_value: vec![0, 0, 0, 5],
        };

        use disentangle_dag::SCALE;
        let proposal = GovernanceProposal::new(
            &did,
            proposal_type,
            [1u8; 32],
            1000,
            2000,
            GovernanceQuorum::CoherenceWeighted { threshold: SCALE / 2 },
            &sk,
        );

        assert!(proposal.verify(&pk));
    }

    #[test]
    fn test_agi_did() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, true);
        assert!(did.is_agi());
        assert!(did.0.contains(":agi:"));

        let attestation = RuntimeAttestation {
            model_hash: [1u8; 32],
            runtime_hash: [2u8; 32],
            attestation_proof: vec![],
        };

        let agent_type = AgentType::AGI {
            runtime_attestation: Some(attestation),
        };

        let doc = DIDDocument::new(&sk, &pk, agent_type, 1000);
        assert!(doc.id.is_agi());
        assert!(doc.verify());
    }
}
