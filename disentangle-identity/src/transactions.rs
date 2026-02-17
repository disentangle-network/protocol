//! Extended Transaction Types
//!
//! Transaction types for identity, capability, introduction, and governance operations.

use crate::capability::{Capability, CapabilityId, DelegationRecord, RevocationScope};
use crate::did::{AgentType, DIDDocument, ServiceEndpoint, VerificationMethod, DID};
use crate::governance::GovernanceVote;
use disentangle_crypto::{
    hash::{sha3_256_multi, Hash256},
    signature::{verify, Signature, VerifyingKey},
    types::Nullifier,
};
use disentangle_dag::Transaction;
use disentangle_simhash::SimHash;
use serde::{Deserialize, Serialize};

// Domain separation tags
const _TX_TAG_LEGACY: &[u8] = b"TX_LEGACY_V2";
const TX_TAG_IDENTITY: &[u8] = b"TX_IDENTITY_V1";
const TX_TAG_CAPABILITY: &[u8] = b"TX_CAPABILITY_V1";
const TX_TAG_INTRODUCTION: &[u8] = b"TX_INTRODUCTION_V1";
const TX_TAG_GOVERNANCE: &[u8] = b"TX_GOVERNANCE_V1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisentangleTransaction {
    Legacy(Transaction),
    Identity(IdentityTransaction),
    Capability(CapabilityTransaction),
    Introduction(IntroductionTransaction),
    Governance(GovernanceTransaction),
}

impl DisentangleTransaction {
    pub fn compute_id(&self) -> Hash256 {
        match self {
            Self::Legacy(tx) => tx.compute_id(),
            Self::Identity(tx) => tx.compute_id(),
            Self::Capability(tx) => tx.compute_id(),
            Self::Introduction(tx) => tx.compute_id(),
            Self::Governance(tx) => tx.compute_id(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityTransaction {
    Register(DIDRegistration),
    Update(DIDUpdate),
    Deactivate(DIDDeactivation),
    RotateKey(KeyRotation),
}

impl IdentityTransaction {
    pub fn compute_id(&self) -> Hash256 {
        match self {
            Self::Register(tx) => tx.compute_id(),
            Self::Update(tx) => tx.compute_id(),
            Self::Deactivate(tx) => tx.compute_id(),
            Self::RotateKey(tx) => tx.compute_id(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDRegistration {
    pub document: DIDDocument,
    pub pow_nonce: u64,
    pub pow_hash: Hash256,
    pub initial_capabilities: Vec<Capability>,
    pub parents: Vec<Hash256>,
    pub depth: u64,
}

impl DIDRegistration {
    pub fn compute_id(&self) -> Hash256 {
        let doc_bytes = bincode::serialize(&self.document).unwrap_or_default();
        sha3_256_multi(&[
            TX_TAG_IDENTITY,
            b"REGISTER",
            &doc_bytes,
            &self.pow_nonce.to_le_bytes(),
            &self.depth.to_le_bytes(),
        ])
    }

    pub fn verify_pow(&self, difficulty: u32) -> bool {
        let leading_zeros = self.pow_hash.iter().take_while(|&&b| b == 0).count() * 8;

        leading_zeros >= difficulty as usize
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDUpdate {
    pub did: DID,
    pub updates: Vec<DIDUpdateOp>,
    pub proof: Signature,
    pub parents: Vec<Hash256>,
    pub depth: u64,
}

impl DIDUpdate {
    pub fn compute_id(&self) -> Hash256 {
        let updates_bytes = bincode::serialize(&self.updates).unwrap_or_default();
        sha3_256_multi(&[
            TX_TAG_IDENTITY,
            b"UPDATE",
            self.did.0.as_bytes(),
            &updates_bytes,
            &self.depth.to_le_bytes(),
        ])
    }

    pub fn verify_signature(&self, pk: &VerifyingKey) -> bool {
        let message = self.signing_payload();
        verify(pk, &message, &self.proof).is_ok()
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"DID_UPDATE_V1");
        payload.extend_from_slice(self.did.0.as_bytes());
        if let Ok(bytes) = bincode::serialize(&self.updates) {
            payload.extend_from_slice(&bytes);
        }
        payload.extend_from_slice(&self.depth.to_le_bytes());
        payload
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DIDUpdateOp {
    AddVerificationMethod(VerificationMethod),
    RemoveVerificationMethod(String),
    AddService(ServiceEndpoint),
    RemoveService(String),
    UpdateAgentType(AgentType),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDeactivation {
    pub did: DID,
    pub proof: Signature,
    pub parents: Vec<Hash256>,
    pub depth: u64,
}

impl DIDDeactivation {
    pub fn compute_id(&self) -> Hash256 {
        sha3_256_multi(&[
            TX_TAG_IDENTITY,
            b"DEACTIVATE",
            self.did.0.as_bytes(),
            &self.depth.to_le_bytes(),
        ])
    }

    pub fn verify_signature(&self, pk: &VerifyingKey) -> bool {
        let message = self.signing_payload();
        verify(pk, &message, &self.proof).is_ok()
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"DID_DEACTIVATE_V1");
        payload.extend_from_slice(self.did.0.as_bytes());
        payload.extend_from_slice(&self.depth.to_le_bytes());
        payload
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotation {
    pub did: DID,
    pub old_key_id: String,
    pub new_method: VerificationMethod,
    pub proof_old: Signature,
    pub proof_new: Signature,
    pub parents: Vec<Hash256>,
    pub depth: u64,
}

impl KeyRotation {
    pub fn compute_id(&self) -> Hash256 {
        let new_method_bytes = bincode::serialize(&self.new_method).unwrap_or_default();
        sha3_256_multi(&[
            TX_TAG_IDENTITY,
            b"ROTATE_KEY",
            self.did.0.as_bytes(),
            self.old_key_id.as_bytes(),
            &new_method_bytes,
            &self.depth.to_le_bytes(),
        ])
    }

    pub fn verify_signatures(&self, old_pk: &VerifyingKey, new_pk: &VerifyingKey) -> bool {
        let message = self.signing_payload();
        verify(old_pk, &message, &self.proof_old).is_ok()
            && verify(new_pk, &message, &self.proof_new).is_ok()
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"KEY_ROTATION_V1");
        payload.extend_from_slice(self.did.0.as_bytes());
        payload.extend_from_slice(self.old_key_id.as_bytes());
        if let Ok(bytes) = bincode::serialize(&self.new_method) {
            payload.extend_from_slice(&bytes);
        }
        payload.extend_from_slice(&self.depth.to_le_bytes());
        payload
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroductionTransaction {
    pub introducer_did: DID,
    pub introduced_did: DID,
    pub edge_name: String,
    pub context: IntroductionContext,
    pub capability_grants: Vec<Capability>,
    pub proof: Signature,
    pub parents: Vec<Hash256>,
    pub depth: u64,
}

impl IntroductionTransaction {
    pub fn compute_id(&self) -> Hash256 {
        let context_bytes = bincode::serialize(&self.context).unwrap_or_default();
        sha3_256_multi(&[
            TX_TAG_INTRODUCTION,
            self.introducer_did.0.as_bytes(),
            self.introduced_did.0.as_bytes(),
            self.edge_name.as_bytes(),
            &context_bytes,
            &self.depth.to_le_bytes(),
        ])
    }

    pub fn verify_signature(&self, pk: &VerifyingKey) -> bool {
        let message = self.signing_payload();
        verify(pk, &message, &self.proof).is_ok()
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"INTRODUCTION_V1");
        payload.extend_from_slice(self.introducer_did.0.as_bytes());
        payload.extend_from_slice(self.introduced_did.0.as_bytes());
        payload.extend_from_slice(self.edge_name.as_bytes());
        if let Ok(bytes) = bincode::serialize(&self.context) {
            payload.extend_from_slice(&bytes);
        }
        payload.extend_from_slice(&self.depth.to_le_bytes());
        payload
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntroductionContext {
    Direct,
    Directory { directory_did: DID },
    Delegation { capability: CapabilityId },
    Discovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTransaction {
    pub identity: TransactionIdentity,
    pub operation: CapabilityOperation,
    pub parents: Vec<Hash256>,
    pub simhash: SimHash,
    pub depth: u64,
}

impl CapabilityTransaction {
    pub fn compute_id(&self) -> Hash256 {
        let identity_bytes = bincode::serialize(&self.identity).unwrap_or_default();
        let operation_bytes = bincode::serialize(&self.operation).unwrap_or_default();
        sha3_256_multi(&[
            TX_TAG_CAPABILITY,
            &identity_bytes,
            &operation_bytes,
            &self.depth.to_le_bytes(),
        ])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionIdentity {
    pub ephemeral_pk: VerifyingKey,
    pub did_binding_proof: Vec<u8>, // Serialized STARK proof (Phase 2)
    pub nullifier: Nullifier,
    pub reputation_bucket: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapabilityOperation {
    Invoke {
        capability_id: CapabilityId,
        invocation_proof: Vec<u8>, // Serialized STARK proof (Phase 2)
        action: Vec<u8>,
    },
    Delegate(DelegationRecord),
    Revoke {
        capability_id: CapabilityId,
        scope: RevocationScope,
    },
    Transfer {
        confidential_outputs: Vec<disentangle_zkp::ConfidentialOutput>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceTransaction {
    pub vote: GovernanceVote,
    pub parents: Vec<Hash256>,
    pub depth: u64,
}

impl GovernanceTransaction {
    pub fn compute_id(&self) -> Hash256 {
        let vote_bytes = bincode::serialize(&self.vote).unwrap_or_default();
        sha3_256_multi(&[TX_TAG_GOVERNANCE, &vote_bytes, &self.depth.to_le_bytes()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::AgentType;
    use disentangle_crypto::signature::{generate_keypair, sign};

    #[test]
    fn test_did_registration_id() {
        let (sk, pk) = generate_keypair();
        let doc = DIDDocument::new(&sk, &pk, AgentType::Human, 100);

        let reg = DIDRegistration {
            document: doc,
            pow_nonce: 12345,
            pow_hash: [0u8; 32],
            initial_capabilities: vec![],
            parents: vec![],
            depth: 100,
        };

        let id1 = reg.compute_id();
        let id2 = reg.compute_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_introduction_transaction() {
        let (sk, pk) = generate_keypair();
        let did1 = DID::new(&pk, false);

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let tx = IntroductionTransaction {
            introducer_did: did1,
            introduced_did: did2,
            edge_name: "Friend".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: sign(&sk, b"test"),
            parents: vec![],
            depth: 100,
        };

        let id = tx.compute_id();
        assert_eq!(id.len(), 32);
    }

    // ── Transaction verify_signature tests ──

    #[test]
    fn test_did_registration_document_verify() {
        let (sk, pk) = generate_keypair();
        let doc = DIDDocument::new(&sk, &pk, AgentType::Human, 100);

        let reg = DIDRegistration {
            document: doc,
            pow_nonce: 12345,
            pow_hash: [0u8; 32],
            initial_capabilities: vec![],
            parents: vec![],
            depth: 100,
        };

        // The embedded document should verify via its own proof
        assert!(reg.document.verify());
    }

    #[test]
    fn test_did_registration_compute_id_deterministic() {
        let (sk, pk) = generate_keypair();
        let doc = DIDDocument::new(&sk, &pk, AgentType::Human, 100);

        let reg = DIDRegistration {
            document: doc,
            pow_nonce: 42,
            pow_hash: [0u8; 32],
            initial_capabilities: vec![],
            parents: vec![],
            depth: 100,
        };

        let id_a = reg.compute_id();
        let id_b = reg.compute_id();
        assert_eq!(id_a, id_b);
        assert_ne!(id_a, [0u8; 32]); // must not be zero
    }

    #[test]
    fn test_did_update_verify_signature_valid() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        let updates = vec![DIDUpdateOp::RemoveService("svc-1".to_string())];
        let mut tx = DIDUpdate {
            did: did.clone(),
            updates,
            proof: Signature::from_bytes(&vec![0u8; 4627]).unwrap(),
            parents: vec![],
            depth: 200,
        };

        // Sign with the correct payload
        let payload = tx.signing_payload();
        tx.proof = sign(&sk, &payload);

        assert!(tx.verify_signature(&pk));
    }

    #[test]
    fn test_did_update_verify_signature_tampered() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        let updates = vec![DIDUpdateOp::RemoveService("svc-1".to_string())];
        let mut tx = DIDUpdate {
            did: did.clone(),
            updates,
            proof: Signature::from_bytes(&vec![0u8; 4627]).unwrap(),
            parents: vec![],
            depth: 200,
        };

        let payload = tx.signing_payload();
        tx.proof = sign(&sk, &payload);

        // Tamper with the depth number after signing
        tx.depth = 999;
        assert!(!tx.verify_signature(&pk));
    }

    #[test]
    fn test_did_deactivation_verify_signature_valid() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        let mut tx = DIDDeactivation {
            did: did.clone(),
            proof: Signature::from_bytes(&vec![0u8; 4627]).unwrap(),
            parents: vec![],
            depth: 300,
        };

        let payload = tx.signing_payload();
        tx.proof = sign(&sk, &payload);

        assert!(tx.verify_signature(&pk));
    }

    #[test]
    fn test_did_deactivation_verify_signature_tampered() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        let mut tx = DIDDeactivation {
            did: did.clone(),
            proof: Signature::from_bytes(&vec![0u8; 4627]).unwrap(),
            parents: vec![],
            depth: 300,
        };

        let payload = tx.signing_payload();
        tx.proof = sign(&sk, &payload);

        // Tamper: change the DID after signing
        let (_, pk_other) = generate_keypair();
        tx.did = DID::new(&pk_other, false);
        assert!(!tx.verify_signature(&pk));
    }

    #[test]
    fn test_key_rotation_verify_signatures_valid() {
        let (sk_old, pk_old) = generate_keypair();
        let (sk_new, pk_new) = generate_keypair();
        let did = DID::new(&pk_old, false);

        let new_method = VerificationMethod {
            id: format!("{}#key-2", did.0),
            method_type: crate::did::VerificationMethodType::Dilithium5Key2026,
            controller: did.clone(),
            public_key_bytes: pk_new.to_bytes(),
        };

        let mut tx = KeyRotation {
            did: did.clone(),
            old_key_id: format!("{}#key-1", did.0),
            new_method,
            proof_old: Signature::from_bytes(&vec![0u8; 4627]).unwrap(),
            proof_new: Signature::from_bytes(&vec![0u8; 4627]).unwrap(),
            parents: vec![],
            depth: 400,
        };

        let payload = tx.signing_payload();
        tx.proof_old = sign(&sk_old, &payload);
        tx.proof_new = sign(&sk_new, &payload);

        assert!(tx.verify_signatures(&pk_old, &pk_new));
    }

    #[test]
    fn test_key_rotation_verify_signatures_wrong_old_key() {
        let (sk_old, pk_old) = generate_keypair();
        let (sk_new, pk_new) = generate_keypair();
        let (_, pk_unrelated) = generate_keypair();
        let did = DID::new(&pk_old, false);

        let new_method = VerificationMethod {
            id: format!("{}#key-2", did.0),
            method_type: crate::did::VerificationMethodType::Dilithium5Key2026,
            controller: did.clone(),
            public_key_bytes: pk_new.to_bytes(),
        };

        let mut tx = KeyRotation {
            did: did.clone(),
            old_key_id: format!("{}#key-1", did.0),
            new_method,
            proof_old: Signature::from_bytes(&vec![0u8; 4627]).unwrap(),
            proof_new: Signature::from_bytes(&vec![0u8; 4627]).unwrap(),
            parents: vec![],
            depth: 400,
        };

        let payload = tx.signing_payload();
        tx.proof_old = sign(&sk_old, &payload);
        tx.proof_new = sign(&sk_new, &payload);

        // Verify with wrong old key -- should fail
        assert!(!tx.verify_signatures(&pk_unrelated, &pk_new));
    }

    #[test]
    fn test_introduction_verify_signature_valid() {
        let (sk, pk) = generate_keypair();
        let did1 = DID::new(&pk, false);

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let mut tx = IntroductionTransaction {
            introducer_did: did1.clone(),
            introduced_did: did2.clone(),
            edge_name: "Colleague".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: Signature::from_bytes(&vec![0u8; 4627]).unwrap(),
            parents: vec![],
            depth: 500,
        };

        let payload = tx.signing_payload();
        tx.proof = sign(&sk, &payload);

        assert!(tx.verify_signature(&pk));
    }

    #[test]
    fn test_introduction_verify_signature_tampered() {
        let (sk, pk) = generate_keypair();
        let did1 = DID::new(&pk, false);

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let mut tx = IntroductionTransaction {
            introducer_did: did1.clone(),
            introduced_did: did2.clone(),
            edge_name: "Colleague".to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: Signature::from_bytes(&vec![0u8; 4627]).unwrap(),
            parents: vec![],
            depth: 500,
        };

        let payload = tx.signing_payload();
        tx.proof = sign(&sk, &payload);

        // Tamper: change edge name after signing
        tx.edge_name = "Enemy".to_string();
        assert!(!tx.verify_signature(&pk));
    }

    #[test]
    fn test_introduction_compute_id_deterministic() {
        let (sk, pk) = generate_keypair();
        let did1 = DID::new(&pk, false);

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let tx = IntroductionTransaction {
            introducer_did: did1,
            introduced_did: did2,
            edge_name: "Neighbor".to_string(),
            context: IntroductionContext::Discovery,
            capability_grants: vec![],
            proof: sign(&sk, b"dummy"),
            parents: vec![],
            depth: 600,
        };

        let id_a = tx.compute_id();
        let id_b = tx.compute_id();
        assert_eq!(id_a, id_b);
    }
}
