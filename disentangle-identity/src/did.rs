//! DID Types and Documents
//!
//! Implements the did:disentangle DID method with support for Human, AGI, and Hybrid agent types.

use disentangle_crypto::{
    hash::{Hash256, sha3_256, sha3_256_multi},
    signature::{VerifyingKey, Signature, SigningKey, sign, verify},
};
use serde::{Serialize, Deserialize};

pub type CapabilityRef = String;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DID(pub String);

impl DID {
    /// Create a new DID from a root public key.
    /// Format: did:disentangle:<hex(sha3_256(pk))> or did:disentangle:agi:<hex(sha3_256(pk))>
    pub fn new(root_pk: &VerifyingKey, is_agi: bool) -> Self {
        let pk_hash = sha3_256(&root_pk.to_bytes());
        let hex_id = hex::encode(pk_hash);

        if is_agi {
            Self(format!("did:disentangle:agi:{}", hex_id))
        } else {
            Self(format!("did:disentangle:{}", hex_id))
        }
    }

    /// Extract the method-specific ID portion (the part after did:disentangle:)
    pub fn method_specific_id(&self) -> &str {
        if let Some(id) = self.0.strip_prefix("did:disentangle:agi:") {
            id
        } else if let Some(id) = self.0.strip_prefix("did:disentangle:") {
            id
        } else {
            &self.0
        }
    }

    /// Check if this is an AGI DID
    pub fn is_agi(&self) -> bool {
        self.0.contains(":agi:")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDocument {
    pub id: DID,
    pub controller: DID,
    pub verification_methods: Vec<VerificationMethod>,
    pub capability_invocation: Vec<CapabilityRef>,
    pub capability_delegation: Vec<CapabilityRef>,
    pub service: Vec<ServiceEndpoint>,
    pub agent_type: AgentType,
    pub created_depth: u64,
    pub updated_depth: u64,
    pub proof: Signature,
}

impl DIDDocument {
    /// Create a new DID document signed with the provided key
    pub fn new(signing_key: &SigningKey, verifying_key: &VerifyingKey, agent_type: AgentType, depth: u64) -> Self {
        let is_agi = matches!(agent_type, AgentType::AGI { .. });
        let did = DID::new(verifying_key, is_agi);

        let verification_method = VerificationMethod {
            id: format!("{}#key-1", did.0),
            method_type: VerificationMethodType::Dilithium5Key2026,
            controller: did.clone(),
            public_key_bytes: verifying_key.to_bytes(),
        };

        let mut doc = Self {
            id: did.clone(),
            controller: did,
            verification_methods: vec![verification_method],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
            agent_type,
            created_depth: depth,
            updated_depth: depth,
            proof: Signature::from_bytes(&vec![0u8; 4627]).unwrap(), // Placeholder
        };

        // Sign the document
        let message = doc.signing_payload();
        doc.proof = sign(signing_key, &message);

        doc
    }

    /// Verify the document's signature
    pub fn verify(&self) -> bool {
        if self.verification_methods.is_empty() {
            return false;
        }

        let message = self.signing_payload();

        // Try to verify with the first verification method
        if let Ok(pk) = VerifyingKey::from_bytes(&self.verification_methods[0].public_key_bytes) {
            verify(&pk, &message, &self.proof).is_ok()
        } else {
            false
        }
    }

    /// Compute the document's ID hash for use as a NodeId
    pub fn id_hash(&self) -> Hash256 {
        sha3_256_multi(&[
            b"DID_DOC_V1",
            self.id.0.as_bytes(),
            &self.created_depth.to_le_bytes(),
        ])
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"DID_DOC_V1");
        payload.extend_from_slice(self.id.0.as_bytes());
        payload.extend_from_slice(self.controller.0.as_bytes());

        // Serialize verification methods
        if let Ok(vm_bytes) = bincode::serialize(&self.verification_methods) {
            payload.extend_from_slice(&vm_bytes);
        }

        payload.extend_from_slice(&self.created_depth.to_le_bytes());
        payload.extend_from_slice(&self.updated_depth.to_le_bytes());

        // Serialize agent type
        if let Ok(agent_bytes) = bincode::serialize(&self.agent_type) {
            payload.extend_from_slice(&agent_bytes);
        }

        payload
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentType {
    Human,
    AGI { runtime_attestation: Option<RuntimeAttestation> },
    Hybrid { human_did: DID, agi_did: DID },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    pub method_type: VerificationMethodType,
    pub controller: DID,
    pub public_key_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationMethodType {
    Dilithium5Key2026,
    Kyber1024Key2026,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeAttestation {
    pub model_hash: Hash256,
    pub runtime_hash: Hash256,
    pub attestation_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    pub service_type: String,
    pub endpoint: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use disentangle_crypto::signature::generate_keypair;

    #[test]
    fn test_did_creation() {
        let (_, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        assert!(did.0.starts_with("did:disentangle:"));
        assert!(!did.is_agi());
    }

    #[test]
    fn test_agi_did_creation() {
        let (_, pk) = generate_keypair();
        let did = DID::new(&pk, true);
        assert!(did.0.starts_with("did:disentangle:agi:"));
        assert!(did.is_agi());
    }

    #[test]
    fn test_method_specific_id() {
        let (_, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let id = did.method_specific_id();
        assert!(!id.starts_with("did:"));
        assert_eq!(id.len(), 64); // hex encoding of 32 bytes
    }

    #[test]
    fn test_did_document_creation() {
        let (sk, pk) = generate_keypair();
        let agent_type = AgentType::Human;
        let doc = DIDDocument::new(&sk, &pk, agent_type, 1000);

        assert_eq!(doc.created_depth, 1000);
        assert_eq!(doc.updated_depth, 1000);
        assert_eq!(doc.verification_methods.len(), 1);
    }

    #[test]
    fn test_did_document_id_hash() {
        let (sk, pk) = generate_keypair();
        let doc = DIDDocument::new(&sk, &pk, AgentType::Human, 1000);
        let hash = doc.id_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_agi_agent_type() {
        let (sk, pk) = generate_keypair();
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
    }

    // ── DIDDocument tampered data tests ──

    #[test]
    fn test_did_document_verify_valid() {
        let (sk, pk) = generate_keypair();
        let doc = DIDDocument::new(&sk, &pk, AgentType::Human, 500);
        assert!(doc.verify());
    }

    #[test]
    fn test_did_document_tampered_created_depth() {
        let (sk, pk) = generate_keypair();
        let mut doc = DIDDocument::new(&sk, &pk, AgentType::Human, 500);
        // Tamper with the created depth after signing
        doc.created_depth = 999;
        assert!(!doc.verify());
    }

    #[test]
    fn test_did_document_tampered_updated_depth() {
        let (sk, pk) = generate_keypair();
        let mut doc = DIDDocument::new(&sk, &pk, AgentType::Human, 500);
        // Tamper with the updated field
        doc.updated_depth = 12345;
        assert!(!doc.verify());
    }

    #[test]
    fn test_did_document_tampered_controller() {
        let (sk, pk) = generate_keypair();
        let mut doc = DIDDocument::new(&sk, &pk, AgentType::Human, 500);
        // Tamper: change the controller DID
        let (_, pk_other) = generate_keypair();
        doc.controller = DID::new(&pk_other, false);
        assert!(!doc.verify());
    }

    #[test]
    fn test_did_document_tampered_agent_type() {
        let (sk, pk) = generate_keypair();
        let mut doc = DIDDocument::new(&sk, &pk, AgentType::Human, 500);
        // Tamper: change agent type from Human to AGI
        doc.agent_type = AgentType::AGI { runtime_attestation: None };
        assert!(!doc.verify());
    }

    #[test]
    fn test_did_document_empty_verification_methods() {
        let (sk, pk) = generate_keypair();
        let mut doc = DIDDocument::new(&sk, &pk, AgentType::Human, 500);
        // Remove all verification methods -- verify should return false
        doc.verification_methods.clear();
        assert!(!doc.verify());
    }

    // ── Hybrid agent type tests ──

    #[test]
    fn test_hybrid_agent_type_creation() {
        let (sk, pk) = generate_keypair();
        let (_, pk_human) = generate_keypair();
        let (_, pk_agi) = generate_keypair();

        let human_did = DID::new(&pk_human, false);
        let agi_did = DID::new(&pk_agi, true);

        let agent_type = AgentType::Hybrid {
            human_did: human_did.clone(),
            agi_did: agi_did.clone(),
        };

        let doc = DIDDocument::new(&sk, &pk, agent_type, 1000);

        // Hybrid DIDs are not AGI DIDs (is_agi checks the DID string, not agent type)
        assert!(!doc.id.is_agi());
        assert!(doc.verify());

        // Verify the agent type was preserved
        match &doc.agent_type {
            AgentType::Hybrid { human_did: h, agi_did: a } => {
                assert_eq!(h, &human_did);
                assert_eq!(a, &agi_did);
            }
            other => panic!("Expected Hybrid agent type, got: {:?}", other),
        }
    }

    #[test]
    fn test_hybrid_agent_type_document_verify_and_hash() {
        let (sk, pk) = generate_keypair();
        let (_, pk_human) = generate_keypair();
        let (_, pk_agi) = generate_keypair();

        let human_did = DID::new(&pk_human, false);
        let agi_did = DID::new(&pk_agi, true);

        let agent_type = AgentType::Hybrid {
            human_did,
            agi_did,
        };

        let doc = DIDDocument::new(&sk, &pk, agent_type, 2000);

        // Verify signature is valid
        assert!(doc.verify());

        // Verify id_hash is a 32-byte hash
        let hash = doc.id_hash();
        assert_eq!(hash.len(), 32);

        // Verify id_hash is deterministic
        let hash2 = doc.id_hash();
        assert_eq!(hash, hash2);
    }
}
