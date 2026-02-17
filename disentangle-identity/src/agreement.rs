//! Settlement Agreement Types
//!
//! Bilateral commitments with measurable completion for agent coordination.

use disentangle_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};

/// Status of a service agreement
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgreementStatus {
    /// Proposed by provider, awaiting consumer acceptance
    Proposed,
    /// Active agreement, both parties have signed
    Active,
    /// Completed with success status and outcome hash
    Completed {
        success: bool,
        outcome_hash: Hash256,
    },
    /// Expired due to deadline_depth exceeded
    Expired,
    /// Under dispute
    Disputed,
}

/// Terms of a service agreement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgreementTerms {
    /// Human-readable description of the service
    pub description: String,
    /// Optional deadline as a DAG depth
    pub deadline_depth: Option<u64>,
    /// Success criteria (human-readable checklist)
    pub success_criteria: Vec<String>,
    /// Optional maximum number of invocations
    pub max_invocations: Option<u32>,
}

/// Coherence effect of a settlement (topological mass impact)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CoherenceEffect {
    /// No topological mass change from this interaction
    None,
    /// Coherence change derived from SharedIntent participation (set by protocol, not user)
    Derived { intent_id: Hash256 },
}

/// Resource type for receipts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceType {
    Compute,
    Storage,
    Bandwidth,
    ApiCall,
    Custom(String),
}

/// Receipt for resource consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReceipt {
    pub id: Hash256,
    pub payer_did: String,
    pub resource_type: ResourceType,
    pub amount: u64,
    pub settlement_id: Option<Hash256>,
    pub depth: u64,
    pub timestamp: u64,
}

/// A bilateral settlement agreement between two agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementAgreement {
    /// Unique identifier for the agreement
    pub id: Hash256,
    /// Provider DID (the agent providing the service)
    pub provider_did: String,
    /// Consumer DID (the agent receiving the service)
    pub consumer_did: String,
    /// Optional capability ID that this agreement exercises
    pub capability_id: Option<Hash256>,
    /// Terms of the agreement
    pub terms: AgreementTerms,
    /// Current status
    pub status: AgreementStatus,
    /// Coherence effect of this settlement
    pub coherence_effect: CoherenceEffect,
    /// DAG depth at which the agreement was created
    pub created_depth: u64,
    /// DAG depth at which the agreement was completed (if applicable)
    pub completed_depth: Option<u64>,
    /// Provider's signature (created at proposal time)
    pub provider_signature: Vec<u8>,
    /// Consumer's signature (added at acceptance time)
    pub consumer_signature: Option<Vec<u8>>,
}

impl SettlementAgreement {
    /// Create a new proposed agreement
    pub fn new(
        provider_did: String,
        consumer_did: String,
        capability_id: Option<Hash256>,
        terms: AgreementTerms,
        created_depth: u64,
        provider_signature: Vec<u8>,
    ) -> Self {
        // Compute agreement ID from content
        let id = Self::compute_id(
            &provider_did,
            &consumer_did,
            &terms.description,
            created_depth,
        );

        Self {
            id,
            provider_did,
            consumer_did,
            capability_id,
            terms,
            status: AgreementStatus::Proposed,
            coherence_effect: CoherenceEffect::None,
            created_depth,
            completed_depth: None,
            provider_signature,
            consumer_signature: None,
        }
    }

    /// Compute agreement ID from key parameters
    fn compute_id(
        provider_did: &str,
        consumer_did: &str,
        description: &str,
        created_depth: u64,
    ) -> Hash256 {
        use disentangle_crypto::hash::sha3_256_multi;

        sha3_256_multi(&[
            b"AGREEMENT_ID_V1",
            provider_did.as_bytes(),
            consumer_did.as_bytes(),
            description.as_bytes(),
            &created_depth.to_le_bytes(),
        ])
    }

    /// Accept the agreement (consumer signature)
    pub fn accept(&mut self, consumer_signature: Vec<u8>) {
        if self.status == AgreementStatus::Proposed {
            self.consumer_signature = Some(consumer_signature);
            self.status = AgreementStatus::Active;
        }
    }

    /// Mark the agreement as completed
    pub fn complete(&mut self, success: bool, outcome_hash: Hash256, completed_depth: u64) {
        if self.status == AgreementStatus::Active {
            self.status = AgreementStatus::Completed {
                success,
                outcome_hash,
            };
            self.completed_depth = Some(completed_depth);
        }
    }

    /// Check if the agreement has expired
    pub fn check_expiry(&mut self, current_depth: u64) {
        if let Some(deadline) = self.terms.deadline_depth {
            if current_depth > deadline
                && matches!(
                    self.status,
                    AgreementStatus::Active | AgreementStatus::Proposed
                )
            {
                self.status = AgreementStatus::Expired;
            }
        }
    }

    /// Check if the agreement involves the given DID
    pub fn involves_did(&self, did: &str) -> bool {
        self.provider_did == did || self.consumer_did == did
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agreement_creation() {
        let terms = AgreementTerms {
            description: "Compute 100 embeddings".to_string(),
            deadline_depth: Some(1000),
            success_criteria: vec![
                "All 100 embeddings returned".to_string(),
                "Latency < 500ms".to_string(),
            ],
            max_invocations: Some(100),
        };

        let agreement = SettlementAgreement::new(
            "did:disentangle:provider".to_string(),
            "did:disentangle:consumer".to_string(),
            None,
            terms,
            100,
            vec![1, 2, 3], // Mock signature
        );

        assert_eq!(agreement.status, AgreementStatus::Proposed);
        assert!(agreement.consumer_signature.is_none());
        assert_eq!(agreement.created_depth, 100);
    }

    #[test]
    fn test_agreement_acceptance() {
        let terms = AgreementTerms {
            description: "Test service".to_string(),
            deadline_depth: None,
            success_criteria: vec![],
            max_invocations: None,
        };

        let mut agreement = SettlementAgreement::new(
            "did:a".to_string(),
            "did:b".to_string(),
            None,
            terms,
            100,
            vec![1, 2, 3],
        );

        agreement.accept(vec![4, 5, 6]);

        assert_eq!(agreement.status, AgreementStatus::Active);
        assert!(agreement.consumer_signature.is_some());
    }

    #[test]
    fn test_agreement_completion() {
        let terms = AgreementTerms {
            description: "Test service".to_string(),
            deadline_depth: None,
            success_criteria: vec![],
            max_invocations: None,
        };

        let mut agreement = SettlementAgreement::new(
            "did:a".to_string(),
            "did:b".to_string(),
            None,
            terms,
            100,
            vec![1, 2, 3],
        );

        agreement.accept(vec![4, 5, 6]);

        let outcome_hash = [42u8; 32];
        agreement.complete(true, outcome_hash, 200);

        match agreement.status {
            AgreementStatus::Completed {
                success,
                outcome_hash: hash,
            } => {
                assert!(success);
                assert_eq!(hash, outcome_hash);
            }
            _ => panic!("Expected Completed status"),
        }
        assert_eq!(agreement.completed_depth, Some(200));
    }

    #[test]
    fn test_agreement_expiry() {
        let terms = AgreementTerms {
            description: "Test service".to_string(),
            deadline_depth: Some(500),
            success_criteria: vec![],
            max_invocations: None,
        };

        let mut agreement = SettlementAgreement::new(
            "did:a".to_string(),
            "did:b".to_string(),
            None,
            terms,
            100,
            vec![1, 2, 3],
        );

        agreement.accept(vec![4, 5, 6]);
        assert_eq!(agreement.status, AgreementStatus::Active);

        // Check before deadline
        agreement.check_expiry(400);
        assert_eq!(agreement.status, AgreementStatus::Active);

        // Check after deadline
        agreement.check_expiry(600);
        assert_eq!(agreement.status, AgreementStatus::Expired);
    }

    #[test]
    fn test_agreement_involves_did() {
        let terms = AgreementTerms {
            description: "Test".to_string(),
            deadline_depth: None,
            success_criteria: vec![],
            max_invocations: None,
        };

        let agreement = SettlementAgreement::new(
            "did:provider".to_string(),
            "did:consumer".to_string(),
            None,
            terms,
            100,
            vec![],
        );

        assert!(agreement.involves_did("did:provider"));
        assert!(agreement.involves_did("did:consumer"));
        assert!(!agreement.involves_did("did:other"));
    }

    #[test]
    fn test_agreement_id_deterministic() {
        let terms = AgreementTerms {
            description: "Test service".to_string(),
            deadline_depth: None,
            success_criteria: vec![],
            max_invocations: None,
        };

        let agreement1 = SettlementAgreement::new(
            "did:a".to_string(),
            "did:b".to_string(),
            None,
            terms.clone(),
            100,
            vec![1, 2, 3],
        );

        let agreement2 = SettlementAgreement::new(
            "did:a".to_string(),
            "did:b".to_string(),
            None,
            terms,
            100,
            vec![1, 2, 3],
        );

        assert_eq!(agreement1.id, agreement2.id);
    }
}
