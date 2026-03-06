//! Capability Types and Operations
//!
//! Object capabilities with delegation, constraints, and revocation support.

use crate::did::DID;
use crate::IdentityError;
use disentangle_crypto::{
    hash::{sha3_256_multi, Hash256},
    signature::{sign, verify, Signature, SigningKey, VerifyingKey},
};
use disentangle_dag::{FixedPoint, SCALE};
use serde::{Deserialize, Serialize};

/// Capability tiers derived from composite coherence score.
/// Each tier unlocks progressively more network capabilities.
/// Thresholds are expressed as fractions of SCALE (65536).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CoherenceTier {
    /// Score < 10% SCALE (~6554). New or isolated nodes.
    /// Can: read public state, submit basic transactions
    Observer,
    /// Score >= 10% SCALE. Established local presence.
    /// Can: participate in consensus, receive delegations
    Participant,
    /// Score >= 30% SCALE (~19661). Significant network contribution.
    /// Can: delegate capabilities, vote in governance, serve as introducer
    Contributor,
    /// Score >= 55% SCALE (~36045). Strong coherence across all dimensions.
    /// Can: propose governance changes, serve as oracle, issue attestations
    Authority,
    /// Score >= 80% SCALE (~52429). Exceptional sustained coherence.
    /// Can: manage network parameters, revoke capabilities, anchor trust
    Steward,
}

impl CoherenceTier {
    /// Threshold for Observer tier (always qualifies)
    const OBSERVER_THRESHOLD: i64 = 0;
    /// Threshold for Participant tier: 10% of SCALE
    const PARTICIPANT_THRESHOLD: i64 = (SCALE as i64 * 10) / 100;
    /// Threshold for Contributor tier: 30% of SCALE
    const CONTRIBUTOR_THRESHOLD: i64 = (SCALE as i64 * 30) / 100;
    /// Threshold for Authority tier: 55% of SCALE
    const AUTHORITY_THRESHOLD: i64 = (SCALE as i64 * 55) / 100;
    /// Threshold for Steward tier: 80% of SCALE
    const STEWARD_THRESHOLD: i64 = (SCALE as i64 * 80) / 100;

    /// Map a composite coherence score to its corresponding tier.
    pub fn from_score(score: i64) -> CoherenceTier {
        if score >= Self::STEWARD_THRESHOLD {
            CoherenceTier::Steward
        } else if score >= Self::AUTHORITY_THRESHOLD {
            CoherenceTier::Authority
        } else if score >= Self::CONTRIBUTOR_THRESHOLD {
            CoherenceTier::Contributor
        } else if score >= Self::PARTICIPANT_THRESHOLD {
            CoherenceTier::Participant
        } else {
            CoherenceTier::Observer
        }
    }

    /// Return the minimum composite score required for this tier.
    pub fn minimum_score(&self) -> i64 {
        match self {
            CoherenceTier::Observer => Self::OBSERVER_THRESHOLD,
            CoherenceTier::Participant => Self::PARTICIPANT_THRESHOLD,
            CoherenceTier::Contributor => Self::CONTRIBUTOR_THRESHOLD,
            CoherenceTier::Authority => Self::AUTHORITY_THRESHOLD,
            CoherenceTier::Steward => Self::STEWARD_THRESHOLD,
        }
    }

    /// Check whether this tier is sufficient to perform an action requiring `required` tier.
    ///
    /// Returns true if `self >= required`.
    pub fn can_perform(&self, required: CoherenceTier) -> bool {
        *self >= required
    }
}

pub type CapabilityId = Hash256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: CapabilityId,
    pub issuer: DID,
    pub subject: CapabilitySubject,
    pub constraints: Vec<Constraint>,
    pub delegatable: bool,
    pub max_delegation_depth: u32,
    pub expiry: Option<u64>,
    pub proof: Signature,
}

impl Capability {
    /// Create a new capability signed by the issuer
    pub fn new(
        issuer: &DID,
        _issuer_pk: &VerifyingKey,
        subject: CapabilitySubject,
        sk: &SigningKey,
    ) -> Self {
        let mut cap = Self {
            id: [0u8; 32],
            issuer: issuer.clone(),
            subject,
            constraints: vec![],
            delegatable: true,
            max_delegation_depth: 10,
            expiry: None,
            proof: Signature::from_bytes(&vec![0u8; 4627]).unwrap(), // Placeholder
        };

        cap.id = cap.compute_id();

        // Sign the capability
        let message = cap.signing_payload();
        cap.proof = sign(sk, &message);

        cap
    }

    /// Compute the capability ID from its content
    pub fn compute_id(&self) -> CapabilityId {
        let content = bincode::serialize(&(
            &self.issuer,
            &self.subject,
            &self.constraints,
            self.delegatable,
            self.max_delegation_depth,
            &self.expiry,
        ))
        .unwrap_or_default();

        sha3_256_multi(&[b"CAPABILITY_ID_V1", &content])
    }

    /// Verify the capability's signature
    pub fn verify(&self, issuer_pk: &VerifyingKey) -> bool {
        let message = self.signing_payload();
        verify(issuer_pk, &message, &self.proof).is_ok()
    }

    /// Check if all constraints are satisfied in the given context
    pub fn check_constraints(&self, context: &ConstraintContext) -> bool {
        for constraint in &self.constraints {
            if !constraint.is_satisfied(context) {
                return false;
            }
        }
        true
    }

    fn signing_payload(&self) -> Vec<u8> {
        bincode::serialize(&(
            &self.id,
            &self.issuer,
            &self.subject,
            &self.constraints,
            self.delegatable,
            self.max_delegation_depth,
            &self.expiry,
        ))
        .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapabilitySubject {
    Transact {
        scope: TransactionScope,
    },
    Name {
        namespace: DID,
        operations: Vec<NameOp>,
    },
    Access {
        resource_id: Hash256,
        operations: Vec<AccessOp>,
    },
    Govern {
        scope: GovernanceScope,
        weight: FixedPoint,
    },
    Custom {
        type_uri: String,
        parameters: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionScope {
    All,
    Transfer,
    Introduction,
    Governance,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NameOp {
    Read,
    Write,
    Delegate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AccessOp {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceScope {
    ProtocolParameters,
    CapabilityPolicy,
    NamingHub,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Constraint {
    TemporalBound {
        not_before: u64,
        not_after: u64,
    },
    ReputationMinimum {
        bucket: u8,
    },
    CoherenceMinimum {
        min_mass: u64,
    },
    DelegationDepth {
        max_depth: u32,
    },
    RequiresCapability {
        prerequisite: CapabilityId,
    },
    /// Require the entity to hold at least the specified coherence tier.
    TierMinimum {
        tier: CoherenceTier,
    },
}

impl Constraint {
    pub fn is_satisfied(&self, context: &ConstraintContext) -> bool {
        match self {
            Self::TemporalBound {
                not_before,
                not_after,
            } => context.current_depth >= *not_before && context.current_depth <= *not_after,
            Self::ReputationMinimum { bucket } => context.reputation_bucket >= *bucket,
            Self::CoherenceMinimum { min_mass } => {
                // Compare without overflow: mass/SCALE >= min_mass
                (context.topological_mass / SCALE) as u64 >= *min_mass
            }
            Self::DelegationDepth { max_depth } => context.current_delegation_depth <= *max_depth,
            Self::RequiresCapability { prerequisite } => {
                context.held_capabilities.contains(prerequisite)
            }
            Self::TierMinimum { tier } => context.coherence_tier.can_perform(*tier),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConstraintContext {
    pub current_depth: u64,
    pub reputation_bucket: u8,
    pub topological_mass: FixedPoint,
    pub current_delegation_depth: u32,
    pub held_capabilities: Vec<CapabilityId>,
    /// The entity's current coherence tier, used for TierMinimum constraints.
    pub coherence_tier: CoherenceTier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRecord {
    pub capability_id: CapabilityId,
    pub delegator: DID,
    pub delegatee: DID,
    pub additional_constraints: Vec<Constraint>,
    pub chain_depth: u32,
    pub depth: u64,
    pub proof: Signature,
}

impl DelegationRecord {
    /// Create a new delegation record
    pub fn new(
        cap: &Capability,
        delegator: &DID,
        delegatee: &DID,
        sk: &SigningKey,
        depth: u64,
    ) -> Result<Self, IdentityError> {
        if !cap.delegatable {
            return Err(IdentityError::ConstraintNotSatisfied(
                "Capability is not delegatable".to_string(),
            ));
        }

        let mut record = Self {
            capability_id: cap.id,
            delegator: delegator.clone(),
            delegatee: delegatee.clone(),
            additional_constraints: vec![],
            chain_depth: 1,
            depth,
            proof: Signature::from_bytes(&vec![0u8; 4627]).unwrap(), // Placeholder
        };

        // Sign the delegation
        let message = record.signing_payload();
        record.proof = sign(sk, &message);

        Ok(record)
    }

    /// Verify a delegation chain is valid
    pub fn verify_chain(
        chain: &[DelegationRecord],
        capability: &Capability,
        delegator_pks: &[VerifyingKey],
    ) -> bool {
        if chain.is_empty() {
            return true;
        }

        if chain.len() != delegator_pks.len() {
            return false;
        }

        // Check depth doesn't exceed max
        if chain.len() as u32 > capability.max_delegation_depth {
            return false;
        }

        // Verify each delegation signature
        for (i, (record, pk)) in chain.iter().zip(delegator_pks.iter()).enumerate() {
            if record.capability_id != capability.id {
                return false;
            }

            if record.chain_depth != (i as u32) + 1 {
                return false;
            }

            let message = record.signing_payload();
            if verify(pk, &message, &record.proof).is_err() {
                return false;
            }

            // Verify chain continuity (delegator of next must be delegatee of current)
            if i > 0 && chain[i - 1].delegatee != record.delegator {
                return false;
            }
        }

        true
    }

    fn signing_payload(&self) -> Vec<u8> {
        bincode::serialize(&(
            &self.capability_id,
            &self.delegator,
            &self.delegatee,
            &self.additional_constraints,
            self.chain_depth,
            self.depth,
        ))
        .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationScope {
    Single,
    Subtree,
    All,
}

/// Pre-defined capability templates for common agent interactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapabilityTemplate {
    /// Compute invocation capability
    ComputeInvoke {
        endpoint: String,
        max_calls_per_epoch: u32,
    },
    /// Data read access
    DataRead { scope: String, ttl_depth: u64 },
    /// Data write access
    DataWrite { scope: String, max_size_bytes: u64 },
    /// Spending authorization
    SpendAuthorize {
        max_amount: u64,
        rate_limit_per_epoch: u32,
        allowed_recipients: Option<Vec<String>>,
    },
    /// Delegation proxy capability
    DelegateProxy {
        max_depth: u32,
        allowed_subjects: Vec<String>,
    },
    /// Custom capability with arbitrary schema
    Custom {
        schema: String,
        params: serde_json::Value,
    },
}

impl CapabilityTemplate {
    /// Get a list of all available templates
    pub fn list_templates() -> Vec<String> {
        vec![
            "ComputeInvoke".to_string(),
            "DataRead".to_string(),
            "DataWrite".to_string(),
            "SpendAuthorize".to_string(),
            "DelegateProxy".to_string(),
            "Custom".to_string(),
        ]
    }

    /// Convert a template to a capability subject and constraints
    pub fn to_capability_params(&self) -> (CapabilitySubject, Vec<Constraint>) {
        match self {
            Self::ComputeInvoke {
                endpoint,
                max_calls_per_epoch,
            } => {
                let subject = CapabilitySubject::Custom {
                    type_uri: format!("compute://{}", endpoint),
                    parameters: max_calls_per_epoch.to_le_bytes().to_vec(),
                };
                (subject, vec![])
            }
            Self::DataRead { scope, ttl_depth } => {
                // Create a resource ID from the scope
                let resource_id = disentangle_crypto::hash::sha3_256(scope.as_bytes());
                let subject = CapabilitySubject::Access {
                    resource_id,
                    operations: vec![AccessOp::Read],
                };
                let constraint = Constraint::TemporalBound {
                    not_before: 0,
                    not_after: *ttl_depth,
                };
                (subject, vec![constraint])
            }
            Self::DataWrite {
                scope,
                max_size_bytes,
            } => {
                let params_bytes = max_size_bytes.to_le_bytes().to_vec();
                let subject = CapabilitySubject::Custom {
                    type_uri: format!("data:write:{}", scope),
                    parameters: params_bytes,
                };
                (subject, vec![])
            }
            Self::SpendAuthorize {
                max_amount,
                rate_limit_per_epoch,
                allowed_recipients,
            } => {
                let mut params = max_amount.to_le_bytes().to_vec();
                params.extend_from_slice(&rate_limit_per_epoch.to_le_bytes());
                if let Some(recipients) = allowed_recipients {
                    for recipient in recipients {
                        params.extend_from_slice(recipient.as_bytes());
                    }
                }
                let subject = CapabilitySubject::Custom {
                    type_uri: "spend:authorize".to_string(),
                    parameters: params,
                };
                (subject, vec![])
            }
            Self::DelegateProxy {
                max_depth,
                allowed_subjects,
            } => {
                let subject = CapabilitySubject::Govern {
                    scope: GovernanceScope::CapabilityPolicy,
                    weight: 0, // Weight not used for proxy
                };
                let constraint = Constraint::DelegationDepth {
                    max_depth: *max_depth,
                };
                let mut params = Vec::new();
                for subj in allowed_subjects {
                    params.extend_from_slice(subj.as_bytes());
                }
                (subject, vec![constraint])
            }
            Self::Custom { schema, params } => {
                let params_bytes = serde_json::to_vec(params).unwrap_or_default();
                let subject = CapabilitySubject::Custom {
                    type_uri: schema.clone(),
                    parameters: params_bytes,
                };
                (subject, vec![])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use disentangle_crypto::signature::generate_keypair;

    #[test]
    fn test_capability_creation() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let subject = CapabilitySubject::Transact {
            scope: TransactionScope::All,
        };

        let cap = Capability::new(&did, &pk, subject, &sk);

        assert_eq!(cap.issuer, did);
        assert!(cap.delegatable);
        assert_eq!(cap.max_delegation_depth, 10);
    }

    #[test]
    fn test_capability_id_computation() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let subject = CapabilitySubject::Transact {
            scope: TransactionScope::All,
        };

        let cap = Capability::new(&did, &pk, subject, &sk);
        let id1 = cap.compute_id();
        let id2 = cap.compute_id();

        assert_eq!(id1, id2);
        assert_eq!(id1, cap.id);
    }

    #[test]
    fn test_capability_verification() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let subject = CapabilitySubject::Transact {
            scope: TransactionScope::All,
        };

        let cap = Capability::new(&did, &pk, subject, &sk);
        assert!(cap.verify(&pk));
    }

    #[test]
    fn test_temporal_constraint() {
        let constraint = Constraint::TemporalBound {
            not_before: 100,
            not_after: 200,
        };

        let context = ConstraintContext {
            current_depth: 150,
            reputation_bucket: 0,
            topological_mass: 0,
            current_delegation_depth: 0,
            held_capabilities: vec![],
            coherence_tier: CoherenceTier::Observer,
        };

        assert!(constraint.is_satisfied(&context));

        let early_context = ConstraintContext {
            current_depth: 50,
            ..context.clone()
        };
        assert!(!constraint.is_satisfied(&early_context));

        let late_context = ConstraintContext {
            current_depth: 250,
            ..context
        };
        assert!(!constraint.is_satisfied(&late_context));
    }

    #[test]
    fn test_delegation_creation() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let subject = CapabilitySubject::Transact {
            scope: TransactionScope::All,
        };

        let cap = Capability::new(&did, &pk, subject, &sk);

        let (_, delegatee_pk) = generate_keypair();
        let delegatee_did = DID::new(&delegatee_pk, false);

        let delegation = DelegationRecord::new(&cap, &did, &delegatee_did, &sk, 1000);
        assert!(delegation.is_ok());

        let record = delegation.unwrap();
        assert_eq!(record.capability_id, cap.id);
        assert_eq!(record.chain_depth, 1);
    }

    // ── Constraint checking tests ──

    #[test]
    fn test_reputation_minimum_passes() {
        let constraint = Constraint::ReputationMinimum { bucket: 3 };
        let context = ConstraintContext {
            current_depth: 0,
            reputation_bucket: 5, // 5 >= 3 -> pass
            topological_mass: 0,
            current_delegation_depth: 0,
            held_capabilities: vec![],
            coherence_tier: CoherenceTier::Observer,
        };
        assert!(constraint.is_satisfied(&context));
    }

    #[test]
    fn test_reputation_minimum_exact_boundary() {
        let constraint = Constraint::ReputationMinimum { bucket: 3 };
        let context = ConstraintContext {
            current_depth: 0,
            reputation_bucket: 3, // exactly equal -> pass
            topological_mass: 0,
            current_delegation_depth: 0,
            held_capabilities: vec![],
            coherence_tier: CoherenceTier::Observer,
        };
        assert!(constraint.is_satisfied(&context));
    }

    #[test]
    fn test_reputation_minimum_fails() {
        let constraint = Constraint::ReputationMinimum { bucket: 3 };
        let context = ConstraintContext {
            current_depth: 0,
            reputation_bucket: 2, // 2 < 3 -> fail
            topological_mass: 0,
            current_delegation_depth: 0,
            held_capabilities: vec![],
            coherence_tier: CoherenceTier::Observer,
        };
        assert!(!constraint.is_satisfied(&context));
    }

    #[test]
    fn test_coherence_minimum_passes() {
        // min_mass is compared against mass/SCALE (integer division)
        // topological_mass is i32 (FixedPoint), so use values that fit.
        // With min_mass=100, we need topological_mass/SCALE >= 100,
        // i.e. topological_mass >= 100 * 65536 = 6_553_600
        let constraint = Constraint::CoherenceMinimum { min_mass: 100 };
        let context = ConstraintContext {
            current_depth: 0,
            reputation_bucket: 0,
            topological_mass: 100 * SCALE, // exactly meets threshold
            current_delegation_depth: 0,
            held_capabilities: vec![],
            coherence_tier: CoherenceTier::Observer,
        };
        assert!(constraint.is_satisfied(&context));
    }

    #[test]
    fn test_coherence_minimum_fails() {
        let constraint = Constraint::CoherenceMinimum { min_mass: 100 };
        let context = ConstraintContext {
            current_depth: 0,
            reputation_bucket: 0,
            topological_mass: 99 * SCALE, // just below threshold
            current_delegation_depth: 0,
            held_capabilities: vec![],
            coherence_tier: CoherenceTier::Observer,
        };
        assert!(!constraint.is_satisfied(&context));
    }

    #[test]
    fn test_requires_capability_passes() {
        let prerequisite_id = [42u8; 32];
        let constraint = Constraint::RequiresCapability {
            prerequisite: prerequisite_id,
        };
        let context = ConstraintContext {
            current_depth: 0,
            reputation_bucket: 0,
            topological_mass: 0,
            current_delegation_depth: 0,
            held_capabilities: vec![[1u8; 32], prerequisite_id, [3u8; 32]],
            coherence_tier: CoherenceTier::Observer,
        };
        assert!(constraint.is_satisfied(&context));
    }

    #[test]
    fn test_requires_capability_fails() {
        let prerequisite_id = [42u8; 32];
        let constraint = Constraint::RequiresCapability {
            prerequisite: prerequisite_id,
        };
        let context = ConstraintContext {
            current_depth: 0,
            reputation_bucket: 0,
            topological_mass: 0,
            current_delegation_depth: 0,
            held_capabilities: vec![[1u8; 32], [2u8; 32]], // does not contain prerequisite
            coherence_tier: CoherenceTier::Observer,
        };
        assert!(!constraint.is_satisfied(&context));
    }

    // ── Capability-level constraint checking (multiple constraints) ──

    #[test]
    fn test_capability_multiple_constraints_all_pass() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let subject = CapabilitySubject::Transact {
            scope: TransactionScope::All,
        };

        let mut cap = Capability::new(&did, &pk, subject, &sk);
        cap.constraints = vec![
            Constraint::ReputationMinimum { bucket: 2 },
            Constraint::CoherenceMinimum { min_mass: 100 },
            Constraint::TemporalBound {
                not_before: 10,
                not_after: 1000,
            },
        ];

        let context = ConstraintContext {
            current_depth: 500,
            reputation_bucket: 5,
            topological_mass: 200 * SCALE,
            current_delegation_depth: 0,
            held_capabilities: vec![],
            coherence_tier: CoherenceTier::Observer,
        };

        assert!(cap.check_constraints(&context));
    }

    #[test]
    fn test_capability_multiple_constraints_one_fails() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let subject = CapabilitySubject::Transact {
            scope: TransactionScope::All,
        };

        let mut cap = Capability::new(&did, &pk, subject, &sk);
        cap.constraints = vec![
            Constraint::ReputationMinimum { bucket: 2 }, // passes (5 >= 2)
            Constraint::CoherenceMinimum { min_mass: 100 }, // fails (50 < 100)
            Constraint::TemporalBound {
                not_before: 10,
                not_after: 1000,
            }, // passes
        ];

        let context = ConstraintContext {
            current_depth: 500,
            reputation_bucket: 5,
            topological_mass: 50 * SCALE, // too low for CoherenceMinimum
            current_delegation_depth: 0,
            held_capabilities: vec![],
            coherence_tier: CoherenceTier::Observer,
        };

        assert!(!cap.check_constraints(&context));
    }

    // ── Delegation non-delegatable error ──

    #[test]
    fn test_delegation_non_delegatable_returns_error() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let subject = CapabilitySubject::Transact {
            scope: TransactionScope::All,
        };

        let mut cap = Capability::new(&did, &pk, subject, &sk);
        cap.delegatable = false; // mark as non-delegatable

        let (_, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let result = DelegationRecord::new(&cap, &did, &did2, &sk, 1000);
        assert!(result.is_err());

        // Verify it is the correct error variant
        let err = result.unwrap_err();
        match err {
            IdentityError::ConstraintNotSatisfied(msg) => {
                assert!(msg.contains("not delegatable"));
            }
            other => panic!("Expected ConstraintNotSatisfied, got: {:?}", other),
        }
    }

    #[test]
    fn test_delegation_chain_verification() {
        let (sk1, pk1) = generate_keypair();
        let did1 = DID::new(&pk1, false);
        let subject = CapabilitySubject::Transact {
            scope: TransactionScope::All,
        };

        let cap = Capability::new(&did1, &pk1, subject, &sk1);

        let (_sk2, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let delegation = DelegationRecord::new(&cap, &did1, &did2, &sk1, 1000).unwrap();

        // Verify single delegation
        assert!(DelegationRecord::verify_chain(&[delegation], &cap, &[pk1]));

        // Empty chain should verify
        assert!(DelegationRecord::verify_chain(&[], &cap, &[]));
    }

    // ── CoherenceTier tests ──

    #[test]
    fn test_tier_from_score_boundaries() {
        // Compute exact thresholds from integer arithmetic
        let participant_threshold = (SCALE as i64 * 10) / 100; // 6553
        let contributor_threshold = (SCALE as i64 * 30) / 100; // 19660
        let authority_threshold = (SCALE as i64 * 55) / 100; // 36044
        let steward_threshold = (SCALE as i64 * 80) / 100; // 52428

        // Observer: score < participant_threshold
        assert_eq!(CoherenceTier::from_score(0), CoherenceTier::Observer);
        assert_eq!(
            CoherenceTier::from_score(participant_threshold - 1),
            CoherenceTier::Observer
        );

        // Participant: participant_threshold <= score < contributor_threshold
        assert_eq!(
            CoherenceTier::from_score(participant_threshold),
            CoherenceTier::Participant
        );
        assert_eq!(
            CoherenceTier::from_score(contributor_threshold - 1),
            CoherenceTier::Participant
        );

        // Contributor: contributor_threshold <= score < authority_threshold
        assert_eq!(
            CoherenceTier::from_score(contributor_threshold),
            CoherenceTier::Contributor
        );
        assert_eq!(
            CoherenceTier::from_score(authority_threshold - 1),
            CoherenceTier::Contributor
        );

        // Authority: authority_threshold <= score < steward_threshold
        assert_eq!(
            CoherenceTier::from_score(authority_threshold),
            CoherenceTier::Authority
        );
        assert_eq!(
            CoherenceTier::from_score(steward_threshold - 1),
            CoherenceTier::Authority
        );

        // Steward: score >= steward_threshold
        assert_eq!(
            CoherenceTier::from_score(steward_threshold),
            CoherenceTier::Steward
        );
        assert_eq!(
            CoherenceTier::from_score(SCALE as i64),
            CoherenceTier::Steward
        );
    }

    #[test]
    fn test_tier_ordering() {
        assert!(CoherenceTier::Observer < CoherenceTier::Participant);
        assert!(CoherenceTier::Participant < CoherenceTier::Contributor);
        assert!(CoherenceTier::Contributor < CoherenceTier::Authority);
        assert!(CoherenceTier::Authority < CoherenceTier::Steward);
    }

    #[test]
    fn test_tier_can_perform() {
        // Steward can perform everything
        assert!(CoherenceTier::Steward.can_perform(CoherenceTier::Observer));
        assert!(CoherenceTier::Steward.can_perform(CoherenceTier::Participant));
        assert!(CoherenceTier::Steward.can_perform(CoherenceTier::Contributor));
        assert!(CoherenceTier::Steward.can_perform(CoherenceTier::Authority));
        assert!(CoherenceTier::Steward.can_perform(CoherenceTier::Steward));

        // Observer can only perform Observer-level actions
        assert!(CoherenceTier::Observer.can_perform(CoherenceTier::Observer));
        assert!(!CoherenceTier::Observer.can_perform(CoherenceTier::Participant));
        assert!(!CoherenceTier::Observer.can_perform(CoherenceTier::Contributor));
        assert!(!CoherenceTier::Observer.can_perform(CoherenceTier::Authority));
        assert!(!CoherenceTier::Observer.can_perform(CoherenceTier::Steward));

        // Contributor can perform Observer, Participant, and Contributor
        assert!(CoherenceTier::Contributor.can_perform(CoherenceTier::Observer));
        assert!(CoherenceTier::Contributor.can_perform(CoherenceTier::Participant));
        assert!(CoherenceTier::Contributor.can_perform(CoherenceTier::Contributor));
        assert!(!CoherenceTier::Contributor.can_perform(CoherenceTier::Authority));
        assert!(!CoherenceTier::Contributor.can_perform(CoherenceTier::Steward));
    }

    #[test]
    fn test_tier_minimum_score() {
        assert_eq!(CoherenceTier::Observer.minimum_score(), 0);
        assert_eq!(
            CoherenceTier::Participant.minimum_score(),
            (SCALE as i64 * 10) / 100
        );
        assert_eq!(
            CoherenceTier::Contributor.minimum_score(),
            (SCALE as i64 * 30) / 100
        );
        assert_eq!(
            CoherenceTier::Authority.minimum_score(),
            (SCALE as i64 * 55) / 100
        );
        assert_eq!(
            CoherenceTier::Steward.minimum_score(),
            (SCALE as i64 * 80) / 100
        );
    }

    #[test]
    fn test_tier_minimum_constraint() {
        let constraint = Constraint::TierMinimum {
            tier: CoherenceTier::Contributor,
        };

        // Contributor meets Contributor requirement
        let context_pass = ConstraintContext {
            current_depth: 0,
            reputation_bucket: 0,
            topological_mass: 0,
            current_delegation_depth: 0,
            held_capabilities: vec![],
            coherence_tier: CoherenceTier::Contributor,
        };
        assert!(constraint.is_satisfied(&context_pass));

        // Authority exceeds Contributor requirement
        let context_exceeds = ConstraintContext {
            coherence_tier: CoherenceTier::Authority,
            ..context_pass.clone()
        };
        assert!(constraint.is_satisfied(&context_exceeds));

        // Observer is below Contributor requirement
        let context_fail = ConstraintContext {
            coherence_tier: CoherenceTier::Observer,
            ..context_pass.clone()
        };
        assert!(!constraint.is_satisfied(&context_fail));

        // Participant is below Contributor requirement
        let context_below = ConstraintContext {
            coherence_tier: CoherenceTier::Participant,
            ..context_pass
        };
        assert!(!constraint.is_satisfied(&context_below));
    }

    #[test]
    fn test_tier_serialization_roundtrip() {
        let tiers = [
            CoherenceTier::Observer,
            CoherenceTier::Participant,
            CoherenceTier::Contributor,
            CoherenceTier::Authority,
            CoherenceTier::Steward,
        ];

        for tier in &tiers {
            let serialized = bincode::serialize(tier).unwrap();
            let deserialized: CoherenceTier = bincode::deserialize(&serialized).unwrap();
            assert_eq!(*tier, deserialized);
        }

        // Also test roundtrip within a Constraint
        let constraint = Constraint::TierMinimum {
            tier: CoherenceTier::Authority,
        };
        let serialized = bincode::serialize(&constraint).unwrap();
        let deserialized: Constraint = bincode::deserialize(&serialized).unwrap();
        match deserialized {
            Constraint::TierMinimum { tier } => {
                assert_eq!(tier, CoherenceTier::Authority);
            }
            other => panic!("Expected TierMinimum, got: {:?}", other),
        }
    }
}
