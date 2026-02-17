//! Capability Types and Operations
//!
//! Object capabilities with delegation, constraints, and revocation support.

use crate::did::DID;
use crate::IdentityError;
use disentangle_crypto::{
    hash::{Hash256, sha3_256_multi},
    signature::{SigningKey, Signature, sign, verify, VerifyingKey},
};
use disentangle_dag::{FixedPoint, SCALE};
use serde::{Serialize, Deserialize};

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
    pub fn new(issuer: &DID, _issuer_pk: &VerifyingKey, subject: CapabilitySubject, sk: &SigningKey) -> Self {
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
        )).unwrap_or_default();

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
        )).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapabilitySubject {
    Transact { scope: TransactionScope },
    Name { namespace: DID, operations: Vec<NameOp> },
    Access { resource_id: Hash256, operations: Vec<AccessOp> },
    Govern { scope: GovernanceScope, weight: FixedPoint },
    Custom { type_uri: String, parameters: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionScope {
    All,
    Transfer,
    Introduction,
    Governance,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NameOp { Read, Write, Delegate }

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AccessOp { Read, Write, Execute }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceScope {
    ProtocolParameters,
    CapabilityPolicy,
    NamingHub,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Constraint {
    TemporalBound { not_before: u64, not_after: u64 },
    ReputationMinimum { bucket: u8 },
    CoherenceMinimum { min_mass: u64 },
    DelegationDepth { max_depth: u32 },
    RequiresCapability { prerequisite: CapabilityId },
}

impl Constraint {
    pub fn is_satisfied(&self, context: &ConstraintContext) -> bool {
        match self {
            Self::TemporalBound { not_before, not_after } => {
                context.current_depth >= *not_before && context.current_depth <= *not_after
            }
            Self::ReputationMinimum { bucket } => {
                context.reputation_bucket >= *bucket
            }
            Self::CoherenceMinimum { min_mass } => {
                // Compare without overflow: mass/SCALE >= min_mass
                (context.topological_mass / SCALE) as u64 >= *min_mass
            }
            Self::DelegationDepth { max_depth } => {
                context.current_delegation_depth <= *max_depth
            }
            Self::RequiresCapability { prerequisite } => {
                context.held_capabilities.contains(prerequisite)
            }
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
            return Err(IdentityError::ConstraintNotSatisfied("Capability is not delegatable".to_string()));
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
        )).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationScope {
    Single,
    Subtree,
    All,
}

#[cfg(test)]
mod tests {
    use super::*;
    use disentangle_crypto::signature::generate_keypair;

    #[test]
    fn test_capability_creation() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let subject = CapabilitySubject::Transact { scope: TransactionScope::All };

        let cap = Capability::new(&did, &pk, subject, &sk);

        assert_eq!(cap.issuer, did);
        assert!(cap.delegatable);
        assert_eq!(cap.max_delegation_depth, 10);
    }

    #[test]
    fn test_capability_id_computation() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let subject = CapabilitySubject::Transact { scope: TransactionScope::All };

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
        let subject = CapabilitySubject::Transact { scope: TransactionScope::All };

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
        let subject = CapabilitySubject::Transact { scope: TransactionScope::All };

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
        };
        assert!(!constraint.is_satisfied(&context));
    }

    #[test]
    fn test_requires_capability_passes() {
        let prerequisite_id = [42u8; 32];
        let constraint = Constraint::RequiresCapability { prerequisite: prerequisite_id };
        let context = ConstraintContext {
            current_depth: 0,
            reputation_bucket: 0,
            topological_mass: 0,
            current_delegation_depth: 0,
            held_capabilities: vec![[1u8; 32], prerequisite_id, [3u8; 32]],
        };
        assert!(constraint.is_satisfied(&context));
    }

    #[test]
    fn test_requires_capability_fails() {
        let prerequisite_id = [42u8; 32];
        let constraint = Constraint::RequiresCapability { prerequisite: prerequisite_id };
        let context = ConstraintContext {
            current_depth: 0,
            reputation_bucket: 0,
            topological_mass: 0,
            current_delegation_depth: 0,
            held_capabilities: vec![[1u8; 32], [2u8; 32]], // does not contain prerequisite
        };
        assert!(!constraint.is_satisfied(&context));
    }

    // ── Capability-level constraint checking (multiple constraints) ──

    #[test]
    fn test_capability_multiple_constraints_all_pass() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let subject = CapabilitySubject::Transact { scope: TransactionScope::All };

        let mut cap = Capability::new(&did, &pk, subject, &sk);
        cap.constraints = vec![
            Constraint::ReputationMinimum { bucket: 2 },
            Constraint::CoherenceMinimum { min_mass: 100 },
            Constraint::TemporalBound { not_before: 10, not_after: 1000 },
        ];

        let context = ConstraintContext {
            current_depth: 500,
            reputation_bucket: 5,
            topological_mass: 200 * SCALE,
            current_delegation_depth: 0,
            held_capabilities: vec![],
        };

        assert!(cap.check_constraints(&context));
    }

    #[test]
    fn test_capability_multiple_constraints_one_fails() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let subject = CapabilitySubject::Transact { scope: TransactionScope::All };

        let mut cap = Capability::new(&did, &pk, subject, &sk);
        cap.constraints = vec![
            Constraint::ReputationMinimum { bucket: 2 },  // passes (5 >= 2)
            Constraint::CoherenceMinimum { min_mass: 100 }, // fails (50 < 100)
            Constraint::TemporalBound { not_before: 10, not_after: 1000 }, // passes
        ];

        let context = ConstraintContext {
            current_depth: 500,
            reputation_bucket: 5,
            topological_mass: 50 * SCALE, // too low for CoherenceMinimum
            current_delegation_depth: 0,
            held_capabilities: vec![],
        };

        assert!(!cap.check_constraints(&context));
    }

    // ── Delegation non-delegatable error ──

    #[test]
    fn test_delegation_non_delegatable_returns_error() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);
        let subject = CapabilitySubject::Transact { scope: TransactionScope::All };

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
        let subject = CapabilitySubject::Transact { scope: TransactionScope::All };

        let cap = Capability::new(&did1, &pk1, subject, &sk1);

        let (_sk2, pk2) = generate_keypair();
        let did2 = DID::new(&pk2, false);

        let delegation = DelegationRecord::new(&cap, &did1, &did2, &sk1, 1000).unwrap();

        // Verify single delegation
        assert!(DelegationRecord::verify_chain(&[delegation], &cap, &[pk1]));

        // Empty chain should verify
        assert!(DelegationRecord::verify_chain(&[], &cap, &[]));
    }
}
