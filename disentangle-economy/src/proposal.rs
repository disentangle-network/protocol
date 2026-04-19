//! Proposal Types
//!
//! Mass-commitment ignition for SharedIntent formation.
//! Approval is joining. No voting exists.

use disentangle_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalStatus {
    /// Waiting for mass commitment
    Attracting,
    /// Enough mass committed — auto-instantiated as SharedIntent
    Activated { intent_id: Hash256 },
    /// Expiry depth reached without activation
    Expired,
    /// Manually archived by initiator
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: Hash256,
    pub initiator_did: String,
    /// Hash of the goal description (stored off-chain or in payload)
    pub intent_hash: Hash256,
    /// Human-readable short description
    pub description: String,
    /// Topological mass threshold for activation
    pub activation_mass: f64,
    /// Minimum distinct joiners for diversity requirement
    pub min_participants: u32,
    /// DAG depth at which this expires if not activated
    pub expiry_depth: u64,
    /// Current committed mass (sum of joiners' confirmed mass)
    pub committed_mass: f64,
    /// Agents who have joined
    pub joiners: Vec<JoinCommitment>,
    pub status: ProposalStatus,
    pub created_depth: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinCommitment {
    pub did: String,
    /// Mass at time of join (snapshot, not live)
    pub committed_mass: f64,
    /// Depth at which join was confirmed
    pub join_depth: u64,
}

impl Proposal {
    pub fn new(
        initiator_did: String,
        intent_hash: Hash256,
        description: String,
        activation_mass: f64,
        min_participants: u32,
        expiry_depth: u64,
        created_depth: u64,
    ) -> Self {
        // Compute proposal ID from content
        let id = Self::compute_id(&initiator_did, &intent_hash, created_depth);

        Self {
            id,
            initiator_did,
            intent_hash,
            description,
            activation_mass,
            min_participants,
            expiry_depth,
            committed_mass: 0.0,
            joiners: Vec::new(),
            status: ProposalStatus::Attracting,
            created_depth,
        }
    }

    fn compute_id(initiator_did: &str, intent_hash: &Hash256, created_depth: u64) -> Hash256 {
        use disentangle_crypto::hash::sha3_256_multi;

        sha3_256_multi(&[
            b"PROPOSAL_ID_V1",
            initiator_did.as_bytes(),
            intent_hash,
            &created_depth.to_le_bytes(),
        ])
    }

    /// Check if proposal should activate based on current conditions
    pub fn check_activation(&self) -> bool {
        self.committed_mass >= self.activation_mass
            && self.joiners.len() >= self.min_participants as usize
    }

    /// Check if proposal has expired
    pub fn check_expiry(&mut self, current_depth: u64) {
        if current_depth > self.expiry_depth && self.status == ProposalStatus::Attracting {
            self.status = ProposalStatus::Expired;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proposal_creation() {
        let intent_hash = [1u8; 32];
        let proposal = Proposal::new(
            "did:disentangle:alice".to_string(),
            intent_hash,
            "Build collaborative AI".to_string(),
            100.0,
            3,
            1000,
            100,
        );

        assert_eq!(proposal.status, ProposalStatus::Attracting);
        assert_eq!(proposal.committed_mass, 0.0);
        assert_eq!(proposal.joiners.len(), 0);
    }

    #[test]
    fn test_proposal_activation_check() {
        let intent_hash = [1u8; 32];
        let mut proposal = Proposal::new(
            "did:disentangle:alice".to_string(),
            intent_hash,
            "Test".to_string(),
            100.0,
            2,
            1000,
            100,
        );

        // Not enough mass or participants
        assert!(!proposal.check_activation());

        // Add joiners with enough mass
        proposal.joiners.push(JoinCommitment {
            did: "did:disentangle:bob".to_string(),
            committed_mass: 60.0,
            join_depth: 101,
        });
        proposal.committed_mass = 60.0;

        // Still only one participant
        assert!(!proposal.check_activation());

        // Add second joiner
        proposal.joiners.push(JoinCommitment {
            did: "did:disentangle:carol".to_string(),
            committed_mass: 50.0,
            join_depth: 102,
        });
        proposal.committed_mass = 110.0;

        // Now should activate
        assert!(proposal.check_activation());
    }

    #[test]
    fn test_proposal_expiry() {
        let intent_hash = [1u8; 32];
        let mut proposal = Proposal::new(
            "did:disentangle:alice".to_string(),
            intent_hash,
            "Test".to_string(),
            100.0,
            2,
            1000,
            100,
        );

        // Before expiry
        proposal.check_expiry(999);
        assert_eq!(proposal.status, ProposalStatus::Attracting);

        // After expiry
        proposal.check_expiry(1001);
        assert_eq!(proposal.status, ProposalStatus::Expired);
    }

    #[test]
    fn test_proposal_id_deterministic() {
        let intent_hash = [1u8; 32];
        let proposal1 = Proposal::new(
            "did:disentangle:alice".to_string(),
            intent_hash,
            "Test".to_string(),
            100.0,
            2,
            1000,
            100,
        );

        let proposal2 = Proposal::new(
            "did:disentangle:alice".to_string(),
            intent_hash,
            "Test".to_string(),
            100.0,
            2,
            1000,
            100,
        );

        assert_eq!(proposal1.id, proposal2.id);
    }
}
