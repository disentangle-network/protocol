//! Governance Types and Evaluation
//!
//! Coherence-weighted governance with proposals, voting, and quorum evaluation.

use crate::did::DID;
use crate::coherence::CoherenceProfile;
use crate::transactions::TransactionIdentity;
use disentangle_crypto::{
    hash::{Hash256, sha3_256_multi},
    signature::{SigningKey, Signature, sign, verify, VerifyingKey},
};
use disentangle_dag::{FixedPoint, SCALE};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub id: Hash256,
    pub proposer: DID,
    pub proposal_type: ProposalType,
    pub description_hash: Hash256,
    pub voting_start: u64,
    pub voting_end: u64,
    pub quorum: GovernanceQuorum,
    pub proof: Signature,
}

impl GovernanceProposal {
    /// Create a new governance proposal
    pub fn new(
        proposer: &DID,
        proposal_type: ProposalType,
        description_hash: Hash256,
        voting_start: u64,
        voting_end: u64,
        quorum: GovernanceQuorum,
        sk: &SigningKey,
    ) -> Self {
        let mut proposal = Self {
            id: [0u8; 32],
            proposer: proposer.clone(),
            proposal_type,
            description_hash,
            voting_start,
            voting_end,
            quorum,
            proof: Signature::from_bytes(&vec![0u8; 4627]).unwrap(), // Placeholder
        };

        proposal.id = proposal.compute_id();

        // Sign the proposal
        let message = proposal.signing_payload();
        proposal.proof = sign(sk, &message);

        proposal
    }

    /// Verify the proposal's signature
    pub fn verify(&self, proposer_pk: &VerifyingKey) -> bool {
        let message = self.signing_payload();
        verify(proposer_pk, &message, &self.proof).is_ok()
    }

    fn compute_id(&self) -> Hash256 {
        let type_bytes = bincode::serialize(&self.proposal_type).unwrap_or_default();
        sha3_256_multi(&[
            b"GOVERNANCE_PROPOSAL_V1",
            self.proposer.0.as_bytes(),
            &type_bytes,
            &self.description_hash,
            &self.voting_start.to_le_bytes(),
            &self.voting_end.to_le_bytes(),
        ])
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"GOVERNANCE_PROPOSAL_V1");
        payload.extend_from_slice(&self.id);
        payload.extend_from_slice(self.proposer.0.as_bytes());
        if let Ok(bytes) = bincode::serialize(&self.proposal_type) {
            payload.extend_from_slice(&bytes);
        }
        payload.extend_from_slice(&self.description_hash);
        payload.extend_from_slice(&self.voting_start.to_le_bytes());
        payload.extend_from_slice(&self.voting_end.to_le_bytes());
        payload
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalType {
    ProtocolParameter { parameter: String, new_value: Vec<u8> },
    CapabilityPolicy { policy: Vec<u8> },
    NamingHubRecognition { hub_did: DID },
    EmergencyAction { action: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceVote {
    pub proposal_id: Hash256,
    pub voter_identity: TransactionIdentity,
    pub vote: VoteChoice,
    pub parents: Vec<Hash256>,
    pub depth: u64,
}

impl GovernanceVote {
    pub fn compute_id(&self) -> Hash256 {
        let identity_bytes = bincode::serialize(&self.voter_identity).unwrap_or_default();
        sha3_256_multi(&[
            b"GOVERNANCE_VOTE_V1",
            &self.proposal_id,
            &identity_bytes,
            &[self.vote as u8],
            &self.depth.to_le_bytes(),
        ])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VoteChoice {
    For = 0,
    Against = 1,
    Abstain = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceQuorum {
    CoherenceWeighted { threshold: FixedPoint },
    DiversityMinimum { min_supporters: u64, min_mass: FixedPoint },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalResult {
    Passed,
    Failed,
    Pending,
}

/// Evaluate a governance proposal based on votes and coherence profiles
///
/// This computes coherence-weighted vote tallies and checks quorum conditions.
/// For Phase 1, we use simplified coherence profiles.
pub fn evaluate_proposal(
    proposal: &GovernanceProposal,
    votes: &[GovernanceVote],
    _profiles: &HashMap<DID, CoherenceProfile>,
    current_depth: u64,
) -> ProposalResult {
    // Check if voting period has ended
    if current_depth < proposal.voting_end {
        return ProposalResult::Pending;
    }

    // Filter votes for this proposal within voting period
    let relevant_votes: Vec<&GovernanceVote> = votes.iter()
        .filter(|v| v.proposal_id == proposal.id)
        .filter(|v| v.depth >= proposal.voting_start && v.depth <= proposal.voting_end)
        .collect();

    // Compute coherence-weighted tallies
    let mut for_weight: i64 = 0;
    let mut total_weight: i64 = 0;
    let mut unique_supporters = 0u64;

    // For Phase 1, we can't link voter_identity to DID without ZK proofs,
    // so this is a placeholder implementation that would work with ZK in Phase 2
    for vote in &relevant_votes {
        // In Phase 2, we would verify the ZK proof and get the DID's coherence profile
        // For Phase 1, we use a default weight
        let voter_weight = SCALE as i64; // Placeholder: equal weight

        match vote.vote {
            VoteChoice::For => {
                for_weight += voter_weight;
                unique_supporters += 1;
            }
            VoteChoice::Against => {
                // Against votes counted in total but not in for_weight
            }
            VoteChoice::Abstain => {}
        }

        total_weight += voter_weight;
    }

    // Check quorum conditions
    match &proposal.quorum {
        GovernanceQuorum::CoherenceWeighted { threshold } => {
            if total_weight == 0 {
                return ProposalResult::Failed;
            }

            // Compute support ratio
            let support_ratio = (for_weight * SCALE as i64) / total_weight;

            if support_ratio >= *threshold as i64 {
                ProposalResult::Passed
            } else {
                ProposalResult::Failed
            }
        }
        GovernanceQuorum::DiversityMinimum { min_supporters, min_mass } => {
            if unique_supporters >= *min_supporters && for_weight >= *min_mass as i64 {
                ProposalResult::Passed
            } else {
                ProposalResult::Failed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use disentangle_crypto::signature::generate_keypair;
    use crate::transactions::TransactionIdentity;
    use disentangle_crypto::types::Nullifier;

    #[test]
    fn test_governance_proposal_creation() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        let proposal_type = ProposalType::ProtocolParameter {
            parameter: "alpha_max".to_string(),
            new_value: vec![0, 0, 0, 5],
        };

        let proposal = GovernanceProposal::new(
            &did,
            proposal_type,
            [1u8; 32],
            1000,
            2000,
            GovernanceQuorum::CoherenceWeighted { threshold: SCALE / 2 },
            &sk,
        );

        assert_eq!(proposal.proposer, did);
        assert_eq!(proposal.voting_start, 1000);
        assert_eq!(proposal.voting_end, 2000);
    }

    #[test]
    fn test_governance_proposal_verification() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        let proposal_type = ProposalType::ProtocolParameter {
            parameter: "alpha_max".to_string(),
            new_value: vec![0, 0, 0, 5],
        };

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
    fn test_evaluate_proposal_pending() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        let proposal = GovernanceProposal::new(
            &did,
            ProposalType::ProtocolParameter {
                parameter: "test".to_string(),
                new_value: vec![],
            },
            [1u8; 32],
            1000,
            2000,
            GovernanceQuorum::CoherenceWeighted { threshold: SCALE / 2 },
            &sk,
        );

        let profiles = HashMap::new();
        let votes = vec![];

        // Current depth is before voting ends
        let result = evaluate_proposal(&proposal, &votes, &profiles, 1500);
        assert_eq!(result, ProposalResult::Pending);
    }

    #[test]
    fn test_evaluate_proposal_coherence_weighted() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        let proposal = GovernanceProposal::new(
            &did,
            ProposalType::ProtocolParameter {
                parameter: "test".to_string(),
                new_value: vec![],
            },
            [1u8; 32],
            1000,
            2000,
            GovernanceQuorum::CoherenceWeighted { threshold: SCALE / 2 }, // 50% threshold
            &sk,
        );

        let (_, voter_pk) = generate_keypair();
        let voter_identity = TransactionIdentity {
            ephemeral_pk: voter_pk,
            did_binding_proof: vec![],
            nullifier: Nullifier([2u8; 32]),
            reputation_bucket: 3,
        };

        let vote_for = GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: voter_identity.clone(),
            vote: VoteChoice::For,
            parents: vec![],
            depth: 1500,
        };

        let votes = vec![vote_for];
        let profiles = HashMap::new();

        // After voting period, 100% support
        let result = evaluate_proposal(&proposal, &votes, &profiles, 2001);
        assert_eq!(result, ProposalResult::Passed);
    }

    #[test]
    fn test_evaluate_proposal_diversity_minimum() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        let proposal = GovernanceProposal::new(
            &did,
            ProposalType::ProtocolParameter {
                parameter: "test".to_string(),
                new_value: vec![],
            },
            [1u8; 32],
            1000,
            2000,
            GovernanceQuorum::DiversityMinimum {
                min_supporters: 2,
                min_mass: SCALE * 10,
            },
            &sk,
        );

        // Only one vote - not enough diversity
        let (_, voter_pk) = generate_keypair();
        let voter_identity = TransactionIdentity {
            ephemeral_pk: voter_pk,
            did_binding_proof: vec![],
            nullifier: Nullifier([2u8; 32]),
            reputation_bucket: 3,
        };

        let vote = GovernanceVote {
            proposal_id: proposal.id,
            voter_identity,
            vote: VoteChoice::For,
            parents: vec![],
            depth: 1500,
        };

        let votes = vec![vote];
        let profiles = HashMap::new();

        let result = evaluate_proposal(&proposal, &votes, &profiles, 2001);
        assert_eq!(result, ProposalResult::Failed);
    }
}
