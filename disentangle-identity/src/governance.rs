//! Governance Types and Evaluation
//!
//! Coherence-weighted governance with proposals, voting, and quorum evaluation.

use crate::coherence::CoherenceProfile;
use crate::did::DID;
use crate::transactions::TransactionIdentity;
use disentangle_crypto::{
    hash::{sha3_256, sha3_256_multi, Hash256},
    signature::{sign, verify, Signature, SigningKey, VerifyingKey},
};
use disentangle_dag::{FixedPoint, SCALE};
use serde::{Deserialize, Serialize};
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
    ProtocolParameter {
        parameter: String,
        new_value: Vec<u8>,
    },
    CapabilityPolicy {
        policy: Vec<u8>,
    },
    NamingHubRecognition {
        hub_did: DID,
    },
    EmergencyAction {
        action: Vec<u8>,
    },
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
    CoherenceWeighted {
        threshold: FixedPoint,
    },
    DiversityMinimum {
        min_supporters: u64,
        min_mass: FixedPoint,
    },
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
/// Each voter's weight is their composite coherence score, looked up by matching
/// the vote's ephemeral public key to the DID that was created from that key.
/// In Phase 1, ephemeral_pk is the voter's real public key; in Phase 2, ZK proofs
/// will replace this direct lookup.
pub fn evaluate_proposal(
    proposal: &GovernanceProposal,
    votes: &[GovernanceVote],
    profiles: &HashMap<DID, CoherenceProfile>,
    current_depth: u64,
) -> ProposalResult {
    // Check if voting period has ended
    if current_depth < proposal.voting_end {
        return ProposalResult::Pending;
    }

    // Filter votes for this proposal within voting period
    let relevant_votes: Vec<&GovernanceVote> = votes
        .iter()
        .filter(|v| v.proposal_id == proposal.id)
        .filter(|v| v.depth >= proposal.voting_start && v.depth <= proposal.voting_end)
        .collect();

    // Compute coherence-weighted tallies
    let mut for_weight: i64 = 0;
    let mut total_weight: i64 = 0;
    let mut unique_supporters = 0u64;

    for vote in &relevant_votes {
        // Look up the voter's coherence weight by matching their ephemeral_pk to a DID.
        // DID = did:disentangle:[agi:]<hex(sha3_256(pk_bytes))>, so we hash the
        // ephemeral_pk and compare against each DID's method-specific ID.
        // In Phase 2, ZK proofs will replace this direct key-to-DID mapping.
        let pk_hash_hex = hex::encode(sha3_256(&vote.voter_identity.ephemeral_pk.to_bytes()));
        let voter_weight = profiles
            .iter()
            .find(|(did, _)| did.method_specific_id() == pk_hash_hex)
            .map(|(_, profile)| profile.composite_score(current_depth) as i64)
            .unwrap_or(SCALE as i64); // Fallback to default weight if DID not found

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
        GovernanceQuorum::DiversityMinimum {
            min_supporters,
            min_mass,
        } => {
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
    use crate::transactions::TransactionIdentity;
    use disentangle_crypto::signature::generate_keypair;
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
            GovernanceQuorum::CoherenceWeighted {
                threshold: SCALE / 2,
            },
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
            GovernanceQuorum::CoherenceWeighted {
                threshold: SCALE / 2,
            },
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
            GovernanceQuorum::CoherenceWeighted {
                threshold: SCALE / 2,
            },
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
            GovernanceQuorum::CoherenceWeighted {
                threshold: SCALE / 2,
            }, // 50% threshold
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

    #[test]
    fn test_coherence_weighted_voting_high_coherence_wins() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        // 50% threshold
        let proposal = GovernanceProposal::new(
            &did,
            ProposalType::ProtocolParameter {
                parameter: "test".to_string(),
                new_value: vec![],
            },
            [1u8; 32],
            1000,
            2000,
            GovernanceQuorum::CoherenceWeighted {
                threshold: SCALE / 2,
            },
            &sk,
        );

        // High-coherence voter votes For
        let (_, high_pk) = generate_keypair();
        let high_did = DID::new(&high_pk, false);
        let high_profile = CoherenceProfile {
            did: high_did.clone(),
            topological_mass: SCALE * 10,
            mean_local_curvature: SCALE / 2,
            relational_diversity: 50,
            temporal_depth: 5000,
            capability_coherence: SCALE,
            introduction_coherence: SCALE,
            last_active_depth: 2000,
        };

        // Low-coherence voter votes Against
        let (_, low_pk) = generate_keypair();
        let low_did = DID::new(&low_pk, false);
        let low_profile = CoherenceProfile {
            did: low_did.clone(),
            topological_mass: SCALE / 10,
            mean_local_curvature: 0,
            relational_diversity: 1,
            temporal_depth: 100,
            capability_coherence: 0,
            introduction_coherence: 0,
            last_active_depth: 2000,
        };

        let high_vote = GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: TransactionIdentity {
                ephemeral_pk: high_pk,
                did_binding_proof: vec![],
                nullifier: Nullifier([3u8; 32]),
                reputation_bucket: 5,
            },
            vote: VoteChoice::For,
            parents: vec![],
            depth: 1500,
        };

        let low_vote = GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: TransactionIdentity {
                ephemeral_pk: low_pk,
                did_binding_proof: vec![],
                nullifier: Nullifier([4u8; 32]),
                reputation_bucket: 1,
            },
            vote: VoteChoice::Against,
            parents: vec![],
            depth: 1500,
        };

        let votes = vec![high_vote, low_vote];
        let mut profiles = HashMap::new();
        profiles.insert(high_did, high_profile);
        profiles.insert(low_did, low_profile);

        // High-coherence voter's For should outweigh low-coherence Against
        let result = evaluate_proposal(&proposal, &votes, &profiles, 2001);
        assert_eq!(result, ProposalResult::Passed);
    }

    #[test]
    fn test_coherence_weighted_voting_low_coherence_loses() {
        let (sk, pk) = generate_keypair();
        let did = DID::new(&pk, false);

        // 50% threshold
        let proposal = GovernanceProposal::new(
            &did,
            ProposalType::ProtocolParameter {
                parameter: "test".to_string(),
                new_value: vec![],
            },
            [1u8; 32],
            1000,
            2000,
            GovernanceQuorum::CoherenceWeighted {
                threshold: SCALE / 2,
            },
            &sk,
        );

        // Low-coherence voter votes For
        let (_, low_pk) = generate_keypair();
        let low_did = DID::new(&low_pk, false);
        let low_profile = CoherenceProfile {
            did: low_did.clone(),
            topological_mass: SCALE / 10,
            mean_local_curvature: 0,
            relational_diversity: 1,
            temporal_depth: 100,
            capability_coherence: 0,
            introduction_coherence: 0,
            last_active_depth: 2000,
        };

        // High-coherence voter votes Against
        let (_, high_pk) = generate_keypair();
        let high_did = DID::new(&high_pk, false);
        let high_profile = CoherenceProfile {
            did: high_did.clone(),
            topological_mass: SCALE * 10,
            mean_local_curvature: SCALE / 2,
            relational_diversity: 50,
            temporal_depth: 5000,
            capability_coherence: SCALE,
            introduction_coherence: SCALE,
            last_active_depth: 2000,
        };

        let low_vote = GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: TransactionIdentity {
                ephemeral_pk: low_pk,
                did_binding_proof: vec![],
                nullifier: Nullifier([3u8; 32]),
                reputation_bucket: 1,
            },
            vote: VoteChoice::For,
            parents: vec![],
            depth: 1500,
        };

        let high_vote = GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: TransactionIdentity {
                ephemeral_pk: high_pk,
                did_binding_proof: vec![],
                nullifier: Nullifier([4u8; 32]),
                reputation_bucket: 5,
            },
            vote: VoteChoice::Against,
            parents: vec![],
            depth: 1500,
        };

        let votes = vec![low_vote, high_vote];
        let mut profiles = HashMap::new();
        profiles.insert(low_did, low_profile);
        profiles.insert(high_did, high_profile);

        // Low-coherence For is outweighed by high-coherence Against -> fails
        let result = evaluate_proposal(&proposal, &votes, &profiles, 2001);
        assert_eq!(result, ProposalResult::Failed);
    }

    #[test]
    fn test_coherence_weighted_fallback_for_unknown_voter() {
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
            GovernanceQuorum::CoherenceWeighted {
                threshold: SCALE / 2,
            },
            &sk,
        );

        // Voter not in profiles -- should fallback to SCALE weight
        let (_, voter_pk) = generate_keypair();
        let vote = GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: TransactionIdentity {
                ephemeral_pk: voter_pk,
                did_binding_proof: vec![],
                nullifier: Nullifier([5u8; 32]),
                reputation_bucket: 0,
            },
            vote: VoteChoice::For,
            parents: vec![],
            depth: 1500,
        };

        let votes = vec![vote];
        let profiles = HashMap::new(); // No profiles -- fallback to SCALE

        // 100% For with default weight -> passes
        let result = evaluate_proposal(&proposal, &votes, &profiles, 2001);
        assert_eq!(result, ProposalResult::Passed);
    }
}
