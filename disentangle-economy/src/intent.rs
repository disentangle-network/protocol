//! SharedIntent Types
//!
//! Post-transactional collaboration with no explicit completion state.
//! The topology IS the outcome measurement.

use disentangle_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntentStatus {
    /// Active collaboration
    Active,
    /// Archived — coherence snapshot taken at archive time
    Archived {
        archive_depth: u64,
        coherence_delta: f64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedIntent {
    pub id: Hash256,
    /// The proposal that ignited this (if any)
    pub source_proposal: Option<Hash256>,
    pub description: String,
    pub intent_hash: Hash256,
    pub participants: Vec<IntentParticipant>,
    pub status: IntentStatus,
    pub created_depth: u64,
    /// Snapshot of neighborhood curvature at creation
    pub baseline_curvature: f64,
    /// Snapshot of sum participant mass at creation
    pub baseline_mass: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentParticipant {
    pub did: String,
    pub joined_depth: u64,
    /// Mass snapshot at join time
    pub mass_at_join: f64,
    /// Capabilities contributed to this intent
    pub contributed_capabilities: Vec<Hash256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentCoherenceSnapshot {
    pub intent_id: Hash256,
    pub participant_count: usize,
    pub baseline_mass: f64,
    pub current_mass: f64,
    pub mass_delta: f64,
    pub baseline_curvature: f64,
    pub current_curvature: f64,
    pub curvature_delta: f64,
    pub depth: u64,
}

impl SharedIntent {
    pub fn new(
        source_proposal: Option<Hash256>,
        description: String,
        intent_hash: Hash256,
        initial_participants: Vec<IntentParticipant>,
        created_depth: u64,
        baseline_curvature: f64,
        baseline_mass: f64,
    ) -> Self {
        // Compute intent ID from content
        let id = Self::compute_id(&intent_hash, created_depth);

        Self {
            id,
            source_proposal,
            description,
            intent_hash,
            participants: initial_participants,
            status: IntentStatus::Active,
            created_depth,
            baseline_curvature,
            baseline_mass,
        }
    }

    fn compute_id(intent_hash: &Hash256, created_depth: u64) -> Hash256 {
        use disentangle_crypto::hash::sha3_256_multi;

        sha3_256_multi(&[b"INTENT_ID_V1", intent_hash, &created_depth.to_le_bytes()])
    }

    /// Archive the intent with coherence snapshot
    pub fn archive(&mut self, archive_depth: u64, coherence_delta: f64) {
        if self.status == IntentStatus::Active {
            self.status = IntentStatus::Archived {
                archive_depth,
                coherence_delta,
            };
        }
    }

    /// Check if a DID is a participant
    pub fn has_participant(&self, did: &str) -> bool {
        self.participants.iter().any(|p| p.did == did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_creation() {
        let intent_hash = [1u8; 32];
        let participants = vec![
            IntentParticipant {
                did: "did:disentangle:alice".to_string(),
                joined_depth: 100,
                mass_at_join: 50.0,
                contributed_capabilities: vec![],
            },
            IntentParticipant {
                did: "did:disentangle:bob".to_string(),
                joined_depth: 100,
                mass_at_join: 60.0,
                contributed_capabilities: vec![],
            },
        ];

        let intent = SharedIntent::new(
            None,
            "Collaborative AI research".to_string(),
            intent_hash,
            participants,
            100,
            0.5,
            110.0,
        );

        assert_eq!(intent.status, IntentStatus::Active);
        assert_eq!(intent.participants.len(), 2);
        assert_eq!(intent.baseline_curvature, 0.5);
        assert_eq!(intent.baseline_mass, 110.0);
    }

    #[test]
    fn test_intent_archiving() {
        let intent_hash = [1u8; 32];
        let mut intent =
            SharedIntent::new(None, "Test".to_string(), intent_hash, vec![], 100, 0.0, 0.0);

        assert_eq!(intent.status, IntentStatus::Active);

        intent.archive(200, 15.5);

        match intent.status {
            IntentStatus::Archived {
                archive_depth,
                coherence_delta,
            } => {
                assert_eq!(archive_depth, 200);
                assert_eq!(coherence_delta, 15.5);
            }
            _ => panic!("Expected Archived status"),
        }
    }

    #[test]
    fn test_has_participant() {
        let intent_hash = [1u8; 32];
        let participants = vec![IntentParticipant {
            did: "did:disentangle:alice".to_string(),
            joined_depth: 100,
            mass_at_join: 50.0,
            contributed_capabilities: vec![],
        }];

        let intent = SharedIntent::new(
            None,
            "Test".to_string(),
            intent_hash,
            participants,
            100,
            0.0,
            0.0,
        );

        assert!(intent.has_participant("did:disentangle:alice"));
        assert!(!intent.has_participant("did:disentangle:bob"));
    }

    #[test]
    fn test_intent_id_deterministic() {
        let intent_hash = [1u8; 32];
        let intent1 =
            SharedIntent::new(None, "Test".to_string(), intent_hash, vec![], 100, 0.0, 0.0);

        let intent2 = SharedIntent::new(
            None,
            "Different description".to_string(),
            intent_hash,
            vec![],
            100,
            0.0,
            0.0,
        );

        assert_eq!(intent1.id, intent2.id);
    }
}
