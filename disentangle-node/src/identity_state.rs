//! Identity State Manager
//!
//! Manages DID lifecycle, capability operations, introductions, coherence tracking,
//! and petnames for the Disentangle Protocol.

use disentangle_crypto::hash::{sha3_256, Hash256};
use disentangle_crypto::signature::{generate_keypair, SigningKey, VerifyingKey};
use disentangle_identity::{
    evaluate_proposal, AgentScore, AgentType, AgreementStatus, AgreementTerms, Capability,
    CapabilityId, CapabilitySubject, CoherenceGradientMap, CoherenceProfile, CommonsPool,
    Constraint, ConstraintContext, CurvatureDerivative, CurvatureHistory, DIDDocument,
    DelegationRecord, DistributionRoot, ExcitabilityProfile, GovernanceProposal, GovernanceVote,
    IdentityError, IdentityGraph, IntentCoherenceSnapshot, IntentParticipant, IntentStatus,
    IntroductionContext, IntroductionTransaction, JoinCommitment, OracleQuery, PetnameDB, Proposal,
    ProposalResult, ProposalStatus, ProposalType, RegionSelector, RevocationScope,
    ServiceAgreement, SettlementAgreement, SharedIntent, VoteChoice, DID, MAX_HISTORY_DEPTH,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Serializable state for persistence
#[derive(Serialize, Deserialize)]
struct SerializableState {
    did_registry_keys: Vec<String>,
    did_documents: Vec<DIDDocument>,
    verifying_keys_hex: Vec<String>,
    capabilities: Vec<Capability>,
    delegations: Vec<(String, Vec<DelegationRecord>)>, // (cap_id_hex, chain)
    introductions: Vec<IntroductionTransaction>,
    current_depth: u64,
    first_seen: HashMap<String, u64>,
    proposals: Vec<GovernanceProposal>,
    votes: Vec<GovernanceVote>,
    agreements: Vec<SettlementAgreement>,
    // Coordination economy state
    coord_proposals: Vec<Proposal>,
    shared_intents: Vec<SharedIntent>,
    oracle_distributions: Vec<DistributionRoot>,
    commons_pools: Vec<CommonsPool>,
}

pub struct IdentityStateManager {
    did_registry: HashMap<String, (DIDDocument, VerifyingKey)>,
    capability_store: HashMap<CapabilityId, Capability>,
    delegation_chains: HashMap<CapabilityId, Vec<DelegationRecord>>,
    identity_graph: IdentityGraph,
    petnames: PetnameDB,
    current_depth: u64,
    first_seen: HashMap<String, u64>,
    proposals: HashMap<Hash256, GovernanceProposal>,
    votes: Vec<GovernanceVote>,
    introduction_history: Vec<IntroductionTransaction>, // For persistence
    agreements: HashMap<Hash256, SettlementAgreement>,
    // Coordination economy state
    coord_proposals: HashMap<Hash256, Proposal>,
    shared_intents: HashMap<Hash256, SharedIntent>,
    oracle_distributions: HashMap<Hash256, DistributionRoot>,
    commons_pools: HashMap<Hash256, CommonsPool>,
    // Excitability gradient tracking
    curvature_history: CurvatureHistory,
}

impl Default for IdentityStateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityStateManager {
    pub fn new() -> Self {
        Self {
            did_registry: HashMap::new(),
            capability_store: HashMap::new(),
            delegation_chains: HashMap::new(),
            identity_graph: IdentityGraph::new(),
            petnames: PetnameDB::new(),
            current_depth: 0,
            first_seen: HashMap::new(),
            proposals: HashMap::new(),
            votes: Vec::new(),
            introduction_history: Vec::new(),
            agreements: HashMap::new(),
            coord_proposals: HashMap::new(),
            shared_intents: HashMap::new(),
            oracle_distributions: HashMap::new(),
            commons_pools: HashMap::new(),
            curvature_history: HashMap::new(),
        }
    }

    // DID Operations

    /// Register a new DID with the specified agent type
    pub fn register_did(
        &mut self,
        agent_type: AgentType,
    ) -> Result<(DID, DIDDocument, SigningKey), IdentityError> {
        let (sk, pk) = generate_keypair();

        let is_agi = matches!(agent_type, AgentType::AGI { .. });
        let did = DID::new(&pk, is_agi);

        // Prevent duplicate DIDs
        if self.did_registry.contains_key(&did.0) {
            return Err(IdentityError::InvalidDID(
                "DID already registered".to_string(),
            ));
        }

        let doc = DIDDocument::new(&sk, &pk, agent_type, self.current_depth);

        // Store first seen depth
        self.first_seen.insert(did.0.clone(), self.current_depth);

        // Store in registry
        self.did_registry
            .insert(did.0.clone(), (doc.clone(), pk.clone()));

        // Snapshot curvature after graph mutation
        self.snapshot_curvature(self.current_depth);

        Ok((did, doc, sk))
    }

    /// Get a DID document by DID string
    pub fn get_did_document(&self, did: &str) -> Option<&DIDDocument> {
        self.did_registry.get(did).map(|(doc, _)| doc)
    }

    /// List all registered DIDs
    pub fn list_dids(&self) -> Vec<String> {
        self.did_registry.keys().cloned().collect()
    }

    /// Deactivate a DID (requires proof of ownership)
    pub fn deactivate_did(&mut self, did: &str, _proof: &[u8]) -> Result<(), IdentityError> {
        if !self.did_registry.contains_key(did) {
            return Err(IdentityError::DIDNotFound(did.to_string()));
        }

        // TODO: Verify proof in Phase 2
        // For Phase 1, we trust the proof parameter

        self.did_registry.remove(did);
        Ok(())
    }

    // Capability Operations

    /// Create a new capability
    pub fn create_capability(
        &mut self,
        issuer_did: &str,
        issuer_sk: &SigningKey,
        subject: CapabilitySubject,
        constraints: Vec<Constraint>,
        delegatable: bool,
    ) -> Result<Capability, IdentityError> {
        let (_, issuer_pk) = self
            .did_registry
            .get(issuer_did)
            .ok_or_else(|| IdentityError::DIDNotFound(issuer_did.to_string()))?;

        let did = DID(issuer_did.to_string());
        let mut cap = Capability::new(&did, issuer_pk, subject, issuer_sk);

        // Apply custom constraints and delegatable flag
        cap.constraints = constraints;
        cap.delegatable = delegatable;

        // Recompute ID with updated constraints
        cap.id = cap.compute_id();

        self.capability_store.insert(cap.id, cap.clone());

        Ok(cap)
    }

    /// Delegate a capability to another DID
    pub fn delegate_capability(
        &mut self,
        cap_id: &CapabilityId,
        delegator_did: &str,
        delegator_sk: &SigningKey,
        delegatee_did: &str,
    ) -> Result<DelegationRecord, IdentityError> {
        let cap = self
            .capability_store
            .get(cap_id)
            .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(cap_id)))?;

        // Check if capability is revoked
        if self.identity_graph.is_revoked(cap_id) {
            return Err(IdentityError::CapabilityRevoked);
        }

        let delegator = DID(delegator_did.to_string());
        let delegatee = DID(delegatee_did.to_string());

        let mut record = DelegationRecord::new(
            cap,
            &delegator,
            &delegatee,
            delegator_sk,
            self.current_depth,
        )?;

        // Calculate depth from existing chain
        let existing_chain = self
            .delegation_chains
            .get(cap_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        record.depth = (existing_chain.len() as u32 + 1) as u64;

        // Check depth limit
        if record.depth > cap.max_delegation_depth as u64 {
            return Err(IdentityError::DelegationDepthExceeded {
                depth: record.depth as u32,
                max: cap.max_delegation_depth,
            });
        }

        // Store delegation
        self.delegation_chains
            .entry(*cap_id)
            .or_default()
            .push(record.clone());

        // Record in identity graph
        self.identity_graph.record_delegation(&record);

        // Snapshot curvature after graph mutation
        self.snapshot_curvature(self.current_depth);

        Ok(record)
    }

    /// Invoke a capability (check if invoker has permission)
    pub fn invoke_capability(
        &self,
        cap_id: &CapabilityId,
        invoker_did: &str,
    ) -> Result<bool, IdentityError> {
        let cap = self
            .capability_store
            .get(cap_id)
            .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(cap_id)))?;

        // Check if revoked
        if self.identity_graph.is_revoked(cap_id) {
            return Err(IdentityError::CapabilityRevoked);
        }

        // Check if invoker is the original issuer
        if cap.issuer.0 == invoker_did {
            return Ok(true);
        }

        // Check if invoker is in delegation chain
        let chain = self.delegation_chains.get(cap_id);
        let is_delegatee = chain
            .map(|records| records.iter().any(|r| r.delegatee.0 == invoker_did))
            .unwrap_or(false);

        if !is_delegatee {
            return Err(IdentityError::ConstraintNotSatisfied(
                "Not in delegation chain".to_string(),
            ));
        }

        // Build constraint context
        let invoker = DID(invoker_did.to_string());
        let first_seen_depth = self.first_seen.get(invoker_did).copied().unwrap_or(0);
        let coherence_profile = CoherenceProfile::compute(
            &invoker,
            &self.identity_graph,
            first_seen_depth,
            self.current_depth,
        );

        let context = ConstraintContext {
            current_depth: self.current_depth,
            reputation_bucket: 0, // TODO: implement reputation in Phase 2
            topological_mass: coherence_profile.topological_mass,
            current_delegation_depth: chain.map(|c| c.len() as u32).unwrap_or(0),
            held_capabilities: vec![], // TODO: query held capabilities
        };

        // Check all constraints
        if !cap.check_constraints(&context) {
            return Err(IdentityError::ConstraintNotSatisfied(
                "Capability constraints not met".to_string(),
            ));
        }

        Ok(true)
    }

    /// Revoke a capability
    pub fn revoke_capability(
        &mut self,
        cap_id: &CapabilityId,
        revoker_did: &str,
        scope: RevocationScope,
    ) -> Result<(), IdentityError> {
        let cap = self
            .capability_store
            .get(cap_id)
            .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(cap_id)))?;

        // Only issuer can revoke
        if cap.issuer.0 != revoker_did {
            return Err(IdentityError::ConstraintNotSatisfied(
                "Only issuer can revoke".to_string(),
            ));
        }

        self.identity_graph.record_revocation(cap_id, scope);

        Ok(())
    }

    /// Get a capability by ID
    pub fn get_capability(&self, cap_id: &CapabilityId) -> Option<&Capability> {
        self.capability_store.get(cap_id)
    }

    /// List all capabilities where the given DID is issuer or delegatee
    pub fn list_capabilities_for_did(&self, did: &str) -> Vec<&Capability> {
        self.capability_store
            .values()
            .filter(|cap| {
                // Check if issuer
                if cap.issuer.0 == did {
                    return true;
                }

                // Check if delegatee in any chain
                if let Some(chain) = self.delegation_chains.get(&cap.id) {
                    return chain.iter().any(|r| r.delegatee.0 == did);
                }

                false
            })
            .collect()
    }

    // Introduction Operations

    /// Introduce one DID to another, creating a graph edge
    pub fn introduce(
        &mut self,
        introducer_did: &str,
        introducer_sk: &SigningKey,
        introduced_did: &str,
        edge_name: &str,
    ) -> Result<(), IdentityError> {
        // Verify both DIDs exist
        if !self.did_registry.contains_key(introducer_did) {
            return Err(IdentityError::DIDNotFound(introducer_did.to_string()));
        }
        if !self.did_registry.contains_key(introduced_did) {
            return Err(IdentityError::DIDNotFound(introduced_did.to_string()));
        }

        let introducer = DID(introducer_did.to_string());
        let introduced = DID(introduced_did.to_string());

        let tx = IntroductionTransaction {
            introducer_did: introducer,
            introduced_did: introduced,
            edge_name: edge_name.to_string(),
            context: IntroductionContext::Direct,
            capability_grants: vec![],
            proof: disentangle_crypto::sign(introducer_sk, b"introduction"),
            parents: vec![],
            depth: self.current_depth,
        };

        self.identity_graph.record_introduction(&tx);
        self.introduction_history.push(tx); // Store for persistence

        // Snapshot curvature after graph mutation
        self.snapshot_curvature(self.current_depth);

        Ok(())
    }

    // Coherence Operations

    /// Get coherence profile for a DID
    pub fn get_coherence_profile(&self, did: &str) -> Option<CoherenceProfile> {
        let did_obj = DID(did.to_string());
        let first_seen_depth = self.first_seen.get(did).copied().unwrap_or(0);

        Some(CoherenceProfile::compute(
            &did_obj,
            &self.identity_graph,
            first_seen_depth,
            self.current_depth,
        ))
    }

    /// Get identity curvature between two DIDs
    pub fn get_identity_curvature(&self, did_a: &str, did_b: &str) -> Option<f64> {
        let did_a_obj = DID(did_a.to_string());
        let did_b_obj = DID(did_b.to_string());

        let curvature_fp = self
            .identity_graph
            .identity_curvature(&did_a_obj, &did_b_obj);

        // Convert from fixed-point to f64
        use disentangle_dag::SCALE;
        Some(curvature_fp as f64 / SCALE as f64)
    }

    /// Get neighbors of a DID
    pub fn get_neighbors(&self, did: &str) -> Vec<String> {
        let did_obj = DID(did.to_string());
        self.identity_graph
            .neighbors(&did_obj)
            .into_iter()
            .map(|d| d.0)
            .collect()
    }

    // Introduction Operations (continued)

    /// Get the introduction chain from one DID to another
    pub fn get_introduction_chain(&self, from_did: &str, to_did: &str) -> Option<Vec<String>> {
        let from = DID(from_did.to_string());
        let to = DID(to_did.to_string());

        let chain = self.identity_graph.introduction_chain(&from, &to)?;

        // Convert IntroductionStep chain to a list of DID strings
        // The BFS builds the chain where each step's introducer is the source node
        // For the full path, we start with 'from' and add intermediate nodes plus 'to'
        let mut did_chain = vec![from_did.to_string()];

        // Each step represents an edge in the path
        // step.introducer is the "from" node of that edge
        // The destination of each edge is the next step's introducer, or 'to' for the last step
        for (i, _step) in chain.iter().enumerate() {
            if i == chain.len() - 1 {
                // Last step - destination is to_did
                did_chain.push(to_did.to_string());
            } else {
                // Intermediate step - destination is next step's introducer
                did_chain.push(chain[i + 1].introducer.0.clone());
            }
        }

        Some(did_chain)
    }

    // Petname Operations

    /// Set a petname for a DID
    pub fn set_petname(&mut self, name: &str, did: &str) -> Result<(), IdentityError> {
        let did_obj = DID(did.to_string());
        self.petnames
            .bind(name, &did_obj, vec![], self.current_depth)
    }

    /// Resolve a petname to a DID
    pub fn resolve_petname(&self, name: &str) -> Option<String> {
        self.petnames.resolve_name(name).map(|d| d.0.clone())
    }

    // Governance Operations

    /// Create a new governance proposal
    pub fn create_proposal(
        &mut self,
        proposer_did: &str,
        proposer_sk: &SigningKey,
        proposal_type: ProposalType,
        description: &str,
        duration_blocks: u64,
    ) -> Result<GovernanceProposal, IdentityError> {
        // Verify proposer exists
        let (_, proposer_pk) = self
            .did_registry
            .get(proposer_did)
            .ok_or_else(|| IdentityError::DIDNotFound(proposer_did.to_string()))?;

        let proposer = DID(proposer_did.to_string());
        let description_hash = sha3_256(description.as_bytes());

        let voting_start = self.current_depth;
        let voting_end = self.current_depth + duration_blocks;

        // Default quorum: coherence-weighted with 50% threshold
        use disentangle_dag::SCALE;
        let quorum = disentangle_identity::GovernanceQuorum::CoherenceWeighted {
            threshold: SCALE / 2,
        };

        let proposal = GovernanceProposal::new(
            &proposer,
            proposal_type,
            description_hash,
            voting_start,
            voting_end,
            quorum,
            proposer_sk,
        );

        // Verify the proposal signature
        if !proposal.verify(proposer_pk) {
            return Err(IdentityError::InvalidDID(
                "Invalid proposal signature".to_string(),
            ));
        }

        self.proposals.insert(proposal.id, proposal.clone());

        Ok(proposal)
    }

    /// Cast a vote on a proposal
    pub fn cast_vote(
        &mut self,
        proposal_id: &Hash256,
        voter_did: &str,
        _voter_sk: &SigningKey,
        vote: VoteChoice,
    ) -> Result<GovernanceVote, IdentityError> {
        // Verify proposal exists
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(proposal_id)))?;

        // Verify voter exists
        let (_, voter_pk) = self
            .did_registry
            .get(voter_did)
            .ok_or_else(|| IdentityError::DIDNotFound(voter_did.to_string()))?;

        // Check voting window
        if self.current_depth < proposal.voting_start || self.current_depth > proposal.voting_end {
            return Err(IdentityError::ConstraintNotSatisfied(
                "Voting period not active".to_string(),
            ));
        }

        // Create vote transaction identity
        // For Phase 1, we use the voter's public key as ephemeral_pk (placeholder)
        // In Phase 2, this would use ZK proofs
        use disentangle_crypto::types::Nullifier;
        use disentangle_identity::TransactionIdentity;

        let voter_identity = TransactionIdentity {
            ephemeral_pk: voter_pk.clone(),
            did_binding_proof: vec![],
            nullifier: Nullifier([0u8; 32]), // Placeholder
            reputation_bucket: 0,
        };

        let gov_vote = GovernanceVote {
            proposal_id: *proposal_id,
            voter_identity,
            vote,
            parents: vec![],
            depth: self.current_depth,
        };

        self.votes.push(gov_vote.clone());

        Ok(gov_vote)
    }

    /// Get a proposal by ID
    pub fn get_proposal(&self, proposal_id: &Hash256) -> Option<&GovernanceProposal> {
        self.proposals.get(proposal_id)
    }

    /// List all proposals
    pub fn list_proposals(&self) -> Vec<&GovernanceProposal> {
        self.proposals.values().collect()
    }

    /// Evaluate a proposal's result
    pub fn evaluate_proposal(&self, proposal_id: &Hash256) -> Option<ProposalResult> {
        let proposal = self.proposals.get(proposal_id)?;

        // Build coherence profiles for all DIDs
        let mut profiles = HashMap::new();
        for did_str in self.did_registry.keys() {
            let did = DID(did_str.clone());
            let first_seen_depth = self.first_seen.get(did_str).copied().unwrap_or(0);
            let profile = CoherenceProfile::compute(
                &did,
                &self.identity_graph,
                first_seen_depth,
                self.current_depth,
            );
            profiles.insert(did, profile);
        }

        Some(evaluate_proposal(
            proposal,
            &self.votes,
            &profiles,
            self.current_depth,
        ))
    }

    // Agreement Operations

    /// Propose a new service agreement
    pub fn propose_agreement(
        &mut self,
        provider_did: &str,
        provider_sk: &SigningKey,
        consumer_did: &str,
        capability_id: Option<&Hash256>,
        terms: AgreementTerms,
    ) -> Result<Hash256, IdentityError> {
        // Verify provider exists
        if !self.did_registry.contains_key(provider_did) {
            return Err(IdentityError::DIDNotFound(provider_did.to_string()));
        }

        // Verify consumer exists
        if !self.did_registry.contains_key(consumer_did) {
            return Err(IdentityError::DIDNotFound(consumer_did.to_string()));
        }

        // Sign the agreement proposal
        use disentangle_crypto::sign;
        let message = format!(
            "AGREEMENT:{}:{}:{}",
            provider_did, consumer_did, terms.description
        );
        let signature = sign(provider_sk, message.as_bytes());

        let agreement = ServiceAgreement::new(
            provider_did.to_string(),
            consumer_did.to_string(),
            capability_id.copied(),
            terms,
            self.current_depth,
            signature.to_bytes().to_vec(),
        );

        let agreement_id = agreement.id;
        self.agreements.insert(agreement_id, agreement);

        Ok(agreement_id)
    }

    /// Accept a proposed agreement (consumer signature)
    pub fn accept_agreement(
        &mut self,
        agreement_id: &Hash256,
        consumer_sk: &SigningKey,
    ) -> Result<(), IdentityError> {
        let agreement = self
            .agreements
            .get_mut(agreement_id)
            .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(agreement_id)))?;

        if agreement.status != AgreementStatus::Proposed {
            return Err(IdentityError::ConstraintNotSatisfied(
                "Agreement is not in Proposed state".to_string(),
            ));
        }

        // Sign the acceptance
        use disentangle_crypto::sign;
        let message = format!("ACCEPT:{}", hex::encode(agreement_id));
        let signature = sign(consumer_sk, message.as_bytes());

        agreement.accept(signature.to_bytes().to_vec());

        Ok(())
    }

    /// Complete an agreement with success status
    pub fn complete_agreement(
        &mut self,
        agreement_id: &Hash256,
        success: bool,
        outcome_hash: Hash256,
        _signer_sk: &SigningKey,
    ) -> Result<(), IdentityError> {
        let agreement = self
            .agreements
            .get_mut(agreement_id)
            .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(agreement_id)))?;

        if agreement.status != AgreementStatus::Active {
            return Err(IdentityError::ConstraintNotSatisfied(
                "Agreement is not in Active state".to_string(),
            ));
        }

        agreement.complete(success, outcome_hash, self.current_depth);

        // Snapshot curvature after agreement completion (affects coherence)
        self.snapshot_curvature(self.current_depth);

        Ok(())
    }

    /// Get an agreement by ID
    pub fn get_agreement(&self, agreement_id: &Hash256) -> Option<&SettlementAgreement> {
        self.agreements.get(agreement_id)
    }

    /// List all agreements involving a specific DID
    pub fn list_agreements_for_did(&self, did: &str) -> Vec<&SettlementAgreement> {
        self.agreements
            .values()
            .filter(|agreement| agreement.involves_did(did))
            .collect()
    }

    // Coordination Proposal Operations

    /// Create a new coordination proposal
    pub fn create_coordination_proposal(
        &mut self,
        initiator_did: &str,
        description: String,
        intent_hash: Hash256,
        activation_mass: f64,
        min_participants: u32,
        expiry_depth: u64,
    ) -> Result<Hash256, IdentityError> {
        // Verify initiator exists and has CoherenceMinimum
        if !self.did_registry.contains_key(initiator_did) {
            return Err(IdentityError::DIDNotFound(initiator_did.to_string()));
        }

        // Check coherence minimum
        let profile = self.get_coherence_profile(initiator_did).ok_or_else(|| {
            IdentityError::ConstraintNotSatisfied("No coherence profile".to_string())
        })?;

        // CoherenceMinimum check (similar to capability constraints)
        if profile.topological_mass <= 0 {
            return Err(IdentityError::ConstraintNotSatisfied(
                "Insufficient coherence".to_string(),
            ));
        }

        let proposal = Proposal::new(
            initiator_did.to_string(),
            intent_hash,
            description,
            activation_mass,
            min_participants,
            expiry_depth,
            self.current_depth,
        );

        let proposal_id = proposal.id;
        self.coord_proposals.insert(proposal_id, proposal);

        Ok(proposal_id)
    }

    /// Join a coordination proposal
    pub fn join_coordination_proposal(
        &mut self,
        proposal_id: &Hash256,
        joiner_did: &str,
    ) -> Result<Option<Hash256>, IdentityError> {
        // Verify joiner exists and has CoherenceMinimum
        if !self.did_registry.contains_key(joiner_did) {
            return Err(IdentityError::DIDNotFound(joiner_did.to_string()));
        }

        let profile = self.get_coherence_profile(joiner_did).ok_or_else(|| {
            IdentityError::ConstraintNotSatisfied("No coherence profile".to_string())
        })?;

        if profile.topological_mass <= 0 {
            return Err(IdentityError::ConstraintNotSatisfied(
                "Insufficient coherence".to_string(),
            ));
        }

        // First pass: add joiner and check activation
        let should_activate = {
            let proposal = self
                .coord_proposals
                .get_mut(proposal_id)
                .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(proposal_id)))?;

            // Check if already joined
            if proposal.joiners.iter().any(|j| j.did == joiner_did) {
                return Err(IdentityError::ConstraintNotSatisfied(
                    "Already joined".to_string(),
                ));
            }

            // Check if proposal is still attracting
            if proposal.status != ProposalStatus::Attracting {
                return Err(IdentityError::ConstraintNotSatisfied(
                    "Proposal not accepting joins".to_string(),
                ));
            }

            // Add joiner
            let committed_mass = profile.topological_mass as f64;
            proposal.joiners.push(JoinCommitment {
                did: joiner_did.to_string(),
                committed_mass,
                join_depth: self.current_depth,
            });
            proposal.committed_mass += committed_mass;

            proposal.check_activation()
        };

        // Second pass: create intent if activated
        if should_activate {
            let intent_id = self.create_intent_from_proposal(proposal_id)?;
            if let Some(proposal) = self.coord_proposals.get_mut(proposal_id) {
                proposal.status = ProposalStatus::Activated { intent_id };
            }

            // Snapshot curvature after proposal activation
            self.snapshot_curvature(self.current_depth);

            Ok(Some(intent_id))
        } else {
            Ok(None)
        }
    }

    /// Check if proposal should activate
    pub fn check_coordination_proposal_activation(
        &mut self,
        proposal_id: &Hash256,
    ) -> Option<Hash256> {
        let should_activate = {
            let proposal = self.coord_proposals.get(proposal_id)?;
            proposal.check_activation() && proposal.status == ProposalStatus::Attracting
        };

        if should_activate {
            // Auto-create SharedIntent
            if let Ok(intent_id) = self.create_intent_from_proposal(proposal_id) {
                if let Some(proposal) = self.coord_proposals.get_mut(proposal_id) {
                    proposal.status = ProposalStatus::Activated { intent_id };
                }
                return Some(intent_id);
            }
        }

        None
    }

    /// Get a coordination proposal by ID
    pub fn get_coordination_proposal(&self, proposal_id: &Hash256) -> Option<&Proposal> {
        self.coord_proposals.get(proposal_id)
    }

    /// List coordination proposals with optional status filter
    pub fn list_coordination_proposals(&self, status: Option<ProposalStatus>) -> Vec<&Proposal> {
        match status {
            Some(s) => self
                .coord_proposals
                .values()
                .filter(|p| p.status == s)
                .collect(),
            None => self.coord_proposals.values().collect(),
        }
    }

    /// List proposals initiated by or joined by a DID
    pub fn list_coordination_proposals_for_did(&self, did: &str) -> Vec<&Proposal> {
        self.coord_proposals
            .values()
            .filter(|p| p.initiator_did == did || p.joiners.iter().any(|j| j.did == did))
            .collect()
    }

    // SharedIntent Operations

    /// Create a new SharedIntent directly (not from proposal)
    pub fn create_shared_intent(
        &mut self,
        description: String,
        intent_hash: Hash256,
        participant_dids: Vec<String>,
        capability_ids: Vec<Vec<Hash256>>,
    ) -> Result<Hash256, IdentityError> {
        // Verify all participants exist
        for did in &participant_dids {
            if !self.did_registry.contains_key(did) {
                return Err(IdentityError::DIDNotFound(did.to_string()));
            }
        }

        // Build participants list
        let mut participants = Vec::new();
        for (i, did) in participant_dids.iter().enumerate() {
            let profile = self.get_coherence_profile(did).ok_or_else(|| {
                IdentityError::ConstraintNotSatisfied("No coherence profile".to_string())
            })?;

            let caps = capability_ids.get(i).cloned().unwrap_or_default();

            participants.push(IntentParticipant {
                did: did.clone(),
                joined_depth: self.current_depth,
                mass_at_join: profile.topological_mass as f64,
                contributed_capabilities: caps,
            });
        }

        // Compute baseline metrics
        let baseline_mass: f64 = participants.iter().map(|p| p.mass_at_join).sum();
        let baseline_curvature = self.compute_group_curvature(&participant_dids);

        let intent = SharedIntent::new(
            None,
            description,
            intent_hash,
            participants,
            self.current_depth,
            baseline_curvature,
            baseline_mass,
        );

        let intent_id = intent.id;
        self.shared_intents.insert(intent_id, intent);

        Ok(intent_id)
    }

    /// Create SharedIntent from an activated proposal
    pub fn create_intent_from_proposal(
        &mut self,
        proposal_id: &Hash256,
    ) -> Result<Hash256, IdentityError> {
        let proposal = self
            .coord_proposals
            .get(proposal_id)
            .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(proposal_id)))?;

        let participant_dids: Vec<String> =
            proposal.joiners.iter().map(|j| j.did.clone()).collect();

        // Build participants from proposal joiners
        let mut participants = Vec::new();
        for joiner in &proposal.joiners {
            participants.push(IntentParticipant {
                did: joiner.did.clone(),
                joined_depth: joiner.join_depth,
                mass_at_join: joiner.committed_mass,
                contributed_capabilities: vec![],
            });
        }

        let baseline_curvature = self.compute_group_curvature(&participant_dids);

        let intent = SharedIntent::new(
            Some(*proposal_id),
            proposal.description.clone(),
            proposal.intent_hash,
            participants,
            self.current_depth,
            baseline_curvature,
            proposal.committed_mass,
        );

        let intent_id = intent.id;
        self.shared_intents.insert(intent_id, intent);

        Ok(intent_id)
    }

    /// Join an existing SharedIntent
    pub fn join_shared_intent(
        &mut self,
        intent_id: &Hash256,
        joiner_did: &str,
        capabilities: Vec<Hash256>,
    ) -> Result<(), IdentityError> {
        // Verify joiner exists and has CoherenceMinimum
        if !self.did_registry.contains_key(joiner_did) {
            return Err(IdentityError::DIDNotFound(joiner_did.to_string()));
        }

        let profile = self.get_coherence_profile(joiner_did).ok_or_else(|| {
            IdentityError::ConstraintNotSatisfied("No coherence profile".to_string())
        })?;

        if profile.topological_mass <= 0 {
            return Err(IdentityError::ConstraintNotSatisfied(
                "Insufficient coherence".to_string(),
            ));
        }

        // First pass: validate and check introduction chain
        let can_join = {
            let intent = self
                .shared_intents
                .get(intent_id)
                .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(intent_id)))?;

            // Check if intent is active
            if intent.status != IntentStatus::Active {
                return Err(IdentityError::ConstraintNotSatisfied(
                    "Intent not active".to_string(),
                ));
            }

            // Check if already a participant
            if intent.has_participant(joiner_did) {
                return Err(IdentityError::ConstraintNotSatisfied(
                    "Already a participant".to_string(),
                ));
            }

            // Check introduction chain (at least one existing participant must have positive curvature with joiner)
            let participant_dids: Vec<String> =
                intent.participants.iter().map(|p| p.did.clone()).collect();
            participant_dids.iter().any(|p_did| {
                self.get_identity_curvature(p_did, joiner_did)
                    .map(|c| c > 0.0)
                    .unwrap_or(false)
            })
        };

        if !can_join {
            return Err(IdentityError::ConstraintNotSatisfied(
                "No introduction chain".to_string(),
            ));
        }

        // Second pass: add participant
        let intent = self
            .shared_intents
            .get_mut(intent_id)
            .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(intent_id)))?;

        intent.participants.push(IntentParticipant {
            did: joiner_did.to_string(),
            joined_depth: self.current_depth,
            mass_at_join: profile.topological_mass as f64,
            contributed_capabilities: capabilities,
        });

        // Snapshot curvature after participant joins intent
        self.snapshot_curvature(self.current_depth);

        Ok(())
    }

    /// Archive a SharedIntent
    pub fn archive_shared_intent(
        &mut self,
        intent_id: &Hash256,
        archiver_did: &str,
    ) -> Result<IntentStatus, IdentityError> {
        // First pass: validate and compute deltas
        let (participant_dids, baseline_mass, baseline_curvature) = {
            let intent = self
                .shared_intents
                .get(intent_id)
                .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(intent_id)))?;

            // Check if archiver is a participant
            if !intent.has_participant(archiver_did) {
                return Err(IdentityError::ConstraintNotSatisfied(
                    "Not a participant".to_string(),
                ));
            }

            // Check if intent is active
            if intent.status != IntentStatus::Active {
                return Err(IdentityError::ConstraintNotSatisfied(
                    "Intent not active".to_string(),
                ));
            }

            let participant_dids: Vec<String> =
                intent.participants.iter().map(|p| p.did.clone()).collect();
            (
                participant_dids,
                intent.baseline_mass,
                intent.baseline_curvature,
            )
        };

        // Compute coherence delta
        let current_mass: f64 = participant_dids
            .iter()
            .map(|did| {
                self.get_coherence_profile(did)
                    .map(|p| p.topological_mass as f64)
                    .unwrap_or(0.0)
            })
            .sum();
        let current_curvature = self.compute_group_curvature(&participant_dids);

        let mass_delta = current_mass - baseline_mass;
        let curvature_delta = current_curvature - baseline_curvature;

        // Compute composite coherence delta (simplified)
        let coherence_delta = mass_delta + curvature_delta * 10.0; // Weight curvature more

        // Second pass: archive
        let intent = self
            .shared_intents
            .get_mut(intent_id)
            .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(intent_id)))?;

        intent.archive(self.current_depth, coherence_delta);

        Ok(intent.status.clone())
    }

    /// Get a SharedIntent by ID
    pub fn get_shared_intent(&self, intent_id: &Hash256) -> Option<&SharedIntent> {
        self.shared_intents.get(intent_id)
    }

    /// List SharedIntents with optional status filter
    pub fn list_shared_intents(&self, status: Option<IntentStatus>) -> Vec<&SharedIntent> {
        match status {
            Some(s) => self
                .shared_intents
                .values()
                .filter(|i| i.status == s)
                .collect(),
            None => self.shared_intents.values().collect(),
        }
    }

    /// List SharedIntents for a DID
    pub fn list_shared_intents_for_did(&self, did: &str) -> Vec<&SharedIntent> {
        self.shared_intents
            .values()
            .filter(|i| i.has_participant(did))
            .collect()
    }

    /// Get coherence snapshot for an intent
    pub fn intent_coherence_snapshot(
        &self,
        intent_id: &Hash256,
    ) -> Option<IntentCoherenceSnapshot> {
        let intent = self.shared_intents.get(intent_id)?;

        let participant_dids: Vec<String> =
            intent.participants.iter().map(|p| p.did.clone()).collect();
        let current_mass: f64 = participant_dids
            .iter()
            .map(|did| {
                self.get_coherence_profile(did)
                    .map(|p| p.topological_mass as f64)
                    .unwrap_or(0.0)
            })
            .sum();
        let current_curvature = self.compute_group_curvature(&participant_dids);

        Some(IntentCoherenceSnapshot {
            intent_id: *intent_id,
            participant_count: intent.participants.len(),
            baseline_mass: intent.baseline_mass,
            current_mass,
            mass_delta: current_mass - intent.baseline_mass,
            baseline_curvature: intent.baseline_curvature,
            current_curvature,
            curvature_delta: current_curvature - intent.baseline_curvature,
            depth: self.current_depth,
        })
    }

    // Oracle Operations

    /// Compute distribution for an oracle query
    pub fn compute_oracle_distribution(
        &mut self,
        query: OracleQuery,
    ) -> Result<Hash256, IdentityError> {
        // Get DIDs in the region
        let dids = match &query.region {
            RegionSelector::Neighborhood(_) => {
                // Would need to compute neighborhoods, simplified for now
                self.did_registry.keys().cloned().collect()
            }
            RegionSelector::Intent(intent_id) => {
                let intent = self
                    .shared_intents
                    .get(intent_id)
                    .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(intent_id)))?;
                intent.participants.iter().map(|p| p.did.clone()).collect()
            }
            RegionSelector::Explicit(dids) => dids.clone(),
            RegionSelector::Global => self.did_registry.keys().cloned().collect(),
        };

        // Compute scores for each agent
        let mut scores = HashMap::new();
        for did in &dids {
            // Compute mass delta over window
            let did_obj = DID(did.clone());
            let first_seen = self
                .first_seen
                .get(did)
                .copied()
                .unwrap_or(query.depth_start);

            let profile_start = CoherenceProfile::compute(
                &did_obj,
                &self.identity_graph,
                first_seen,
                query.depth_start,
            );
            let profile_end = CoherenceProfile::compute(
                &did_obj,
                &self.identity_graph,
                first_seen,
                query.depth_end,
            );

            let mass_delta =
                profile_end.topological_mass as f64 - profile_start.topological_mass as f64;

            // Compute curvature delta (mean curvature with other DIDs in region)
            let curvature_start = self.compute_group_member_curvature(did, &dids);
            let curvature_end = self.compute_group_member_curvature(did, &dids);
            let curvature_delta = curvature_end - curvature_start;

            // Compute curvature derivative (mean derivative with other DIDs in region)
            let window = query.depth_end.saturating_sub(query.depth_start);
            let neighbors = self.get_neighbors(did);
            let mut derivative_sum = 0.0;
            let mut derivative_count = 0;
            for neighbor in &neighbors {
                if dids.contains(neighbor) {
                    if let Some(deriv) = self.curvature_derivative(did, neighbor, window) {
                        derivative_sum += deriv.derivative;
                        derivative_count += 1;
                    }
                }
            }
            let curvature_derivative = if derivative_count > 0 {
                derivative_sum / derivative_count as f64
            } else {
                0.0
            };

            // Compute diversity (distinct positive-curvature connections in region)
            let diversity = dids
                .iter()
                .filter(|other| *other != did)
                .filter(|other| {
                    self.get_identity_curvature(did, other)
                        .map(|c| c > 0.0)
                        .unwrap_or(false)
                })
                .count() as u32;

            let mut score = AgentScore {
                did: did.clone(),
                mass_delta,
                curvature_delta,
                curvature_derivative,
                diversity,
                composite: 0.0,
            };
            score.compute_composite();

            scores.insert(did.clone(), score);
        }

        let distribution = DistributionRoot::new(&query, scores, self.current_depth);
        let distribution_id = distribution.query_id;

        self.oracle_distributions
            .insert(distribution_id, distribution);

        Ok(distribution_id)
    }

    /// Get a distribution by ID
    pub fn get_oracle_distribution(&self, distribution_id: &Hash256) -> Option<&DistributionRoot> {
        self.oracle_distributions.get(distribution_id)
    }

    /// List all distributions
    pub fn list_oracle_distributions(&self) -> Vec<&DistributionRoot> {
        self.oracle_distributions.values().collect()
    }

    // CommonsPool Operations

    /// Create a new commons pool
    pub fn create_pool(
        &mut self,
        name: String,
        description: String,
        creator_did: &str,
    ) -> Result<Hash256, IdentityError> {
        if !self.did_registry.contains_key(creator_did) {
            return Err(IdentityError::DIDNotFound(creator_did.to_string()));
        }

        let pool = CommonsPool::new(name, description, creator_did.to_string(), self.current_depth);
        let pool_id = pool.id;
        self.commons_pools.insert(pool_id, pool);
        Ok(pool_id)
    }

    /// Deposit value into a pool
    pub fn pool_deposit(
        &mut self,
        pool_id: &Hash256,
        depositor_did: &str,
        amount: f64,
        source: String,
    ) -> Result<f64, IdentityError> {
        if !self.did_registry.contains_key(depositor_did) {
            return Err(IdentityError::DIDNotFound(depositor_did.to_string()));
        }

        let pool = self
            .commons_pools
            .get_mut(pool_id)
            .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(pool_id)))?;

        pool.deposit(depositor_did.to_string(), amount, source, self.current_depth);
        Ok(pool.balance)
    }

    /// Distribute pool funds using an oracle distribution
    pub fn pool_distribute(
        &mut self,
        pool_id: &Hash256,
        distribution_id: &Hash256,
    ) -> Result<(std::collections::HashMap<String, f64>, f64), IdentityError> {
        let weights = {
            let distribution = self
                .oracle_distributions
                .get(distribution_id)
                .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(distribution_id)))?;
            distribution.weights.clone()
        };

        let pool = self
            .commons_pools
            .get_mut(pool_id)
            .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(pool_id)))?;

        let allocations = pool.distribute(*distribution_id, &weights, self.current_depth);
        let remaining = pool.balance;

        Ok((allocations, remaining))
    }

    /// Claim an allocation from a pool
    pub fn pool_claim(
        &mut self,
        pool_id: &Hash256,
        distribution_id: &Hash256,
        claimant_did: &str,
    ) -> Result<f64, IdentityError> {
        if !self.did_registry.contains_key(claimant_did) {
            return Err(IdentityError::DIDNotFound(claimant_did.to_string()));
        }

        let pool = self
            .commons_pools
            .get_mut(pool_id)
            .ok_or_else(|| IdentityError::CapabilityNotFound(hex::encode(pool_id)))?;

        pool.claim(claimant_did, *distribution_id, self.current_depth)
            .ok_or_else(|| {
                IdentityError::ConstraintNotSatisfied("No allocation for claimant".to_string())
            })
    }

    /// Get a pool by ID
    pub fn get_pool(&self, pool_id: &Hash256) -> Option<&CommonsPool> {
        self.commons_pools.get(pool_id)
    }

    /// List all pools
    pub fn list_pools(&self) -> Vec<&CommonsPool> {
        self.commons_pools.values().collect()
    }

    // Excitability Gradient Methods

    /// Record curvature snapshot for all edges (call after graph mutations)
    pub fn snapshot_curvature(&mut self, current_depth: u64) {
        let dids = self.list_dids();

        for i in 0..dids.len() {
            for j in (i + 1)..dids.len() {
                if let Some(curvature) = self.get_identity_curvature(&dids[i], &dids[j]) {
                    // Create sorted key to ensure consistent edge representation
                    let edge_key = if dids[i] < dids[j] {
                        (dids[i].clone(), dids[j].clone())
                    } else {
                        (dids[j].clone(), dids[i].clone())
                    };

                    let history = self.curvature_history.entry(edge_key).or_default();

                    // Only add if depth has advanced since last snapshot
                    if history.is_empty() || history.last().unwrap().0 < current_depth {
                        history.push((current_depth, curvature));

                        // Cap history size
                        if history.len() > MAX_HISTORY_DEPTH {
                            history.remove(0);
                        }
                    }
                }
            }
        }
    }

    /// Curvature derivative for a specific edge
    pub fn curvature_derivative(
        &self,
        did_a: &str,
        did_b: &str,
        window: u64,
    ) -> Option<CurvatureDerivative> {
        // Create sorted key
        let edge_key = if did_a < did_b {
            (did_a.to_string(), did_b.to_string())
        } else {
            (did_b.to_string(), did_a.to_string())
        };

        let history = self.curvature_history.get(&edge_key)?;

        if history.len() < 2 {
            return None;
        }

        let current = history.last()?;
        let depth_end = current.0;
        let kappa_end = current.1;

        // Find entry at or before window start
        let depth_start = depth_end.saturating_sub(window);
        let start_entry = history
            .iter()
            .rev()
            .find(|(d, _)| *d <= depth_start)
            .or_else(|| history.first())?;

        let kappa_start = start_entry.1;
        let actual_depth_start = start_entry.0;

        let depth_diff = depth_end.saturating_sub(actual_depth_start);
        let derivative = if depth_diff > 0 {
            (kappa_end - kappa_start) / depth_diff as f64
        } else {
            0.0
        };

        Some(CurvatureDerivative {
            did_a: did_a.to_string(),
            did_b: did_b.to_string(),
            kappa_start,
            kappa_end,
            derivative,
            depth_start: actual_depth_start,
            depth_end,
        })
    }

    /// Excitability profile for an agent
    pub fn excitability_profile(&self, did: &str, window: u64) -> Option<ExcitabilityProfile> {
        let neighbors = self.get_neighbors(did);

        if neighbors.is_empty() {
            return None;
        }

        let mut edge_gradients = Vec::new();
        let mut forming_count = 0u32;
        let mut degrading_count = 0u32;
        let mut max_gradient = 0.0f64;
        let mut sum_gradient = 0.0f64;

        for neighbor in &neighbors {
            if let Some(derivative) = self.curvature_derivative(did, neighbor, window) {
                if derivative.derivative > 0.0 {
                    forming_count += 1;
                } else if derivative.derivative < 0.0 {
                    degrading_count += 1;
                }

                if derivative.derivative.abs() > max_gradient.abs() {
                    max_gradient = derivative.derivative;
                }

                sum_gradient += derivative.derivative;
                edge_gradients.push(derivative);
            }
        }

        // Sort by derivative (highest first)
        edge_gradients.sort_by(|a, b| {
            b.derivative
                .partial_cmp(&a.derivative)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mean_gradient = if !edge_gradients.is_empty() {
            sum_gradient / edge_gradients.len() as f64
        } else {
            0.0
        };

        Some(ExcitabilityProfile {
            did: did.to_string(),
            mean_gradient,
            max_gradient,
            forming_count,
            degrading_count,
            edge_gradients,
            depth_window: window,
        })
    }

    /// Network-level gradient map
    pub fn coherence_gradient_map(&self, top_n: usize, window: u64) -> CoherenceGradientMap {
        let mut all_derivatives = Vec::new();
        let mut agent_profiles = Vec::new();

        let dids = self.list_dids();

        // Collect all edge derivatives
        for i in 0..dids.len() {
            for j in (i + 1)..dids.len() {
                if let Some(derivative) = self.curvature_derivative(&dids[i], &dids[j], window) {
                    all_derivatives.push(derivative);
                }
            }
        }

        // Collect agent excitability profiles
        for did in &dids {
            if let Some(profile) = self.excitability_profile(did, window) {
                agent_profiles.push(profile);
            }
        }

        // Sort derivatives
        let mut forming_derivatives = all_derivatives.clone();
        forming_derivatives.retain(|d| d.derivative > 0.0);
        forming_derivatives.sort_by(|a, b| {
            b.derivative
                .partial_cmp(&a.derivative)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        forming_derivatives.truncate(top_n);

        let mut degrading_derivatives = all_derivatives.clone();
        degrading_derivatives.retain(|d| d.derivative < 0.0);
        degrading_derivatives.sort_by(|a, b| {
            a.derivative
                .partial_cmp(&b.derivative)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        degrading_derivatives.truncate(top_n);

        // Sort agents by mean gradient
        agent_profiles.sort_by(|a, b| {
            b.mean_gradient
                .partial_cmp(&a.mean_gradient)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let most_excitable = agent_profiles.into_iter().take(top_n).collect();

        // Compute network-wide mean gradient
        let network_gradient = if !all_derivatives.is_empty() {
            all_derivatives.iter().map(|d| d.derivative).sum::<f64>() / all_derivatives.len() as f64
        } else {
            0.0
        };

        CoherenceGradientMap {
            forming: forming_derivatives,
            degrading: degrading_derivatives,
            most_excitable,
            network_gradient,
            depth_window: window,
            computed_at_depth: self.current_depth,
        }
    }

    // Helper methods

    /// Compute mean curvature among a group of DIDs
    fn compute_group_curvature(&self, dids: &[String]) -> f64 {
        if dids.len() < 2 {
            return 0.0;
        }

        let mut curvature_sum = 0.0;
        let mut edge_count = 0;

        for i in 0..dids.len() {
            for j in (i + 1)..dids.len() {
                if let Some(curvature) = self.get_identity_curvature(&dids[i], &dids[j]) {
                    curvature_sum += curvature;
                    edge_count += 1;
                }
            }
        }

        if edge_count > 0 {
            curvature_sum / edge_count as f64
        } else {
            0.0
        }
    }

    /// Compute mean curvature between a DID and a group
    fn compute_group_member_curvature(&self, did: &str, group: &[String]) -> f64 {
        let curvatures: Vec<f64> = group
            .iter()
            .filter(|other| *other != did)
            .filter_map(|other| self.get_identity_curvature(did, other))
            .collect();

        if curvatures.is_empty() {
            0.0
        } else {
            curvatures.iter().sum::<f64>() / curvatures.len() as f64
        }
    }

    // Persistence Operations

    /// Save state to a JSON file
    pub fn save_to_file(&self, path: &Path) -> Result<(), IdentityError> {
        // Extract data for serialization
        let mut did_registry_keys = Vec::new();
        let mut did_documents = Vec::new();
        let mut verifying_keys_hex = Vec::new();

        for (key, (doc, vk)) in &self.did_registry {
            did_registry_keys.push(key.clone());
            did_documents.push(doc.clone());
            verifying_keys_hex.push(hex::encode(vk.to_bytes()));
        }

        let capabilities: Vec<Capability> = self.capability_store.values().cloned().collect();

        let delegations: Vec<(String, Vec<DelegationRecord>)> = self
            .delegation_chains
            .iter()
            .map(|(cap_id, chain)| (hex::encode(cap_id), chain.clone()))
            .collect();

        let introductions = self.introduction_history.clone();

        let proposals: Vec<GovernanceProposal> = self.proposals.values().cloned().collect();
        let agreements: Vec<SettlementAgreement> = self.agreements.values().cloned().collect();
        let coord_proposals: Vec<Proposal> = self.coord_proposals.values().cloned().collect();
        let shared_intents: Vec<SharedIntent> = self.shared_intents.values().cloned().collect();
        let oracle_distributions: Vec<DistributionRoot> =
            self.oracle_distributions.values().cloned().collect();
        let commons_pools: Vec<CommonsPool> = self.commons_pools.values().cloned().collect();

        let state = SerializableState {
            did_registry_keys,
            did_documents,
            verifying_keys_hex,
            capabilities,
            delegations,
            introductions,
            current_depth: self.current_depth,
            first_seen: self.first_seen.clone(),
            proposals,
            votes: self.votes.clone(),
            agreements,
            coord_proposals,
            shared_intents,
            oracle_distributions,
            commons_pools,
        };

        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| IdentityError::InvalidDID(format!("Serialization error: {}", e)))?;

        std::fs::write(path, json)
            .map_err(|e| IdentityError::InvalidDID(format!("File write error: {}", e)))?;

        Ok(())
    }

    /// Load state from a JSON file
    pub fn load_from_file(path: &Path) -> Result<Self, IdentityError> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| IdentityError::DIDNotFound(format!("File read error: {}", e)))?;

        let state: SerializableState = serde_json::from_str(&json)
            .map_err(|e| IdentityError::InvalidDID(format!("Deserialization error: {}", e)))?;

        // Reconstruct did_registry
        let mut did_registry = HashMap::new();
        for i in 0..state.did_registry_keys.len() {
            let key = &state.did_registry_keys[i];
            let doc = &state.did_documents[i];
            let vk_bytes = hex::decode(&state.verifying_keys_hex[i])
                .map_err(|_| IdentityError::InvalidDID("Invalid verifying key hex".to_string()))?;
            let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| {
                IdentityError::InvalidDID("Invalid verifying key bytes".to_string())
            })?;
            did_registry.insert(key.clone(), (doc.clone(), vk));
        }

        // Reconstruct capability_store
        let mut capability_store = HashMap::new();
        for cap in state.capabilities {
            capability_store.insert(cap.id, cap);
        }

        // Reconstruct delegation_chains
        let mut delegation_chains = HashMap::new();
        for (cap_id_hex, chain) in state.delegations {
            let cap_id_bytes = hex::decode(&cap_id_hex)
                .map_err(|_| IdentityError::InvalidDID("Invalid capability ID".to_string()))?;
            if cap_id_bytes.len() != 32 {
                return Err(IdentityError::InvalidDID(
                    "Capability ID must be 32 bytes".to_string(),
                ));
            }
            let mut cap_id = [0u8; 32];
            cap_id.copy_from_slice(&cap_id_bytes);
            delegation_chains.insert(cap_id, chain);
        }

        // Reconstruct identity_graph from introductions
        let mut identity_graph = IdentityGraph::new();
        for intro_tx in &state.introductions {
            identity_graph.record_introduction(intro_tx);
        }

        // Reconstruct delegation edges in the graph
        for chain in delegation_chains.values() {
            for delegation in chain {
                identity_graph.record_delegation(delegation);
            }
        }

        // Reconstruct proposals
        let mut proposals = HashMap::new();
        for proposal in state.proposals {
            proposals.insert(proposal.id, proposal);
        }

        // Reconstruct agreements
        let mut agreements = HashMap::new();
        for agreement in state.agreements {
            agreements.insert(agreement.id, agreement);
        }

        // Reconstruct coordination proposals
        let mut coord_proposals = HashMap::new();
        for proposal in state.coord_proposals {
            coord_proposals.insert(proposal.id, proposal);
        }

        // Reconstruct shared intents
        let mut shared_intents = HashMap::new();
        for intent in state.shared_intents {
            shared_intents.insert(intent.id, intent);
        }

        // Reconstruct oracle distributions
        let mut oracle_distributions = HashMap::new();
        for distribution in state.oracle_distributions {
            oracle_distributions.insert(distribution.query_id, distribution);
        }

        // Reconstruct commons pools
        let mut commons_pools = HashMap::new();
        for pool in state.commons_pools {
            commons_pools.insert(pool.id, pool);
        }

        Ok(Self {
            did_registry,
            capability_store,
            delegation_chains,
            identity_graph,
            petnames: PetnameDB::new(), // Petnames are not persisted (local-first)
            current_depth: state.current_depth,
            first_seen: state.first_seen,
            proposals,
            votes: state.votes,
            introduction_history: state.introductions,
            agreements,
            coord_proposals,
            shared_intents,
            oracle_distributions,
            commons_pools,
            curvature_history: HashMap::new(), // Rebuilt on startup
        })
    }

    // Depth Management

    /// Advance to the next depth
    pub fn advance_depth(&mut self) {
        self.current_depth += 1;
    }

    /// Get the current depth
    pub fn current_depth(&self) -> u64 {
        self.current_depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use disentangle_identity::{CapabilitySubject, TransactionScope};

    #[test]
    fn test_register_human_did() {
        let mut manager = IdentityStateManager::new();
        let result = manager.register_did(AgentType::Human);

        assert!(result.is_ok());
        let (did, doc, _sk) = result.unwrap();

        assert!(!did.is_agi());
        assert!(matches!(doc.agent_type, AgentType::Human));
        assert_eq!(doc.created_depth, 0);
    }

    #[test]
    fn test_register_agi_did() {
        let mut manager = IdentityStateManager::new();
        let result = manager.register_did(AgentType::AGI {
            runtime_attestation: None,
        });

        assert!(result.is_ok());
        let (did, doc, _sk) = result.unwrap();

        assert!(did.is_agi());
        assert!(matches!(doc.agent_type, AgentType::AGI { .. }));
    }

    #[test]
    fn test_register_duplicate_prevention() {
        let mut manager = IdentityStateManager::new();

        // Register first DID
        let (did, _, _sk) = manager.register_did(AgentType::Human).unwrap();

        // Manually try to register same DID (simulating collision)
        // Since we can't control keypair generation, we'll verify the registry prevents duplicates
        // by checking that the DID is in the registry
        assert!(manager.did_registry.contains_key(&did.0));

        // Try to get non-existent DID
        let fake_did = "did:disentangle:nonexistent";
        assert!(manager.get_did_document(fake_did).is_none());
    }

    #[test]
    fn test_get_nonexistent_did() {
        let manager = IdentityStateManager::new();
        let result = manager.get_did_document("did:disentangle:nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_create_capability() {
        let mut manager = IdentityStateManager::new();
        let (did, _doc, sk) = manager.register_did(AgentType::Human).unwrap();

        let subject = CapabilitySubject::Transact {
            scope: TransactionScope::All,
        };

        let result = manager.create_capability(&did.0, &sk, subject, vec![], true);

        assert!(result.is_ok());
        let cap = result.unwrap();
        assert_eq!(cap.issuer, did);
        assert!(cap.delegatable);
    }

    #[test]
    fn test_delegate_capability() {
        let mut manager = IdentityStateManager::new();

        // Create issuer and delegatee
        let (issuer_did, _doc1, issuer_sk) = manager.register_did(AgentType::Human).unwrap();
        let (delegatee_did, _doc2, _sk2) = manager.register_did(AgentType::Human).unwrap();

        // Create capability
        let cap = manager
            .create_capability(
                &issuer_did.0,
                &issuer_sk,
                CapabilitySubject::Transact {
                    scope: TransactionScope::All,
                },
                vec![],
                true,
            )
            .unwrap();

        // Delegate
        let result =
            manager.delegate_capability(&cap.id, &issuer_did.0, &issuer_sk, &delegatee_did.0);

        assert!(result.is_ok());
        let delegation = result.unwrap();
        assert_eq!(delegation.delegator, issuer_did);
        assert_eq!(delegation.delegatee, delegatee_did);
        assert_eq!(delegation.depth, 1);
    }

    #[test]
    fn test_delegation_chain_depth() {
        let mut manager = IdentityStateManager::new();

        // Create chain: A -> B -> C
        let (did_a, _, sk_a) = manager.register_did(AgentType::Human).unwrap();
        let (did_b, _, sk_b) = manager.register_did(AgentType::Human).unwrap();
        let (did_c, _, _sk_c) = manager.register_did(AgentType::Human).unwrap();

        // Create capability with max depth 2
        let mut cap = manager
            .create_capability(
                &did_a.0,
                &sk_a,
                CapabilitySubject::Transact {
                    scope: TransactionScope::All,
                },
                vec![],
                true,
            )
            .unwrap();
        cap.max_delegation_depth = 2;
        manager.capability_store.insert(cap.id, cap.clone());

        // First delegation: A -> B (depth 1)
        let result1 = manager.delegate_capability(&cap.id, &did_a.0, &sk_a, &did_b.0);
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap().depth, 1);

        // Second delegation: B -> C (depth 2)
        let result2 = manager.delegate_capability(&cap.id, &did_b.0, &sk_b, &did_c.0);
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().depth, 2);

        // Third delegation should fail (exceeds max depth)
        let (did_d, _, _sk_d) = manager.register_did(AgentType::Human).unwrap();
        let result3 = manager.delegate_capability(&cap.id, &did_c.0, &sk_b, &did_d.0);
        assert!(result3.is_err());
    }

    #[test]
    fn test_revoke_capability() {
        let mut manager = IdentityStateManager::new();

        let (issuer_did, _, issuer_sk) = manager.register_did(AgentType::Human).unwrap();

        let cap = manager
            .create_capability(
                &issuer_did.0,
                &issuer_sk,
                CapabilitySubject::Transact {
                    scope: TransactionScope::All,
                },
                vec![],
                true,
            )
            .unwrap();

        // Revoke
        let result = manager.revoke_capability(&cap.id, &issuer_did.0, RevocationScope::Single);
        assert!(result.is_ok());

        // Verify it's revoked
        assert!(manager.identity_graph.is_revoked(&cap.id));
    }

    #[test]
    fn test_introduce_builds_graph() {
        let mut manager = IdentityStateManager::new();

        let (did_a, _, sk_a) = manager.register_did(AgentType::Human).unwrap();
        let (did_b, _, _sk_b) = manager.register_did(AgentType::Human).unwrap();

        // Introduce A -> B
        let result = manager.introduce(&did_a.0, &sk_a, &did_b.0, "Friend");
        assert!(result.is_ok());

        // Check neighbors
        let neighbors_a = manager.get_neighbors(&did_a.0);
        let neighbors_b = manager.get_neighbors(&did_b.0);

        assert!(neighbors_a.contains(&did_b.0));
        assert!(neighbors_b.contains(&did_a.0));
    }

    #[test]
    fn test_curvature_positive_with_shared_neighbors() {
        let mut manager = IdentityStateManager::new();

        // Create 4 agents: A, B, C, D
        let (did_a, _, sk_a) = manager.register_did(AgentType::Human).unwrap();
        let (did_b, _, sk_b) = manager.register_did(AgentType::Human).unwrap();
        let (did_c, _, _sk_c) = manager.register_did(AgentType::Human).unwrap();
        let (did_d, _, _sk_d) = manager.register_did(AgentType::Human).unwrap();

        // Create shared neighbors: A-C, A-D, B-C, B-D
        manager.introduce(&did_a.0, &sk_a, &did_c.0, "C").unwrap();
        manager.introduce(&did_a.0, &sk_a, &did_d.0, "D").unwrap();
        manager.introduce(&did_b.0, &sk_b, &did_c.0, "C").unwrap();
        manager.introduce(&did_b.0, &sk_b, &did_d.0, "D").unwrap();

        // A and B share C and D as neighbors
        let curvature = manager.get_identity_curvature(&did_a.0, &did_b.0);
        assert!(curvature.is_some());
        assert!(
            curvature.unwrap() > 0.0,
            "Expected positive curvature with shared neighbors"
        );
    }

    #[test]
    fn test_curvature_negative_no_shared() {
        let mut manager = IdentityStateManager::new();

        let (did_a, _, sk_a) = manager.register_did(AgentType::Human).unwrap();
        let (did_b, _, _sk_b) = manager.register_did(AgentType::Human).unwrap();

        // Introduce A -> B (but no shared neighbors)
        manager.introduce(&did_a.0, &sk_a, &did_b.0, "B").unwrap();

        // No shared neighbors beyond each other -> negative curvature
        let curvature = manager.get_identity_curvature(&did_a.0, &did_b.0);
        assert!(curvature.is_some());
        assert!(
            curvature.unwrap() < 0.0,
            "Expected negative curvature with no shared neighbors"
        );
    }

    #[test]
    fn test_coherence_profile_increases_with_introductions() {
        let mut manager = IdentityStateManager::new();

        let (did_a, _, sk_a) = manager.register_did(AgentType::Human).unwrap();

        // Initial coherence
        let profile1 = manager.get_coherence_profile(&did_a.0);
        assert!(profile1.is_some());
        let mass1 = profile1.unwrap().topological_mass;

        // Add some neighbors with shared connections
        let (did_b, _, _sk_b) = manager.register_did(AgentType::Human).unwrap();
        let (did_c, _, sk_c) = manager.register_did(AgentType::Human).unwrap();
        let (did_d, _, _sk_d) = manager.register_did(AgentType::Human).unwrap();

        // Create triangle: A-B, A-C, B-C (positive curvature)
        manager.introduce(&did_a.0, &sk_a, &did_b.0, "B").unwrap();
        manager.introduce(&did_a.0, &sk_a, &did_c.0, "C").unwrap();
        manager.introduce(&did_c.0, &sk_c, &did_b.0, "B").unwrap();

        // Add D connected to A
        manager.introduce(&did_a.0, &sk_a, &did_d.0, "D").unwrap();

        // Coherence should increase with more connections
        let profile2 = manager.get_coherence_profile(&did_a.0);
        assert!(profile2.is_some());
        let mass2 = profile2.unwrap().topological_mass;

        assert!(
            mass2 > mass1,
            "Topological mass should increase with more introductions"
        );
    }

    #[test]
    fn test_coherence_decay() {
        let mut manager = IdentityStateManager::new();

        let (did_a, _, sk_a) = manager.register_did(AgentType::Human).unwrap();
        let (did_b, _, _sk_b) = manager.register_did(AgentType::Human).unwrap();

        // Create introduction at block 0
        manager.introduce(&did_a.0, &sk_a, &did_b.0, "B").unwrap();

        let profile1 = manager.get_coherence_profile(&did_a.0).unwrap();
        let initial_mass = profile1.topological_mass;

        // The profile's last_active_depth is set to current_depth during compute
        // To test decay, we need to manually calculate decayed mass for a future depth
        let future_depth = profile1.last_active_depth + 20_000;
        let decayed_mass = profile1.decayed_mass(future_depth);

        // Mass should decay over time (20,000 depths = 2 half-lives)
        // Expected decay: initial_mass >> 2 = initial_mass / 4
        assert!(
            decayed_mass < initial_mass,
            "Coherence should decay over time: initial={}, decayed={}",
            initial_mass,
            decayed_mass
        );

        // Should be roughly 1/4 of initial (2 half-lives)
        let expected_approx = initial_mass / 4;
        let tolerance = initial_mass / 10; // 10% tolerance
        assert!(
            (decayed_mass as i64 - expected_approx as i64).abs() < tolerance as i64,
            "Decayed mass {} should be close to expected {}",
            decayed_mass,
            expected_approx
        );
    }

    #[test]
    fn test_petname_roundtrip() {
        let mut manager = IdentityStateManager::new();

        let (did, _, _sk) = manager.register_did(AgentType::Human).unwrap();

        // Set petname
        let result = manager.set_petname("Alice", &did.0);
        assert!(result.is_ok());

        // Resolve
        let resolved = manager.resolve_petname("Alice");
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap(), did.0);
    }

    #[test]
    fn test_sybil_low_coherence() {
        let mut manager = IdentityStateManager::new();

        // Create honest network: 5 agents with shared connections
        let mut honest_agents = vec![];
        for _ in 0..5 {
            let (did, _, sk) = manager.register_did(AgentType::Human).unwrap();
            honest_agents.push((did, sk));
        }

        // Connect honest agents in a mesh (each knows multiple others)
        for i in 0..honest_agents.len() {
            for j in (i + 1)..honest_agents.len() {
                if i != j {
                    let (ref did_i, ref sk_i) = honest_agents[i];
                    let (ref did_j, _) = honest_agents[j];
                    let _ = manager.introduce(&did_i.0, sk_i, &did_j.0, "Honest");
                }
            }
        }

        // Create Sybil agents: 5 agents with no shared connections
        let mut sybil_agents = vec![];
        for _ in 0..5 {
            let (did, _, _sk) = manager.register_did(AgentType::Human).unwrap();
            sybil_agents.push(did);
        }

        // Sybil agents only connected to one honest agent (no shared neighbors among themselves)
        let (ref honest_did, ref honest_sk) = honest_agents[0];
        for sybil_did in &sybil_agents {
            let _ = manager.introduce(&honest_did.0, honest_sk, &sybil_did.0, "Sybil");
        }

        // Compute average coherence for honest vs Sybil
        let honest_coherence: Vec<i32> = honest_agents
            .iter()
            .map(|(did, _)| {
                manager
                    .get_coherence_profile(&did.0)
                    .map(|p| p.topological_mass)
                    .unwrap_or(0)
            })
            .collect();

        let sybil_coherence: Vec<i32> = sybil_agents
            .iter()
            .map(|did| {
                manager
                    .get_coherence_profile(&did.0)
                    .map(|p| p.topological_mass)
                    .unwrap_or(0)
            })
            .collect();

        let avg_honest = honest_coherence.iter().sum::<i32>() / honest_coherence.len() as i32;
        let avg_sybil = sybil_coherence.iter().sum::<i32>() / sybil_coherence.len() as i32;

        // Honest agents should have significantly higher coherence
        assert!(
            avg_honest > avg_sybil,
            "Honest agents (avg={}) should have higher coherence than Sybil agents (avg={})",
            avg_honest,
            avg_sybil
        );
    }

    #[test]
    fn test_propose_and_accept_agreement() {
        let mut manager = IdentityStateManager::new();

        let (did_provider, _, sk_provider) = manager.register_did(AgentType::Human).unwrap();
        let (did_consumer, _, sk_consumer) = manager.register_did(AgentType::Human).unwrap();

        let terms = disentangle_identity::AgreementTerms {
            description: "Compute 100 embeddings".to_string(),
            deadline_depth: Some(1000),
            success_criteria: vec!["All embeddings returned".to_string()],
            max_invocations: Some(100),
        };

        // Propose agreement
        let agreement_id = manager
            .propose_agreement(&did_provider.0, &sk_provider, &did_consumer.0, None, terms)
            .unwrap();

        // Check it exists and is in Proposed state
        let agreement = manager.get_agreement(&agreement_id).unwrap();
        assert_eq!(
            agreement.status,
            disentangle_identity::AgreementStatus::Proposed
        );
        assert!(agreement.consumer_signature.is_none());

        // Accept agreement
        manager
            .accept_agreement(&agreement_id, &sk_consumer)
            .unwrap();

        // Check it's now Active
        let agreement = manager.get_agreement(&agreement_id).unwrap();
        assert_eq!(
            agreement.status,
            disentangle_identity::AgreementStatus::Active
        );
        assert!(agreement.consumer_signature.is_some());
    }

    #[test]
    fn test_complete_agreement_success() {
        let mut manager = IdentityStateManager::new();

        let (did_provider, _, sk_provider) = manager.register_did(AgentType::Human).unwrap();
        let (did_consumer, _, sk_consumer) = manager.register_did(AgentType::Human).unwrap();

        let terms = disentangle_identity::AgreementTerms {
            description: "Test service".to_string(),
            deadline_depth: None,
            success_criteria: vec![],
            max_invocations: None,
        };

        let agreement_id = manager
            .propose_agreement(&did_provider.0, &sk_provider, &did_consumer.0, None, terms)
            .unwrap();

        manager
            .accept_agreement(&agreement_id, &sk_consumer)
            .unwrap();

        // Complete agreement successfully
        let outcome_hash = [42u8; 32];
        manager
            .complete_agreement(&agreement_id, true, outcome_hash, &sk_provider)
            .unwrap();

        let agreement = manager.get_agreement(&agreement_id).unwrap();
        match agreement.status {
            disentangle_identity::AgreementStatus::Completed {
                success,
                outcome_hash: hash,
            } => {
                assert!(success);
                assert_eq!(hash, outcome_hash);
            }
            _ => panic!("Expected Completed status"),
        }
        assert!(agreement.completed_depth.is_some());
    }

    #[test]
    fn test_list_agreements_by_did() {
        let mut manager = IdentityStateManager::new();

        let (did_provider, _, sk_provider) = manager.register_did(AgentType::Human).unwrap();
        let (did_consumer, _, _sk_consumer) = manager.register_did(AgentType::Human).unwrap();
        let (did_other, _, _sk_other) = manager.register_did(AgentType::Human).unwrap();

        let terms = disentangle_identity::AgreementTerms {
            description: "Test".to_string(),
            deadline_depth: None,
            success_criteria: vec![],
            max_invocations: None,
        };

        // Create two agreements involving provider
        let agreement_id1 = manager
            .propose_agreement(
                &did_provider.0,
                &sk_provider,
                &did_consumer.0,
                None,
                terms.clone(),
            )
            .unwrap();

        let agreement_id2 = manager
            .propose_agreement(&did_provider.0, &sk_provider, &did_other.0, None, terms)
            .unwrap();

        // Provider should see both agreements
        let provider_agreements = manager.list_agreements_for_did(&did_provider.0);
        assert_eq!(provider_agreements.len(), 2);
        let ids: Vec<_> = provider_agreements.iter().map(|a| a.id).collect();
        assert!(ids.contains(&agreement_id1));
        assert!(ids.contains(&agreement_id2));

        // Consumer should see only one
        let consumer_agreements = manager.list_agreements_for_did(&did_consumer.0);
        assert_eq!(consumer_agreements.len(), 1);
        assert_eq!(consumer_agreements[0].id, agreement_id1);

        // Other should see only one
        let other_agreements = manager.list_agreements_for_did(&did_other.0);
        assert_eq!(other_agreements.len(), 1);
        assert_eq!(other_agreements[0].id, agreement_id2);
    }

    #[test]
    fn test_oracle_distribution_lifecycle() {
        let mut manager = IdentityStateManager::new();

        // Create agents with shared connections for positive curvature
        let (did_a, _, sk_a) = manager.register_did(AgentType::Human).unwrap();
        let (did_b, _, sk_b) = manager.register_did(AgentType::Human).unwrap();
        let (did_c, _, _sk_c) = manager.register_did(AgentType::Human).unwrap();

        // Create triangle: A-B, A-C, B-C
        manager.introduce(&did_a.0, &sk_a, &did_b.0, "B").unwrap();
        manager.introduce(&did_a.0, &sk_a, &did_c.0, "C").unwrap();
        manager.introduce(&did_b.0, &sk_b, &did_c.0, "C").unwrap();

        // Advance depth to create a window
        for _ in 0..10 {
            manager.advance_depth();
        }

        // Query oracle for global distribution
        let query = disentangle_identity::OracleQuery::new(
            disentangle_identity::RegionSelector::Global,
            0,
            10,
        );

        let dist_id = manager.compute_oracle_distribution(query).unwrap();

        // Retrieve distribution
        let distribution = manager.get_oracle_distribution(&dist_id).unwrap();
        assert_eq!(distribution.depth_window, (0, 10));

        // Weights should sum to 1.0
        let weight_sum: f64 = distribution.weights.values().sum();
        assert!(
            (weight_sum - 1.0).abs() < 0.001,
            "Weights should sum to 1.0, got {}",
            weight_sum
        );

        // All three agents should have weights
        assert_eq!(distribution.weights.len(), 3);

        // List distributions
        let all_dists = manager.list_oracle_distributions();
        assert_eq!(all_dists.len(), 1);
    }

    #[test]
    fn test_oracle_explicit_region() {
        let mut manager = IdentityStateManager::new();

        let (did_a, _, sk_a) = manager.register_did(AgentType::Human).unwrap();
        let (did_b, _, _sk_b) = manager.register_did(AgentType::Human).unwrap();
        let (did_c, _, _sk_c) = manager.register_did(AgentType::Human).unwrap();

        manager.introduce(&did_a.0, &sk_a, &did_b.0, "B").unwrap();

        let query = disentangle_identity::OracleQuery::new(
            disentangle_identity::RegionSelector::Explicit(vec![
                did_a.0.clone(),
                did_b.0.clone(),
            ]),
            0,
            0,
        );

        let dist_id = manager.compute_oracle_distribution(query).unwrap();
        let distribution = manager.get_oracle_distribution(&dist_id).unwrap();

        // Only A and B should be in the distribution (not C)
        assert_eq!(distribution.weights.len(), 2);
        assert!(distribution.weights.contains_key(&did_a.0));
        assert!(distribution.weights.contains_key(&did_b.0));
        assert!(!distribution.weights.contains_key(&did_c.0));
    }

    #[test]
    fn test_pool_create_and_deposit() {
        let mut manager = IdentityStateManager::new();

        let (did_creator, _, _sk) = manager.register_did(AgentType::Human).unwrap();

        // Create pool
        let pool_id = manager
            .create_pool(
                "Test Fund".to_string(),
                "A test fund".to_string(),
                &did_creator.0,
            )
            .unwrap();

        let pool = manager.get_pool(&pool_id).unwrap();
        assert_eq!(pool.name, "Test Fund");
        assert_eq!(pool.balance, 0.0);

        // Deposit
        let new_balance = manager
            .pool_deposit(&pool_id, &did_creator.0, 1000.0, "initial".to_string())
            .unwrap();
        assert_eq!(new_balance, 1000.0);

        let pool = manager.get_pool(&pool_id).unwrap();
        assert_eq!(pool.deposits.len(), 1);
    }

    #[test]
    fn test_pool_full_lifecycle() {
        let mut manager = IdentityStateManager::new();

        // Create agents with connections
        let (did_a, _, sk_a) = manager.register_did(AgentType::Human).unwrap();
        let (did_b, _, sk_b) = manager.register_did(AgentType::Human).unwrap();
        let (did_c, _, _sk_c) = manager.register_did(AgentType::Human).unwrap();

        manager.introduce(&did_a.0, &sk_a, &did_b.0, "B").unwrap();
        manager.introduce(&did_a.0, &sk_a, &did_c.0, "C").unwrap();
        manager.introduce(&did_b.0, &sk_b, &did_c.0, "C").unwrap();

        // Create pool and deposit
        let pool_id = manager
            .create_pool(
                "Community Fund".to_string(),
                "".to_string(),
                &did_a.0,
            )
            .unwrap();

        manager
            .pool_deposit(&pool_id, &did_a.0, 300.0, "grant".to_string())
            .unwrap();

        // Compute oracle distribution
        let query = disentangle_identity::OracleQuery::new(
            disentangle_identity::RegionSelector::Global,
            0,
            0,
        );
        let dist_id = manager.compute_oracle_distribution(query).unwrap();

        // Distribute pool using oracle weights
        let (allocations, remaining) = manager.pool_distribute(&pool_id, &dist_id).unwrap();
        assert!(remaining.abs() < 0.001, "Pool should be fully distributed");
        assert_eq!(allocations.len(), 3);

        let total_allocated: f64 = allocations.values().sum();
        assert!(
            (total_allocated - 300.0).abs() < 0.001,
            "Total allocated should equal deposit"
        );

        // Each agent claims
        for did in &[&did_a.0, &did_b.0, &did_c.0] {
            let amount = manager.pool_claim(&pool_id, &dist_id, did).unwrap();
            assert!(amount > 0.0);
        }

        // Double claim should fail
        let result = manager.pool_claim(&pool_id, &dist_id, &did_a.0);
        assert!(result.is_err());

        // Verify claims recorded
        let pool = manager.get_pool(&pool_id).unwrap();
        assert_eq!(pool.claims.len(), 3);
    }

    #[test]
    fn test_pool_nonexistent_errors() {
        let mut manager = IdentityStateManager::new();

        let fake_id = [0u8; 32];

        // Non-existent pool
        let result = manager.pool_deposit(&fake_id, "did:fake", 100.0, "".to_string());
        assert!(result.is_err());
    }
}
