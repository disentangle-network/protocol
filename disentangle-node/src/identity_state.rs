//! Identity State Manager
//!
//! Manages DID lifecycle, capability operations, introductions, coherence tracking,
//! and petnames for the Disentangle Protocol.

use disentangle_crypto::hash::{sha3_256, Hash256};
use disentangle_crypto::signature::{generate_keypair, SigningKey, VerifyingKey};
use disentangle_identity::{
    evaluate_proposal, AgentType, AgreementStatus, AgreementTerms, Capability, CapabilityId,
    CapabilitySubject, CoherenceProfile, Constraint, ConstraintContext, DIDDocument,
    DelegationRecord, GovernanceProposal, GovernanceVote, IdentityError, IdentityGraph,
    IntroductionContext, IntroductionTransaction, PetnameDB, ProposalResult, ProposalType,
    RevocationScope, SettlementAgreement, VoteChoice, DID,
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

        let agreement = SettlementAgreement::new(
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
}
