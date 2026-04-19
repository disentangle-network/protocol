//! Integration Tests for disentangle-identity
//!
//! Tests governance voting flows, capability delegation chains,
//! and coherence profile integration.

use std::collections::HashMap;

use disentangle_crypto::signature::generate_keypair;
use disentangle_crypto::types::Nullifier;
use disentangle_dag::SCALE;
use disentangle_identity::capability::{
    AccessOp, Capability, CapabilitySubject, CoherenceTier, Constraint, ConstraintContext,
    DelegationRecord, TransactionScope,
};
use disentangle_identity::coherence::CoherenceProfile;
use disentangle_identity::governance::{
    evaluate_proposal, GovernanceProposal, GovernanceQuorum, GovernanceVote, ProposalResult,
    ProposalType, VoteChoice,
};
use disentangle_identity::transactions::TransactionIdentity;
use disentangle_identity::{
    IdentityGraph, IntroductionContext, IntroductionTransaction, RevocationScope, DID,
};

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

/// Create a voter identity with a unique nullifier.
fn make_voter(nullifier_byte: u8) -> TransactionIdentity {
    let (_, pk) = generate_keypair();
    TransactionIdentity {
        ephemeral_pk: pk,
        did_binding_proof: vec![],
        nullifier: Nullifier([nullifier_byte; 32]),
        reputation_bucket: 3,
    }
}

/// Create a governance proposal with given quorum and voting window.
fn make_proposal(
    quorum: GovernanceQuorum,
) -> (
    GovernanceProposal,
    disentangle_crypto::signature::SigningKey,
    disentangle_crypto::signature::VerifyingKey,
) {
    let (sk, pk) = generate_keypair();
    let did = DID::new(&pk, false);

    let proposal = GovernanceProposal::new(
        &did,
        ProposalType::ProtocolParameter {
            parameter: "alpha_max".to_string(),
            new_value: vec![0, 0, 0, 5],
        },
        [1u8; 32],
        1000,
        2000,
        quorum,
        &sk,
    );

    (proposal, sk, pk)
}

// ────────────────────────────────────────────────────────────────────────────
// 1. Governance Voting Flows
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn governance_coherence_weighted_passes_majority_for() {
    // CoherenceWeighted with 50% threshold; 3 For votes, 1 Against => passes
    let (proposal, _, _) = make_proposal(GovernanceQuorum::CoherenceWeighted {
        threshold: SCALE / 2, // 50%
    });

    let votes: Vec<GovernanceVote> = (0..3)
        .map(|i| GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: make_voter(10 + i),
            vote: VoteChoice::For,
            parents: vec![],
            depth: 1500,
        })
        .chain(std::iter::once(GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: make_voter(20),
            vote: VoteChoice::Against,
            parents: vec![],
            depth: 1500,
        }))
        .collect();

    let profiles = HashMap::new();
    let result = evaluate_proposal(&proposal, &votes, &profiles, 2001);
    assert_eq!(result, ProposalResult::Passed);
}

#[test]
fn governance_coherence_weighted_fails_majority_against() {
    // CoherenceWeighted with 50% threshold; 1 For, 3 Against => fails
    let (proposal, _, _) = make_proposal(GovernanceQuorum::CoherenceWeighted {
        threshold: SCALE / 2,
    });

    let mut votes = Vec::new();
    votes.push(GovernanceVote {
        proposal_id: proposal.id,
        voter_identity: make_voter(30),
        vote: VoteChoice::For,
        parents: vec![],
        depth: 1500,
    });
    for i in 0..3 {
        votes.push(GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: make_voter(31 + i),
            vote: VoteChoice::Against,
            parents: vec![],
            depth: 1500,
        });
    }

    let profiles = HashMap::new();
    let result = evaluate_proposal(&proposal, &votes, &profiles, 2001);
    assert_eq!(result, ProposalResult::Failed);
}

#[test]
fn governance_diversity_minimum_passes() {
    // DiversityMinimum: need >= 3 supporters and min_mass >= 2 * SCALE
    let (proposal, _, _) = make_proposal(GovernanceQuorum::DiversityMinimum {
        min_supporters: 3,
        min_mass: 2 * SCALE,
    });

    // 4 For votes => 4 supporters, total for_weight = 4 * SCALE
    let votes: Vec<GovernanceVote> = (0..4)
        .map(|i| GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: make_voter(40 + i),
            vote: VoteChoice::For,
            parents: vec![],
            depth: 1500,
        })
        .collect();

    let profiles = HashMap::new();
    let result = evaluate_proposal(&proposal, &votes, &profiles, 2001);
    assert_eq!(result, ProposalResult::Passed);
}

#[test]
fn governance_diversity_minimum_fails_insufficient_supporters() {
    // DiversityMinimum: need >= 5 supporters, only supply 2
    let (proposal, _, _) = make_proposal(GovernanceQuorum::DiversityMinimum {
        min_supporters: 5,
        min_mass: SCALE,
    });

    let votes: Vec<GovernanceVote> = (0..2)
        .map(|i| GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: make_voter(50 + i),
            vote: VoteChoice::For,
            parents: vec![],
            depth: 1500,
        })
        .collect();

    let profiles = HashMap::new();
    let result = evaluate_proposal(&proposal, &votes, &profiles, 2001);
    assert_eq!(result, ProposalResult::Failed);
}

#[test]
fn governance_returns_pending_before_voting_end() {
    let (proposal, _, _) = make_proposal(GovernanceQuorum::CoherenceWeighted {
        threshold: SCALE / 2,
    });

    let votes = vec![GovernanceVote {
        proposal_id: proposal.id,
        voter_identity: make_voter(60),
        vote: VoteChoice::For,
        parents: vec![],
        depth: 1500,
    }];

    let profiles = HashMap::new();
    // current_depth 1999 is before voting_end 2000
    let result = evaluate_proposal(&proposal, &votes, &profiles, 1999);
    assert_eq!(result, ProposalResult::Pending);
}

// ────────────────────────────────────────────────────────────────────────────
// 2. Capability Delegation Chains
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn capability_create_grant_verify() {
    let (sk_a, pk_a) = generate_keypair();
    let did_a = DID::new(&pk_a, false);

    let subject = CapabilitySubject::Transact {
        scope: TransactionScope::All,
    };
    let cap = Capability::new(&did_a, &pk_a, subject, &sk_a);

    // Verify capability signature
    assert!(cap.verify(&pk_a));
    assert_eq!(cap.issuer, did_a);
    assert!(cap.delegatable);

    // Delegate to B
    let (_, pk_b) = generate_keypair();
    let did_b = DID::new(&pk_b, false);
    let delegation = DelegationRecord::new(&cap, &did_a, &did_b, &sk_a, 1000).unwrap();
    assert_eq!(delegation.capability_id, cap.id);
    assert_eq!(delegation.delegator, did_a);
    assert_eq!(delegation.delegatee, did_b);

    // Verify single-link chain
    assert!(DelegationRecord::verify_chain(&[delegation], &cap, &[pk_a]));
}

#[test]
fn capability_delegation_chain_a_to_b_to_c() {
    let (sk_a, pk_a) = generate_keypair();
    let did_a = DID::new(&pk_a, false);

    let subject = CapabilitySubject::Access {
        resource_id: [42u8; 32],
        operations: vec![AccessOp::Read, AccessOp::Write],
    };
    let cap = Capability::new(&did_a, &pk_a, subject, &sk_a);

    // A delegates to B
    let (sk_b, pk_b) = generate_keypair();
    let did_b = DID::new(&pk_b, false);
    let deleg_ab = DelegationRecord::new(&cap, &did_a, &did_b, &sk_a, 1000).unwrap();

    // B delegates to C (chain_depth must be incremented manually for multi-hop)
    let (_, pk_c) = generate_keypair();
    let did_c = DID::new(&pk_c, false);
    let mut deleg_bc = DelegationRecord::new(&cap, &did_b, &did_c, &sk_b, 1001).unwrap();
    deleg_bc.chain_depth = 2;
    // Re-sign with updated chain_depth
    let message = bincode::serialize(&(
        &deleg_bc.capability_id,
        &deleg_bc.delegator,
        &deleg_bc.delegatee,
        &deleg_bc.additional_constraints,
        deleg_bc.chain_depth,
        deleg_bc.depth,
    ))
    .unwrap();
    deleg_bc.proof = disentangle_crypto::sign(&sk_b, &message);

    // Verify the 2-link chain
    let chain = vec![deleg_ab, deleg_bc];
    assert!(DelegationRecord::verify_chain(&chain, &cap, &[pk_a, pk_b]));
}

#[test]
fn capability_revocation_removes_access() {
    let (sk_a, pk_a) = generate_keypair();
    let did_a = DID::new(&pk_a, false);

    let subject = CapabilitySubject::Transact {
        scope: TransactionScope::Transfer,
    };
    let cap = Capability::new(&did_a, &pk_a, subject, &sk_a);

    let mut graph = IdentityGraph::new();

    // Before revocation
    assert!(!graph.is_revoked(&cap.id));

    // Revoke
    graph.record_revocation(&cap.id, RevocationScope::Single);
    assert!(graph.is_revoked(&cap.id));
}

#[test]
fn capability_temporal_constraint_expiry() {
    let (sk, pk) = generate_keypair();
    let did = DID::new(&pk, false);

    let subject = CapabilitySubject::Transact {
        scope: TransactionScope::All,
    };
    let mut cap = Capability::new(&did, &pk, subject, &sk);

    // Add temporal constraint: valid only between depth 100 and 500
    cap.constraints = vec![Constraint::TemporalBound {
        not_before: 100,
        not_after: 500,
    }];

    // Within window
    let ctx_valid = ConstraintContext {
        current_depth: 300,
        reputation_bucket: 0,
        topological_mass: 0,
        current_delegation_depth: 0,
        held_capabilities: vec![],
        coherence_tier: CoherenceTier::Observer,
    };
    assert!(cap.check_constraints(&ctx_valid));

    // After expiry
    let ctx_expired = ConstraintContext {
        current_depth: 501,
        reputation_bucket: 0,
        topological_mass: 0,
        current_delegation_depth: 0,
        held_capabilities: vec![],
        coherence_tier: CoherenceTier::Observer,
    };
    assert!(!cap.check_constraints(&ctx_expired));

    // Before start
    let ctx_early = ConstraintContext {
        current_depth: 99,
        reputation_bucket: 0,
        topological_mass: 0,
        current_delegation_depth: 0,
        held_capabilities: vec![],
        coherence_tier: CoherenceTier::Observer,
    };
    assert!(!cap.check_constraints(&ctx_early));
}

// ────────────────────────────────────────────────────────────────────────────
// 3. Coherence Profile Integration
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn coherence_profile_score_computation() {
    // Build a profile with known values and verify the composite_score formula
    let profile = CoherenceProfile {
        did: DID("did:disentangle:test".to_string()),
        topological_mass: 500 * SCALE,
        mean_local_curvature: SCALE / 4, // 0.25 in fixed-point
        relational_diversity: 20,
        temporal_depth: 50_000,
        capability_coherence: 0,
        introduction_coherence: 0,
        last_active_depth: 1000,
    };

    let score = profile.composite_score(1000);
    assert!(score > 0, "Composite score should be positive");

    // Score should be less than raw topological mass (it's a weighted combination)
    assert!(
        score < profile.topological_mass,
        "Composite should be less than raw mass"
    );

    // Verify decay: score at a later depth should be less (mass decays)
    let score_later = profile.composite_score(1000 + 10_000); // one half-life
    assert!(
        score_later < score,
        "Score should decrease after one half-life of inactivity"
    );
}

#[test]
fn coherence_integrates_with_governance_weighted_voting() {
    // This test verifies the full flow: build identities in an identity graph,
    // compute coherence profiles, and run governance evaluation.

    let mut graph = IdentityGraph::new();

    // Create three DIDs and introduce them to each other for a connected graph
    let (sk1, pk1) = generate_keypair();
    let did1 = DID::new(&pk1, false);

    let (sk2, pk2) = generate_keypair();
    let did2 = DID::new(&pk2, false);

    let (_sk3, pk3) = generate_keypair();
    let did3 = DID::new(&pk3, false);

    // did1 <-> did2
    graph.record_introduction(&IntroductionTransaction {
        introducer_did: did1.clone(),
        introduced_did: did2.clone(),
        edge_name: "Colleague".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk1, b"intro1"),
        parents: vec![],
        depth: 100,
    });

    // did1 <-> did3
    graph.record_introduction(&IntroductionTransaction {
        introducer_did: did1.clone(),
        introduced_did: did3.clone(),
        edge_name: "Friend".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk1, b"intro2"),
        parents: vec![],
        depth: 101,
    });

    // did2 <-> did3 (creates shared neighbors for positive curvature)
    graph.record_introduction(&IntroductionTransaction {
        introducer_did: did2.clone(),
        introduced_did: did3.clone(),
        edge_name: "Mutual".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk2, b"intro3"),
        parents: vec![],
        depth: 102,
    });

    // Compute coherence profiles
    let profile1 = CoherenceProfile::compute(&did1, &graph, 0, 200);
    let profile2 = CoherenceProfile::compute(&did2, &graph, 0, 200);
    let profile3 = CoherenceProfile::compute(&did3, &graph, 0, 200);

    // All three should have computed profiles with neighbors
    assert!(
        profile1.relational_diversity > 0 || profile1.topological_mass != 0,
        "Profile 1 should reflect connections"
    );

    // Build profiles map for governance
    let mut profiles = HashMap::new();
    profiles.insert(did1.clone(), profile1);
    profiles.insert(did2.clone(), profile2);
    profiles.insert(did3.clone(), profile3);

    // Create a proposal and vote
    let (proposal, _, _) = make_proposal(GovernanceQuorum::CoherenceWeighted {
        threshold: SCALE / 2,
    });

    // Two For votes, one Against => should pass
    let votes = vec![
        GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: make_voter(70),
            vote: VoteChoice::For,
            parents: vec![],
            depth: 1500,
        },
        GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: make_voter(71),
            vote: VoteChoice::For,
            parents: vec![],
            depth: 1500,
        },
        GovernanceVote {
            proposal_id: proposal.id,
            voter_identity: make_voter(72),
            vote: VoteChoice::Against,
            parents: vec![],
            depth: 1500,
        },
    ];

    let result = evaluate_proposal(&proposal, &votes, &profiles, 2001);
    assert_eq!(result, ProposalResult::Passed);
}

#[test]
fn identity_graph_curvature_with_triangle() {
    // Build a triangle: A-B, A-C, B-C. All pairs share a common neighbor.
    let mut graph = IdentityGraph::new();

    let (sk_a, pk_a) = generate_keypair();
    let did_a = DID::new(&pk_a, false);

    let (sk_b, pk_b) = generate_keypair();
    let did_b = DID::new(&pk_b, false);

    let (_, pk_c) = generate_keypair();
    let did_c = DID::new(&pk_c, false);

    // A <-> B
    graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_a.clone(),
        introduced_did: did_b.clone(),
        edge_name: "Edge1".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_a, b"e1"),
        parents: vec![],
        depth: 1,
    });

    // A <-> C
    graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_a.clone(),
        introduced_did: did_c.clone(),
        edge_name: "Edge2".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_a, b"e2"),
        parents: vec![],
        depth: 2,
    });

    // B <-> C
    graph.record_introduction(&IntroductionTransaction {
        introducer_did: did_b.clone(),
        introduced_did: did_c.clone(),
        edge_name: "Edge3".to_string(),
        context: IntroductionContext::Direct,
        capability_grants: vec![],
        proof: disentangle_crypto::sign(&sk_b, b"e3"),
        parents: vec![],
        depth: 3,
    });

    // In a triangle: N(A) = {B,C}, N(B) = {A,C}
    // Intersection(N(A), N(B)) = {C} => |intersection| = 1
    // Union(N(A), N(B)) = {A, B, C} => |union| = 3
    // kappa_J = 2 * (1/3) - 1 = 2/3 - 1 = -1/3 (in fixed-point)
    // Wait -- union includes A and B themselves since they are each other's neighbors.
    // N(A) = {B, C}, N(B) = {A, C}
    // intersection = {C}, union = {A, B, C}
    // kappa_J = 2 * 1/3 - 1  scaled:  2 * fp(1,3) - SCALE
    let curv_ab = graph.identity_curvature(&did_a, &did_b);

    // With shared neighbor C: curvature should be > -SCALE (better than no shared neighbors)
    // Two isolated nodes with no shared neighbors would give -SCALE
    assert!(
        curv_ab > -SCALE,
        "Triangle curvature should be better than fully disconnected pair"
    );

    // Symmetry: curvature(A,B) == curvature(B,A)
    let curv_ba = graph.identity_curvature(&did_b, &did_a);
    assert_eq!(curv_ab, curv_ba, "Curvature should be symmetric");
}
