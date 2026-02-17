#[cfg(test)]
mod tests {
    use disentangle_identity::{AgentType, ProposalType, VoteChoice};
    use disentangle_node::identity_state::IdentityStateManager;
    use std::path::Path;

    #[test]
    fn test_introduction_chain_pathfinding() {
        let mut mgr = IdentityStateManager::new();

        // Create three DIDs
        let (did_a, _, sk_a) = mgr.register_did(AgentType::Human).unwrap();
        let (did_b, _, sk_b) = mgr.register_did(AgentType::Human).unwrap();
        let (did_c, _, _sk_c) = mgr.register_did(AgentType::Human).unwrap();

        // Create introduction chain: A -> B -> C
        mgr.introduce(&did_a.0, &sk_a, &did_b.0, "Friend").unwrap();
        mgr.introduce(&did_b.0, &sk_b, &did_c.0, "FriendOfFriend")
            .unwrap();

        // Test pathfinding
        let chain = mgr.get_introduction_chain(&did_a.0, &did_c.0);
        assert!(chain.is_some());
        let chain = chain.unwrap();
        assert_eq!(chain.len(), 3); // [A, B, C]
        assert_eq!(chain[0], did_a.0);
        assert_eq!(chain[1], did_b.0);
        assert_eq!(chain[2], did_c.0);

        // Test direct connection
        let direct = mgr.get_introduction_chain(&did_a.0, &did_b.0);
        assert!(direct.is_some());
        assert_eq!(direct.unwrap().len(), 2); // [A, B]
    }

    #[test]
    fn test_governance_proposal_and_voting() {
        let mut mgr = IdentityStateManager::new();

        // Register DIDs
        let (proposer_did, _, proposer_sk) = mgr.register_did(AgentType::Human).unwrap();
        let (voter_did, _, voter_sk) = mgr.register_did(AgentType::Human).unwrap();

        // Create proposal
        let proposal_type = ProposalType::ProtocolParameter {
            parameter: "alpha_max".to_string(),
            new_value: vec![0, 0, 0, 5],
        };

        let proposal = mgr
            .create_proposal(
                &proposer_did.0,
                &proposer_sk,
                proposal_type,
                "Increase alpha_max to 5",
                100, // duration_blocks
            )
            .unwrap();

        // Cast vote
        let vote = mgr
            .cast_vote(&proposal.id, &voter_did.0, &voter_sk, VoteChoice::For)
            .unwrap();

        assert_eq!(vote.vote, VoteChoice::For);
        assert_eq!(vote.proposal_id, proposal.id);

        // List proposals
        let proposals = mgr.list_proposals();
        assert_eq!(proposals.len(), 1);

        // Get proposal
        let retrieved = mgr.get_proposal(&proposal.id);
        assert!(retrieved.is_some());

        // Evaluate (should be pending since we haven't advanced blocks)
        let result = mgr.evaluate_proposal(&proposal.id);
        assert!(result.is_some());
    }

    #[test]
    fn test_state_persistence() {
        let temp_path = Path::new("/tmp/test_disentangle_state.json");

        // Clean up if exists
        let _ = std::fs::remove_file(temp_path);

        // Create state and save
        {
            let mut mgr = IdentityStateManager::new();

            let (did_a, _, sk_a) = mgr.register_did(AgentType::Human).unwrap();
            let (did_b, _, _sk_b) = mgr.register_did(AgentType::Human).unwrap();

            mgr.introduce(&did_a.0, &sk_a, &did_b.0, "Friend").unwrap();
            mgr.set_petname("Alice", &did_a.0).unwrap();

            mgr.save_to_file(temp_path).unwrap();
        }

        // Load state and verify
        {
            let loaded = IdentityStateManager::load_from_file(temp_path).unwrap();

            let dids = loaded.list_dids();
            assert_eq!(dids.len(), 2);

            // Petnames are not persisted (local-first)
            // but DIDs and introductions should be

            // Verify introduction chain exists
            let chain = loaded
                .get_introduction_chain(&dids[0], &dids[1])
                .or_else(|| loaded.get_introduction_chain(&dids[1], &dids[0]));
            assert!(chain.is_some());
        }

        // Clean up
        let _ = std::fs::remove_file(temp_path);
    }
}
