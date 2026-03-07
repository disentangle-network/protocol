#[cfg(test)]
mod tests {
    use disentangle_identity::{
        AgentType, CapabilitySubject, ProposalType, TransactionScope, VoteChoice,
    };
    use disentangle_node::identity_state::IdentityStateManager;
    use std::path::Path;
    use tempfile::TempDir;

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

    #[test]
    fn save_creates_parent_directories() {
        let tmp = TempDir::new().unwrap();
        let nested_path = tmp.path().join("deep").join("nested").join("state.json");

        let mut mgr = IdentityStateManager::new();
        let (_did, _, _sk) = mgr.register_did(AgentType::Human).unwrap();

        // Should succeed even though deep/nested/ doesn't exist
        mgr.save_to_file(&nested_path).unwrap();
        assert!(nested_path.exists());

        // Should load back
        let loaded = IdentityStateManager::load_from_file(&nested_path).unwrap();
        assert_eq!(loaded.list_dids().len(), 1);
    }

    #[test]
    fn load_nonexistent_file_returns_persistence_error() {
        let result = IdentityStateManager::load_from_file(Path::new(
            "/tmp/nonexistent_disentangle_state_12345.json",
        ));
        assert!(result.is_err());
        // Should be PersistenceError, not DIDNotFound
        let err = match result {
            Err(e) => format!("{}", e),
            Ok(_) => panic!("expected error"),
        };
        assert!(err.contains("persistence error"));
    }

    #[test]
    fn load_corrupt_file_returns_persistence_error() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("corrupt.json");
        std::fs::write(&path, "this is not valid json {{{").unwrap();

        let result = IdentityStateManager::load_from_file(&path);
        assert!(result.is_err());
        let err = match result {
            Err(e) => format!("{}", e),
            Ok(_) => panic!("expected error"),
        };
        assert!(err.contains("persistence error"));
    }

    #[test]
    fn save_atomic_no_partial_files_on_success() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state.json");

        let mut mgr = IdentityStateManager::new();
        mgr.register_did(AgentType::Human).unwrap();
        mgr.save_to_file(&path).unwrap();

        // After successful save, no .tmp file should remain
        let tmp_path = tmp.path().join("state.json.tmp");
        assert!(!tmp_path.exists());
        // But the real file should exist
        assert!(path.exists());
    }

    #[test]
    fn round_trip_preserves_full_state() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("full_state.json");

        let mut mgr = IdentityStateManager::new();

        // Create two DIDs
        let (did_a, _, sk_a) = mgr.register_did(AgentType::Human).unwrap();
        let (did_b, _, _sk_b) = mgr
            .register_did(AgentType::AGI {
                runtime_attestation: None,
            })
            .unwrap();

        // Create an introduction
        mgr.introduce(&did_a.0, &sk_a, &did_b.0, "colleague")
            .unwrap();

        // Grant a capability
        let cap = mgr
            .create_capability(
                &did_a.0,
                &sk_a,
                CapabilitySubject::Transact {
                    scope: TransactionScope::All,
                },
                vec![],
                false,
            )
            .unwrap();

        // Save
        mgr.save_to_file(&path).unwrap();

        // Load and verify
        let loaded = IdentityStateManager::load_from_file(&path).unwrap();
        assert_eq!(loaded.list_dids().len(), 2);
        assert!(loaded.get_capability(&cap.id).is_some());

        let chain = loaded
            .get_introduction_chain(&did_a.0, &did_b.0)
            .or_else(|| loaded.get_introduction_chain(&did_b.0, &did_a.0));
        assert!(chain.is_some());
    }
}
