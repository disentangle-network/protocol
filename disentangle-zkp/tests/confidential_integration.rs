//! Integration tests for Phase 4: Confidential Transactions

use disentangle_crypto::kem::generate_kem_keypair;
use disentangle_zkp::stealth::generate_stealth_address;
use disentangle_zkp::{AmountCommitment, BalanceWitness, ConfidentialOutput, RangeWitness};
use p3_matrix::Matrix;

#[test]
fn test_full_confidential_transaction_flow() {
    // Setup: Alice and Bob generate KEM keypairs for stealth addresses
    let (alice_ek, alice_dk) = generate_kem_keypair();
    let (bob_ek, bob_dk) = generate_kem_keypair();

    // Transaction inputs (Alice's UTXOs)
    let input1_amount = 1000u64;
    let input1_blinding = [42u8; 32];
    let input2_amount = 500u64;
    let input2_blinding = [43u8; 32];

    // Transaction outputs
    let output1_amount = 800u64; // To Bob
    let output1_blinding = [44u8; 32];
    let output2_amount = 700u64; // Change back to Alice
    let output2_blinding = [45u8; 32];

    // Step 1: Create commitments for inputs
    let _input1_commitment = AmountCommitment::commit(input1_amount, &input1_blinding);
    let _input2_commitment = AmountCommitment::commit(input2_amount, &input2_blinding);

    // Step 2: Create commitments for outputs
    let _output1_commitment = AmountCommitment::commit(output1_amount, &output1_blinding);
    let _output2_commitment = AmountCommitment::commit(output2_amount, &output2_blinding);

    // Step 3: Generate balance proof witness
    let inputs = vec![
        (input1_amount, input1_blinding),
        (input2_amount, input2_blinding),
    ];
    let outputs = vec![
        (output1_amount, output1_blinding),
        (output2_amount, output2_blinding),
    ];

    let balance_witness = BalanceWitness::new(inputs.clone(), outputs.clone());
    assert!(balance_witness.is_some(), "Balance should be conserved");

    let balance_witness = balance_witness.unwrap();
    let balance_trace = balance_witness.generate_trace();
    assert_eq!(balance_trace.height(), 1);
    assert_eq!(balance_trace.width(), 20); // MAX_IO_COUNT * 2 + 4

    // Step 4: Generate range proofs for each output
    let range_proof_1 = RangeWitness::new(output1_amount);
    let range_trace_1 = range_proof_1.generate_trace();
    assert_eq!(range_trace_1.width(), 66); // RANGE_BITS + 2

    let range_proof_2 = RangeWitness::new(output2_amount);
    let range_trace_2 = range_proof_2.generate_trace();
    assert_eq!(range_trace_2.width(), 66);

    // Step 5: Create confidential outputs with stealth addresses
    let conf_output_to_bob = ConfidentialOutput::new(output1_amount, output1_blinding, &bob_ek);

    let conf_output_to_alice = ConfidentialOutput::new(output2_amount, output2_blinding, &alice_ek);

    // Step 6: Bob tries to decrypt his output
    let bob_result = conf_output_to_bob.try_decrypt(&bob_dk);
    assert!(
        bob_result.is_ok(),
        "Bob should be able to decrypt his output"
    );

    let (bob_amount, bob_blinding) = bob_result.unwrap();
    assert_eq!(
        bob_amount, output1_amount,
        "Bob should receive correct amount"
    );
    assert_eq!(
        bob_blinding, output1_blinding,
        "Blinding factors should match"
    );

    // Step 7: Verify commitment opens correctly
    assert!(conf_output_to_bob
        .commitment
        .verify_opening(bob_amount, &bob_blinding));

    // Step 8: Alice tries to decrypt her change output
    let alice_result = conf_output_to_alice.try_decrypt(&alice_dk);
    assert!(
        alice_result.is_ok(),
        "Alice should be able to decrypt her output"
    );

    let (alice_amount, alice_blinding) = alice_result.unwrap();
    assert_eq!(alice_amount, output2_amount);
    assert_eq!(alice_blinding, output2_blinding);

    // Step 9: Bob should NOT be able to decrypt Alice's output
    let bob_tries_alice = conf_output_to_alice.try_decrypt(&bob_dk);
    assert!(
        bob_tries_alice.is_err(),
        "Bob should not be able to decrypt Alice's output"
    );

    // Step 10: Alice should NOT be able to decrypt Bob's output
    let alice_tries_bob = conf_output_to_bob.try_decrypt(&alice_dk);
    assert!(
        alice_tries_bob.is_err(),
        "Alice should not be able to decrypt Bob's output"
    );
}

#[test]
fn test_balance_proof_rejects_unbalanced_transaction() {
    // Inputs sum to 1500
    let inputs = vec![(1000u64, [1u8; 32]), (500u64, [2u8; 32])];

    // Outputs sum to 1400 (trying to create money out of thin air!)
    let outputs = vec![(800u64, [3u8; 32]), (600u64, [4u8; 32])];

    let balance_witness = BalanceWitness::new(inputs, outputs);
    assert!(
        balance_witness.is_none(),
        "Unbalanced transaction should be rejected"
    );
}

#[test]
fn test_range_proof_for_large_amounts() {
    // Test with maximum u64 value
    let witness = RangeWitness::new(u64::MAX);
    let trace = witness.generate_trace();

    assert_eq!(trace.height(), 1);
    assert_eq!(trace.width(), 66);
}

#[test]
fn test_stealth_address_unlinkability() {
    let (ek, _) = generate_kem_keypair();

    // Generate two stealth addresses for the same recipient
    let (addr1, _, _) = generate_stealth_address(&ek);
    let (addr2, _, _) = generate_stealth_address(&ek);

    // They should be different (unlinkable)
    assert_ne!(addr1, addr2, "Stealth addresses should be unlinkable");
}

#[test]
fn test_commitment_hiding_property() {
    // Two different amounts with different blindings
    let amount1 = 1000u64;
    let blinding1 = [10u8; 32];
    let commitment1 = AmountCommitment::commit(amount1, &blinding1);

    let amount2 = 2000u64;
    let blinding2 = [20u8; 32];
    let commitment2 = AmountCommitment::commit(amount2, &blinding2);

    // Commitments should be different (hiding property)
    assert_ne!(commitment1, commitment2);

    // Same amount but different blinding should also give different commitment
    let commitment3 = AmountCommitment::commit(amount1, &blinding2);
    assert_ne!(commitment1, commitment3);

    // Same amount and blinding should give same commitment (deterministic)
    let commitment4 = AmountCommitment::commit(amount1, &blinding1);
    assert_eq!(commitment1, commitment4);
}

#[test]
fn test_multi_output_confidential_transaction() {
    // Simulate a transaction with 1 input and 3 outputs
    let input_amount = 10000u64;
    let input_blinding = [100u8; 32];

    let output1_amount = 3000u64;
    let output1_blinding = [101u8; 32];

    let output2_amount = 4500u64;
    let output2_blinding = [102u8; 32];

    let output3_amount = 2500u64; // Change
    let output3_blinding = [103u8; 32];

    let inputs = vec![(input_amount, input_blinding)];
    let outputs = vec![
        (output1_amount, output1_blinding),
        (output2_amount, output2_blinding),
        (output3_amount, output3_blinding),
    ];

    let balance_witness = BalanceWitness::new(inputs, outputs);
    assert!(
        balance_witness.is_some(),
        "Multi-output transaction should balance"
    );

    let witness = balance_witness.unwrap();
    assert_eq!(witness.inputs.len(), 1);
    assert_eq!(witness.outputs.len(), 3);
    assert_eq!(witness.input_commitments.len(), 1);
    assert_eq!(witness.output_commitments.len(), 3);
}
