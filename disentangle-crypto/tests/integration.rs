//! Integration tests for disentangle-crypto
//!
//! These tests exercise the public API through realistic cross-module scenarios
//! that go beyond the inline unit tests. Each test verifies behavior that a real
//! protocol consumer would depend on.

use disentangle_crypto::{
    decapsulate, encapsulate, generate_kem_keypair, generate_keypair, sha3_256, sha3_256_multi,
    sign, verify, Ciphertext, CryptoError, DecapsulationKey, EncapsulationKey, Signature,
    SigningKey, VerifyingKey,
};

// --------------------------------------------------------------------------
// 1. Signature: sign/verify roundtrip with varied message sizes
// --------------------------------------------------------------------------

#[test]
fn sign_verify_roundtrip_varied_messages() {
    let (sk, vk) = generate_keypair();

    // Empty message
    let sig_empty = sign(&sk, b"");
    assert!(verify(&vk, b"", &sig_empty).is_ok());

    // Short message
    let short = b"hello";
    let sig_short = sign(&sk, short);
    assert!(verify(&vk, short, &sig_short).is_ok());

    // Large message (4 KB of structured data, simulating a serialized transaction)
    let large: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let sig_large = sign(&sk, &large);
    assert!(verify(&vk, &large, &sig_large).is_ok());
}

// --------------------------------------------------------------------------
// 2. Signature: wrong key rejects
// --------------------------------------------------------------------------

#[test]
fn sign_verify_wrong_key_rejects() {
    let (sk_alice, _vk_alice) = generate_keypair();
    let (_sk_bob, vk_bob) = generate_keypair();

    let message = b"message signed by alice";
    let sig = sign(&sk_alice, message);

    // Bob's verifying key must not accept Alice's signature
    let err = verify(&vk_bob, message, &sig).unwrap_err();
    assert!(
        matches!(err, CryptoError::SignatureVerificationFailed),
        "expected SignatureVerificationFailed, got: {err:?}"
    );
}

// --------------------------------------------------------------------------
// 3. Signature: tampered message rejects
// --------------------------------------------------------------------------

#[test]
fn sign_verify_tampered_message_rejects() {
    let (sk, vk) = generate_keypair();
    let original = b"transfer 100 tokens to alice";
    let sig = sign(&sk, original);

    // Flip one byte in the message
    let mut tampered = original.to_vec();
    tampered[0] ^= 0xFF;

    let err = verify(&vk, &tampered, &sig).unwrap_err();
    assert!(matches!(err, CryptoError::SignatureVerificationFailed));
}

// --------------------------------------------------------------------------
// 4. KEM: encapsulate/decapsulate roundtrip
// --------------------------------------------------------------------------

#[test]
fn kem_roundtrip_shared_secrets_match() {
    let (ek, dk) = generate_kem_keypair();
    let (ct, ss_sender) = encapsulate(&ek);
    let ss_receiver = decapsulate(&dk, &ct).expect("decapsulation should succeed");

    assert_eq!(
        ss_sender, ss_receiver,
        "sender and receiver must derive the same shared secret"
    );
    // Shared secret should be exactly 32 bytes
    assert_eq!(ss_sender.as_bytes().len(), 32);
}

// --------------------------------------------------------------------------
// 5. KEM: wrong decapsulation key produces different secret
// --------------------------------------------------------------------------

#[test]
fn kem_wrong_decapsulation_key_produces_different_secret() {
    let (ek_alice, _dk_alice) = generate_kem_keypair();
    let (_ek_eve, dk_eve) = generate_kem_keypair();

    let (ct, ss_alice) = encapsulate(&ek_alice);

    // Kyber's decapsulate is implicitly-rejecting: it returns a pseudorandom
    // value rather than an error when given the wrong key. The critical property
    // is that the derived secret differs.
    let ss_eve =
        decapsulate(&dk_eve, &ct).expect("kyber decapsulate returns Ok even with wrong key");
    assert_ne!(
        ss_alice, ss_eve,
        "wrong decapsulation key must not derive the correct shared secret"
    );
}

// --------------------------------------------------------------------------
// 6. Hash: SHA3-256 determinism across invocations
// --------------------------------------------------------------------------

#[test]
fn sha3_256_determinism() {
    let data = b"deterministic hashing is fundamental to consensus";
    let h1 = sha3_256(data);
    let h2 = sha3_256(data);
    let h3 = sha3_256(data);
    assert_eq!(h1, h2);
    assert_eq!(h2, h3);
    // Output must be exactly 32 bytes
    assert_eq!(h1.len(), 32);
}

// --------------------------------------------------------------------------
// 7. Hash: collision resistance (distinct inputs -> distinct outputs)
// --------------------------------------------------------------------------

#[test]
fn sha3_256_collision_resistance() {
    // Hashes of closely-related inputs must differ
    let inputs: Vec<&[u8]> = vec![
        b"input", b"Input",   // case difference
        b"input ",  // trailing space
        b"input\0", // trailing null
        b"inpu",    // truncated
        b"",        // empty
    ];

    let hashes: Vec<_> = inputs.iter().map(|i| sha3_256(i)).collect();

    // All pairwise distinct
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "collision between input[{i}] and input[{j}]"
            );
        }
    }
}

// --------------------------------------------------------------------------
// 8. Hash: sha3_256_multi streaming equivalence
// --------------------------------------------------------------------------

#[test]
fn sha3_256_multi_streaming_equivalence() {
    // Multi-part hashing must equal single-pass hashing of the concatenation
    let part_a = b"epoch:42|";
    let part_b = b"nullifier:";
    let part_c = b"abc123";

    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(part_a);
    concatenated.extend_from_slice(part_b);
    concatenated.extend_from_slice(part_c);

    let h_multi = sha3_256_multi(&[part_a, part_b, part_c]);
    let h_single = sha3_256(&concatenated);
    assert_eq!(h_multi, h_single);

    // But splitting at different boundaries must also produce the same result
    let h_two_parts = sha3_256_multi(&[&concatenated[..5], &concatenated[5..]]);
    assert_eq!(h_multi, h_two_parts);
}

// --------------------------------------------------------------------------
// 9. Cross-module: signed KEM exchange (full handshake flow)
// --------------------------------------------------------------------------

#[test]
fn cross_module_signed_kem_handshake() {
    // Scenario: Alice wants to establish a shared secret with Bob.
    // 1. Bob generates a KEM keypair and publishes his encapsulation key.
    // 2. Alice signs her encapsulation request (containing Bob's EK hash) with
    //    her Dilithium5 signing key, then encapsulates against Bob's EK.
    // 3. Bob verifies Alice's signature, then decapsulates to get the shared secret.
    // 4. Both parties hash the shared secret for use as a symmetric key.

    // Alice's identity keypair (Dilithium5)
    let (sk_alice, vk_alice) = generate_keypair();

    // Bob's KEM keypair (Kyber1024)
    let (ek_bob, dk_bob) = generate_kem_keypair();

    // Alice computes a fingerprint of Bob's encapsulation key
    let ek_bob_fingerprint = sha3_256(&ek_bob.to_bytes());

    // Alice creates and signs a key-exchange request
    let request_payload = sha3_256_multi(&[b"KEX_REQUEST_V1", &ek_bob_fingerprint]);
    let request_sig = sign(&sk_alice, &request_payload);

    // Alice encapsulates against Bob's key
    let (ciphertext, ss_alice) = encapsulate(&ek_bob);

    // --- Network boundary: ciphertext, request_payload, request_sig, vk_alice sent to Bob ---

    // Bob verifies Alice's identity
    verify(&vk_alice, &request_payload, &request_sig).expect("Bob should verify Alice's signature");

    // Bob decapsulates to derive the shared secret
    let ss_bob = decapsulate(&dk_bob, &ciphertext).expect("Bob should successfully decapsulate");

    // Both parties must have the same shared secret
    assert_eq!(ss_alice, ss_bob);

    // Both derive a symmetric key from the shared secret
    let sym_key_alice = sha3_256(ss_alice.as_bytes());
    let sym_key_bob = sha3_256(ss_bob.as_bytes());
    assert_eq!(sym_key_alice, sym_key_bob);
}

// --------------------------------------------------------------------------
// 10. Serialization roundtrip: keys and signatures survive byte encoding
// --------------------------------------------------------------------------

#[test]
fn serialization_roundtrip_signing_keys() {
    let (sk, vk) = generate_keypair();
    let message = b"roundtrip test payload";
    let sig = sign(&sk, message);

    // VerifyingKey roundtrip via to_bytes/from_bytes
    let vk_bytes = vk.to_bytes();
    let vk_restored = VerifyingKey::from_bytes(&vk_bytes).expect("VK deserialization");
    assert_eq!(vk, vk_restored);

    // SigningKey roundtrip via to_bytes/from_bytes
    let sk_bytes = sk.to_bytes();
    let sk_restored = SigningKey::from_bytes(&sk_bytes).expect("SK deserialization");
    // Verify the restored key can produce a valid signature
    let sig_restored = sign(&sk_restored, message);
    assert!(verify(&vk, message, &sig_restored).is_ok());

    // Signature roundtrip via to_bytes/from_bytes
    let sig_bytes = sig.to_bytes().to_vec();
    let sig_from_bytes = Signature::from_bytes(&sig_bytes).expect("Sig deserialization");
    assert!(verify(&vk, message, &sig_from_bytes).is_ok());
}

#[test]
fn serialization_roundtrip_kem_keys() {
    let (ek, dk) = generate_kem_keypair();

    // EncapsulationKey roundtrip
    let ek_bytes = ek.to_bytes();
    let ek_restored = EncapsulationKey::from_bytes(&ek_bytes).expect("EK deserialization");
    assert_eq!(ek, ek_restored);

    // DecapsulationKey roundtrip: verify restored key can decapsulate
    let dk_bytes = dk.to_bytes();
    let dk_restored = DecapsulationKey::from_bytes(&dk_bytes).expect("DK deserialization");

    let (ct, ss_original) = encapsulate(&ek);
    let ss_from_restored = decapsulate(&dk_restored, &ct).expect("decapsulate with restored DK");
    assert_eq!(ss_original, ss_from_restored);

    // Ciphertext roundtrip
    let ct_bytes = ct.to_bytes();
    let ct_restored = Ciphertext::from_bytes(&ct_bytes).expect("CT deserialization");
    let ss_from_ct_restored = decapsulate(&dk, &ct_restored).expect("decapsulate with restored CT");
    assert_eq!(ss_original, ss_from_ct_restored);
}

// --------------------------------------------------------------------------
// 11. Invalid key lengths produce proper errors
// --------------------------------------------------------------------------

#[test]
fn invalid_key_lengths_produce_errors() {
    // Too short
    let err = SigningKey::from_bytes(&[0u8; 10]).unwrap_err();
    assert!(matches!(
        err,
        CryptoError::InvalidKeyLength {
            expected: 4896,
            got: 10,
        }
    ));

    let err = VerifyingKey::from_bytes(&[0u8; 10]).unwrap_err();
    assert!(matches!(
        err,
        CryptoError::InvalidKeyLength {
            expected: 2592,
            got: 10,
        }
    ));

    let err = Signature::from_bytes(&[0u8; 10]).unwrap_err();
    assert!(matches!(
        err,
        CryptoError::InvalidKeyLength {
            expected: 4627,
            got: 10,
        }
    ));

    let err = EncapsulationKey::from_bytes(&[0u8; 10]).unwrap_err();
    assert!(matches!(
        err,
        CryptoError::InvalidKeyLength {
            expected: 1568,
            got: 10,
        }
    ));

    let err = DecapsulationKey::from_bytes(&[0u8; 10]).unwrap_err();
    assert!(matches!(
        err,
        CryptoError::InvalidKeyLength {
            expected: 3168,
            got: 10,
        }
    ));

    let err = Ciphertext::from_bytes(&[0u8; 10]).unwrap_err();
    assert!(matches!(
        err,
        CryptoError::InvalidKeyLength {
            expected: 1568,
            got: 10,
        }
    ));

    // Empty
    let err = SigningKey::from_bytes(&[]).unwrap_err();
    assert!(matches!(err, CryptoError::InvalidKeyLength { got: 0, .. }));
}

// --------------------------------------------------------------------------
// 12. Cross-module: NodeId derivation from PublicKey is consistent
// --------------------------------------------------------------------------

#[test]
fn node_id_derivation_consistency() {
    // NodeId is Hash256, and the convention is to derive it by hashing the
    // public key bytes. Verify that the same public key always produces the
    // same NodeId, and different keys produce different NodeIds.
    use disentangle_crypto::NodeId;

    let (_, vk1) = generate_keypair();
    let (_, vk2) = generate_keypair();

    let node_id_1a: NodeId = sha3_256(&vk1.to_bytes());
    let node_id_1b: NodeId = sha3_256(&vk1.to_bytes());
    let node_id_2: NodeId = sha3_256(&vk2.to_bytes());

    // Same key -> same NodeId
    assert_eq!(node_id_1a, node_id_1b);
    // Different keys -> different NodeIds
    assert_ne!(node_id_1a, node_id_2);
    // NodeId is 32 bytes
    assert_eq!(node_id_1a.len(), 32);
}
