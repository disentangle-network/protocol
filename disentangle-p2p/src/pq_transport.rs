//! Post-Quantum Transport Re-keying Protocol
//!
//! Implements hybrid Noise-XX + Kyber1024 key exchange for quantum-resistant transport.
//! After completing the standard Noise handshake, this module performs a post-handshake
//! re-keying using Kyber1024 KEM to establish PQ-secure session keys.

use disentangle_crypto::hash::sha3_256_multi;
use disentangle_crypto::kem::{
    generate_kem_keypair, encapsulate, decapsulate,
    EncapsulationKey, DecapsulationKey, Ciphertext, SharedSecret,
};
use serde::{Serialize, Deserialize};

/// Post-quantum re-keying protocol messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PqRekeyMessage {
    /// Step 1: Initiator sends their encapsulation key
    Request {
        /// Initiator's ephemeral Kyber1024 encapsulation key
        initiator_ek: Vec<u8>,  // 1568 bytes
        /// Random nonce for session binding
        nonce: [u8; 32],
        /// Protocol version for future upgrades
        version: u8,
    },
    /// Step 2: Responder sends back both ciphertexts
    Response {
        /// Responder's ephemeral encapsulation key
        responder_ek: Vec<u8>,  // 1568 bytes
        /// Ciphertext encapsulating to initiator's key
        initiator_ct: Vec<u8>,  // 1568 bytes
        /// Ciphertext encapsulating to responder's key (initiator will compute)
        responder_ct: Vec<u8>,  // 1568 bytes
    },
    /// Step 3: Initiator confirms key derivation succeeded
    Confirm {
        /// Ciphertext encapsulating to responder's key
        responder_ct: Vec<u8>,  // 1568 bytes
        /// MAC over (nonce || "PQ_REKEY_CONFIRM") using derived key
        confirmation_mac: [u8; 32],
    },
    /// Failure: one side couldn't complete re-key
    Error {
        reason: PqRekeyError,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PqRekeyError {
    UnsupportedVersion,
    DecapsulationFailed,
    InvalidKeyLength,
    Timeout,
}

impl std::fmt::Display for PqRekeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion => write!(f, "Unsupported protocol version"),
            Self::DecapsulationFailed => write!(f, "KEM decapsulation failed"),
            Self::InvalidKeyLength => write!(f, "Invalid key length"),
            Self::Timeout => write!(f, "Re-key protocol timeout"),
        }
    }
}

impl std::error::Error for PqRekeyError {}

/// Session keys derived from PQ re-keying
#[derive(Debug, Clone)]
pub struct PqSessionKeys {
    /// Key for sending messages (our direction)
    pub send_key: [u8; 32],
    /// Key for receiving messages (peer direction)
    pub recv_key: [u8; 32],
}

/// Derive PQ session keys from both shared secrets (initiator side)
///
/// Combines both Kyber1024 shared secrets with the session nonce
/// and derives separate keys for each direction using SHA3-256 with domain separation.
pub fn derive_pq_session_keys_initiator(
    initiator_ss: &SharedSecret,  // From responder encapsulating to initiator
    responder_ss: &SharedSecret,  // From initiator encapsulating to responder
    nonce: &[u8; 32],
) -> PqSessionKeys {
    // Combine both shared secrets with nonce
    let ikm = sha3_256_multi(&[
        b"ENTANGLE_PQ_TRANSPORT_V1",
        initiator_ss.as_bytes(),
        responder_ss.as_bytes(),
        nonce,
    ]);

    // Derive separate keys for each direction
    let initiator_to_responder = sha3_256_multi(&[&ikm, b"INITIATOR_TO_RESPONDER"]);
    let responder_to_initiator = sha3_256_multi(&[&ikm, b"RESPONDER_TO_INITIATOR"]);

    let mut send_key = [0u8; 32];
    let mut recv_key = [0u8; 32];
    send_key.copy_from_slice(&initiator_to_responder);
    recv_key.copy_from_slice(&responder_to_initiator);

    PqSessionKeys { send_key, recv_key }
}

/// Derive PQ session keys from both shared secrets (responder side)
///
/// Combines both Kyber1024 shared secrets with the session nonce
/// and derives separate keys for each direction using SHA3-256 with domain separation.
pub fn derive_pq_session_keys_responder(
    initiator_ss: &SharedSecret,  // From responder encapsulating to initiator
    responder_ss: &SharedSecret,  // From initiator encapsulating to responder
    nonce: &[u8; 32],
) -> PqSessionKeys {
    // Combine both shared secrets with nonce
    let ikm = sha3_256_multi(&[
        b"ENTANGLE_PQ_TRANSPORT_V1",
        initiator_ss.as_bytes(),
        responder_ss.as_bytes(),
        nonce,
    ]);

    // Derive separate keys for each direction (swapped from initiator)
    let initiator_to_responder = sha3_256_multi(&[&ikm, b"INITIATOR_TO_RESPONDER"]);
    let responder_to_initiator = sha3_256_multi(&[&ikm, b"RESPONDER_TO_INITIATOR"]);

    let mut send_key = [0u8; 32];
    let mut recv_key = [0u8; 32];
    send_key.copy_from_slice(&responder_to_initiator);
    recv_key.copy_from_slice(&initiator_to_responder);

    PqSessionKeys { send_key, recv_key }
}

/// Generate initiator's re-key request message
pub fn create_rekey_request(nonce: [u8; 32]) -> (PqRekeyMessage, DecapsulationKey) {
    let (ek, dk) = generate_kem_keypair();
    let msg = PqRekeyMessage::Request {
        initiator_ek: ek.to_bytes(),
        nonce,
        version: 1,
    };
    (msg, dk)
}

/// Process initiator's request and create response
pub fn process_rekey_request(
    request: &PqRekeyMessage,
) -> Result<(PqRekeyMessage, DecapsulationKey, SharedSecret), PqRekeyError> {
    match request {
        PqRekeyMessage::Request { initiator_ek, version, .. } => {
            if *version != 1 {
                return Err(PqRekeyError::UnsupportedVersion);
            }

            // Parse initiator's encapsulation key
            let initiator_ek = EncapsulationKey::from_bytes(initiator_ek)
                .map_err(|_| PqRekeyError::InvalidKeyLength)?;

            // Generate our own keypair
            let (responder_ek, responder_dk) = generate_kem_keypair();

            // Encapsulate to initiator's key
            let (initiator_ct, initiator_ss) = encapsulate(&initiator_ek);

            // Create response with our key and ciphertext
            let response = PqRekeyMessage::Response {
                responder_ek: responder_ek.to_bytes(),
                initiator_ct: initiator_ct.to_bytes(),
                responder_ct: vec![], // Will be sent in Confirm message by initiator
            };

            Ok((response, responder_dk, initiator_ss))
        }
        _ => Err(PqRekeyError::DecapsulationFailed),
    }
}

/// Process responder's response and create confirmation
pub fn process_rekey_response(
    response: &PqRekeyMessage,
    initiator_dk: &DecapsulationKey,
    nonce: &[u8; 32],
) -> Result<(PqRekeyMessage, PqSessionKeys), PqRekeyError> {
    match response {
        PqRekeyMessage::Response { responder_ek, initiator_ct, .. } => {
            // Parse responder's encapsulation key
            let responder_ek = EncapsulationKey::from_bytes(responder_ek)
                .map_err(|_| PqRekeyError::InvalidKeyLength)?;

            // Decapsulate initiator_ct with our key
            let initiator_ct = Ciphertext::from_bytes(initiator_ct)
                .map_err(|_| PqRekeyError::InvalidKeyLength)?;
            let initiator_ss = decapsulate(initiator_dk, &initiator_ct)
                .map_err(|_| PqRekeyError::DecapsulationFailed)?;

            // Encapsulate to responder's key
            let (responder_ct, responder_ss) = encapsulate(&responder_ek);

            // Derive session keys (initiator perspective)
            let keys = derive_pq_session_keys_initiator(&initiator_ss, &responder_ss, nonce);

            // Create confirmation MAC
            let confirmation_mac = sha3_256_multi(&[
                &keys.send_key,
                nonce,
                b"PQ_REKEY_CONFIRM",
            ]);

            let confirm = PqRekeyMessage::Confirm {
                responder_ct: responder_ct.to_bytes(),
                confirmation_mac,
            };

            Ok((confirm, keys))
        }
        _ => Err(PqRekeyError::DecapsulationFailed),
    }
}

/// Verify confirmation message (responder side)
///
/// Responder receives the confirmation from initiator and verifies it,
/// then decapsulates the responder_ct to derive final session keys.
pub fn verify_rekey_confirm(
    confirm: &PqRekeyMessage,
    responder_dk: &DecapsulationKey,
    initiator_ss: &SharedSecret,
    nonce: &[u8; 32],
) -> Result<PqSessionKeys, PqRekeyError> {
    match confirm {
        PqRekeyMessage::Confirm { responder_ct, confirmation_mac } => {
            // Parse and decapsulate responder_ct to get responder_ss
            let responder_ct = Ciphertext::from_bytes(responder_ct)
                .map_err(|_| PqRekeyError::InvalidKeyLength)?;
            let responder_ss = decapsulate(responder_dk, &responder_ct)
                .map_err(|_| PqRekeyError::DecapsulationFailed)?;

            // Derive session keys (responder perspective)
            let keys = derive_pq_session_keys_responder(initiator_ss, &responder_ss, nonce);

            // Compute expected MAC (from responder's perspective, use recv_key)
            let expected_mac = sha3_256_multi(&[
                &keys.recv_key,
                nonce,
                b"PQ_REKEY_CONFIRM",
            ]);

            if confirmation_mac == &expected_mac {
                Ok(keys)
            } else {
                Err(PqRekeyError::DecapsulationFailed)
            }
        }
        _ => Err(PqRekeyError::DecapsulationFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let nonce = [42u8; 32];
        let (request, _) = create_rekey_request(nonce);

        // Test Request serialization
        let serialized = bincode::serialize(&request).unwrap();
        let deserialized: PqRekeyMessage = bincode::deserialize(&serialized).unwrap();

        match (&request, &deserialized) {
            (
                PqRekeyMessage::Request { initiator_ek: ek1, nonce: n1, version: v1 },
                PqRekeyMessage::Request { initiator_ek: ek2, nonce: n2, version: v2 },
            ) => {
                assert_eq!(ek1, ek2);
                assert_eq!(n1, n2);
                assert_eq!(v1, v2);
            }
            _ => panic!("Message type mismatch"),
        }
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let (ek1, dk1) = generate_kem_keypair();
        let (ek2, dk2) = generate_kem_keypair();

        let (ct1, ss1) = encapsulate(&ek1);
        let (ct2, ss2) = encapsulate(&ek2);

        let nonce = [99u8; 32];
        let keys1 = derive_pq_session_keys_initiator(&ss1, &ss2, &nonce);
        let keys2 = derive_pq_session_keys_initiator(&ss1, &ss2, &nonce);

        assert_eq!(keys1.send_key, keys2.send_key);
        assert_eq!(keys1.recv_key, keys2.recv_key);

        // Verify decapsulation matches
        let ss1_recovered = decapsulate(&dk1, &ct1).unwrap();
        let ss2_recovered = decapsulate(&dk2, &ct2).unwrap();

        let keys_recovered = derive_pq_session_keys_initiator(&ss1_recovered, &ss2_recovered, &nonce);
        assert_eq!(keys1.send_key, keys_recovered.send_key);
        assert_eq!(keys1.recv_key, keys_recovered.recv_key);
    }

    #[test]
    fn test_key_derivation_different_nonces() {
        let (ek1, _) = generate_kem_keypair();
        let (ek2, _) = generate_kem_keypair();

        let (_, ss1) = encapsulate(&ek1);
        let (_, ss2) = encapsulate(&ek2);

        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];

        let keys1 = derive_pq_session_keys_initiator(&ss1, &ss2, &nonce1);
        let keys2 = derive_pq_session_keys_initiator(&ss1, &ss2, &nonce2);

        assert_ne!(keys1.send_key, keys2.send_key);
        assert_ne!(keys1.recv_key, keys2.recv_key);
    }

    #[test]
    fn test_full_rekey_protocol() {
        // Initiator creates request
        let nonce = [123u8; 32];
        let (request, initiator_dk) = create_rekey_request(nonce);

        // Responder processes request
        let (response, responder_dk, initiator_ss_responder) =
            process_rekey_request(&request).unwrap();

        // Initiator processes response and creates confirmation
        let (confirm, initiator_keys) =
            process_rekey_response(&response, &initiator_dk, &nonce).unwrap();

        // Responder verifies confirmation and derives session keys
        let responder_keys = verify_rekey_confirm(
            &confirm,
            &responder_dk,
            &initiator_ss_responder,
            &nonce
        ).unwrap();

        // Verify keys match (initiator's send = responder's recv)
        assert_eq!(initiator_keys.send_key, responder_keys.recv_key);
        assert_eq!(initiator_keys.recv_key, responder_keys.send_key);
    }

    #[test]
    fn test_error_types() {
        let error = PqRekeyError::UnsupportedVersion;
        assert!(error.to_string().contains("version"));

        let error = PqRekeyError::DecapsulationFailed;
        assert!(error.to_string().contains("decapsulation"));
    }

    #[test]
    fn test_manual_protocol_flow() {
        // This test manually walks through the protocol to debug the issue
        let nonce = [42u8; 32];

        // Step 1: Initiator generates keypair and sends public key
        let (initiator_ek, initiator_dk) = generate_kem_keypair();

        // Step 2: Responder generates keypair and encapsulates to initiator
        let (responder_ek, responder_dk) = generate_kem_keypair();
        let (initiator_ct, initiator_ss_by_responder) = encapsulate(&initiator_ek);

        // Step 3: Initiator decapsulates and verifies they get the same shared secret
        let initiator_ss_by_initiator = decapsulate(&initiator_dk, &initiator_ct).unwrap();
        assert_eq!(initiator_ss_by_responder, initiator_ss_by_initiator);

        // Step 4: Initiator encapsulates to responder
        let (responder_ct, responder_ss_by_initiator) = encapsulate(&responder_ek);

        // Step 5: Responder decapsulates and verifies they get the same shared secret
        let responder_ss_by_responder = decapsulate(&responder_dk, &responder_ct).unwrap();
        assert_eq!(responder_ss_by_initiator, responder_ss_by_responder);

        // Step 6: Both derive session keys with their respective roles
        let initiator_keys = derive_pq_session_keys_initiator(
            &initiator_ss_by_initiator,
            &responder_ss_by_initiator,
            &nonce
        );

        let responder_keys = derive_pq_session_keys_responder(
            &initiator_ss_by_responder,
            &responder_ss_by_responder,
            &nonce
        );

        // Step 7: Verify keys match (send/recv are swapped)
        assert_eq!(initiator_keys.send_key, responder_keys.recv_key);
        assert_eq!(initiator_keys.recv_key, responder_keys.send_key);
    }
}
