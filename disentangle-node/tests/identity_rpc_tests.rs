//! Integration tests for Identity RPC handlers
//!
//! Tests the Capability-Coherence Identity Protocol (CCIP) HTTP endpoints
//! using Axum's test utilities.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use disentangle_node::identity_rpc::*;
use disentangle_node::identity_state::IdentityStateManager;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::util::ServiceExt;

/// Create a test router with identity endpoints
fn create_test_router() -> Router {
    let state = Arc::new(Mutex::new(IdentityStateManager::new()));

    Router::new()
        // Identity endpoints
        .route("/identity/register", axum::routing::post(identity_register_handler))
        .route("/identity/:did", axum::routing::get(identity_get_handler))
        .route("/identity", axum::routing::get(identity_list_handler))
        .route("/identity/:did", axum::routing::delete(identity_deactivate_handler))
        // Capability endpoints
        .route("/capability/create", axum::routing::post(capability_create_handler))
        .route("/capability/delegate", axum::routing::post(capability_delegate_handler))
        .route("/capability/invoke", axum::routing::post(capability_invoke_handler))
        .route("/capability/revoke", axum::routing::post(capability_revoke_handler))
        .route("/capability/:cap_id_hex", axum::routing::get(capability_get_handler))
        .route("/capability/by-did/:did", axum::routing::get(capability_list_by_did_handler))
        // Introduction endpoints
        .route("/introduction", axum::routing::post(introduction_create_handler))
        .route("/introduction/chain/:from_did/:to_did", axum::routing::get(introduction_chain_handler))
        // Coherence endpoints
        .route("/coherence/:did", axum::routing::get(coherence_profile_handler))
        .route("/coherence/curvature/:did_a/:did_b", axum::routing::get(coherence_curvature_handler))
        .route("/coherence/neighbors/:did", axum::routing::get(coherence_neighbors_handler))
        // Petname endpoints
        .route("/petname", axum::routing::post(petname_set_handler))
        .route("/petname/:name", axum::routing::get(petname_resolve_handler))
        .with_state(state)
}

/// Helper to send a JSON POST request
async fn post_json(router: &Router, path: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_json: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));

    (status, body_json)
}

/// Helper to send a GET request
async fn get_request(router: &Router, path: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_json: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));

    (status, body_json)
}

/// Helper to send a DELETE request
async fn delete_request(router: &Router, path: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("DELETE")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_json: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));

    (status, body_json)
}

// ============================================================================
// IDENTITY ENDPOINT TESTS
// ============================================================================

#[tokio::test]
async fn test_register_human_identity() {
    let router = create_test_router();

    let body = json!({
        "agent_type": "human"
    });

    let (status, response) = post_json(&router, "/identity/register", body).await;

    assert_eq!(status, StatusCode::OK);
    assert!(response["did"].is_string());
    assert!(response["signing_key_hex"].is_string());
    assert!(response["document"].is_object());

    // Verify DID format
    let did = response["did"].as_str().unwrap();
    assert!(did.starts_with("did:disentangle:"));

    // Verify signing key is hex
    let sk_hex = response["signing_key_hex"].as_str().unwrap();
    assert!(hex::decode(sk_hex).is_ok());
}

#[tokio::test]
async fn test_register_agi_identity() {
    let router = create_test_router();

    let body = json!({
        "agent_type": "agi",
        "runtime_attestation": "test_attestation"
    });

    let (status, response) = post_json(&router, "/identity/register", body).await;

    assert_eq!(status, StatusCode::OK);
    assert!(response["did"].is_string());

    // AGI DIDs should have agi: prefix after did:disentangle:
    let did = response["did"].as_str().unwrap();
    assert!(did.starts_with("did:disentangle:agi:"));
}

#[tokio::test]
async fn test_register_invalid_agent_type() {
    let router = create_test_router();

    let body = json!({
        "agent_type": "robot"
    });

    let (status, response) = post_json(&router, "/identity/register", body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(response["error"].as_str().unwrap().contains("Invalid agent_type"));
}

#[tokio::test]
async fn test_get_identity() {
    let router = create_test_router();

    // First register an identity
    let body = json!({"agent_type": "human"});
    let (_, register_response) = post_json(&router, "/identity/register", body).await;
    let did = register_response["did"].as_str().unwrap();

    // Now retrieve it
    let (status, response) = get_request(&router, &format!("/identity/{}", did)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(response["document"].is_object());
}

#[tokio::test]
async fn test_get_nonexistent_identity() {
    let router = create_test_router();

    let (status, response) = get_request(&router, "/identity/did:disentangle:nonexistent").await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(response["error"].as_str().unwrap().contains("DID not found"));
}

#[tokio::test]
async fn test_list_identities() {
    let router = create_test_router();

    // Register two identities
    post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    post_json(&router, "/identity/register", json!({"agent_type": "agi"})).await;

    // List all
    let (status, response) = get_request(&router, "/identity").await;

    assert_eq!(status, StatusCode::OK);
    assert!(response["dids"].is_array());
    let dids = response["dids"].as_array().unwrap();
    assert_eq!(dids.len(), 2);
}

#[tokio::test]
async fn test_deactivate_identity() {
    let router = create_test_router();

    // Register an identity
    let body = json!({"agent_type": "human"});
    let (_, register_response) = post_json(&router, "/identity/register", body).await;
    let did = register_response["did"].as_str().unwrap();

    // Deactivate it (using dummy proof for now)
    let deactivate_body = json!({
        "proof_hex": "deadbeef"
    });

    let (status, response) = delete_request(&router, &format!("/identity/{}", did), deactivate_body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["success"], true);

    // Verify it's gone
    let (get_status, _) = get_request(&router, &format!("/identity/{}", did)).await;
    assert_eq!(get_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_deactivate_nonexistent_identity() {
    let router = create_test_router();

    let body = json!({
        "proof_hex": "deadbeef"
    });

    let (status, _) = delete_request(&router, "/identity/did:disentangle:nonexistent", body).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_deactivate_invalid_hex() {
    let router = create_test_router();

    // Register an identity
    let body = json!({"agent_type": "human"});
    let (_, register_response) = post_json(&router, "/identity/register", body).await;
    let did = register_response["did"].as_str().unwrap();

    // Try to deactivate with invalid hex
    let deactivate_body = json!({
        "proof_hex": "not-valid-hex!"
    });

    let (status, response) = delete_request(&router, &format!("/identity/{}", did), deactivate_body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(response["error"].as_str().unwrap().contains("Invalid proof hex"));
}

// ============================================================================
// CAPABILITY ENDPOINT TESTS
// ============================================================================

#[tokio::test]
async fn test_create_capability() {
    let router = create_test_router();

    // Register an identity
    let body = json!({"agent_type": "human"});
    let (_, register_response) = post_json(&router, "/identity/register", body).await;
    let did = register_response["did"].as_str().unwrap();
    let sk_hex = register_response["signing_key_hex"].as_str().unwrap();

    // Create a capability
    let cap_body = json!({
        "issuer_did": did,
        "signing_key_hex": sk_hex,
        "subject": {
            "Transact": {
                "scope": "All"
            }
        },
        "constraints": [],
        "delegatable": true
    });

    let (status, response) = post_json(&router, "/capability/create", cap_body).await;

    assert_eq!(status, StatusCode::OK);
    assert!(response["capability_id_hex"].is_string());
    assert!(response["capability"].is_object());

    // Verify capability ID is valid hex
    let cap_id_hex = response["capability_id_hex"].as_str().unwrap();
    let cap_id_bytes = hex::decode(cap_id_hex).unwrap();
    assert_eq!(cap_id_bytes.len(), 32);
}

#[tokio::test]
async fn test_create_capability_invalid_signing_key() {
    let router = create_test_router();

    // Register an identity
    let body = json!({"agent_type": "human"});
    let (_, register_response) = post_json(&router, "/identity/register", body).await;
    let did = register_response["did"].as_str().unwrap();

    // Create capability with invalid signing key
    let cap_body = json!({
        "issuer_did": did,
        "signing_key_hex": "not-valid-hex",
        "subject": {
            "Transact": {
                "scope": "All"
            }
        },
        "constraints": [],
        "delegatable": true
    });

    let (status, response) = post_json(&router, "/capability/create", cap_body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(response["error"].as_str().unwrap().contains("Invalid signing key hex"));
}

#[tokio::test]
async fn test_delegate_capability() {
    let router = create_test_router();

    // Register two identities
    let (_, issuer_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let issuer_did = issuer_resp["did"].as_str().unwrap();
    let issuer_sk = issuer_resp["signing_key_hex"].as_str().unwrap();

    let (_, delegatee_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let delegatee_did = delegatee_resp["did"].as_str().unwrap();

    // Create a delegatable capability
    let cap_body = json!({
        "issuer_did": issuer_did,
        "signing_key_hex": issuer_sk,
        "subject": {"Transact": {"scope": "All"}},
        "constraints": [],
        "delegatable": true
    });
    let (_, cap_resp) = post_json(&router, "/capability/create", cap_body).await;
    let cap_id_hex = cap_resp["capability_id_hex"].as_str().unwrap();

    // Delegate it
    let delegate_body = json!({
        "capability_id_hex": cap_id_hex,
        "delegator_did": issuer_did,
        "delegator_sk_hex": issuer_sk,
        "delegatee_did": delegatee_did
    });

    let (status, response) = post_json(&router, "/capability/delegate", delegate_body).await;

    assert_eq!(status, StatusCode::OK);
    assert!(response["delegation"].is_object());
}

#[tokio::test]
async fn test_delegate_nonexistent_capability() {
    let router = create_test_router();

    // Register an identity
    let (_, issuer_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let issuer_did = issuer_resp["did"].as_str().unwrap();
    let issuer_sk = issuer_resp["signing_key_hex"].as_str().unwrap();

    let (_, delegatee_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let delegatee_did = delegatee_resp["did"].as_str().unwrap();

    // Try to delegate nonexistent capability
    let fake_cap_id = "0".repeat(64);
    let delegate_body = json!({
        "capability_id_hex": fake_cap_id,
        "delegator_did": issuer_did,
        "delegator_sk_hex": issuer_sk,
        "delegatee_did": delegatee_did
    });

    let (status, response) = post_json(&router, "/capability/delegate", delegate_body).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(response["error"].as_str().unwrap().contains("Failed to delegate"));
}

#[tokio::test]
async fn test_delegate_invalid_cap_id_length() {
    let router = create_test_router();

    let (_, issuer_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let issuer_did = issuer_resp["did"].as_str().unwrap();
    let issuer_sk = issuer_resp["signing_key_hex"].as_str().unwrap();

    let (_, delegatee_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let delegatee_did = delegatee_resp["did"].as_str().unwrap();

    // Cap ID that's too short
    let delegate_body = json!({
        "capability_id_hex": "deadbeef",
        "delegator_did": issuer_did,
        "delegator_sk_hex": issuer_sk,
        "delegatee_did": delegatee_did
    });

    let (status, response) = post_json(&router, "/capability/delegate", delegate_body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(response["error"].as_str().unwrap().contains("must be 32 bytes"));
}

#[tokio::test]
async fn test_invoke_capability_as_issuer() {
    let router = create_test_router();

    // Register identity and create capability
    let (_, issuer_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let issuer_did = issuer_resp["did"].as_str().unwrap();
    let issuer_sk = issuer_resp["signing_key_hex"].as_str().unwrap();

    let cap_body = json!({
        "issuer_did": issuer_did,
        "signing_key_hex": issuer_sk,
        "subject": {"Transact": {"scope": "All"}},
        "constraints": [],
        "delegatable": true
    });
    let (_, cap_resp) = post_json(&router, "/capability/create", cap_body).await;
    let cap_id_hex = cap_resp["capability_id_hex"].as_str().unwrap();

    // Invoke as issuer
    let invoke_body = json!({
        "capability_id_hex": cap_id_hex,
        "invoker_did": issuer_did
    });

    let (status, response) = post_json(&router, "/capability/invoke", invoke_body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["success"], true);
    assert!(response["message"].as_str().unwrap().contains("successfully"));
}

#[tokio::test]
async fn test_invoke_capability_unauthorized() {
    let router = create_test_router();

    // Register two identities
    let (_, issuer_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let issuer_did = issuer_resp["did"].as_str().unwrap();
    let issuer_sk = issuer_resp["signing_key_hex"].as_str().unwrap();

    let (_, other_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let other_did = other_resp["did"].as_str().unwrap();

    // Create capability
    let cap_body = json!({
        "issuer_did": issuer_did,
        "signing_key_hex": issuer_sk,
        "subject": {"Transact": {"scope": "All"}},
        "constraints": [],
        "delegatable": false
    });
    let (_, cap_resp) = post_json(&router, "/capability/create", cap_body).await;
    let cap_id_hex = cap_resp["capability_id_hex"].as_str().unwrap();

    // Try to invoke as unauthorized user
    let invoke_body = json!({
        "capability_id_hex": cap_id_hex,
        "invoker_did": other_did
    });

    let (status, response) = post_json(&router, "/capability/invoke", invoke_body).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(response["error"].as_str().unwrap().contains("not permitted") ||
            response["error"].as_str().unwrap().contains("delegation chain"));
}

#[tokio::test]
async fn test_revoke_capability() {
    let router = create_test_router();

    // Register identity and create capability
    let (_, issuer_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let issuer_did = issuer_resp["did"].as_str().unwrap();
    let issuer_sk = issuer_resp["signing_key_hex"].as_str().unwrap();

    let cap_body = json!({
        "issuer_did": issuer_did,
        "signing_key_hex": issuer_sk,
        "subject": {"Transact": {"scope": "All"}},
        "constraints": [],
        "delegatable": true
    });
    let (_, cap_resp) = post_json(&router, "/capability/create", cap_body).await;
    let cap_id_hex = cap_resp["capability_id_hex"].as_str().unwrap();

    // Revoke it
    let revoke_body = json!({
        "capability_id_hex": cap_id_hex,
        "revoker_did": issuer_did,
        "scope": "single"
    });

    let (status, response) = post_json(&router, "/capability/revoke", revoke_body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["success"], true);

    // Try to invoke revoked capability
    let invoke_body = json!({
        "capability_id_hex": cap_id_hex,
        "invoker_did": issuer_did
    });
    let (invoke_status, invoke_response) = post_json(&router, "/capability/invoke", invoke_body).await;
    assert_eq!(invoke_status, StatusCode::FORBIDDEN);
    assert!(invoke_response["error"].as_str().unwrap().contains("revoked"));
}

#[tokio::test]
async fn test_revoke_invalid_scope() {
    let router = create_test_router();

    let (_, issuer_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let issuer_did = issuer_resp["did"].as_str().unwrap();
    let issuer_sk = issuer_resp["signing_key_hex"].as_str().unwrap();

    let cap_body = json!({
        "issuer_did": issuer_did,
        "signing_key_hex": issuer_sk,
        "subject": {"Transact": {"scope": "All"}},
        "constraints": [],
        "delegatable": true
    });
    let (_, cap_resp) = post_json(&router, "/capability/create", cap_body).await;
    let cap_id_hex = cap_resp["capability_id_hex"].as_str().unwrap();

    // Revoke with invalid scope
    let revoke_body = json!({
        "capability_id_hex": cap_id_hex,
        "revoker_did": issuer_did,
        "scope": "invalid_scope"
    });

    let (status, response) = post_json(&router, "/capability/revoke", revoke_body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(response["error"].as_str().unwrap().contains("Invalid scope"));
}

#[tokio::test]
async fn test_get_capability() {
    let router = create_test_router();

    // Create capability
    let (_, issuer_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let issuer_did = issuer_resp["did"].as_str().unwrap();
    let issuer_sk = issuer_resp["signing_key_hex"].as_str().unwrap();

    let cap_body = json!({
        "issuer_did": issuer_did,
        "signing_key_hex": issuer_sk,
        "subject": {"Transact": {"scope": "All"}},
        "constraints": [],
        "delegatable": true
    });
    let (_, cap_resp) = post_json(&router, "/capability/create", cap_body).await;
    let cap_id_hex = cap_resp["capability_id_hex"].as_str().unwrap();

    // Get capability
    let (status, response) = get_request(&router, &format!("/capability/{}", cap_id_hex)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(response["capability"].is_object());
}

#[tokio::test]
async fn test_get_nonexistent_capability() {
    let router = create_test_router();

    let fake_cap_id = "0".repeat(64);
    let (status, response) = get_request(&router, &format!("/capability/{}", fake_cap_id)).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(response["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn test_get_capability_invalid_hex() {
    let router = create_test_router();

    let (status, response) = get_request(&router, "/capability/not-valid-hex").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(response["error"].as_str().unwrap().contains("Invalid capability ID hex"));
}

#[tokio::test]
async fn test_list_capabilities_by_did() {
    let router = create_test_router();

    // Register identity
    let (_, issuer_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let issuer_did = issuer_resp["did"].as_str().unwrap();
    let issuer_sk = issuer_resp["signing_key_hex"].as_str().unwrap();

    // Initially no capabilities
    let (status, response) = get_request(&router, &format!("/capability/by-did/{}", issuer_did)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["capabilities"].as_array().unwrap().len(), 0);

    // Create a capability
    let cap_body = json!({
        "issuer_did": issuer_did,
        "signing_key_hex": issuer_sk,
        "subject": {"Transact": {"scope": "All"}},
        "constraints": [],
        "delegatable": true
    });
    post_json(&router, "/capability/create", cap_body).await;

    // Now should have 1 capability
    let (status, response) = get_request(&router, &format!("/capability/by-did/{}", issuer_did)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(response["capabilities"].is_array());
    let caps = response["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 1);

    // Verify the capability belongs to the issuer
    assert_eq!(caps[0]["issuer"].as_str().unwrap(), issuer_did);
}

// ============================================================================
// INTRODUCTION ENDPOINT TESTS
// ============================================================================

#[tokio::test]
async fn test_create_introduction() {
    let router = create_test_router();

    // Register two identities
    let (_, introducer_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let introducer_did = introducer_resp["did"].as_str().unwrap();
    let introducer_sk = introducer_resp["signing_key_hex"].as_str().unwrap();

    let (_, introduced_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let introduced_did = introduced_resp["did"].as_str().unwrap();

    // Create introduction
    let intro_body = json!({
        "introducer_did": introducer_did,
        "introducer_sk_hex": introducer_sk,
        "introduced_did": introduced_did,
        "edge_name": "Friend"
    });

    let (status, response) = post_json(&router, "/introduction", intro_body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["success"], true);
}

#[tokio::test]
async fn test_introduction_nonexistent_did() {
    let router = create_test_router();

    let (_, introducer_resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let introducer_did = introducer_resp["did"].as_str().unwrap();
    let introducer_sk = introducer_resp["signing_key_hex"].as_str().unwrap();

    let intro_body = json!({
        "introducer_did": introducer_did,
        "introducer_sk_hex": introducer_sk,
        "introduced_did": "did:disentangle:nonexistent",
        "edge_name": "Friend"
    });

    let (status, response) = post_json(&router, "/introduction", intro_body).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(response["error"].as_str().unwrap().contains("DID not found"));
}

// ============================================================================
// COHERENCE ENDPOINT TESTS
// ============================================================================

#[tokio::test]
async fn test_get_coherence_profile() {
    let router = create_test_router();

    // Register identity
    let (_, resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did = resp["did"].as_str().unwrap();

    // Get coherence profile
    let (status, response) = get_request(&router, &format!("/coherence/{}", did)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(response["profile"].is_object());
}

#[tokio::test]
async fn test_get_coherence_profile_nonexistent() {
    let router = create_test_router();

    let (status, _response) = get_request(&router, "/coherence/did:disentangle:nonexistent").await;

    // Note: get_coherence_profile returns Some even for nonexistent DIDs
    // because CoherenceProfile::compute doesn't check if DID exists
    // This might be expected behavior or could be a bug to fix
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_get_curvature_between_dids() {
    let router = create_test_router();

    // Register two identities and introduce them
    let (_, resp_a) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_a = resp_a["did"].as_str().unwrap();
    let sk_a = resp_a["signing_key_hex"].as_str().unwrap();

    let (_, resp_b) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_b = resp_b["did"].as_str().unwrap();

    // Introduce them
    let intro_body = json!({
        "introducer_did": did_a,
        "introducer_sk_hex": sk_a,
        "introduced_did": did_b,
        "edge_name": "Friend"
    });
    post_json(&router, "/introduction", intro_body).await;

    // Get curvature
    let (status, response) = get_request(&router, &format!("/coherence/curvature/{}/{}", did_a, did_b)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(response["curvature"].is_number());
}

#[tokio::test]
async fn test_get_neighbors() {
    let router = create_test_router();

    // Register two identities and introduce them
    let (_, resp_a) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_a = resp_a["did"].as_str().unwrap();
    let sk_a = resp_a["signing_key_hex"].as_str().unwrap();

    let (_, resp_b) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_b = resp_b["did"].as_str().unwrap();

    // Introduce them
    let intro_body = json!({
        "introducer_did": did_a,
        "introducer_sk_hex": sk_a,
        "introduced_did": did_b,
        "edge_name": "Friend"
    });
    post_json(&router, "/introduction", intro_body).await;

    // Get neighbors
    let (status, response) = get_request(&router, &format!("/coherence/neighbors/{}", did_a)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(response["neighbors"].is_array());
    let neighbors = response["neighbors"].as_array().unwrap();
    assert_eq!(neighbors.len(), 1);
    assert_eq!(neighbors[0].as_str().unwrap(), did_b);
}

// ============================================================================
// PETNAME ENDPOINT TESTS
// ============================================================================

#[tokio::test]
async fn test_set_petname() {
    let router = create_test_router();

    // Register identity
    let (_, resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did = resp["did"].as_str().unwrap();

    // Set petname
    let petname_body = json!({
        "name": "Alice",
        "did": did
    });

    let (status, response) = post_json(&router, "/petname", petname_body).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["success"], true);
}

#[tokio::test]
async fn test_resolve_petname() {
    let router = create_test_router();

    // Register identity
    let (_, resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did = resp["did"].as_str().unwrap();

    // Set petname
    let petname_body = json!({
        "name": "Bob",
        "did": did
    });
    post_json(&router, "/petname", petname_body).await;

    // Resolve it
    let (status, response) = get_request(&router, "/petname/Bob").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["did"].as_str().unwrap(), did);
}

#[tokio::test]
async fn test_resolve_nonexistent_petname() {
    let router = create_test_router();

    let (status, response) = get_request(&router, "/petname/NonExistent").await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(response["error"].as_str().unwrap().contains("not found"));
}

// ============================================================================
// END-TO-END WORKFLOW TESTS
// ============================================================================

#[tokio::test]
async fn test_full_capability_delegation_chain() {
    let router = create_test_router();

    // Register three identities: A -> B -> C
    let (_, resp_a) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_a = resp_a["did"].as_str().unwrap();
    let sk_a = resp_a["signing_key_hex"].as_str().unwrap();

    let (_, resp_b) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_b = resp_b["did"].as_str().unwrap();
    let sk_b = resp_b["signing_key_hex"].as_str().unwrap();

    let (_, resp_c) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_c = resp_c["did"].as_str().unwrap();

    // A creates capability
    let cap_body = json!({
        "issuer_did": did_a,
        "signing_key_hex": sk_a,
        "subject": {"Transact": {"scope": "All"}},
        "constraints": [],
        "delegatable": true
    });
    let (_, cap_resp) = post_json(&router, "/capability/create", cap_body).await;
    let cap_id_hex = cap_resp["capability_id_hex"].as_str().unwrap();

    // A delegates to B
    let delegate_ab = json!({
        "capability_id_hex": cap_id_hex,
        "delegator_did": did_a,
        "delegator_sk_hex": sk_a,
        "delegatee_did": did_b
    });
    let (status, _) = post_json(&router, "/capability/delegate", delegate_ab).await;
    assert_eq!(status, StatusCode::OK);

    // B delegates to C
    let delegate_bc = json!({
        "capability_id_hex": cap_id_hex,
        "delegator_did": did_b,
        "delegator_sk_hex": sk_b,
        "delegatee_did": did_c
    });
    let (status, _) = post_json(&router, "/capability/delegate", delegate_bc).await;
    assert_eq!(status, StatusCode::OK);

    // C can invoke the capability
    let invoke_body = json!({
        "capability_id_hex": cap_id_hex,
        "invoker_did": did_c
    });
    let (status, response) = post_json(&router, "/capability/invoke", invoke_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["success"], true);
}

#[tokio::test]
async fn test_coherence_with_introduction_graph() {
    let router = create_test_router();

    // Create a small social graph: A introduces B and C, B introduces D
    let (_, resp_a) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_a = resp_a["did"].as_str().unwrap();
    let sk_a = resp_a["signing_key_hex"].as_str().unwrap();

    let (_, resp_b) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_b = resp_b["did"].as_str().unwrap();
    let sk_b = resp_b["signing_key_hex"].as_str().unwrap();

    let (_, resp_c) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_c = resp_c["did"].as_str().unwrap();

    let (_, resp_d) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_d = resp_d["did"].as_str().unwrap();

    // A introduces B
    post_json(&router, "/introduction", json!({
        "introducer_did": did_a,
        "introducer_sk_hex": sk_a,
        "introduced_did": did_b,
        "edge_name": "Colleague"
    })).await;

    // A introduces C
    post_json(&router, "/introduction", json!({
        "introducer_did": did_a,
        "introducer_sk_hex": sk_a,
        "introduced_did": did_c,
        "edge_name": "Friend"
    })).await;

    // B introduces D
    post_json(&router, "/introduction", json!({
        "introducer_did": did_b,
        "introducer_sk_hex": sk_b,
        "introduced_did": did_d,
        "edge_name": "Friend"
    })).await;

    // Verify A has 2 neighbors
    let (status, response) = get_request(&router, &format!("/coherence/neighbors/{}", did_a)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["neighbors"].as_array().unwrap().len(), 2);

    // Verify A has a coherence profile
    let (status, response) = get_request(&router, &format!("/coherence/{}", did_a)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(response["profile"]["topological_mass"].is_number());
}

// ============================================================================
// CROSS-CRATE INTEGRATION TESTS: REVOCATION PROPAGATION + COHERENCE GATING
// ============================================================================

#[tokio::test]
async fn test_capability_revocation_prevents_downstream_invocation() {
    //! Verifies that revoking a capability at the root (A) prevents downstream
    //! delegatees (C) from invoking it, even though the delegation chain A->B->C
    //! was valid at creation time.
    //!
    //! This is a cross-crate boundary test: identity_state (capability store +
    //! revocation tracking via IdentityGraph) is exercised through the HTTP RPC layer.

    let router = create_test_router();

    // Register three identities: A, B, C
    let (_, resp_a) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_a = resp_a["did"].as_str().unwrap().to_string();
    let sk_a = resp_a["signing_key_hex"].as_str().unwrap().to_string();

    let (_, resp_b) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_b = resp_b["did"].as_str().unwrap().to_string();
    let sk_b = resp_b["signing_key_hex"].as_str().unwrap().to_string();

    let (_, resp_c) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_c = resp_c["did"].as_str().unwrap().to_string();

    // A creates a delegatable capability
    let cap_body = json!({
        "issuer_did": did_a,
        "signing_key_hex": sk_a,
        "subject": {"Transact": {"scope": "All"}},
        "constraints": [],
        "delegatable": true
    });
    let (status, cap_resp) = post_json(&router, "/capability/create", cap_body).await;
    assert_eq!(status, StatusCode::OK);
    let cap_id_hex = cap_resp["capability_id_hex"].as_str().unwrap().to_string();

    // A delegates to B
    let (status, _) = post_json(&router, "/capability/delegate", json!({
        "capability_id_hex": cap_id_hex,
        "delegator_did": did_a,
        "delegator_sk_hex": sk_a,
        "delegatee_did": did_b
    })).await;
    assert_eq!(status, StatusCode::OK);

    // B delegates to C
    let (status, _) = post_json(&router, "/capability/delegate", json!({
        "capability_id_hex": cap_id_hex,
        "delegator_did": did_b,
        "delegator_sk_hex": sk_b,
        "delegatee_did": did_c
    })).await;
    assert_eq!(status, StatusCode::OK);

    // Verify C can invoke before revocation
    let (status, response) = post_json(&router, "/capability/invoke", json!({
        "capability_id_hex": cap_id_hex,
        "invoker_did": did_c
    })).await;
    assert_eq!(status, StatusCode::OK, "C should be able to invoke before revocation");
    assert_eq!(response["success"], true);

    // A revokes the capability
    let (status, response) = post_json(&router, "/capability/revoke", json!({
        "capability_id_hex": cap_id_hex,
        "revoker_did": did_a,
        "scope": "single"
    })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["success"], true);

    // C should no longer be able to invoke
    let (status, response) = post_json(&router, "/capability/invoke", json!({
        "capability_id_hex": cap_id_hex,
        "invoker_did": did_c
    })).await;
    assert_eq!(status, StatusCode::FORBIDDEN,
        "C should NOT be able to invoke after A revoked the capability");
    assert!(
        response["error"].as_str().unwrap().contains("revoked"),
        "Error should mention revocation, got: {}",
        response["error"]
    );

    // B should also be blocked
    let (status, response) = post_json(&router, "/capability/invoke", json!({
        "capability_id_hex": cap_id_hex,
        "invoker_did": did_b
    })).await;
    assert_eq!(status, StatusCode::FORBIDDEN,
        "B should NOT be able to invoke after A revoked the capability");
    assert!(
        response["error"].as_str().unwrap().contains("revoked"),
        "Error should mention revocation for B as well"
    );

    // Even the original issuer A is blocked (revocation is absolute)
    let (status, response) = post_json(&router, "/capability/invoke", json!({
        "capability_id_hex": cap_id_hex,
        "invoker_did": did_a
    })).await;
    assert_eq!(status, StatusCode::FORBIDDEN,
        "A should NOT be able to invoke their own revoked capability");
    assert!(
        response["error"].as_str().unwrap().contains("revoked"),
        "Error should mention revocation for A as well"
    );
}

#[tokio::test]
async fn test_combined_delegation_and_coherence_constraint() {
    //! Verifies the cross-crate interaction between the introduction graph
    //! (coherence computation from disentangle-identity) and capability
    //! constraint evaluation (from disentangle-identity::capability),
    //! exercised through the HTTP RPC layer (disentangle-node).
    //!
    //! Creates a capability with a CoherenceMinimum constraint, builds an
    //! introduction graph so one agent has high coherence and another has
    //! zero coherence, then verifies that only the high-coherence agent
    //! can invoke the capability.

    let router = create_test_router();

    // Register identities: issuer + hub agent + connected agents + isolated agent
    let (_, resp_issuer) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_issuer = resp_issuer["did"].as_str().unwrap().to_string();
    let sk_issuer = resp_issuer["signing_key_hex"].as_str().unwrap().to_string();

    // "Hub" agent -- will have high coherence through many positive-curvature edges
    let (_, resp_hub) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_hub = resp_hub["did"].as_str().unwrap().to_string();
    let sk_hub = resp_hub["signing_key_hex"].as_str().unwrap().to_string();

    // Create several agents to form a mesh around the hub
    let mut mesh_dids = vec![];
    let mut mesh_sks = vec![];
    for _ in 0..5 {
        let (_, resp) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
        mesh_dids.push(resp["did"].as_str().unwrap().to_string());
        mesh_sks.push(resp["signing_key_hex"].as_str().unwrap().to_string());
    }

    // Isolated agent -- zero coherence (no introductions at all)
    let (_, resp_isolated) = post_json(&router, "/identity/register", json!({"agent_type": "human"})).await;
    let did_isolated = resp_isolated["did"].as_str().unwrap().to_string();

    // Build introduction graph: hub introduces all mesh agents
    for i in 0..mesh_dids.len() {
        let (status, _) = post_json(&router, "/introduction", json!({
            "introducer_did": did_hub,
            "introducer_sk_hex": sk_hub,
            "introduced_did": mesh_dids[i],
            "edge_name": "Colleague"
        })).await;
        assert_eq!(status, StatusCode::OK);
    }

    // Mesh agents introduce each other to create triangles (positive curvature)
    for i in 0..mesh_dids.len() {
        for j in (i + 1)..mesh_dids.len() {
            let (status, _) = post_json(&router, "/introduction", json!({
                "introducer_did": mesh_dids[i],
                "introducer_sk_hex": mesh_sks[i],
                "introduced_did": mesh_dids[j],
                "edge_name": "Peer"
            })).await;
            assert_eq!(status, StatusCode::OK);
        }
    }

    // Also connect issuer to the hub so issuer has introductions
    let (status, _) = post_json(&router, "/introduction", json!({
        "introducer_did": did_issuer,
        "introducer_sk_hex": sk_issuer,
        "introduced_did": did_hub,
        "edge_name": "Friend"
    })).await;
    assert_eq!(status, StatusCode::OK);

    // Verify hub has high coherence (topological_mass > 0)
    let (status, hub_profile) = get_request(&router, &format!("/coherence/{}", did_hub)).await;
    assert_eq!(status, StatusCode::OK);
    let hub_mass = hub_profile["profile"]["topological_mass"].as_i64().unwrap();
    println!("    Hub topological mass: {}", hub_mass);
    assert!(hub_mass > 0, "Hub should have positive topological mass from mesh connections");

    // Verify isolated agent has zero coherence
    let (status, isolated_profile) = get_request(&router, &format!("/coherence/{}", did_isolated)).await;
    assert_eq!(status, StatusCode::OK);
    let isolated_mass = isolated_profile["profile"]["topological_mass"].as_i64().unwrap();
    println!("    Isolated agent topological mass: {}", isolated_mass);
    assert_eq!(isolated_mass, 0, "Isolated agent should have zero topological mass");

    // Create a capability with CoherenceMinimum constraint.
    // The min_mass is in units of topological_mass / SCALE, so we set it
    // to a value that the hub can satisfy but the isolated agent cannot.
    // Since CoherenceMinimum checks (topological_mass / SCALE) >= min_mass,
    // and SCALE = 65536, we need hub_mass / 65536 >= our min_mass.
    let min_mass_threshold = 1u64; // Hub with positive mass should pass; isolated with 0 fails

    let cap_body = json!({
        "issuer_did": did_issuer,
        "signing_key_hex": sk_issuer,
        "subject": {"Transact": {"scope": "All"}},
        "constraints": [
            {"CoherenceMinimum": {"min_mass": min_mass_threshold}}
        ],
        "delegatable": true
    });
    let (status, cap_resp) = post_json(&router, "/capability/create", cap_body).await;
    assert_eq!(status, StatusCode::OK);
    let cap_id_hex = cap_resp["capability_id_hex"].as_str().unwrap().to_string();

    // Delegate to both hub and isolated
    let (status, _) = post_json(&router, "/capability/delegate", json!({
        "capability_id_hex": cap_id_hex,
        "delegator_did": did_issuer,
        "delegator_sk_hex": sk_issuer,
        "delegatee_did": did_hub
    })).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = post_json(&router, "/capability/delegate", json!({
        "capability_id_hex": cap_id_hex,
        "delegator_did": did_issuer,
        "delegator_sk_hex": sk_issuer,
        "delegatee_did": did_isolated
    })).await;
    assert_eq!(status, StatusCode::OK);

    // Hub should be able to invoke (high coherence >= min_mass)
    let (status, response) = post_json(&router, "/capability/invoke", json!({
        "capability_id_hex": cap_id_hex,
        "invoker_did": did_hub
    })).await;
    assert_eq!(status, StatusCode::OK,
        "Hub agent with high coherence should be able to invoke. Response: {:?}",
        response);
    assert_eq!(response["success"], true);

    // Isolated agent should be blocked (zero coherence < min_mass)
    let (status, response) = post_json(&router, "/capability/invoke", json!({
        "capability_id_hex": cap_id_hex,
        "invoker_did": did_isolated
    })).await;
    assert_eq!(status, StatusCode::FORBIDDEN,
        "Isolated agent with zero coherence should be blocked by CoherenceMinimum constraint. Response: {:?}",
        response);
    assert!(
        response["error"].as_str().unwrap().contains("constraint") ||
        response["error"].as_str().unwrap().contains("not met") ||
        response["error"].as_str().unwrap().contains("not permitted"),
        "Error should indicate constraint failure, got: {}",
        response["error"]
    );
}
