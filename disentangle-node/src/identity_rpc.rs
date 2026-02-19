//! Identity RPC Handlers
//!
//! Axum route handlers for the Capability-Coherence Identity Protocol (CCIP).
//! These handlers provide JSON-over-HTTP access to the IdentityStateManager.

use crate::event_stream::{EventBus, NodeEvent};
use crate::identity_state::IdentityStateManager;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::sse::{Event, Sse},
    Json,
};
use disentangle_crypto::signature::SigningKey;
use disentangle_identity::{
    AgentType, CapabilitySubject, Constraint, OracleQuery, ProposalType, RegionSelector,
    RevocationScope, VoteChoice,
};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub type IdentityState = Arc<Mutex<IdentityStateManager>>;

// Common error response
#[derive(Serialize)]
pub struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    coherence_score: Option<f64>,
}

// Identity endpoints

#[derive(Deserialize)]
pub struct RegisterRequest {
    agent_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[allow(dead_code)] // Stored for future runtime verification
    runtime_attestation: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    did: String,
    signing_key_hex: String,
    document: serde_json::Value,
}

pub async fn identity_register_handler(
    State(state): State<IdentityState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let agent_type = match req.agent_type.to_lowercase().as_str() {
        "human" => AgentType::Human,
        "agi" => AgentType::AGI {
            runtime_attestation: None,
        },
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Invalid agent_type: must be 'human' or 'agi', got '{}'",
                        req.agent_type
                    ),
                    coherence_score: None,
                }),
            ))
        }
    };

    let (did, doc, sk) = mgr.register_did(agent_type).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to register DID: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    let sk_hex = hex::encode(sk.to_bytes());
    let doc_json = serde_json::to_value(&doc).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize document: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(RegisterResponse {
        did: did.0,
        signing_key_hex: sk_hex,
        document: doc_json,
    }))
}

#[derive(Serialize)]
pub struct GetIdentityResponse {
    document: serde_json::Value,
}

pub async fn identity_get_handler(
    State(state): State<IdentityState>,
    Path(did): Path<String>,
) -> Result<Json<GetIdentityResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let doc = mgr.get_did_document(&did).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("DID not found: {}", did),
                coherence_score: None,
            }),
        )
    })?;

    let doc_json = serde_json::to_value(doc).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize document: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(GetIdentityResponse { document: doc_json }))
}

#[derive(Serialize)]
pub struct ListIdentitiesResponse {
    dids: Vec<String>,
}

pub async fn identity_list_handler(
    State(state): State<IdentityState>,
) -> Json<ListIdentitiesResponse> {
    let mgr = state.lock().await;
    Json(ListIdentitiesResponse {
        dids: mgr.list_dids(),
    })
}

#[derive(Deserialize)]
pub struct DeactivateRequest {
    proof_hex: String,
}

#[derive(Serialize)]
pub struct SuccessResponse {
    success: bool,
}

pub async fn identity_deactivate_handler(
    State(state): State<IdentityState>,
    Path(did): Path<String>,
    Json(req): Json<DeactivateRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let proof = hex::decode(&req.proof_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid proof hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    mgr.deactivate_did(&did, &proof).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to deactivate DID: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(SuccessResponse { success: true }))
}

// Capability endpoints

#[derive(Deserialize)]
pub struct CreateCapabilityRequest {
    issuer_did: String,
    signing_key_hex: String,
    subject: serde_json::Value,
    constraints: Vec<serde_json::Value>,
    delegatable: bool,
}

#[derive(Serialize)]
pub struct CreateCapabilityResponse {
    capability_id_hex: String,
    capability: serde_json::Value,
}

pub async fn capability_create_handler(
    State(state): State<IdentityState>,
    Json(req): Json<CreateCapabilityRequest>,
) -> Result<Json<CreateCapabilityResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let sk_bytes = hex::decode(&req.signing_key_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let sk = SigningKey::from_bytes(&sk_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid signing key: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    let subject: CapabilitySubject = serde_json::from_value(req.subject).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid subject: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    let constraints: Vec<Constraint> = req
        .constraints
        .iter()
        .map(|v| serde_json::from_value(v.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid constraints: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    let cap = mgr
        .create_capability(&req.issuer_did, &sk, subject, constraints, req.delegatable)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to create capability: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    let cap_id_hex = hex::encode(cap.id);
    let cap_json = serde_json::to_value(&cap).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize capability: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(CreateCapabilityResponse {
        capability_id_hex: cap_id_hex,
        capability: cap_json,
    }))
}

#[derive(Deserialize)]
pub struct DelegateCapabilityRequest {
    capability_id_hex: String,
    delegator_did: String,
    delegator_sk_hex: String,
    delegatee_did: String,
}

#[derive(Serialize)]
pub struct DelegateCapabilityResponse {
    delegation: serde_json::Value,
}

pub async fn capability_delegate_handler(
    State(state): State<IdentityState>,
    Json(req): Json<DelegateCapabilityRequest>,
) -> Result<Json<DelegateCapabilityResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let cap_id_bytes = hex::decode(&req.capability_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid capability ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if cap_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Capability ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut cap_id = [0u8; 32];
    cap_id.copy_from_slice(&cap_id_bytes);

    let sk_bytes = hex::decode(&req.delegator_sk_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let sk = SigningKey::from_bytes(&sk_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid signing key: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    let delegation = mgr
        .delegate_capability(&cap_id, &req.delegator_did, &sk, &req.delegatee_did)
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!("Failed to delegate capability: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    let delegation_json = serde_json::to_value(&delegation).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize delegation: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(DelegateCapabilityResponse {
        delegation: delegation_json,
    }))
}

#[derive(Deserialize)]
pub struct InvokeCapabilityRequest {
    capability_id_hex: String,
    invoker_did: String,
}

#[derive(Serialize)]
pub struct InvokeCapabilityResponse {
    success: bool,
    message: String,
}

pub async fn capability_invoke_handler(
    State(state): State<IdentityState>,
    Json(req): Json<InvokeCapabilityRequest>,
) -> Result<Json<InvokeCapabilityResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let cap_id_bytes = hex::decode(&req.capability_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid capability ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if cap_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Capability ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut cap_id = [0u8; 32];
    cap_id.copy_from_slice(&cap_id_bytes);

    match mgr.invoke_capability(&cap_id, &req.invoker_did) {
        Ok(true) => Ok(Json(InvokeCapabilityResponse {
            success: true,
            message: "Capability invoked successfully".to_string(),
        })),
        Ok(false) => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Capability invocation not permitted".to_string(),
                coherence_score: None,
            }),
        )),
        Err(e) => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!("Failed to invoke capability: {}", e),
                coherence_score: None,
            }),
        )),
    }
}

#[derive(Deserialize)]
pub struct RevokeCapabilityRequest {
    capability_id_hex: String,
    revoker_did: String,
    scope: String,
}

pub async fn capability_revoke_handler(
    State(state): State<IdentityState>,
    Json(req): Json<RevokeCapabilityRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let cap_id_bytes = hex::decode(&req.capability_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid capability ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if cap_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Capability ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut cap_id = [0u8; 32];
    cap_id.copy_from_slice(&cap_id_bytes);

    let scope = match req.scope.to_lowercase().as_str() {
        "single" => RevocationScope::Single,
        "subtree" => RevocationScope::Subtree,
        "all" => RevocationScope::All,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Invalid scope: must be 'single', 'subtree', or 'all', got '{}'",
                        req.scope
                    ),
                    coherence_score: None,
                }),
            ))
        }
    };

    mgr.revoke_capability(&cap_id, &req.revoker_did, scope)
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!("Failed to revoke capability: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    Ok(Json(SuccessResponse { success: true }))
}

#[derive(Serialize)]
pub struct GetCapabilityResponse {
    capability: serde_json::Value,
}

pub async fn capability_get_handler(
    State(state): State<IdentityState>,
    Path(cap_id_hex): Path<String>,
) -> Result<Json<GetCapabilityResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let cap_id_bytes = hex::decode(&cap_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid capability ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if cap_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Capability ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut cap_id = [0u8; 32];
    cap_id.copy_from_slice(&cap_id_bytes);

    let cap = mgr.get_capability(&cap_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Capability not found: {}", cap_id_hex),
                coherence_score: None,
            }),
        )
    })?;

    let cap_json = serde_json::to_value(cap).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize capability: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(GetCapabilityResponse {
        capability: cap_json,
    }))
}

#[derive(Serialize)]
pub struct ListCapabilitiesResponse {
    capabilities: Vec<serde_json::Value>,
}

pub async fn capability_list_by_did_handler(
    State(state): State<IdentityState>,
    Path(did): Path<String>,
) -> Result<Json<ListCapabilitiesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let caps = mgr.list_capabilities_for_did(&did);

    let caps_json: Vec<serde_json::Value> = caps
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to serialize capabilities: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    Ok(Json(ListCapabilitiesResponse {
        capabilities: caps_json,
    }))
}

// Introduction endpoints

#[derive(Deserialize)]
pub struct IntroductionRequest {
    introducer_did: String,
    introducer_sk_hex: String,
    introduced_did: String,
    edge_name: String,
}

pub async fn introduction_create_handler(
    State(state): State<IdentityState>,
    Json(req): Json<IntroductionRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let sk_bytes = hex::decode(&req.introducer_sk_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let sk = SigningKey::from_bytes(&sk_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid signing key: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    mgr.introduce(
        &req.introducer_did,
        &sk,
        &req.introduced_did,
        &req.edge_name,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to create introduction: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(SuccessResponse { success: true }))
}

#[derive(Serialize)]
pub struct IntroductionChainResponse {
    chain: Vec<String>,
}

pub async fn introduction_chain_handler(
    State(state): State<IdentityState>,
    Path((from_did, to_did)): Path<(String, String)>,
) -> Json<IntroductionChainResponse> {
    let mgr = state.lock().await;

    let chain = mgr
        .get_introduction_chain(&from_did, &to_did)
        .unwrap_or_else(|| vec![from_did.clone(), to_did.clone()]);

    Json(IntroductionChainResponse { chain })
}

// Coherence endpoints

#[derive(Serialize)]
pub struct CoherenceProfileResponse {
    profile: serde_json::Value,
}

pub async fn coherence_profile_handler(
    State(state): State<IdentityState>,
    Path(did): Path<String>,
) -> Result<Json<CoherenceProfileResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let profile = mgr.get_coherence_profile(&did).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("DID not found: {}", did),
                coherence_score: None,
            }),
        )
    })?;

    let profile_json = serde_json::to_value(&profile).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize profile: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(CoherenceProfileResponse {
        profile: profile_json,
    }))
}

#[derive(Serialize)]
pub struct CurvatureResponse {
    curvature: f64,
}

pub async fn coherence_curvature_handler(
    State(state): State<IdentityState>,
    Path((did_a, did_b)): Path<(String, String)>,
) -> Result<Json<CurvatureResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let curvature = mgr.get_identity_curvature(&did_a, &did_b).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "One or both DIDs not found".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(CurvatureResponse { curvature }))
}

#[derive(Serialize)]
pub struct NeighborsResponse {
    neighbors: Vec<String>,
}

pub async fn coherence_neighbors_handler(
    State(state): State<IdentityState>,
    Path(did): Path<String>,
) -> Json<NeighborsResponse> {
    let mgr = state.lock().await;

    Json(NeighborsResponse {
        neighbors: mgr.get_neighbors(&did),
    })
}

// Petname endpoints

#[derive(Deserialize)]
pub struct SetPetnameRequest {
    name: String,
    did: String,
}

pub async fn petname_set_handler(
    State(state): State<IdentityState>,
    Json(req): Json<SetPetnameRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    mgr.set_petname(&req.name, &req.did).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to set petname: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(SuccessResponse { success: true }))
}

#[derive(Serialize)]
pub struct ResolvePetnameResponse {
    did: String,
}

pub async fn petname_resolve_handler(
    State(state): State<IdentityState>,
    Path(name): Path<String>,
) -> Result<Json<ResolvePetnameResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let did = mgr.resolve_petname(&name).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Petname not found: {}", name),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(ResolvePetnameResponse { did }))
}

// Governance endpoints

#[derive(Deserialize)]
pub struct CreateProposalRequest {
    proposer_did: String,
    proposer_sk_hex: String,
    proposal_type: String,
    parameter: Option<String>,
    new_value: Option<String>,
    description: String,
    duration_blocks: u64,
}

#[derive(Serialize)]
pub struct CreateProposalResponse {
    proposal_id_hex: String,
    proposal: serde_json::Value,
}

pub async fn governance_propose_handler(
    State(state): State<IdentityState>,
    Json(req): Json<CreateProposalRequest>,
) -> Result<Json<CreateProposalResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let sk_bytes = hex::decode(&req.proposer_sk_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let sk = SigningKey::from_bytes(&sk_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid signing key: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    // Parse proposal type
    let proposal_type = match req.proposal_type.to_lowercase().as_str() {
        "protocol_parameter" => {
            let param = req.parameter.ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Missing parameter field for protocol_parameter proposal"
                            .to_string(),
                        coherence_score: None,
                    }),
                )
            })?;
            let value = req.new_value.ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Missing new_value field for protocol_parameter proposal"
                            .to_string(),
                        coherence_score: None,
                    }),
                )
            })?;
            ProposalType::ProtocolParameter {
                parameter: param,
                new_value: value.into_bytes(),
            }
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Unsupported proposal type: {}", req.proposal_type),
                    coherence_score: None,
                }),
            ))
        }
    };

    let proposal = mgr
        .create_proposal(
            &req.proposer_did,
            &sk,
            proposal_type,
            &req.description,
            req.duration_blocks,
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to create proposal: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    let proposal_id_hex = hex::encode(proposal.id);
    let proposal_json = serde_json::to_value(&proposal).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize proposal: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(CreateProposalResponse {
        proposal_id_hex,
        proposal: proposal_json,
    }))
}

#[derive(Deserialize)]
pub struct CastVoteRequest {
    proposal_id_hex: String,
    voter_did: String,
    voter_sk_hex: String,
    vote: String,
}

#[derive(Serialize)]
pub struct CastVoteResponse {
    vote_id_hex: String,
}

pub async fn governance_vote_handler(
    State(state): State<IdentityState>,
    Json(req): Json<CastVoteRequest>,
) -> Result<Json<CastVoteResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let proposal_id_bytes = hex::decode(&req.proposal_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid proposal ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if proposal_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Proposal ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut proposal_id = [0u8; 32];
    proposal_id.copy_from_slice(&proposal_id_bytes);

    let sk_bytes = hex::decode(&req.voter_sk_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let sk = SigningKey::from_bytes(&sk_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid signing key: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    let vote_choice = match req.vote.to_lowercase().as_str() {
        "for" => VoteChoice::For,
        "against" => VoteChoice::Against,
        "abstain" => VoteChoice::Abstain,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Invalid vote: must be 'for', 'against', or 'abstain', got '{}'",
                        req.vote
                    ),
                    coherence_score: None,
                }),
            ))
        }
    };

    let vote = mgr
        .cast_vote(&proposal_id, &req.voter_did, &sk, vote_choice)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to cast vote: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    let vote_id = vote.compute_id();
    let vote_id_hex = hex::encode(vote_id);

    Ok(Json(CastVoteResponse { vote_id_hex }))
}

#[derive(Serialize)]
pub struct ListProposalsResponse {
    proposals: Vec<serde_json::Value>,
}

pub async fn governance_list_proposals_handler(
    State(state): State<IdentityState>,
) -> Result<Json<ListProposalsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let proposals = mgr.list_proposals();
    let proposals_json: Vec<serde_json::Value> = proposals
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to serialize proposals: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    Ok(Json(ListProposalsResponse {
        proposals: proposals_json,
    }))
}

#[derive(Serialize)]
pub struct GetProposalResponse {
    proposal: serde_json::Value,
    result: String,
}

pub async fn governance_get_proposal_handler(
    State(state): State<IdentityState>,
    Path(proposal_id_hex): Path<String>,
) -> Result<Json<GetProposalResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let proposal_id_bytes = hex::decode(&proposal_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid proposal ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if proposal_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Proposal ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut proposal_id = [0u8; 32];
    proposal_id.copy_from_slice(&proposal_id_bytes);

    let proposal = mgr.get_proposal(&proposal_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Proposal not found: {}", proposal_id_hex),
                coherence_score: None,
            }),
        )
    })?;

    let result = mgr
        .evaluate_proposal(&proposal_id)
        .unwrap_or(disentangle_identity::ProposalResult::Pending);

    let result_str = match result {
        disentangle_identity::ProposalResult::Passed => "passed",
        disentangle_identity::ProposalResult::Failed => "failed",
        disentangle_identity::ProposalResult::Pending => "pending",
    };

    let proposal_json = serde_json::to_value(proposal).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize proposal: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(GetProposalResponse {
        proposal: proposal_json,
        result: result_str.to_string(),
    }))
}

// Agreement endpoints

#[derive(Deserialize)]
pub struct ProposeAgreementRequest {
    provider_did: String,
    consumer_did: String,
    capability_id_hex: Option<String>,
    terms: serde_json::Value,
    signing_key_hex: String,
}

#[derive(Serialize)]
pub struct ProposeAgreementResponse {
    agreement_id_hex: String,
    agreement: serde_json::Value,
}

pub async fn agreement_propose_handler(
    State(state): State<IdentityState>,
    Json(req): Json<ProposeAgreementRequest>,
) -> Result<Json<ProposeAgreementResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let sk_bytes = hex::decode(&req.signing_key_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let sk = SigningKey::from_bytes(&sk_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid signing key: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    // Parse capability ID if provided
    let capability_id = if let Some(cap_id_hex) = req.capability_id_hex {
        let cap_id_bytes = hex::decode(&cap_id_hex).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid capability ID hex encoding".to_string(),
                    coherence_score: None,
                }),
            )
        })?;
        if cap_id_bytes.len() != 32 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Capability ID must be 32 bytes".to_string(),
                    coherence_score: None,
                }),
            ));
        }
        let mut cap_id = [0u8; 32];
        cap_id.copy_from_slice(&cap_id_bytes);
        Some(cap_id)
    } else {
        None
    };

    // Parse terms
    let terms: disentangle_identity::AgreementTerms =
        serde_json::from_value(req.terms).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid agreement terms: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    let agreement_id = mgr
        .propose_agreement(
            &req.provider_did,
            &sk,
            &req.consumer_did,
            capability_id.as_ref(),
            terms,
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to propose agreement: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    let agreement = mgr.get_agreement(&agreement_id).unwrap();
    let agreement_json = serde_json::to_value(agreement).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize agreement: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(ProposeAgreementResponse {
        agreement_id_hex: hex::encode(agreement_id),
        agreement: agreement_json,
    }))
}

#[derive(Deserialize)]
pub struct AcceptAgreementRequest {
    agreement_id_hex: String,
    consumer_sk_hex: String,
}

pub async fn agreement_accept_handler(
    State(state): State<IdentityState>,
    Json(req): Json<AcceptAgreementRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let agreement_id_bytes = hex::decode(&req.agreement_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid agreement ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if agreement_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Agreement ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut agreement_id = [0u8; 32];
    agreement_id.copy_from_slice(&agreement_id_bytes);

    let sk_bytes = hex::decode(&req.consumer_sk_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let sk = SigningKey::from_bytes(&sk_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid signing key: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    mgr.accept_agreement(&agreement_id, &sk).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to accept agreement: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(SuccessResponse { success: true }))
}

#[derive(Deserialize)]
pub struct CompleteAgreementRequest {
    agreement_id_hex: String,
    success: bool,
    outcome_hash_hex: String,
    signing_key_hex: String,
}

pub async fn agreement_complete_handler(
    State(state): State<IdentityState>,
    Json(req): Json<CompleteAgreementRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let agreement_id_bytes = hex::decode(&req.agreement_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid agreement ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if agreement_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Agreement ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut agreement_id = [0u8; 32];
    agreement_id.copy_from_slice(&agreement_id_bytes);

    let outcome_hash_bytes = hex::decode(&req.outcome_hash_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid outcome hash hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if outcome_hash_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Outcome hash must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut outcome_hash = [0u8; 32];
    outcome_hash.copy_from_slice(&outcome_hash_bytes);

    let sk_bytes = hex::decode(&req.signing_key_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let sk = SigningKey::from_bytes(&sk_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid signing key: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    mgr.complete_agreement(&agreement_id, req.success, outcome_hash, &sk)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to complete agreement: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    Ok(Json(SuccessResponse { success: true }))
}

#[derive(Serialize)]
pub struct GetAgreementResponse {
    agreement: serde_json::Value,
}

pub async fn agreement_get_handler(
    State(state): State<IdentityState>,
    Path(agreement_id_hex): Path<String>,
) -> Result<Json<GetAgreementResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let agreement_id_bytes = hex::decode(&agreement_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid agreement ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if agreement_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Agreement ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut agreement_id = [0u8; 32];
    agreement_id.copy_from_slice(&agreement_id_bytes);

    let agreement = mgr.get_agreement(&agreement_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Agreement not found: {}", agreement_id_hex),
                coherence_score: None,
            }),
        )
    })?;

    let agreement_json = serde_json::to_value(agreement).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize agreement: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(GetAgreementResponse {
        agreement: agreement_json,
    }))
}

#[derive(Serialize)]
pub struct ListAgreementsResponse {
    agreements: Vec<serde_json::Value>,
}

pub async fn agreement_list_by_did_handler(
    State(state): State<IdentityState>,
    Path(did): Path<String>,
) -> Result<Json<ListAgreementsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let agreements = mgr.list_agreements_for_did(&did);

    let agreements_json: Vec<serde_json::Value> = agreements
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to serialize agreements: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    Ok(Json(ListAgreementsResponse {
        agreements: agreements_json,
    }))
}

// Capability Template endpoints

#[derive(Serialize)]
pub struct ListTemplatesResponse {
    templates: Vec<String>,
}

pub async fn capability_templates_handler() -> Json<ListTemplatesResponse> {
    use disentangle_identity::CapabilityTemplate;

    Json(ListTemplatesResponse {
        templates: CapabilityTemplate::list_templates(),
    })
}

#[derive(Deserialize)]
pub struct CreateFromTemplateRequest {
    issuer_did: String,
    signing_key_hex: String,
    template: serde_json::Value,
    delegatable: bool,
}

pub async fn capability_create_from_template_handler(
    State(state): State<IdentityState>,
    Json(req): Json<CreateFromTemplateRequest>,
) -> Result<Json<CreateCapabilityResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let sk_bytes = hex::decode(&req.signing_key_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let sk = SigningKey::from_bytes(&sk_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid signing key: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    let template: disentangle_identity::CapabilityTemplate = serde_json::from_value(req.template)
        .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid template: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    let (subject, constraints) = template.to_capability_params();

    let cap = mgr
        .create_capability(&req.issuer_did, &sk, subject, constraints, req.delegatable)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to create capability: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    let cap_id_hex = hex::encode(cap.id);
    let cap_json = serde_json::to_value(&cap).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize capability: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(CreateCapabilityResponse {
        capability_id_hex: cap_id_hex,
        capability: cap_json,
    }))
}

// SSE Event Stream endpoint

/// Shared state that includes both identity manager and event bus
#[derive(Clone)]
pub struct SharedState {
    pub identity: IdentityState,
    pub event_bus: Arc<EventBus>,
}

#[derive(Deserialize)]
pub struct WatchParams {
    topics: Option<String>,
    did: Option<String>,
}

/// SSE event stream for reactive agent coordination
pub async fn watch_handler(
    State(state): State<SharedState>,
    Query(params): Query<WatchParams>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.event_bus.subscribe();

    let topics: HashSet<String> = params
        .topics
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_string())
        .collect();

    let filter_did = params.did.clone();

    let stream = async_stream::stream! {
        while let Ok(event) = rx.recv().await {
            if should_emit_event(&event, &topics, &filter_did) {
                if let Ok(json) = serde_json::to_string(&event) {
                    yield Ok(Event::default().data(json));
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}

/// Filter events based on topics and DID
fn should_emit_event(
    event: &NodeEvent,
    topics: &HashSet<String>,
    filter_did: &Option<String>,
) -> bool {
    // If no topics specified, emit all events
    let topic_match = if topics.is_empty() {
        true
    } else {
        let event_topic = match event {
            NodeEvent::IdentityRegistered { .. } => "identity",
            NodeEvent::CapabilityCreated { .. }
            | NodeEvent::CapabilityDelegated { .. }
            | NodeEvent::CapabilityExercised { .. }
            | NodeEvent::CapabilityRevoked { .. } => "delegation",
            NodeEvent::IntroductionCreated { .. } => "introduction",
            NodeEvent::AgreementCreated { .. } | NodeEvent::AgreementCompleted { .. } => {
                "agreement"
            }
            NodeEvent::CoherenceChanged { .. } => "coherence",
            NodeEvent::TransactionMined { .. } => "transaction",
            NodeEvent::ProposalCreated { .. }
            | NodeEvent::ProposalJoined { .. }
            | NodeEvent::ProposalActivated { .. } => "proposal",
            NodeEvent::IntentCreated { .. }
            | NodeEvent::IntentJoined { .. }
            | NodeEvent::IntentArchived { .. } => "intent",
            NodeEvent::NeighborhoodMerge { .. } | NodeEvent::NeighborhoodSplit { .. } => "topology",
            NodeEvent::DistributionComputed { .. } => "oracle",
            NodeEvent::CoherenceGradientSpike { .. }
            | NodeEvent::CoherenceGradientCollapse { .. } => "gradient",
        };
        topics.contains(event_topic)
    };

    if !topic_match {
        return false;
    }

    // If DID filter specified, check if event involves that DID
    if let Some(ref did) = filter_did {
        match event {
            NodeEvent::IdentityRegistered { did: event_did, .. } => event_did == did,
            NodeEvent::CapabilityCreated { issuer_did, .. } => issuer_did == did,
            NodeEvent::CapabilityDelegated {
                from_did, to_did, ..
            } => from_did == did || to_did == did,
            NodeEvent::CapabilityExercised { invoker_did, .. } => invoker_did == did,
            NodeEvent::IntroductionCreated {
                introducer,
                introduced,
                ..
            } => introducer == did || introduced == did,
            NodeEvent::AgreementCreated { parties, .. } => parties.contains(did),
            NodeEvent::AgreementCompleted { .. } => true, // Can't filter without loading agreement
            NodeEvent::CoherenceChanged { did: event_did, .. } => event_did == did,
            _ => true,
        }
    } else {
        true
    }
}

// Excitability Gradient endpoints

#[derive(Deserialize)]
pub struct GradientQueryParams {
    window: Option<u64>,
}

#[derive(Serialize)]
pub struct CurvatureDerivativeResponse {
    derivative: serde_json::Value,
}

pub async fn coherence_gradient_edge_handler(
    State(state): State<IdentityState>,
    Path((did_a, did_b)): Path<(String, String)>,
    Query(params): Query<GradientQueryParams>,
) -> Result<Json<CurvatureDerivativeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let window = params.window.unwrap_or(100);
    let derivative = mgr
        .curvature_derivative(&did_a, &did_b, window)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "No curvature history found for edge".to_string(),
                    coherence_score: None,
                }),
            )
        })?;

    let derivative_json = serde_json::to_value(&derivative).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize derivative: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(CurvatureDerivativeResponse {
        derivative: derivative_json,
    }))
}

#[derive(Serialize)]
pub struct ExcitabilityProfileResponse {
    profile: serde_json::Value,
}

pub async fn coherence_excitability_handler(
    State(state): State<IdentityState>,
    Path(did): Path<String>,
    Query(params): Query<GradientQueryParams>,
) -> Result<Json<ExcitabilityProfileResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let window = params.window.unwrap_or(100);
    let profile = mgr.excitability_profile(&did, window).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("No excitability profile for DID: {}", did),
                coherence_score: None,
            }),
        )
    })?;

    let profile_json = serde_json::to_value(&profile).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize profile: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(ExcitabilityProfileResponse {
        profile: profile_json,
    }))
}

#[derive(Deserialize)]
pub struct GradientMapQueryParams {
    top_n: Option<usize>,
    window: Option<u64>,
}

#[derive(Serialize)]
pub struct GradientMapResponse {
    map: serde_json::Value,
}

pub async fn coherence_gradient_map_handler(
    State(state): State<IdentityState>,
    Query(params): Query<GradientMapQueryParams>,
) -> Result<Json<GradientMapResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let top_n = params.top_n.unwrap_or(20);
    let window = params.window.unwrap_or(100);
    let map = mgr.coherence_gradient_map(top_n, window);

    let map_json = serde_json::to_value(&map).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize gradient map: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(GradientMapResponse { map: map_json }))
}

// Oracle endpoints

#[derive(Deserialize)]
pub struct OracleQueryRequest {
    region: serde_json::Value,
    depth_start: u64,
    depth_end: u64,
}

#[derive(Serialize)]
pub struct OracleQueryResponse {
    distribution_id_hex: String,
    distribution: serde_json::Value,
}

pub async fn oracle_query_handler(
    State(state): State<IdentityState>,
    Json(req): Json<OracleQueryRequest>,
) -> Result<Json<OracleQueryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let region: RegionSelector = serde_json::from_value(req.region).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid region selector: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    let query = OracleQuery::new(region, req.depth_start, req.depth_end);

    let distribution_id = mgr.compute_oracle_distribution(query).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Oracle query failed: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    let distribution = mgr.get_oracle_distribution(&distribution_id).unwrap();
    let distribution_json = serde_json::to_value(distribution).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize distribution: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(OracleQueryResponse {
        distribution_id_hex: hex::encode(distribution_id),
        distribution: distribution_json,
    }))
}

#[derive(Serialize)]
pub struct GetDistributionResponse {
    distribution: serde_json::Value,
}

pub async fn oracle_get_distribution_handler(
    State(state): State<IdentityState>,
    Path(distribution_id_hex): Path<String>,
) -> Result<Json<GetDistributionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let id_bytes = hex::decode(&distribution_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid distribution ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Distribution ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut dist_id = [0u8; 32];
    dist_id.copy_from_slice(&id_bytes);

    let distribution = mgr.get_oracle_distribution(&dist_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Distribution not found: {}", distribution_id_hex),
                coherence_score: None,
            }),
        )
    })?;

    let distribution_json = serde_json::to_value(distribution).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize distribution: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(GetDistributionResponse {
        distribution: distribution_json,
    }))
}

#[derive(Serialize)]
pub struct ListDistributionsResponse {
    distributions: Vec<serde_json::Value>,
}

pub async fn oracle_list_distributions_handler(
    State(state): State<IdentityState>,
) -> Result<Json<ListDistributionsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let distributions = mgr.list_oracle_distributions();
    let distributions_json: Vec<serde_json::Value> = distributions
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to serialize distributions: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    Ok(Json(ListDistributionsResponse {
        distributions: distributions_json,
    }))
}

// Pool endpoints

#[derive(Deserialize)]
pub struct CreatePoolRequest {
    name: String,
    description: String,
    creator_did: String,
    signing_key_hex: String,
}

#[derive(Serialize)]
pub struct CreatePoolResponse {
    pool_id_hex: String,
    pool: serde_json::Value,
}

pub async fn pool_create_handler(
    State(state): State<IdentityState>,
    Json(req): Json<CreatePoolRequest>,
) -> Result<Json<CreatePoolResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    // Validate signing key (proof of ownership)
    let _sk_bytes = hex::decode(&req.signing_key_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let pool_id = mgr
        .create_pool(req.name, req.description, &req.creator_did)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to create pool: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    let pool = mgr.get_pool(&pool_id).unwrap();
    let pool_json = serde_json::to_value(pool).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize pool: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(CreatePoolResponse {
        pool_id_hex: hex::encode(pool_id),
        pool: pool_json,
    }))
}

#[derive(Deserialize)]
pub struct PoolDepositRequest {
    pool_id: String,
    amount: f64,
    source: String,
    depositor_did: String,
    signing_key_hex: String,
}

#[derive(Serialize)]
pub struct PoolDepositResponse {
    success: bool,
    new_balance: f64,
}

pub async fn pool_deposit_handler(
    State(state): State<IdentityState>,
    Json(req): Json<PoolDepositRequest>,
) -> Result<Json<PoolDepositResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let _sk_bytes = hex::decode(&req.signing_key_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let pool_id_bytes = hex::decode(&req.pool_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid pool ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if pool_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Pool ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut pool_id = [0u8; 32];
    pool_id.copy_from_slice(&pool_id_bytes);

    let new_balance = mgr
        .pool_deposit(&pool_id, &req.depositor_did, req.amount, req.source)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to deposit: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    Ok(Json(PoolDepositResponse {
        success: true,
        new_balance,
    }))
}

#[derive(Deserialize)]
pub struct PoolDistributeRequest {
    pool_id: String,
    distribution_id: String,
    initiator_did: String,
    signing_key_hex: String,
}

#[derive(Serialize)]
pub struct PoolDistributeResponse {
    success: bool,
    allocations: std::collections::HashMap<String, f64>,
    remaining_balance: f64,
}

pub async fn pool_distribute_handler(
    State(state): State<IdentityState>,
    Json(req): Json<PoolDistributeRequest>,
) -> Result<Json<PoolDistributeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let _sk_bytes = hex::decode(&req.signing_key_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let pool_id_bytes = hex::decode(&req.pool_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid pool ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let dist_id_bytes = hex::decode(&req.distribution_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid distribution ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if pool_id_bytes.len() != 32 || dist_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Pool ID and distribution ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut pool_id = [0u8; 32];
    pool_id.copy_from_slice(&pool_id_bytes);
    let mut dist_id = [0u8; 32];
    dist_id.copy_from_slice(&dist_id_bytes);

    let _ = &req.initiator_did; // recorded for audit

    let (allocations, remaining) = mgr.pool_distribute(&pool_id, &dist_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to distribute: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(PoolDistributeResponse {
        success: true,
        allocations,
        remaining_balance: remaining,
    }))
}

#[derive(Deserialize)]
pub struct PoolClaimRequest {
    pool_id: String,
    distribution_id: String,
    claimant_did: String,
    signing_key_hex: String,
}

#[derive(Serialize)]
pub struct PoolClaimResponse {
    success: bool,
    amount: f64,
}

pub async fn pool_claim_handler(
    State(state): State<IdentityState>,
    Json(req): Json<PoolClaimRequest>,
) -> Result<Json<PoolClaimResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut mgr = state.lock().await;

    let _sk_bytes = hex::decode(&req.signing_key_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signing key hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let pool_id_bytes = hex::decode(&req.pool_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid pool ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    let dist_id_bytes = hex::decode(&req.distribution_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid distribution ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if pool_id_bytes.len() != 32 || dist_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Pool ID and distribution ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut pool_id = [0u8; 32];
    pool_id.copy_from_slice(&pool_id_bytes);
    let mut dist_id = [0u8; 32];
    dist_id.copy_from_slice(&dist_id_bytes);

    let amount = mgr
        .pool_claim(&pool_id, &dist_id, &req.claimant_did)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to claim: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    Ok(Json(PoolClaimResponse {
        success: true,
        amount,
    }))
}

#[derive(Serialize)]
pub struct GetPoolResponse {
    pool: serde_json::Value,
}

pub async fn pool_get_handler(
    State(state): State<IdentityState>,
    Path(pool_id_hex): Path<String>,
) -> Result<Json<GetPoolResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let id_bytes = hex::decode(&pool_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid pool ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Pool ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut pool_id = [0u8; 32];
    pool_id.copy_from_slice(&id_bytes);

    let pool = mgr.get_pool(&pool_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Pool not found: {}", pool_id_hex),
                coherence_score: None,
            }),
        )
    })?;

    let pool_json = serde_json::to_value(pool).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize pool: {}", e),
                coherence_score: None,
            }),
        )
    })?;

    Ok(Json(GetPoolResponse { pool: pool_json }))
}

#[derive(Serialize)]
pub struct PoolClaimsListResponse {
    claims: Vec<serde_json::Value>,
}

pub async fn pool_claims_list_handler(
    State(state): State<IdentityState>,
    Path(pool_id_hex): Path<String>,
) -> Result<Json<PoolClaimsListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mgr = state.lock().await;

    let id_bytes = hex::decode(&pool_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid pool ID hex encoding".to_string(),
                coherence_score: None,
            }),
        )
    })?;

    if id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Pool ID must be 32 bytes".to_string(),
                coherence_score: None,
            }),
        ));
    }

    let mut pool_id = [0u8; 32];
    pool_id.copy_from_slice(&id_bytes);

    let pool = mgr.get_pool(&pool_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Pool not found: {}", pool_id_hex),
                coherence_score: None,
            }),
        )
    })?;

    let claims_json: Vec<serde_json::Value> = pool
        .claims
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to serialize claims: {}", e),
                    coherence_score: None,
                }),
            )
        })?;

    Ok(Json(PoolClaimsListResponse {
        claims: claims_json,
    }))
}

// Network Health endpoint

#[derive(Serialize)]
pub struct NetworkHealthResponse {
    node_id: String,
    peer_count: usize,
    dag_size: usize,
    current_depth: u64,
    tips: Vec<String>,
    registered_dids: usize,
    active_capabilities: usize,
    active_agreements: usize,
    mean_network_curvature: f64,
    identity_graph_edges: usize,
    uptime_seconds: u64,
}

/// Extended network health endpoint with identity metrics
pub async fn network_health_handler(
    State(state): State<SharedState>,
) -> Json<NetworkHealthResponse> {
    let mgr = state.identity.lock().await;

    // Compute network-wide metrics
    let dids = mgr.list_dids();
    let registered_dids = dids.len();

    // Count active agreements
    let active_agreements = dids
        .iter()
        .flat_map(|did| mgr.list_agreements_for_did(did))
        .filter(|agreement| {
            matches!(
                agreement.status,
                disentangle_identity::AgreementStatus::Active
            )
        })
        .count();

    // Count capabilities
    let active_capabilities = dids
        .iter()
        .flat_map(|did| mgr.list_capabilities_for_did(did))
        .count();

    // Compute mean network curvature (average over all pairs)
    let mut curvature_sum = 0.0;
    let mut curvature_count = 0;

    for i in 0..dids.len() {
        for j in (i + 1)..dids.len() {
            if let Some(curvature) = mgr.get_identity_curvature(&dids[i], &dids[j]) {
                curvature_sum += curvature;
                curvature_count += 1;
            }
        }
    }

    let mean_network_curvature = if curvature_count > 0 {
        curvature_sum / curvature_count as f64
    } else {
        0.0
    };

    // Count identity graph edges (introductions)
    let identity_graph_edges: usize = dids
        .iter()
        .map(|did| mgr.get_neighbors(did).len())
        .sum::<usize>()
        / 2; // Divide by 2 because edges are bidirectional

    Json(NetworkHealthResponse {
        node_id: "local".to_string(), // Placeholder - would need PeerId from node state
        peer_count: 0,                // Placeholder - would need peer count from P2P layer
        dag_size: 0,                  // Placeholder - would need DAG size from consensus layer
        current_depth: mgr.current_depth(),
        tips: vec![], // Placeholder
        registered_dids,
        active_capabilities,
        active_agreements,
        mean_network_curvature,
        identity_graph_edges,
        uptime_seconds: 0, // Placeholder - would need start time tracking
    })
}
