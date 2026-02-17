//! Identity RPC Handlers
//!
//! Axum route handlers for the Capability-Coherence Identity Protocol (CCIP).
//! These handlers provide JSON-over-HTTP access to the IdentityStateManager.

use crate::identity_state::IdentityStateManager;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use disentangle_crypto::signature::SigningKey;
use disentangle_identity::{
    AgentType, CapabilitySubject, Constraint, ProposalType, RevocationScope, VoteChoice,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
