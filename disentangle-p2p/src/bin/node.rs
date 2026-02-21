//! Disentangle Node Binary
//!
//! Full node with P2P networking and HTTP RPC interface.

use disentangle_consensus::{compute_curvature, resolve_conflict, ConflictWinner};
use disentangle_crypto::{
    hash::{sha3_256, Hash256},
    signature::{generate_keypair as generate_dilithium_keypair, sign as dilithium_sign},
    types::{Epoch, Nullifier},
};
use disentangle_dag::{NodeId, Transaction, SCALE};
use disentangle_node::{identity_rpc, identity_state::IdentityStateManager, HelloWorldPoW};
use disentangle_p2p::{
    behaviour::{DisentangleRequest, DisentangleResponse},
    build_swarm, generate_keypair, parse_peer_addr, SyncResult, SyncState, WireMessage,
    WireTransaction, GOSSIP_TOPIC,
};
use disentangle_simhash::SimHash;

use libp2p::{
    futures::StreamExt,
    gossipsub::{self, IdentTopic},
    identify,
    request_response::{self, OutboundRequestId},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Interval};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

const POW_DIFFICULTY: u8 = 16;
const MINE_INTERVAL_SECS: u64 = 10;

#[derive(Clone)]
struct SharedState {
    sync: Arc<Mutex<SyncState>>,
    local_peer_id: PeerId,
    max_depth: Arc<Mutex<u64>>,
    peer_count: Arc<Mutex<usize>>,
    conflicts_resolved: Arc<Mutex<Vec<ConflictRecord>>>,
    cmd_tx: mpsc::Sender<NodeCommand>,
    identity: Arc<Mutex<IdentityStateManager>>,
}

#[derive(Debug, Clone, Serialize)]
struct ConflictRecord {
    tx_a: String,
    tx_b: String,
    winner: String,
    mass_a: i32,
    mass_b: i32,
    timestamp: u64,
}

enum NodeCommand {
    BroadcastTx(WireTransaction),
    TargetedBroadcast {
        tx: WireTransaction,
        target_peer: Option<usize>,
    },
}

#[derive(Serialize)]
struct StatusResponse {
    peer_id: String,
    peer_count: usize,
    dag_size: usize,
    pending_txs: usize,
    tips: Vec<String>,
    max_depth: u64,
    conflicts_resolved: Vec<ConflictRecord>,
}

#[derive(Deserialize)]
struct SubmitTxRequest {
    sender: String,
    parents: Vec<String>,
    data: String,
}

#[derive(Serialize)]
struct TxResponse {
    success: bool,
    tx_id: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct ConflictResponse {
    success: bool,
    tx_red: String,
    tx_blue: String,
    message: String,
}

#[derive(Serialize)]
struct GraphResponse {
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
    tips: Vec<String>,
    conflicts: Vec<String>,
}

#[derive(Serialize)]
struct GraphNode {
    id: String,
    label: String,
    block: u64,
    ephemeral_pk_prefix: String,
    is_tip: bool,
    is_genesis: bool,
}

#[derive(Serialize)]
struct GraphEdge {
    from: String,
    to: String,
    curvature: f64,
}

async fn status_handler(State(state): State<SharedState>) -> Json<StatusResponse> {
    let sync = state.sync.lock().await;
    let tips: Vec<String> = sync.tips().iter().map(|t| hex::encode(&t[..8])).collect();
    let max_depth = *state.max_depth.lock().await;
    let peer_count = *state.peer_count.lock().await;
    let conflicts = state.conflicts_resolved.lock().await.clone();
    Json(StatusResponse {
        peer_id: state.local_peer_id.to_string(),
        peer_count,
        dag_size: sync.transaction_count(),
        pending_txs: sync.pending_count(),
        tips,
        max_depth,
        conflicts_resolved: conflicts,
    })
}

/// Returns full 32-byte hex-encoded tip hashes suitable for use as parent
/// references in transaction submission.
async fn tips_handler(State(state): State<SharedState>) -> Json<Vec<String>> {
    let sync = state.sync.lock().await;
    let tips: Vec<String> = sync.tips().iter().map(hex::encode).collect();
    Json(tips)
}

async fn graph_handler(State(state): State<SharedState>) -> Json<GraphResponse> {
    let sync = state.sync.lock().await;
    let dag = sync.dag();
    let tips_set: HashSet<NodeId> = sync.tips().into_iter().collect();
    let conflicts = state.conflicts_resolved.lock().await;
    let conflict_ids: HashSet<String> = conflicts
        .iter()
        .flat_map(|c| vec![c.tx_a.clone(), c.tx_b.clone()])
        .collect();
    drop(conflicts);
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for tx_id in dag.transaction_ids() {
        if let Some(tx) = dag.get(tx_id) {
            let id_hex = hex::encode(&tx_id[..8]);
            let is_genesis = tx.parents.is_empty();
            let is_tip = tips_set.contains(tx_id);
            let pk_bytes = tx.ephemeral_pk.to_bytes();
            // v0.3: Use topological depth instead of block field
            let depth = dag.cached_depth(tx_id).unwrap_or(0);
            nodes.push(GraphNode {
                id: id_hex.clone(),
                label: format!("D{}", depth),
                block: depth, // For backward compatibility with API
                ephemeral_pk_prefix: hex::encode(&pk_bytes[..4]),
                is_tip,
                is_genesis,
            });
            for parent in &tx.parents {
                let parent_hex = hex::encode(&parent[..8]);
                let curvature_fp = compute_curvature(dag, tx_id, parent);
                // Convert fixed-point to f64 for display (not consensus-critical)
                let curvature = curvature_fp as f64 / SCALE as f64;
                edges.push(GraphEdge {
                    from: parent_hex,
                    to: id_hex.clone(),
                    curvature,
                });
            }
        }
    }
    let tips: Vec<String> = tips_set.iter().map(|t| hex::encode(&t[..8])).collect();
    let conflicts_list: Vec<String> = conflict_ids.into_iter().collect();
    Json(GraphResponse {
        nodes,
        edges,
        tips,
        conflicts: conflicts_list,
    })
}

async fn submit_tx_handler(
    State(state): State<SharedState>,
    Json(req): Json<SubmitTxRequest>,
) -> Json<TxResponse> {
    // Parse parents from hex
    let mut parents: Vec<Hash256> = Vec::new();
    for p in &req.parents {
        match hex::decode(p) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                parents.push(arr);
            }
            _ => {
                return Json(TxResponse {
                    success: false,
                    tx_id: None,
                    error: Some(format!("Invalid parent hex: {}", p)),
                })
            }
        }
    }

    let mut height = state.max_depth.lock().await;
    *height += 1;
    let block = *height;
    drop(height);

    // Generate ephemeral keypair for this transaction (v0.2)
    let (signing_key, ephemeral_pk) = generate_dilithium_keypair();

    // Compute history root (for now, use a hash of the sender field as placeholder)
    let history_root = sha3_256(req.sender.as_bytes());

    // Compute SimHash from structural inputs only (v0.2 API)
    let simhash = SimHash::from_structural(&parents, &history_root);

    // Compute nullifier to prevent double-spend
    let sk_hash = sha3_256(&signing_key.to_bytes()[..32]);
    let epoch = Epoch::from_depth(block);
    let tx_nonce = format!("manual-{}-{}", req.data, block);
    let nullifier = Nullifier::compute(&sk_hash, epoch, tx_nonce.as_bytes());

    // Sign the transaction data
    let message = sha3_256(format!("TX:{}:{}", req.data, block).as_bytes());
    let signature = dilithium_sign(&signing_key, &message);

    // Build v0.3 Transaction
    let mut tx = Transaction {
        id: [0u8; 32], // will be computed
        ephemeral_pk,
        signature,
        parents,
        simhash,
        nullifier,
        reputation_claim: 0,
        confidential_outputs: vec![],
        payload: None,
    };
    tx.id = tx.compute_id();
    let tx_id = tx.id;

    let tx_header = serialize_tx_header(&tx);
    let pow = HelloWorldPoW::new(POW_DIFFICULTY);
    let nonce = pow.mine(&tx_header);
    let wire_tx = WireTransaction::new(tx, nonce);
    let tx_id_hex = hex::encode(&tx_id[..8]);
    if state
        .cmd_tx
        .send(NodeCommand::BroadcastTx(wire_tx))
        .await
        .is_err()
    {
        return Json(TxResponse {
            success: false,
            tx_id: None,
            error: Some("Failed to send to P2P layer".into()),
        });
    }
    Json(TxResponse {
        success: true,
        tx_id: Some(tx_id_hex),
        error: None,
    })
}

async fn trigger_conflict_handler(State(state): State<SharedState>) -> Json<ConflictResponse> {
    let sync = state.sync.lock().await;
    let tips = sync.tips();
    drop(sync);
    if tips.is_empty() {
        return Json(ConflictResponse {
            success: false,
            tx_red: String::new(),
            tx_blue: String::new(),
            message: "No tips available to create conflict".into(),
        });
    }
    let parent = tips[0];
    let mut height = state.max_depth.lock().await;
    *height += 1;
    let depth = *height;
    drop(height);

    // Generate same identity for both transactions to create true conflict
    let (signing_key, ephemeral_pk) = generate_dilithium_keypair();
    let history_root = sha3_256(&state.local_peer_id.to_bytes());
    let sk_hash = sha3_256(&signing_key.to_bytes()[..32]);
    let epoch = Epoch::from_depth(depth);

    // RED transaction
    let parents_red = vec![parent];
    let simhash_red = SimHash::from_structural(&parents_red, &history_root);
    let nullifier_red = Nullifier::compute(&sk_hash, epoch, b"conflict-RED");
    let message_red = sha3_256(b"RED-BRANCH");
    let signature_red = dilithium_sign(&signing_key, &message_red);
    let mut tx_red = Transaction {
        id: [0u8; 32],
        ephemeral_pk: ephemeral_pk.clone(),
        signature: signature_red,
        parents: parents_red,
        simhash: simhash_red,
        nullifier: nullifier_red,
        reputation_claim: 0,
        confidential_outputs: vec![],
        payload: None,
    };
    tx_red.id = tx_red.compute_id();
    let tx_red_id = tx_red.id;

    // BLUE transaction (same parent, same identity = conflict)
    let parents_blue = vec![parent];
    let simhash_blue = SimHash::from_structural(&parents_blue, &history_root);
    let nullifier_blue = Nullifier::compute(&sk_hash, epoch, b"conflict-BLUE");
    let message_blue = sha3_256(b"BLUE-BRANCH");
    let signature_blue = dilithium_sign(&signing_key, &message_blue);
    let mut tx_blue = Transaction {
        id: [0u8; 32],
        ephemeral_pk: ephemeral_pk.clone(),
        signature: signature_blue,
        parents: parents_blue,
        simhash: simhash_blue,
        nullifier: nullifier_blue,
        reputation_claim: 0,
        confidential_outputs: vec![],
        payload: None,
    };
    tx_blue.id = tx_blue.compute_id();
    let tx_blue_id = tx_blue.id;

    let pow = HelloWorldPoW::new(POW_DIFFICULTY);
    let nonce_red = pow.mine(&serialize_tx_header(&tx_red));
    let nonce_blue = pow.mine(&serialize_tx_header(&tx_blue));
    let wire_red = WireTransaction::new(tx_red, nonce_red);
    let wire_blue = WireTransaction::new(tx_blue, nonce_blue);
    let tx_red_hex = hex::encode(&tx_red_id[..8]);
    let tx_blue_hex = hex::encode(&tx_blue_id[..8]);
    info!(
        "TRIGGERING CONFLICT: RED={} BLUE={}",
        tx_red_hex, tx_blue_hex
    );
    let _ = state
        .cmd_tx
        .send(NodeCommand::TargetedBroadcast {
            tx: wire_red.clone(),
            target_peer: Some(0),
        })
        .await;
    let _ = state
        .cmd_tx
        .send(NodeCommand::TargetedBroadcast {
            tx: wire_blue.clone(),
            target_peer: Some(1),
        })
        .await;
    let mut sync = state.sync.lock().await;
    let _ = sync.receive_transaction(wire_red);
    let _ = sync.receive_transaction(wire_blue);
    drop(sync);
    Json(ConflictResponse {
        success: true,
        tx_red: tx_red_hex,
        tx_blue: tx_blue_hex,
        message: "Conflict injected. RED sent to peer 0, BLUE sent to peer 1.".into(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();
    let args: Vec<String> = env::args().collect();
    let p2p_port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(9000);
    let rpc_port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3000);
    let bootstrap_addr: Option<Multiaddr> = args.get(3).map(|s| parse_peer_addr(s)).transpose()?;
    let keypair = generate_keypair();
    let local_peer_id = PeerId::from(keypair.public());
    info!("========================================");
    info!("     DISENTANGLE NODE STARTING");
    info!("========================================");
    info!("Peer ID: {}", local_peer_id);
    info!("P2P Port: {}", p2p_port);
    info!("RPC Port: {}", rpc_port);
    let mut swarm = build_swarm(keypair)?;
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", p2p_port).parse()?;
    swarm.listen_on(listen_addr)?;
    let is_bootstrap_node = bootstrap_addr.is_none();
    if let Some(addr) = bootstrap_addr {
        info!("Bootstrapping from {}", addr);
        swarm.dial(addr)?;
    }
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NodeCommand>(100);

    // Load or create identity state
    let identity_manager = {
        let state_path = std::path::Path::new("./disentangle-state.json");
        if state_path.exists() {
            info!("Loading identity state from {}", state_path.display());
            match IdentityStateManager::load_from_file(state_path) {
                Ok(mgr) => {
                    info!("Identity state loaded successfully");
                    mgr
                }
                Err(e) => {
                    warn!("Failed to load identity state: {}. Starting fresh.", e);
                    IdentityStateManager::new()
                }
            }
        } else {
            info!("No existing state file. Starting fresh.");
            IdentityStateManager::new()
        }
    };

    let shared_state = SharedState {
        sync: Arc::new(Mutex::new(SyncState::new(POW_DIFFICULTY))),
        local_peer_id,
        max_depth: Arc::new(Mutex::new(0)),
        peer_count: Arc::new(Mutex::new(0)),
        conflicts_resolved: Arc::new(Mutex::new(Vec::new())),
        cmd_tx: cmd_tx.clone(),
        identity: Arc::new(Mutex::new(identity_manager)),
    };
    // Only bootstrap node (no bootstrap_addr) creates genesis
    // Follower nodes will receive genesis via sync protocol
    if is_bootstrap_node {
        let mut sync = shared_state.sync.lock().await;
        create_genesis(&mut sync);
        info!("Bootstrap node: Genesis created");
    } else {
        info!("Follower node: Will sync genesis from bootstrap peer");
    }
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    // Create identity router with its own state
    let identity_state = shared_state.identity.clone();
    let identity_router = Router::new()
        // Identity endpoints
        .route(
            "/identity/register",
            post(identity_rpc::identity_register_handler),
        )
        .route("/identity/:did", get(identity_rpc::identity_get_handler))
        .route(
            "/identity/:did",
            axum::routing::delete(identity_rpc::identity_deactivate_handler),
        )
        .route("/identity", get(identity_rpc::identity_list_handler))
        // Capability endpoints
        .route(
            "/capability/create",
            post(identity_rpc::capability_create_handler),
        )
        .route(
            "/capability/delegate",
            post(identity_rpc::capability_delegate_handler),
        )
        .route(
            "/capability/invoke",
            post(identity_rpc::capability_invoke_handler),
        )
        .route(
            "/capability/revoke",
            post(identity_rpc::capability_revoke_handler),
        )
        .route(
            "/capability/:cap_id_hex",
            get(identity_rpc::capability_get_handler),
        )
        .route(
            "/capability/by-did/:did",
            get(identity_rpc::capability_list_by_did_handler),
        )
        // Introduction endpoints
        .route(
            "/introduction",
            post(identity_rpc::introduction_create_handler),
        )
        .route(
            "/introduction/chain/:from_did/:to_did",
            get(identity_rpc::introduction_chain_handler),
        )
        // Coherence endpoints
        .route(
            "/coherence/:did",
            get(identity_rpc::coherence_profile_handler),
        )
        .route(
            "/coherence/curvature/:did_a/:did_b",
            get(identity_rpc::coherence_curvature_handler),
        )
        .route(
            "/coherence/neighbors/:did",
            get(identity_rpc::coherence_neighbors_handler),
        )
        // Excitability Gradient endpoints
        .route(
            "/coherence/gradient/:did_a/:did_b",
            get(identity_rpc::coherence_gradient_edge_handler),
        )
        .route(
            "/coherence/excitability/:did",
            get(identity_rpc::coherence_excitability_handler),
        )
        .route(
            "/coherence/gradient/map",
            get(identity_rpc::coherence_gradient_map_handler),
        )
        // Petname endpoints
        .route("/petname", post(identity_rpc::petname_set_handler))
        .route("/petname/:name", get(identity_rpc::petname_resolve_handler))
        // Governance endpoints
        .route(
            "/governance/propose",
            post(identity_rpc::governance_propose_handler),
        )
        .route(
            "/governance/vote",
            post(identity_rpc::governance_vote_handler),
        )
        .route(
            "/governance/proposals",
            get(identity_rpc::governance_list_proposals_handler),
        )
        .route(
            "/governance/:proposal_id_hex",
            get(identity_rpc::governance_get_proposal_handler),
        )
        // Oracle endpoints
        .route("/oracle/query", post(identity_rpc::oracle_query_handler))
        .route(
            "/oracle/distribution/:distribution_id_hex",
            get(identity_rpc::oracle_get_distribution_handler),
        )
        .route(
            "/oracle/distributions",
            get(identity_rpc::oracle_list_distributions_handler),
        )
        // Pool endpoints
        .route("/pool/create", post(identity_rpc::pool_create_handler))
        .route("/pool/deposit", post(identity_rpc::pool_deposit_handler))
        .route(
            "/pool/distribute",
            post(identity_rpc::pool_distribute_handler),
        )
        .route("/pool/claim", post(identity_rpc::pool_claim_handler))
        .route("/pool/:pool_id_hex", get(identity_rpc::pool_get_handler))
        .route(
            "/pool/:pool_id_hex/claims",
            get(identity_rpc::pool_claims_list_handler),
        )
        .with_state(identity_state);

    let app = Router::new()
        .route("/status", get(status_handler))
        .route("/tips", get(tips_handler))
        .route("/graph", get(graph_handler))
        .route("/transaction", post(submit_tx_handler))
        .route("/debug/trigger-conflict", post(trigger_conflict_handler))
        .merge(identity_router)
        .layer(cors)
        .with_state(shared_state.clone());
    let rpc_addr = format!("0.0.0.0:{}", rpc_port);
    let listener = tokio::net::TcpListener::bind(&rpc_addr).await?;
    info!("RPC server listening on http://{}", rpc_addr);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("RPC server error: {}", e);
        }
    });
    let mut mine_timer: Interval = interval(Duration::from_secs(MINE_INTERVAL_SECS));
    let mut save_timer: Interval = interval(Duration::from_secs(30));
    let mut payload_timer: Interval = interval(Duration::from_millis(200));
    let topic = IdentTopic::new(GOSSIP_TOPIC);
    let mut connected_peers: Vec<PeerId> = Vec::new();

    // Setup Ctrl+C handler
    let identity_for_shutdown = shared_state.identity.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down. Saving state...");
        let mgr = identity_for_shutdown.lock().await;
        if let Err(e) = mgr.save_to_file(std::path::Path::new("./disentangle-state.json")) {
            warn!("Failed to save state on shutdown: {}", e);
        } else {
            info!("State saved successfully");
        }
        std::process::exit(0);
    });

    info!("Node running. Press Ctrl+C to stop.");
    loop {
        tokio::select! {
            _ = save_timer.tick() => {
                let mgr = shared_state.identity.lock().await;
                if let Err(e) = mgr.save_to_file(std::path::Path::new("./disentangle-state.json")) {
                    warn!("Periodic save failed: {}", e);
                } else {
                    debug!("State saved");
                }
            }
            _ = mine_timer.tick() => {
                let wire_tx = {
                    let mut sync = shared_state.sync.lock().await;
                    let mut height = shared_state.max_depth.lock().await;
                    mine_transaction(&mut sync, &mut height, local_peer_id)
                };
                if let Some(wire_tx) = wire_tx {
                    broadcast_tx(&mut swarm, &topic, &wire_tx);
                    info!("Mined tx. DAG size: {}", shared_state.sync.lock().await.transaction_count());
                }
            }
            _ = payload_timer.tick() => {
                // Drain pending payloads from identity operations and broadcast as DAG transactions
                let payloads = {
                    let mut mgr = shared_state.identity.lock().await;
                    mgr.drain_payloads()
                };
                for pending in payloads {
                    let mut sync = shared_state.sync.lock().await;
                    let mut height = shared_state.max_depth.lock().await;
                    *height += 1;
                    let depth = *height;
                    drop(height);

                    let tips: Vec<NodeId> = sync.tips().into_iter().take(3).collect();
                    let history_root = sha3_256(local_peer_id.to_bytes().as_slice());
                    let simhash = SimHash::from_structural(&tips, &history_root);

                    // Use the signer's key from the pending payload
                    let (signing_key, _) = generate_dilithium_keypair();
                    let sk_hash = sha3_256(&signing_key.to_bytes()[..32]);
                    let epoch = Epoch::from_depth(depth);
                    let tx_nonce = format!("identity-{}-{}", local_peer_id, depth);
                    let nullifier = Nullifier::compute(&sk_hash, epoch, tx_nonce.as_bytes());

                    let message = sha3_256(format!("IDENTITY:{}:{}", local_peer_id, depth).as_bytes());
                    let signature = dilithium_sign(&signing_key, &message);

                    let mut tx = Transaction {
                        id: [0u8; 32],
                        ephemeral_pk: pending.signer_pk,
                        signature,
                        parents: tips,
                        simhash,
                        nullifier,
                        reputation_claim: 0,
                        confidential_outputs: vec![],
                        payload: Some(pending.payload),
                    };
                    tx.id = tx.compute_id();
                    let tx_id_hex = hex::encode(&tx.id[..8]);

                    let pow = HelloWorldPoW::new(POW_DIFFICULTY);
                    let nonce = pow.mine(&serialize_tx_header(&tx));
                    let wire_tx = WireTransaction::new(tx, nonce);

                    match sync.receive_transaction(wire_tx.clone()) {
                        SyncResult::Inserted => {
                            drop(sync);
                            broadcast_tx(&mut swarm, &topic, &wire_tx);
                            info!("Broadcast identity tx {}", tx_id_hex);
                        }
                        other => {
                            debug!("Identity tx {} not inserted: {:?}", tx_id_hex, other);
                        }
                    }
                }
            }
            Some(cmd) = cmd_rx.recv() => {
                handle_command(&mut swarm, &topic, &connected_peers, cmd);
            }
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    &mut swarm,
                    &shared_state,
                    &topic,
                    &mut connected_peers,
                    event
                ).await;
            }
        }
    }
}

fn create_genesis(sync: &mut SyncState) {
    // Generate a deterministic genesis keypair (for reproducibility)
    let (signing_key, ephemeral_pk) = generate_dilithium_keypair();

    // Genesis has no parents, so use empty structural inputs
    let history_root = sha3_256(b"disentangle-genesis-history");
    let simhash = SimHash::from_structural(&[], &history_root);

    // Compute nullifier for genesis
    let sk_hash = sha3_256(&signing_key.to_bytes()[..32]);
    let nullifier = Nullifier::compute(&sk_hash, Epoch(0), b"genesis");

    // Sign genesis
    let message = sha3_256(b"disentangle-genesis");
    let signature = dilithium_sign(&signing_key, &message);

    let mut genesis = Transaction {
        id: [0u8; 32],
        ephemeral_pk,
        signature,
        parents: vec![],
        simhash,
        nullifier,
        reputation_claim: 0,
        confidential_outputs: vec![],
        payload: None,
    };
    genesis.id = genesis.compute_id();
    let genesis_id = genesis.id;

    let wire_tx = WireTransaction::new(genesis, 0);
    sync.receive_transaction(wire_tx);
    info!("Genesis created: {}", hex::encode(&genesis_id[..8]));
}

fn mine_transaction(
    sync: &mut SyncState,
    height: &mut u64,
    peer_id: PeerId,
) -> Option<WireTransaction> {
    let tips = sync.tips();
    // Need at least MIN_PARENTS=2 tips to mine a valid transaction
    if tips.len() < 2 {
        debug!("Skipping mine: only {} tip(s), need at least 2", tips.len());
        return None;
    }
    *height += 1;
    let depth = *height;
    let parents: Vec<NodeId> = tips.into_iter().take(3).collect();

    // Generate ephemeral keypair for this transaction
    let (signing_key, ephemeral_pk) = generate_dilithium_keypair();

    // Compute history root from peer identity
    let history_root = sha3_256(&peer_id.to_bytes());

    // Compute SimHash from structural inputs (v0.3)
    let simhash = SimHash::from_structural(&parents, &history_root);

    // Compute nullifier
    let sk_hash = sha3_256(&signing_key.to_bytes()[..32]);
    let epoch = Epoch::from_depth(depth);
    let tx_nonce = format!("tx-{}-{}", peer_id, depth);
    let nullifier = Nullifier::compute(&sk_hash, epoch, tx_nonce.as_bytes());

    // Sign the transaction
    let message = sha3_256(format!("MINE:{}:{}", peer_id, depth).as_bytes());
    let signature = dilithium_sign(&signing_key, &message);

    let mut tx = Transaction {
        id: [0u8; 32],
        ephemeral_pk,
        signature,
        parents,
        simhash,
        nullifier,
        reputation_claim: 0,
        confidential_outputs: vec![],
        payload: None,
    };
    tx.id = tx.compute_id();

    let pow = HelloWorldPoW::new(POW_DIFFICULTY);
    let nonce = pow.mine(&serialize_tx_header(&tx));
    let wire_tx = WireTransaction::new(tx, nonce);
    match sync.receive_transaction(wire_tx.clone()) {
        SyncResult::Inserted => Some(wire_tx),
        _ => None,
    }
}

fn broadcast_tx(
    swarm: &mut Swarm<disentangle_p2p::DisentangleBehaviour>,
    topic: &IdentTopic,
    wire_tx: &WireTransaction,
) {
    let msg = WireMessage::NewTransaction(wire_tx.clone());
    if let Ok(bytes) = msg.encode() {
        let _ = swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), bytes);
    }
}

fn handle_command(
    swarm: &mut Swarm<disentangle_p2p::DisentangleBehaviour>,
    topic: &IdentTopic,
    peers: &[PeerId],
    cmd: NodeCommand,
) {
    match cmd {
        NodeCommand::BroadcastTx(wire_tx) => {
            broadcast_tx(swarm, topic, &wire_tx);
        }
        NodeCommand::TargetedBroadcast { tx, target_peer } => {
            if let Some(idx) = target_peer {
                if let Some(peer) = peers.get(idx) {
                    info!(
                        "Sending targeted tx {} to peer {}",
                        hex::encode(&tx.tx.id[..8]),
                        peer
                    );
                }
            }
            broadcast_tx(swarm, topic, &tx);
        }
    }
}

async fn handle_swarm_event(
    swarm: &mut Swarm<disentangle_p2p::DisentangleBehaviour>,
    state: &SharedState,
    topic: &IdentTopic,
    connected_peers: &mut Vec<PeerId>,
    event: SwarmEvent<disentangle_p2p::behaviour::DisentangleBehaviourEvent>,
) {
    use disentangle_p2p::behaviour::DisentangleBehaviourEvent;
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            info!("Listening on {}/p2p/{}", address, swarm.local_peer_id());
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            info!("Connected to peer: {}", peer_id);
            connected_peers.push(peer_id);
            *state.peer_count.lock().await = connected_peers.len();

            // If our DAG is empty, request tips from the new peer to sync genesis
            let dag_empty = state.sync.lock().await.transaction_count() == 0;
            if dag_empty {
                info!(
                    "DAG empty, requesting tips from {} for genesis sync",
                    peer_id
                );
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, DisentangleRequest::GetTips);
            }
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            info!("❌ Disconnected from peer: {}", peer_id);
            connected_peers.retain(|p| p != &peer_id);
            *state.peer_count.lock().await = connected_peers.len();
        }
        SwarmEvent::Behaviour(behaviour_event) => {
            match behaviour_event {
                DisentangleBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    message,
                    propagation_source,
                    ..
                }) => {
                    handle_gossip_message(
                        swarm,
                        state,
                        &message.data,
                        propagation_source,
                        topic,
                        connected_peers,
                    )
                    .await;
                }
                DisentangleBehaviourEvent::RequestResponse(request_response::Event::Message {
                    peer,
                    message,
                }) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        handle_request(swarm, state, peer, request, channel).await;
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        handle_response(swarm, state, request_id, response, connected_peers).await;
                    }
                },
                DisentangleBehaviourEvent::Identify(identify::Event::Received {
                    peer_id,
                    info,
                    ..
                }) => {
                    debug!(
                        "Identify received from {}: {:?}",
                        peer_id, info.listen_addrs
                    );
                    // Feed discovered addresses into Kademlia for DHT routing
                    for addr in &info.listen_addrs {
                        swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr.clone());
                    }
                    // Trigger Kademlia bootstrap now that we know a peer
                    if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                        debug!("Kademlia bootstrap attempt: {}", e);
                    }
                }
                DisentangleBehaviourEvent::Kademlia(_) => {
                    // Kademlia events handled internally
                }
                _ => {}
            }
        }
        _ => {}
    }
}

async fn handle_gossip_message(
    swarm: &mut Swarm<disentangle_p2p::DisentangleBehaviour>,
    state: &SharedState,
    data: &[u8],
    source: PeerId,
    _topic: &IdentTopic,
    peers: &[PeerId],
) {
    let msg = match WireMessage::decode(data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Decode error: {}", e);
            return;
        }
    };
    if let WireMessage::NewTransaction(wire_tx) = msg {
        let tx_id = wire_tx.tx.id;
        let tx_id_hex = hex::encode(&tx_id[..8]);
        debug!("Received tx {} from {}", tx_id_hex, source);
        let mut sync = state.sync.lock().await;
        let conflict = detect_conflict(&sync, &wire_tx.tx);
        match sync.receive_transaction(wire_tx.clone()) {
            SyncResult::Inserted => {
                let depth = sync.transaction_count() as u64;
                info!(
                    "Inserted tx {} from gossip. DAG: {}",
                    tx_id_hex,
                    sync.transaction_count()
                );

                // Process identity payload if present
                if let Some(ref payload) = wire_tx.tx.payload {
                    drop(sync); // Release DAG lock before acquiring identity lock
                    let mut mgr = state.identity.lock().await;
                    if let Err(e) =
                        mgr.apply_payload(payload, &tx_id, &wire_tx.tx.ephemeral_pk, depth)
                    {
                        warn!("Failed to apply payload from tx {}: {}", tx_id_hex, e);
                    } else {
                        debug!("Applied identity payload from tx {}", tx_id_hex);
                    }
                    drop(mgr);
                } else {
                    drop(sync);
                }

                if let Some(conflicting_id) = conflict {
                    resolve_and_record_conflict(state, tx_id, conflicting_id).await;
                }
            }
            SyncResult::NeedParents(parents) => {
                for parent_id in parents {
                    if let Some(peer) = peers.first() {
                        let request = DisentangleRequest::GetTransaction(parent_id);
                        swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(peer, request);
                    }
                }
            }
            SyncResult::AlreadyHave | SyncResult::AlreadyPending => {}
            SyncResult::InvalidPoW => {
                warn!("Invalid PoW from {}", source);
            }
            SyncResult::BufferFull => {
                warn!("Buffer full");
            }
        }
    }
}

fn detect_conflict(sync: &SyncState, new_tx: &Transaction) -> Option<NodeId> {
    let dag = sync.dag();
    for existing_id in dag.transaction_ids() {
        if *existing_id == new_tx.id {
            continue;
        }
        if let Some(existing) = dag.get(existing_id) {
            // v0.2: Compare ephemeral public keys to detect same-identity conflicts
            if existing.ephemeral_pk == new_tx.ephemeral_pk {
                let shared_parents: HashSet<_> = existing.parents.iter().collect();
                for p in &new_tx.parents {
                    if shared_parents.contains(p) {
                        info!(
                            "CONFLICT DETECTED: {} vs {} (shared parent {})",
                            hex::encode(&new_tx.id[..8]),
                            hex::encode(&existing_id[..8]),
                            hex::encode(&p[..8])
                        );
                        return Some(*existing_id);
                    }
                }
            }
        }
    }
    None
}

async fn resolve_and_record_conflict(state: &SharedState, tx_a: NodeId, tx_b: NodeId) {
    let mut sync = state.sync.lock().await;
    let dag = sync.dag_mut();
    let fork_point = {
        let tx_a_data = dag.get(&tx_a);
        let tx_b_data = dag.get(&tx_b);
        match (tx_a_data, tx_b_data) {
            (Some(a), Some(b)) => {
                let common: Vec<_> = a
                    .parents
                    .iter()
                    .filter(|p| b.parents.contains(p))
                    .cloned()
                    .collect();
                common.first().cloned()
            }
            _ => None,
        }
    };
    let fork = match fork_point {
        Some(f) => f,
        None => {
            warn!("Could not find fork point for conflict resolution");
            return;
        }
    };
    // v0.3: Use fork depth instead of fork block
    let fork_depth = dag.depth(&fork);
    info!(
        "⚖️  RESOLVING CONFLICT at fork point {}",
        hex::encode(&fork[..8])
    );
    let (winner, mass_a, mass_b) = resolve_conflict(dag, &tx_a, &tx_b, fork_depth);
    let winner_id = match winner {
        ConflictWinner::BranchA => tx_a,
        ConflictWinner::BranchB => tx_b,
    };
    info!("======================================");
    info!("🏆 CONFLICT RESOLVED!");
    info!(
        "   Branch A ({}): Mass {}",
        hex::encode(&tx_a[..8]),
        mass_a.total_mass as f64 / 65536.0
    );
    info!(
        "   Branch B ({}): Mass {}",
        hex::encode(&tx_b[..8]),
        mass_b.total_mass as f64 / 65536.0
    );
    info!("   WINNER: {}", hex::encode(&winner_id[..8]));
    info!("======================================");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let record = ConflictRecord {
        tx_a: hex::encode(&tx_a[..8]),
        tx_b: hex::encode(&tx_b[..8]),
        winner: hex::encode(&winner_id[..8]),
        mass_a: mass_a.total_mass,
        mass_b: mass_b.total_mass,
        timestamp,
    };
    drop(sync);
    state.conflicts_resolved.lock().await.push(record);
}

async fn handle_request(
    swarm: &mut Swarm<disentangle_p2p::DisentangleBehaviour>,
    state: &SharedState,
    _peer: PeerId,
    request: DisentangleRequest,
    channel: request_response::ResponseChannel<DisentangleResponse>,
) {
    match request {
        DisentangleRequest::GetTransaction(tx_id) => {
            let sync = state.sync.lock().await;
            let response = match sync.get_transaction(&tx_id) {
                Some(wire_tx) => DisentangleResponse::Transaction(wire_tx.encode().ok()),
                None => DisentangleResponse::Transaction(None),
            };
            let _ = swarm
                .behaviour_mut()
                .request_response
                .send_response(channel, response);
        }
        DisentangleRequest::GetTips => {
            let sync = state.sync.lock().await;
            let _ = swarm
                .behaviour_mut()
                .request_response
                .send_response(channel, DisentangleResponse::Tips(sync.tips()));
        }
    }
}

async fn handle_response(
    swarm: &mut Swarm<disentangle_p2p::DisentangleBehaviour>,
    state: &SharedState,
    _request_id: OutboundRequestId,
    response: DisentangleResponse,
    peers: &[PeerId],
) {
    match response {
        DisentangleResponse::Tips(tip_ids) => {
            info!("Received {} tips from peer", tip_ids.len());
            // Request each tip transaction to sync the DAG
            for tip_id in tip_ids {
                if let Some(peer) = peers.first() {
                    swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(peer, DisentangleRequest::GetTransaction(tip_id));
                }
            }
        }
        DisentangleResponse::Transaction(Some(data)) => {
            if let Ok(wire_tx) = WireTransaction::decode(&data) {
                let tx_id_hex = hex::encode(&wire_tx.tx.id[..8]);
                let mut sync = state.sync.lock().await;
                if let SyncResult::NeedParents(more) = sync.receive_transaction(wire_tx) {
                    drop(sync);
                    for parent_id in more {
                        if let Some(peer) = peers.first() {
                            let request = DisentangleRequest::GetTransaction(parent_id);
                            swarm
                                .behaviour_mut()
                                .request_response
                                .send_request(peer, request);
                        }
                    }
                } else {
                    info!("Synced transaction: {}", tx_id_hex);
                }
            }
        }
        _ => {}
    }
}

fn serialize_tx_header(tx: &Transaction) -> Vec<u8> {
    let mut header = Vec::new();
    // v0.3: Use ephemeral_pk instead of sender
    header.extend_from_slice(&tx.ephemeral_pk.to_bytes());
    for parent in &tx.parents {
        header.extend_from_slice(parent);
    }
    // v0.3: No block field - temporal properties derive from topological depth
    // Include nullifier in PoW header for double-spend resistance
    header.extend_from_slice(tx.nullifier.as_bytes());
    header
}

// Note: sha3_256 is imported directly from disentangle_crypto::hash
