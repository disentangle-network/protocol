//! # Disentangle P2P v0.3
//!
//! P2P networking layer for Disentangle Protocol.
//!
//! ## Security Notes (v0.2)
//!
//! The current implementation uses libp2p's Noise protocol with X25519.
//! This is NOT post-quantum secure for transport encryption.
//!
//! ### Migration Path to PQ Transport (v0.3)
//!
//! Option A (Recommended): Implement hybrid key exchange after Noise handshake
//! - Complete standard Noise-XX handshake (backward compatible)
//! - Immediately re-key with Kyber1024 encapsulation
//! - All subsequent traffic uses PQ-derived keys
//!
//! Option B: Fork rust-libp2p/noise for native Kyber support
//! - More invasive, requires upstream coordination
//! - Better long-term solution
//!
//! For v0.2, we accept the transport-layer vulnerability with the understanding
//! that an attacker would need a quantum computer to break recorded sessions.
//! The consensus layer (signatures, hashes) IS post-quantum secure.

pub mod behaviour;
pub mod pq_transport;
pub mod pq_wrapper;
pub mod sync;
pub mod wire;

pub use behaviour::{
    DisentangleBehaviour, DisentangleBehaviourEvent, DisentangleRequest, DisentangleResponse,
    PqUpgradeTracker,
};
pub use pq_transport::{
    derive_pq_session_keys_initiator, derive_pq_session_keys_responder, PqRekeyError,
    PqRekeyMessage, PqSessionKeys,
};
pub use pq_wrapper::{PqEncryptedStream, PqEncryptionError};
pub use sync::{SyncResult, SyncState};
pub use wire::{
    WireMessage, WireTransaction, GOSSIP_TOPIC, PQ_REKEY_PROTOCOL, PROTOCOL_VERSION,
    PROTOCOL_VERSION_PQ,
};

use libp2p::{identity::Keypair, noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
use std::time::Duration;
use tracing::info;

pub type DisentangleSwarm = Swarm<DisentangleBehaviour>;

/// Build the libp2p swarm with Noise transport.
///
/// # Security Warning
/// This uses X25519 for key exchange which is NOT post-quantum secure.
/// See module documentation for migration path.
pub fn build_swarm(keypair: Keypair) -> Result<DisentangleSwarm, Box<dyn std::error::Error>> {
    let local_peer_id = PeerId::from(keypair.public());
    info!("Local peer id: {}", local_peer_id);
    let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_dns()?
        .with_behaviour(|_key| DisentangleBehaviour::new(local_peer_id, &keypair))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::MAX))
        .build();
    Ok(swarm)
}

pub fn generate_keypair() -> Keypair {
    Keypair::generate_ed25519()
}

pub fn parse_peer_addr(addr: &str) -> Result<Multiaddr, Box<dyn std::error::Error>> {
    Ok(addr.parse()?)
}
