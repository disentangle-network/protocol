//! Network behavior combining Gossipsub + RequestResponse.

use crate::pq_transport::PqRekeyMessage;
use crate::wire::{GOSSIP_TOPIC, MAX_MESSAGE_SIZE, PQ_REKEY_PROTOCOL, PROTOCOL_VERSION};
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    identify,
    kad::{self, store::MemoryStore},
    request_response::{self, ProtocolSupport},
    swarm::NetworkBehaviour,
    PeerId, StreamProtocol,
};
use std::collections::HashSet;
use std::time::Duration;

#[derive(NetworkBehaviour)]
pub struct DisentangleBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub request_response:
        request_response::cbor::Behaviour<DisentangleRequest, DisentangleResponse>,
    pub pq_rekey: request_response::cbor::Behaviour<PqRekeyMessage, PqRekeyMessage>,
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub identify: identify::Behaviour,
}

/// State for tracking PQ upgrade status per peer
pub struct PqUpgradeTracker {
    pq_upgraded: HashSet<PeerId>,
}

impl PqUpgradeTracker {
    pub fn new() -> Self {
        Self {
            pq_upgraded: HashSet::new(),
        }
    }

    /// Check if a peer has completed PQ upgrade
    pub fn is_pq_upgraded(&self, peer: &PeerId) -> bool {
        self.pq_upgraded.contains(peer)
    }

    /// Mark a peer as PQ upgraded
    pub fn mark_pq_upgraded(&mut self, peer: PeerId) {
        self.pq_upgraded.insert(peer);
    }

    /// Remove a peer from PQ upgraded set (e.g., on disconnect)
    pub fn remove_pq_upgraded(&mut self, peer: &PeerId) {
        self.pq_upgraded.remove(peer);
    }
}

impl Default for PqUpgradeTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl DisentangleBehaviour {
    pub fn new(local_peer_id: PeerId, local_key: &libp2p::identity::Keypair) -> Self {
        let gossipsub = Self::build_gossipsub(local_key);
        let request_response = Self::build_request_response();
        let pq_rekey = Self::build_pq_rekey();
        let kademlia = Self::build_kademlia(local_peer_id);
        let identify = Self::build_identify(local_key);
        Self {
            gossipsub,
            request_response,
            pq_rekey,
            kademlia,
            identify,
        }
    }

    fn build_gossipsub(local_key: &libp2p::identity::Keypair) -> gossipsub::Behaviour {
        let config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(ValidationMode::Strict)
            .max_transmit_size(MAX_MESSAGE_SIZE)
            .build()
            .expect("Valid gossipsub config");
        let mut behaviour =
            gossipsub::Behaviour::new(MessageAuthenticity::Signed(local_key.clone()), config)
                .expect("Valid gossipsub behaviour");
        let topic = IdentTopic::new(GOSSIP_TOPIC);
        behaviour.subscribe(&topic).expect("Subscribe to topic");
        behaviour
    }

    fn build_request_response(
    ) -> request_response::cbor::Behaviour<DisentangleRequest, DisentangleResponse> {
        let protocols = [(StreamProtocol::new(PROTOCOL_VERSION), ProtocolSupport::Full)];
        let config =
            request_response::Config::default().with_request_timeout(Duration::from_secs(30));
        request_response::cbor::Behaviour::new(protocols, config)
    }

    fn build_pq_rekey() -> request_response::cbor::Behaviour<PqRekeyMessage, PqRekeyMessage> {
        let protocols = [(
            StreamProtocol::new(PQ_REKEY_PROTOCOL),
            ProtocolSupport::Full,
        )];
        let config =
            request_response::Config::default().with_request_timeout(Duration::from_secs(10));
        request_response::cbor::Behaviour::new(protocols, config)
    }

    fn build_kademlia(local_peer_id: PeerId) -> kad::Behaviour<MemoryStore> {
        let store = MemoryStore::new(local_peer_id);
        let config = kad::Config::new(StreamProtocol::new("/disentangle/kad/1.0.0"));
        kad::Behaviour::with_config(local_peer_id, store, config)
    }

    fn build_identify(local_key: &libp2p::identity::Keypair) -> identify::Behaviour {
        let config = identify::Config::new(PROTOCOL_VERSION.to_string(), local_key.public());
        identify::Behaviour::new(config)
    }

    pub fn gossip_topic(&self) -> IdentTopic {
        IdentTopic::new(GOSSIP_TOPIC)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum DisentangleRequest {
    GetTransaction([u8; 32]),
    GetTips,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum DisentangleResponse {
    Transaction(Option<Vec<u8>>),
    Tips(Vec<[u8; 32]>),
}
