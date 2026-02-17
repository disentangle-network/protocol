//! Wire format for network transmission.
//!
//! Uses bincode for efficient binary serialization.

use disentangle_dag::{NodeId, Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("Serialization failed: {0}")]
    Serialize(#[from] bincode::Error),
    #[error("Invalid message type: {0}")]
    InvalidType(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    NewTransaction(WireTransaction),
    GetTransaction(NodeId),
    TransactionResponse(Option<WireTransaction>),
    GetTips,
    TipsResponse(Vec<NodeId>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireTransaction {
    pub tx: Transaction,
    pub nonce: u64,
}

impl WireMessage {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        Ok(bincode::serialize(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(bincode::deserialize(bytes)?)
    }
}

impl WireTransaction {
    pub fn new(tx: Transaction, nonce: u64) -> Self {
        Self { tx, nonce }
    }

    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        Ok(bincode::serialize(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(bincode::deserialize(bytes)?)
    }
}

pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
pub const PROTOCOL_VERSION: &str = "/disentangle/1.0.0";
pub const PROTOCOL_VERSION_PQ: &str = "/disentangle/2.0.0";
pub const PQ_REKEY_PROTOCOL: &str = "/disentangle/pq-rekey/1.0.0";
pub const GOSSIP_TOPIC: &str = "disentangle-transactions";
