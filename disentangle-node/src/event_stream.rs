//! Event Stream for Node Operations
//!
//! Server-Sent Events (SSE) for reactive agent coordination.

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Events emitted by the node during identity and capability operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NodeEvent {
    IdentityRegistered {
        did: String,
        agent_type: String,
    },
    CapabilityCreated {
        capability_id: String,
        issuer_did: String,
    },
    CapabilityDelegated {
        capability_id: String,
        from_did: String,
        to_did: String,
    },
    CapabilityExercised {
        capability_id: String,
        invoker_did: String,
        allowed: bool,
    },
    CapabilityRevoked {
        capability_id: String,
    },
    IntroductionCreated {
        introducer: String,
        introduced: String,
        curvature: f64,
    },
    AgreementCreated {
        agreement_id: String,
        parties: Vec<String>,
    },
    AgreementCompleted {
        agreement_id: String,
        success: bool,
    },
    CoherenceChanged {
        did: String,
        old_score: f64,
        new_score: f64,
    },
    TransactionMined {
        tx_id: String,
        depth: u64,
        dag_size: u64,
    },
}

/// Event bus for broadcasting node events to subscribers
pub struct EventBus {
    sender: broadcast::Sender<NodeEvent>,
}

impl EventBus {
    /// Create a new event bus with the specified capacity
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publish an event to all subscribers
    pub fn publish(&self, event: NodeEvent) {
        // Ignore send errors (happens when no receivers)
        let _ = self.sender.send(event);
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.sender.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_bus_publish_subscribe() {
        let bus = EventBus::new(10);
        let mut rx = bus.subscribe();

        let event = NodeEvent::IdentityRegistered {
            did: "did:disentangle:test".to_string(),
            agent_type: "human".to_string(),
        };

        bus.publish(event.clone());

        // Non-blocking receive for testing
        match rx.try_recv() {
            Ok(received) => match (received, event) {
                (
                    NodeEvent::IdentityRegistered {
                        did: d1,
                        agent_type: a1,
                    },
                    NodeEvent::IdentityRegistered {
                        did: d2,
                        agent_type: a2,
                    },
                ) => {
                    assert_eq!(d1, d2);
                    assert_eq!(a1, a2);
                }
                _ => panic!("Event type mismatch"),
            },
            Err(_) => panic!("Failed to receive event"),
        }
    }

    #[test]
    fn test_event_bus_multiple_subscribers() {
        let bus = EventBus::new(10);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let event = NodeEvent::CapabilityCreated {
            capability_id: "abc123".to_string(),
            issuer_did: "did:disentangle:test".to_string(),
        };

        bus.publish(event);

        // Both subscribers should receive the event
        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }

    #[test]
    fn test_event_bus_topic_serialization() {
        let event = NodeEvent::AgreementCreated {
            agreement_id: "agreement123".to_string(),
            parties: vec!["did:a".to_string(), "did:b".to_string()],
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: NodeEvent = serde_json::from_str(&json).unwrap();

        match parsed {
            NodeEvent::AgreementCreated {
                agreement_id,
                parties,
            } => {
                assert_eq!(agreement_id, "agreement123");
                assert_eq!(parties.len(), 2);
            }
            _ => panic!("Event type mismatch after serialization"),
        }
    }
}
