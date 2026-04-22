//! # Disentangle Economy
//!
//! Experimental economic primitives layered on top of the protocol-tier
//! `disentangle-identity` crate. These modules explore how coherence can
//! be translated into measurable economic artifacts — commons pools,
//! shared intents, settlement agreements, and oracle distributions — and
//! are deliberately kept out of the minimal identity surface so the
//! protocol tier can evolve independently from this application layer.
//!
//! ## Modules
//!
//! - [`commons_pool`] — fungible value pools distributed by coherence
//!   weights.
//! - [`intent`] — post-transactional shared intents whose topology is
//!   the outcome measurement.
//! - [`agreement`] — bilateral settlement agreements with measurable
//!   completion.
//! - [`oracle`] — deterministic coherence-to-value computation for
//!   external resource distribution.
//! - [`proposal`] — mass-commitment ignition for [`intent::SharedIntent`]
//!   formation.

pub mod agreement;
pub mod commons_pool;
pub mod intent;
pub mod oracle;
pub mod proposal;

pub use agreement::{
    AgreementStatus, AgreementTerms, CoherenceEffect, ResourceReceipt, ResourceType,
    ServiceAgreement, SettlementAgreement,
};
pub use commons_pool::{CommonsPool, PoolClaim, PoolDeposit};
pub use intent::{IntentCoherenceSnapshot, IntentParticipant, IntentStatus, SharedIntent};
pub use oracle::{AgentScore, DistributionRoot, OracleQuery, RegionSelector};
pub use proposal::{JoinCommitment, Proposal, ProposalStatus};
