//! Coherence Membrane — Research Crate
//!
//! Frequency-selective couplers for the Disentangle protocol.
//! Replaces binary trust gating with coherence-projected filtering:
//! nodes couple proportionally to their harmonic overlap, not by
//! hard-gated pass/fail decisions.
//!
//! Status: RESEARCH — not for integration into production protocol.

pub mod filter;
pub mod foliation;
pub mod level;
pub mod membrane;

pub use filter::{
    simhash_from_bytes, CoherenceBasis, CoherenceFilter, FilterResult, SpectralBasis,
    SpectralFilter,
};
pub use foliation::{Foliation, LeafId, NodeId};
pub use level::{CoherenceLevel, LevelTemporality, TemporalSignature};
pub use membrane::{Membrane, TransferResult};
