use crate::filter::{CoherenceBasis, CoherenceFilter, FilterResult};
use crate::level::LevelTemporality;

/// Result of a full membrane transfer operation.
#[derive(Debug, Clone)]
pub struct TransferResult {
    pub filter_result: FilterResult,
    /// True iff level gap == 0 AND temporal gap < epsilon.
    /// Only matched peers can preserve exact square structure.
    pub square_preserving: bool,
    /// Effective coupling bandwidth after level-temporality gap adjustment.
    pub effective_bandwidth: f64,
}

/// Edge membrane: frequency-selective coupler parameterized by the
/// level-temporality gap between local and peer nodes.
///
/// Combines the CoherenceFilter (what passes) with level-temporality
/// gap measurement (how much passes). The receiver's integration
/// capacity governs bandwidth — never the sender's coherence pressure.
pub struct Membrane {
    filter: CoherenceFilter,
    local_lt: LevelTemporality,
    peer_lt: Option<LevelTemporality>,
    /// Maximum bandwidth, set by receiver's integration capacity.
    max_bandwidth: f64,
}

/// Threshold for temporal gap in square-preservation check.
const TEMPORAL_EPSILON: f64 = 0.1;

impl Membrane {
    pub fn new(local_lt: LevelTemporality, basis: CoherenceBasis) -> Self {
        Membrane {
            filter: CoherenceFilter::new(basis, 0.5), // default selectivity
            local_lt,
            peer_lt: None,
            max_bandwidth: 1.0,
        }
    }

    /// Set peer's level-temporality (learned from handshake or observation).
    pub fn set_peer(&mut self, peer_lt: LevelTemporality) {
        self.peer_lt = Some(peer_lt);
    }

    /// Full transfer operation: compute gap, adapt coupling, filter.
    ///
    /// 1. Compute level-temporality gap with peer
    /// 2. Derive mutual curvature → adapt filter lambda
    /// 3. Filter payload through coherence basis
    /// 4. Compute effective bandwidth from gap
    pub fn transfer(&mut self, payload: &[u8]) -> TransferResult {
        if let Some(ref peer_lt) = self.peer_lt {
            let (level_gap, temporal_gap) = self.local_lt.gap(peer_lt);
            let level_factor = 1.0 / (1.0 + level_gap as f64);
            let temporality_factor = 1.0 / (1.0 + temporal_gap);
            let mutual_curvature = level_factor * temporality_factor;
            self.filter.adapt_lambda(mutual_curvature);
        } else {
            // Unknown peer → maximum selectivity (precautionary)
            self.filter.adapt_lambda(0.0);
        }

        let filter_result = self.filter.filter(payload);
        let effective_bandwidth = self.effective_bandwidth();
        let square_preserving = self.is_square_preserving();

        TransferResult {
            filter_result,
            square_preserving,
            effective_bandwidth,
        }
    }

    /// Whether this membrane currently permits exact square preservation.
    /// Requires level gap == 0 AND temporal gap < epsilon.
    pub fn is_square_preserving(&self) -> bool {
        match &self.peer_lt {
            Some(peer_lt) => {
                let (level_gap, temporal_gap) = self.local_lt.gap(peer_lt);
                level_gap == 0 && temporal_gap < TEMPORAL_EPSILON
            }
            None => false,
        }
    }

    /// Effective bandwidth after level-temporality gap adjustment.
    ///
    /// bandwidth = max_bandwidth * level_factor * temporality_factor
    /// where level_factor = 1.0 / (1.0 + level_gap)
    /// and temporality_factor = 1.0 / (1.0 + temporal_gap.abs())
    ///
    /// Invariant: effective_bandwidth <= max_bandwidth always.
    /// max_bandwidth is set by receiver's integration capacity, never by sender.
    pub fn effective_bandwidth(&self) -> f64 {
        match &self.peer_lt {
            Some(peer_lt) => {
                let (level_gap, temporal_gap) = self.local_lt.gap(peer_lt);
                let level_factor = 1.0 / (1.0 + level_gap as f64);
                let temporality_factor = 1.0 / (1.0 + temporal_gap);
                (self.max_bandwidth * level_factor * temporality_factor).min(self.max_bandwidth)
            }
            // Unknown peer → zero bandwidth (precautionary)
            None => 0.0,
        }
    }

    /// Reference to the underlying filter.
    pub fn filter(&self) -> &CoherenceFilter {
        &self.filter
    }

    /// Mutable reference to the underlying filter.
    pub fn filter_mut(&mut self) -> &mut CoherenceFilter {
        &mut self.filter
    }

    /// Current max bandwidth setting.
    pub fn max_bandwidth(&self) -> f64 {
        self.max_bandwidth
    }

    /// Set max bandwidth (receiver's integration capacity).
    pub fn set_max_bandwidth(&mut self, max: f64) {
        self.max_bandwidth = max.max(0.0);
    }

    /// Reference to local level-temporality.
    pub fn local_lt(&self) -> &LevelTemporality {
        &self.local_lt
    }

    /// Reference to peer level-temporality (if known).
    pub fn peer_lt(&self) -> Option<&LevelTemporality> {
        self.peer_lt.as_ref()
    }
}
