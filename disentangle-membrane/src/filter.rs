use disentangle_crypto::sha3_256;
use disentangle_simhash::SimHash;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SimHash Path — primary, frequency-selective coupler
// ---------------------------------------------------------------------------

/// The receiver's coherence basis: a set of SimHash signatures representing
/// the frequency components the receiver can currently integrate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoherenceBasis {
    pub signatures: Vec<SimHash>,
    /// Maximum hamming distance for basis membership (scope check).
    pub threshold: u32,
}

/// Result of filtering a payload through a coherence basis.
/// This is a coupling measurement, not a binary gate: resonance measures
/// how strongly the payload couples to the receiver's coherence structure.
#[derive(Debug, Clone)]
pub struct FilterResult {
    /// Whether the payload passed the coupling threshold.
    pub passed: bool,
    /// Coupling coefficient: 0.0 = no harmonic overlap, 1.0 = perfect resonance.
    pub resonance: f64,
    /// The payload content that survived projection (None if fully filtered).
    pub projected_payload: Option<Vec<u8>>,
    /// Number of payload components that were attenuated to zero.
    pub dropped_components: usize,
}

/// Frequency-selective coupler using SimHash basis projection.
///
/// Two-layer design:
/// 1. **Basis scope**: payload must be representable in the receiver's basis
///    (hamming distance within threshold). This is non-negotiable — lambda
///    cannot bypass it.
/// 2. **Lambda sensitivity**: among representable payloads, lambda controls
///    the minimum coupling coefficient for passage.
///
/// lambda=0.0 → maximally open (any in-basis payload couples)
/// lambda=1.0 → maximally selective (only exact resonance couples)
#[derive(Debug, Clone)]
pub struct CoherenceFilter {
    basis: CoherenceBasis,
    /// Coupling selectivity. 0.0 = open, 1.0 = closed.
    lambda: f64,
}

impl CoherenceFilter {
    pub fn new(basis: CoherenceBasis, lambda: f64) -> Self {
        CoherenceFilter {
            basis,
            lambda: lambda.clamp(0.0, 1.0),
        }
    }

    /// Core operation: couple payload through coherence basis.
    /// Converts payload bytes to SimHash, then delegates to filter_hash.
    pub fn filter(&self, payload: &[u8]) -> FilterResult {
        let payload_hash = simhash_from_bytes(payload);
        self.filter_hash(payload_hash, Some(payload))
    }

    /// Filter using a pre-computed SimHash. Useful for testing and for
    /// cases where the SimHash is already known (e.g., from DAG metadata).
    pub fn filter_hash(&self, payload_hash: SimHash, raw_payload: Option<&[u8]>) -> FilterResult {
        if self.basis.signatures.is_empty() {
            return FilterResult {
                passed: false,
                resonance: 0.0,
                projected_payload: None,
                dropped_components: 1,
            };
        }

        let min_distance = self
            .basis
            .signatures
            .iter()
            .map(|s| s.hamming_distance(&payload_hash))
            .min()
            .unwrap(); // safe: basis is non-empty

        let resonance = 1.0 - (min_distance as f64 / SimHash::BITS as f64);

        // Layer 1: Basis scope — non-bypassable even at lambda=0.0
        let in_basis = min_distance <= self.basis.threshold;

        // Layer 2: Lambda sensitivity — coupling threshold
        let passed = in_basis && resonance >= self.lambda;

        FilterResult {
            passed,
            resonance,
            projected_payload: if passed {
                raw_payload.map(|p| p.to_vec())
            } else {
                None
            },
            dropped_components: if passed { 0 } else { 1 },
        }
    }

    /// Adapt lambda from observed mutual curvature between sender/receiver.
    /// High mutual curvature → lambda decreases → coupler opens.
    /// curvature ∈ [0.0, 1.0]: 0.0 = no mutual coherence, 1.0 = perfect alignment.
    pub fn adapt_lambda(&mut self, mutual_curvature: f64) {
        self.lambda = (1.0 - mutual_curvature).clamp(0.0, 1.0);
    }

    /// Add a new signature to the basis (learning from filtered exchanges).
    /// Widens the frequency band the coupler can resonate with.
    pub fn extend_basis(&mut self, sig: SimHash) {
        self.basis.signatures.push(sig);
    }

    /// Current bandwidth capacity (0.0 = closed, 1.0 = fully open).
    /// Bandwidth = 1.0 - lambda: inversely proportional to selectivity.
    pub fn bandwidth(&self) -> f64 {
        1.0 - self.lambda
    }

    /// Current lambda (coupling selectivity).
    pub fn lambda(&self) -> f64 {
        self.lambda
    }

    /// Reference to the underlying coherence basis.
    pub fn basis(&self) -> &CoherenceBasis {
        &self.basis
    }
}

/// Convert arbitrary bytes to a SimHash for filtering purposes.
/// Uses SHA3-256 to derive a 128-bit locality-sensitive hash.
pub fn simhash_from_bytes(data: &[u8]) -> SimHash {
    let hash = sha3_256(data);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    SimHash(u128::from_le_bytes(bytes))
}

// ---------------------------------------------------------------------------
// Spectral Path — eigendecomposition-based coherence projection
// ---------------------------------------------------------------------------

/// Spectral coherence basis built from eigendecomposition of the receiver's
/// history covariance matrix. Retains top-k eigenvectors capturing the
/// specified fraction of total energy.
pub struct SpectralBasis {
    pub eigenvectors: nalgebra::DMatrix<f64>,
    pub eigenvalues: nalgebra::DVector<f64>,
    pub energy_threshold: f64,
    /// Number of eigenvectors retained after energy thresholding.
    retained: usize,
}

/// Spectral frequency-selective coupler. Projects incoming payloads onto
/// the receiver's principal coherence components. Low-energy (noise)
/// components are attenuated regardless of lambda.
pub struct SpectralFilter {
    basis: SpectralBasis,
    lambda: f64,
}

impl SpectralFilter {
    /// Build spectral basis from a history of feature vectors.
    /// Computes covariance matrix, eigendecomposes, retains top components
    /// capturing `energy_threshold` fraction of total variance.
    pub fn from_history(feature_vectors: &[Vec<f64>], energy_threshold: f64) -> Self {
        assert!(
            !feature_vectors.is_empty(),
            "need at least one feature vector"
        );
        let dim = feature_vectors[0].len();
        let n = feature_vectors.len();

        // Compute mean
        let mut mean = vec![0.0f64; dim];
        for fv in feature_vectors {
            assert_eq!(
                fv.len(),
                dim,
                "all feature vectors must have same dimension"
            );
            for (i, v) in fv.iter().enumerate() {
                mean[i] += v;
            }
        }
        for m in &mut mean {
            *m /= n as f64;
        }

        // Build centered data matrix (n x dim)
        let mut data = nalgebra::DMatrix::<f64>::zeros(n, dim);
        for (row, fv) in feature_vectors.iter().enumerate() {
            for (col, v) in fv.iter().enumerate() {
                data[(row, col)] = v - mean[col];
            }
        }

        // Covariance matrix (dim x dim)
        let divisor = if n > 1 { (n - 1) as f64 } else { 1.0 };
        let cov = data.transpose() * &data / divisor;

        // Symmetric eigendecomposition
        let eigen = nalgebra::linalg::SymmetricEigen::new(cov);

        // Sort eigenvalues descending
        let mut indices: Vec<usize> = (0..dim).collect();
        indices.sort_by(|&a, &b| {
            eigen.eigenvalues[b]
                .partial_cmp(&eigen.eigenvalues[a])
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let sorted_eigenvalues =
            nalgebra::DVector::from_fn(dim, |i, _| eigen.eigenvalues[indices[i]].max(0.0));

        let sorted_eigenvectors =
            nalgebra::DMatrix::from_fn(dim, dim, |r, c| eigen.eigenvectors[(r, indices[c])]);

        // Determine retained dimensions by cumulative energy
        let total_energy: f64 = sorted_eigenvalues.iter().sum();
        let mut cumulative = 0.0;
        let mut retained = dim;
        if total_energy > 0.0 {
            for (i, &ev) in sorted_eigenvalues.iter().enumerate() {
                cumulative += ev;
                if cumulative / total_energy >= energy_threshold {
                    retained = i + 1;
                    break;
                }
            }
        }

        SpectralFilter {
            basis: SpectralBasis {
                eigenvectors: sorted_eigenvectors,
                eigenvalues: sorted_eigenvalues,
                energy_threshold,
                retained,
            },
            lambda: 0.5,
        }
    }

    /// Project payload features onto spectral basis. Components below the
    /// energy threshold are attenuated — this is inherent to the projection,
    /// not controllable by lambda. Lambda only controls the minimum coupling
    /// coefficient for the retained components.
    pub fn filter(&self, payload_features: &[f64]) -> FilterResult {
        let dim = self.basis.eigenvectors.nrows();
        assert_eq!(
            payload_features.len(),
            dim,
            "feature dimension mismatch: expected {}, got {}",
            dim,
            payload_features.len()
        );

        let payload = nalgebra::DVector::from_row_slice(payload_features);

        // Project onto retained eigenvectors
        let retained = self.basis.retained;
        let basis_slice = self.basis.eigenvectors.columns(0, retained);

        // Coefficients in eigenspace
        let coeffs = basis_slice.transpose() * &payload;

        // Reconstruct from projection
        let reconstructed = basis_slice * &coeffs;

        // Coupling coefficient = fraction of payload energy captured by projection
        let payload_energy = payload.dot(&payload);
        let projected_energy = reconstructed.dot(&reconstructed);

        let resonance = if payload_energy > 0.0 {
            (projected_energy / payload_energy).sqrt().min(1.0)
        } else {
            1.0 // zero-energy payload trivially couples
        };

        let passed = resonance >= self.lambda;
        let dropped = dim - retained;

        FilterResult {
            passed,
            resonance,
            projected_payload: if passed {
                let bytes: Vec<u8> = reconstructed
                    .iter()
                    .flat_map(|&v| v.to_le_bytes())
                    .collect();
                Some(bytes)
            } else {
                None
            },
            dropped_components: dropped,
        }
    }

    /// Number of eigenvectors retained after energy thresholding.
    pub fn retained_dimensions(&self) -> usize {
        self.basis.retained
    }

    /// Original feature space dimensionality.
    pub fn total_dimensions(&self) -> usize {
        self.basis.eigenvectors.nrows()
    }

    /// Set lambda (coupling selectivity) for the spectral filter.
    pub fn set_lambda(&mut self, lambda: f64) {
        self.lambda = lambda.clamp(0.0, 1.0);
    }

    /// Current lambda value.
    pub fn lambda(&self) -> f64 {
        self.lambda
    }
}
