# Disentangle Protocol: Technical Specification v0.3

## Proof of Entanglement (PoE) — A Post-Quantum, Privacy-Preserving Topological Consensus Mechanism

**Status:** Implementation in Progress
**Supersedes:** SPEC v0.2

---

## Abstract

Proof of Entanglement (PoE) reframes distributed consensus from a voting problem to a measurement problem. Rather than asking "who has authority to append blocks," PoE asks "which state is structurally coherent with the network's history."

**Version 0.3 introduces:**
- Emergent time model: topological depth replaces block heights throughout
- Post-quantum cryptographic primitives (Dilithium5, Kyber1024, SHA3-256)
- Privacy-preserving identity model (ephemeral keys, nullifiers)
- Hardened SimHash computation (structural binding only)
- Foundation for zero-knowledge reputation proofs

Security derives from **information theory** and **topology**, not game theory or thermodynamics.

---

## 1. Cryptographic Suite

All cryptographic operations use NIST-standardized post-quantum algorithms.

| Component | Primitive | NIST Level | Size |
|-----------|-----------|------------|------|
| Signatures | Dilithium5 (ML-DSA) | 5 | PK: 2,592B, Sig: 4,627B |
| Key Encapsulation | Kyber1024 (ML-KEM) | 5 | PK: 1,568B, CT: 1,568B |
| Hashing | SHA3-256 | N/A | 32B output |

### 1.1 Domain-Separated Hashing

All hash operations use domain separation to prevent cross-protocol attacks:

```rust
// Transaction ID
sha3_256(b"TX_ID_V3" || ephemeral_pk || nullifier)

// Nullifier derivation
sha3_256(b"NULLIFIER_V2" || secret_key_hash || epoch || nonce)

// Merkle tree nodes
sha3_256(b"MERKLE_NODE" || left || right)
sha3_256(b"MERKLE_LEAF" || data)

// SimHash generation
sha3_256(b"SIMHASH_GEN_V2" || structural_seed)
```

---

## 2. Data Structures

### 2.1 Transaction (v0.2)

```rust
struct Transaction {
    // === Unique Identifier ===
    id: NodeId,                    // SHA3-256 hash of tx content
    
    // === Ephemeral Identity ===
    ephemeral_pk: VerifyingKey,    // One-time Dilithium5 public key
    signature: Signature,          // Dilithium5 signature over tx body
    
    // === DAG Structure ===
    parents: Vec<NodeId>,          // 2-4 parent transaction IDs
    
    // === Proof of Entanglement ===
    simhash: SimHash,              // 128-bit structural fingerprint
    
    // === Privacy ===
    nullifier: Nullifier,          // Prevents identity reuse per epoch
    
    // === Reputation (v0.2: claim, v0.3: ZK-proven) ===
    reputation_claim: u64,         // Claimed reputation score
}
```

**Key Changes from v0.1:**
- `sender` (permanent PublicKey) → `ephemeral_pk` (one-time key)
- Added `nullifier` for double-spend prevention
- Added `reputation_claim` (will be ZK-proven in v0.3)
- Removed `block` field; ordering is determined by topological depth (see Section 2.1.1)

### 2.1.1 Topological Depth (Lamport Clock)

Ordering in the DAG uses **topological depth**, a Lamport clock derived purely from parent references:

```
depth(genesis) = 0
depth(tx) = 1 + max(depth(parent) for parent in tx.parents)
```

Topological depth is a **committed property**: it depends only on the transaction's parents, which are themselves committed. It is computed via iterative DFS with memoization and cached in the DAG:

```rust
struct TransactionDAG {
    // ...
    depth_cache: HashMap<NodeId, u64>,  // Memoized topological depth
}
```

This replaces external block heights with time that **emerges from the DAG structure itself**, eliminating dependence on any external clock or sequencer.

### 2.2 SimHash (Structural Fingerprint)

SimHash provides locality-sensitive hashing for topological coherence detection.

```rust
struct SimHash(pub u128);

impl SimHash {
    /// Compute SimHash from STRUCTURAL INPUTS ONLY.
    /// 
    /// # Security Invariant
    /// NO user-controllable data may influence the SimHash.
    /// This prevents "grinding attacks" where attackers generate
    /// content to achieve favorable topological positions.
    pub fn from_structural(
        parent_hashes: &[Hash256],      // DAG edges
        identity_history_root: &Hash256, // Account state
    ) -> Self;
    
    /// Hamming distance (similarity measure)
    pub fn hamming_distance(&self, other: &SimHash) -> u32;
    
    /// Coherence check
    pub fn is_coherent(&self, other: &SimHash, threshold: u32) -> bool;
}

const COHERENCE_THRESHOLD: u32 = 32;  // Max Hamming distance for coherence
```

### 2.3 Nullifier

Nullifiers prevent double-spending identity reputation within an epoch.

```rust
struct Nullifier(pub Hash256);

impl Nullifier {
    /// Compute nullifier from secret key and epoch.
    /// 
    /// The same identity produces different nullifiers each epoch,
    /// but the same nullifier within an epoch indicates reuse.
    pub fn compute(
        secret_key_hash: &Hash256,
        epoch: Epoch,
        tx_nonce: &[u8],
    ) -> Self {
        sha3_256(b"NULLIFIER_V2" || secret_key_hash || epoch || tx_nonce)
    }
}

struct Epoch(pub u64);

impl Epoch {
    pub const DEPTH_PER_EPOCH: u64 = 100;

    pub fn from_depth(depth: u64) -> Self {
        Self(depth / Self::DEPTH_PER_EPOCH)
    }
}
```

### 2.4 Account State

```rust
struct AccountState {
    history_root: Hash256,     // Merkle root of transaction history
    transaction_count: u64,    // Total confirmed transactions
    first_seen_depth: u64,     // For age-based weighting
    reputation_score: u64,     // Computed from history
}
```

---

## 3. Transaction DAG

### 3.1 Structure

The DAG stores transactions with parent-child relationships:

```rust
struct TransactionDAG {
    transactions: HashMap<NodeId, Transaction>,
    children: HashMap<NodeId, Vec<NodeId>>,
    depth_cache: HashMap<NodeId, u64>,  // Memoized topological depth
    curvature_cache: HashMap<(NodeId, NodeId), CurvatureEntry>,
    nullifier_set: HashSet<Nullifier>,  // Double-spend prevention
}
```

### 3.2 Insertion Rules

```rust
impl TransactionDAG {
    pub fn insert(&mut self, tx: Transaction) -> Result<(), DagError> {
        // 1. Check nullifier uniqueness
        if self.nullifier_set.contains(&tx.nullifier) {
            return Err(DagError::DuplicateNullifier);
        }
        
        // 2. Verify all parents exist
        for parent in &tx.parents {
            if !self.transactions.contains_key(parent) {
                return Err(DagError::MissingParent(*parent));
            }
        }
        
        // 3. Insert transaction and update indices
        self.nullifier_set.insert(tx.nullifier.clone());
        self.children.entry(parent).or_default().push(tx.id);
        self.transactions.insert(tx.id, tx);
        
        Ok(())
    }
}
```

---

## 4. Discrete Curvature

### 4.1 Jaccard-Based Discrete Curvature

We approximate Ollivier-Ricci curvature using the Jaccard index of neighbor sets,
following Pal et al. (2017):

```rust
/// Compute discrete Jaccard curvature for an edge.
///
/// κ_J(u,v) = 2 * J(N(u), N(v)) - 1
/// where J(A,B) = |A ∩ B| / |A ∪ B| is the Jaccard index.
///
/// Range: [-1, +1] in fixed-point ([-SCALE, +SCALE])
///   Positive: Dense community (high neighborhood overlap)
///   Negative: Bridge/bottleneck (low neighborhood overlap)
pub fn discrete_curvature(u: &NodeId, v: &NodeId, current_depth: u64) -> FixedPoint {
    let neighbors_u = self.neighbors(u);
    let neighbors_v = self.neighbors(v);

    let intersection_count = neighbors_u.intersection(&neighbors_v).count() as i32;
    let union_count = neighbors_u.union(&neighbors_v).count() as i32;

    if union_count == 0 {
        return 0;
    }

    // Jaccard curvature: κ_J = 2 * J(A,B) - 1
    2 * fp_from_ratio(intersection_count, union_count) - SCALE
}
```

The Jaccard formulation is preferred over Simpson (`|A∩B| / min(|A|, |B|)`) because
it penalizes asymmetric degree more strongly, which better captures Sybil bridge
topology where one endpoint has high degree and the other does not.

### 4.2 Curvature Weight Function

Negative curvature (bridges) reduces influence:

```rust
/// Post-bootstrap weight (full throttling).
pub fn curvature_weight(curvature: FixedPoint) -> FixedPoint {
    curvature_weight_with_alpha(curvature, ALPHA_MAX)
}

/// Bootstrap-aware weight with ramped throttling.
pub fn curvature_weight_at_depth(curvature: FixedPoint, depth: u64) -> FixedPoint {
    let alpha = effective_alpha(depth);
    curvature_weight_with_alpha(curvature, alpha)
}

fn curvature_weight_with_alpha(curvature: FixedPoint, alpha: i32) -> FixedPoint {
    if alpha == 0 { return SCALE; } // No throttling during early bootstrap
    let weight = SCALE + alpha * curvature;
    weight.clamp(MIN_CURVATURE_WEIGHT, SCALE)
}
```

During bootstrap (depth < `BOOTSTRAP_START`), `effective_alpha` returns 0 so no
throttling is applied. Between `BOOTSTRAP_START` and `BOOTSTRAP_END`, alpha ramps
linearly to prevent the bootstrap cliff attack (see Section 2.2 of IMPROVEMENTS.md).

### 4.3 Curvature Freezing

Curvature values become **frozen** (immutable) once both endpoints of an edge reach confirmation depth:

```rust
/// Check if curvature for edge (u, v) is frozen.
pub fn is_curvature_frozen(&self, u: &NodeId, v: &NodeId, current_depth: u64) -> bool {
    let u_depth = self.depth(u);
    let v_depth = self.depth(v);
    let edge_depth = u_depth.max(v_depth);
    current_depth >= edge_depth + CONFIRMATION_DEPTH
}
```

**Rationale**: Without freezing, curvature would fluctuate as new children arrive, causing potential consensus instability. Frozen curvature ensures deterministic mass computation.

---

## 5. Topological Mass Consensus

### 5.1 Mass Computation

```rust
pub fn compute_topological_mass(
    dag: &mut TransactionDAG,
    root: &NodeId,
    fork_depth: u64,
) -> MassResult {
    let descendants = dag.descendants(root);

    // Collect unique supporters and their reputation claims
    let mut supporter_claims: HashMap<Hash256, u64> = HashMap::new();
    for node_id in &descendants {
        if let Some(tx) = dag.get(node_id) {
            let pk_hash = sha3_256(&tx.ephemeral_pk.to_bytes());
            supporter_claims.insert(pk_hash, tx.reputation_claim);
        }
    }

    // Diversity score: unique supporters × log(total reputation)
    let unique_supporters = supporter_claims.len();
    let total_claimed: u64 = supporter_claims.values().sum();
    let diversity_score = unique_supporters * (SCALE + log1p(total_claimed) / 10);

    // Sum curvature-weighted contributions
    // Path weight = max over paths of Π edge_weight(e) (multiplicative)
    let mut total_mass: i64 = 0;
    for (node_id, reputation_claim) in descendant_data {
        let path_weight = dag.find_best_path_weight(root, &node_id, 15, fork_depth);
        let rep_bonus = bucket_weight(reputation_claim); // ZK-compatible bucketed weight
        total_mass += fp_mul(path_weight, rep_bonus);
    }

    // Apply diversity multiplier
    (total_mass * diversity_score) / SCALE
}
```

### 5.1.1 Path Weight Definition

The path weight from source $t$ to descendant $d$ is the maximum multiplicative weight:

$$w(t, d) = \max_{P \in \text{paths}(t, d)} \prod_{e \in P} \text{edge\_weight}(e)$$

This multiplicative formulation ensures paths crossing multiple bridge edges (Sybil boundaries) are exponentially attenuated.

### 5.2 Conflict Resolution

```rust
pub fn resolve_conflict(
    dag: &mut TransactionDAG,
    branch_a: &NodeId,
    branch_b: &NodeId,
    fork_depth: u64,
) -> ConflictWinner {
    let mass_a = compute_topological_mass(dag, branch_a, fork_depth);
    let mass_b = compute_topological_mass(dag, branch_b, fork_depth);
    
    if mass_a > mass_b {
        ConflictWinner::BranchA
    } else if mass_b > mass_a {
        ConflictWinner::BranchB
    } else {
        // Tiebreaker: lower hash wins (deterministic)
        if branch_a < branch_b { BranchA } else { BranchB }
    }
}
```

### 5.3 Finality

A branch is final when it has 10× the mass of any competitor:

```rust
const FINALITY_RATIO: i32 = 10;

pub fn is_finalized(branch: &NodeId, competitors: &[NodeId]) -> bool {
    let branch_mass = compute_topological_mass(dag, branch, fork_depth);

    for competitor in competitors {
        let comp_mass = compute_topological_mass(dag, competitor, fork_depth);
        if branch_mass < FINALITY_RATIO * comp_mass {
            return false;
        }
    }
    true
}
```

---

## 6. Fixed-Point Arithmetic

All consensus-critical computations use fixed-point integers for determinism.

```rust
pub type FixedPoint = i32;
pub const SCALE: i32 = 65536;  // 2^16

pub fn fp_from_ratio(num: i32, denom: i32) -> FixedPoint {
    ((num as i64 * SCALE as i64) / denom as i64) as i32
}

pub fn fp_mul(a: FixedPoint, b: FixedPoint) -> FixedPoint {
    ((a as i64 * b as i64) / SCALE as i64) as i32
}

pub fn integer_log1p(x: i32) -> FixedPoint {
    if x <= 0 { return 0; }
    let mut result = 0;
    let mut val = x + 1;
    while val > 1 {
        result += SCALE / 4;
        val /= 2;
    }
    result
}
```

---

## 7. Security Analysis

### 7.1 Post-Quantum Security

| Component | Classical Security | Quantum Security |
|-----------|-------------------|------------------|
| Dilithium5 | 256-bit | 128-bit (NIST Level 5) |
| Kyber1024 | 256-bit | 128-bit (NIST Level 5) |
| SHA3-256 | 256-bit collision | 128-bit collision |

### 7.2 Sybil Resistance

Sybil attacks create detectable geometric distortions:

1. **Negative Curvature Detection**: Bridge edges connecting Sybil clusters to the main network exhibit negative curvature.

2. **Curvature Throttling**: With α=3, a bridge with curvature κ=-0.33 has weight:
   ```
   weight = max(0.01, 1.0 + 3 × (-0.33)) = 0.01
   ```
   Sybil influence reduced by 99%.

3. **Diversity Score**: Coordinated attackers have low supporter diversity, reducing total mass.

### 7.3 Double-Spend Prevention

1. **Nullifier Uniqueness**: Each identity can only submit one transaction per epoch with a given nonce.

2. **Structural Binding**: SimHash is derived from account history, preventing attackers from repositioning without actual history.

### 7.4 Grinding Resistance

SimHash computation accepts NO user-controllable inputs:
- ✅ Parent hashes (chosen from existing DAG)
- ✅ Identity history root (determined by past behavior)
- ❌ Memo fields
- ❌ Output data
- ❌ Arbitrary nonces

---

## 8. Implemented Since v0.1

### 8.1 Zero-Knowledge Reputation Proofs (Implemented)

The `disentangle-zkp` crate provides:
- Bucketed reputation proofs (6 buckets, ZK-compatible)
- STARK-based proof generation and verification via Plonky3
- Merkle membership proofs for account state
- `compute_topological_mass_verified()` integrates ZK proofs into consensus

### 8.2 Confidential Transactions (Partially Implemented)

The `disentangle-zkp` crate includes:
- Amount commitments with blinding factors
- Stealth addresses via Kyber1024 key encapsulation
- Balance circuit and range circuit foundations
- Full integration pending production STARK proving

### 8.3 Post-Quantum Transport (Implemented)

The `disentangle-p2p` crate provides:
- Kyber1024-based key encapsulation for session keys
- AES-256-GCM symmetric encryption with nonce management
- Rekey protocol for forward secrecy

## 9. Future Work

### 9.1 Diversity Counting via Window Nullifiers

Replace ephemeral-key-based supporter counting with per-window nullifiers
proven in ZK, resolving the unlinkability/counting conflict (IMPROVEMENTS.md 1.3).

### 9.2 Bridge Mutual Recognition

Allow legitimate inter-community bridges to bypass throttling via
mutual historical integration heuristics (IMPROVEMENTS.md 2.1).

### 9.3 Split-Brain Partition Handling

Detect partition scenarios (comparable mass on both sides of a conflict)
and pause finality rather than discarding an honest partition (IMPROVEMENTS.md 2.3).

---

## Appendix A: Constants

```rust
// Fixed-Point
pub const SCALE: i32 = 65536;

// Curvature Throttling
pub const ALPHA_MAX: i32 = 3;              // Maximum throttling aggressiveness
pub const MIN_CURVATURE_WEIGHT: i32 = SCALE / 100;  // 1% minimum weight

// Bootstrap (ramped throttling)
pub const BOOTSTRAP_START: u64 = 1000;     // Depth when throttling begins
pub const BOOTSTRAP_END: u64 = 6000;       // Depth when full throttling active

// SimHash
pub const COHERENCE_THRESHOLD: u32 = 32;
pub const MAX_DRIFT_BITS: u32 = 8;

// Consensus
pub const FINALITY_RATIO: i32 = 10;
pub const MAX_PATH_DEPTH: usize = 15;
pub const CONFIRMATION_DEPTH: u64 = 6;     // Depth levels before curvature freezes (testing default)

// Epochs
pub const DEPTH_PER_EPOCH: u64 = 100;
```

---

## Appendix B: Crate Structure

```
disentangle-core/
├── disentangle-crypto/     # PQ primitives (Dilithium5, Kyber1024, SHA3-256)
├── disentangle-simhash/    # Structural fingerprints
├── disentangle-dag/        # Transaction DAG with curvature
├── disentangle-zkp/        # ZK reputation proofs, confidential transactions
├── disentangle-consensus/  # Mass computation, conflict resolution
├── disentangle-identity/   # CCIP: DIDs, capabilities, petnames, governance
├── disentangle-node/       # RPC handlers, identity state management
├── disentangle-p2p/        # libp2p networking with PQ transport
└── disentangle-cli/        # Command-line interface
```

---

*Disentangle Protocol Specification v0.3*
*February 17, 2026*
