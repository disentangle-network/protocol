# disentangle-membrane — Implementation Specification

**Status:** Implementation specification, v1 (SimHash path). Derived from the seven settled design decisions in `DECISIONS.md` (2026-04-18) and the Lars + cdesktop synchronous review (2026-04-19). This document governs the v1 shape of the primitive; it is the binding reference for the Group Integrity Monitor productization layer and the PPA-4 "coherence-selective membrane filtering" aspect.
**Scope:** Application-layer coherence-selective coupler. Ingress-dominant. Observer-mode default. Tenant-configurable. PPA-4 claim-bearing.
**Companion document:** `DECISIONS.md` — records the seven open questions and the argumentation behind each settled answer. Read `DECISIONS.md` first if you are new to the primitive; read this document when implementing or reviewing against it.
**Non-goals:** full productization of the GIM SaaS layer (that lives in a separate closed repository and this spec is its substrate, not its spec); protocol-level consensus changes (the DAG and `disentangle-consensus` are out of scope for modification — this spec composes over them); wallet / payment / cryptocurrency semantics (the membrane is a content-filtering primitive, not a value-transfer mechanism); SpectralFilter path productization (see §11).
**Audience:** implementers of the membrane crate, reviewers evaluating claims against prior art, SaaS product engineers composing the primitive into higher-level features, and counsel reviewing PPA-4 claim anchors.
**Last updated:** 2026-04-19.

---

## Table of Contents

1. Primitive overview
2. Data structures
3. Core filter algorithm (SimHash path)
4. Basis provenance (self-anchored, tenant-anchored, governance-attested)
5. Tenant basis scope (isolated, hierarchical)
6. Node integration and positioning
7. Lambda dynamics (adaptive, bounded, attack-mode tightening)
8. Composition with consensus (tagged entry, opt-in hard reject)
9. Capability-check ordering (filter-first, capability-first)
10. Observer channel (Tier 1 aggregate-continuous, Tier 2 per-transaction subpoena-gated)
11. SpectralFilter path — forward reference
12. Failure modes
13. Embodiment variations
14. Compatibility and migration from the research crate

- Appendix A: Worked numerical examples
- Appendix B: PPA-4 claim anchor enumeration
- Appendix C: Conventions and invariant inventory
- Appendix D: Glossary

---

## 1. Primitive Overview

### 1.1 Purpose

The membrane is a *frequency-selective coupler* that operates at the application layer of a Disentangle-substrate node. For each inbound payload destined for a declared receiver (a handler, a topic subscriber, a capability holder), it computes a coupling coefficient — a scalar `resonance ∈ [0.0, 1.0]` — measuring how well the payload's structural signature matches the receiver's coherence basis. Resonance is a continuous quantity, not a boolean. The primitive's output is always `FilterResult { passed: bool, resonance: f64, projected_payload: Option<Vec<u8>>, dropped_components: usize }`, and downstream consumers (DAG insertion, capability enforcement, observer channel, tenant policy engine) choose how to act on it.

The guiding phrase of the primitive is: *coupling, not gating*. Every design decision in this spec is evaluated against whether it preserves that framing, against whether it fits the Group Integrity Monitor (GIM) SaaS product shape described in `PIVOT_AUDIT.md` §4.1, and against whether it supports the PPA-4 claim surface (particularly the "coherence-selective membrane filtering" aspect and its compositions with PPA-4 Aspects 1, 2, 6, and 7).

### 1.2 Invariants

The v1 spec preserves all seven property-based invariants currently established in `tests/safety_invariants.rs`:

- **I1 Non-degradation.** For any membrane configuration, `effective_bandwidth` is in `[0.0, max_bandwidth]`.
- **I2 Bandwidth monotonicity.** For fixed `max_bandwidth` and temporality, `effective_bandwidth` is monotone non-increasing as level gap increases.
- **I3 Basis scope non-bypassability.** For any payload whose hamming distance exceeds the basis threshold against *all* basis signatures, `FilterResult.passed` is false regardless of `lambda`. Lambda cannot open a receiver to payloads outside its basis scope.
- **I4 Square-preservation symmetry.** `square_preserving` is true iff `level_gap == 0 AND temporal_gap < TEMPORAL_EPSILON`.
- **I5 Lambda bounds.** `lambda = 0.0` admits any in-basis payload; `lambda = 1.0` admits only exact-resonance payloads; all intermediate values interpolate monotonically.
- **I6 Bandwidth non-negativity.** `effective_bandwidth >= 0.0` for all valid inputs.
- **I7 Sybil resistance / idempotence.** Processing N copies of the same payload does not produce N-fold influence on the receiver's integration state.

Four additional invariants are introduced by this spec:

- **I8 Receiver-governed bandwidth.** `max_bandwidth` is always set by the receiver's integration capacity, never by the sender or by any sender-controlled field in the payload. Sender-supplied fields must not reach the `Membrane::set_max_bandwidth` call path.
- **I9 Provenance opacity.** The receiver's `BasisProvenance` mode is a receiver property, not a payload property. A sender cannot infer the receiver's provenance mode from a `FilterResult` response.
- **I10 Observer no-content.** The observer channel, at any tier, never emits decrypted payload bytes. The worst-case exposure is per-transaction resonance value, sender/receiver DIDs, timestamp, basis-version, and lambda-at-evaluation.
- **I11 Hard-reject explicitness.** Hard-reject behavior (§8) requires explicit `enforcement_mode = HardReject` on the capability declaration. The default is `Tagged`; a capability issued without the field defaults to `Tagged`.

### 1.3 What the primitive is not

- Not a rate limiter. Rate limiting lives in `disentangle-consensus` bucket weights (PPA-1).
- Not an authentication layer. Authentication is handled by signatures on `Transaction` (PPA-2).
- Not an authorization layer. Authorization is capability validation (PPA-2). The membrane composes with it but does not replace it.
- Not a DLP content classifier. The SimHash basis captures structural fingerprints, not content semantics.
- Not a rule-based WAF. There are no regex, no patterns, no blocklists. The basis is a set of learned or attested structural signatures with a geometric threshold.
- Not a consensus mechanism. The DAG consensus is unchanged at the moment of transaction inclusion; see §8 for the composition with consensus.
- Not a curvature or topological-mass computation. Curvature primitives and topological mass are computed in `disentangle-consensus` and `disentangle-dag` (see PPA-1 and the consensus crate source). The membrane *consumes* the derived signals — coherence tier, level-temporality, per-peer coupling scalars — and applies basis/resonance/filter/foliation machinery on top of them. See §1.4.

### 1.4 Boundary: consumed inputs vs. membrane computation

This subsection is load-bearing for the pitch and for the pivot audit. The membrane's job is narrow by design.

**Consumed from consensus-layer primitives (inputs with defined upstream semantics):**

- **Coherence tier / `CoherenceLevel`.** Computed by `disentangle-consensus` from curvature-and-mass primitives (PPA-1). The membrane treats it as an opaque ordinal per peer, referenced via `LevelTemporality`.
- **Temporal signature / `TemporalSignature`.** Computed by `disentangle-dag` from DAG-depth integration behavior (PPA-3 temporal ordering). The membrane consumes it as an opaque scalar per peer.
- **Topological mass.** Computed by `disentangle-consensus` (PPA-1). The membrane does not read this directly at filter time; it reaches the membrane indirectly through the coherence tier assignment and through revocation-transaction effects (see §8.2).
- **AttackState attestation.** Produced externally by the tenant policy layer or by a governance process (§7.4). The membrane consumes an attested record; it does not decide that an attack is occurring.
- **Basis attestation / governance attestation.** Produced by tenant admin or governance process (§4). The membrane verifies the signature and consumes the signed basis version.

**Computed by the membrane (this spec's scope):**

- **Basis hamming filter** against the receiver's `CoherenceBasis` (§3).
- **Resonance scalar** in `[0.0, 1.0]` from minimum hamming distance over basis (§3).
- **Lambda adaptation** from consumed LT gaps and (optionally) attested AttackState (§7). The local variable `mutual_curvature` in `adapt_lambda` is a *membrane-internal coupling scalar derived from consumed LT gaps* — not the consensus-layer curvature primitive. The name is retained for backward compatibility with the research crate's signature; it denotes the membrane's local coupling computation, distinct from the upstream curvature math.
- **Foliation classification** into leaves over consumed LT signals (§13, Embodiment E).
- **Observer emission** per-tier, bound to the filter result (§10).
- **Effective basis construction** in hierarchical tenant mode (§5.4) — see §5.1 for the named pattern.

**Out of scope for this crate:**

- Curvature derivation from graph structure or mass distribution (PPA-1; `disentangle-consensus`).
- DAG temporal ordering math (PPA-3; `disentangle-dag`).
- Governance process that produces basis attestations (see Q3 decision in `DECISIONS.md` §Q3: the membrane accepts attestations; it does not implement the process that emits them).
- Attack-detection heuristics that produce `AttackState` (see §7.4 — the membrane accepts the attested record and records its provenance; external systems decide that an attack is occurring).

The parallel with Q3's governance decoupling is deliberate. Just as the membrane accepts governance attestations without implementing governance, it accepts coherence signals without implementing curvature. This separation is what keeps the membrane a focused primitive that can be licensed, vendored, and composed across deployment shapes.

---

## 2. Data Structures

This section defines the types that appear in the algorithms and the observer channel. Types are given as Rust-like pseudocode; the actual Rust definitions will be authored in the membrane crate's `filter.rs`, `membrane.rs`, `provenance.rs` (new), `policy.rs` (new), `observer.rs` (new), and `attack.rs` (new). Serialization is via `serde` + `bincode` consistent with the rest of the protocol workspace.

### 2.1 Core types (existing, retained)

```rust
pub struct SimHash(pub u128);                          // 128-bit locality-sensitive hash
pub struct CoherenceBasis {
    pub signatures: Vec<SimHash>,                      // Set of basis signatures
    pub threshold: u32,                                 // Max hamming distance for membership
    pub version: u64,                                   // Monotonic version, increments on mutation
}
pub struct FilterResult {
    pub passed: bool,
    pub resonance: f64,                                 // [0.0, 1.0]
    pub projected_payload: Option<Vec<u8>>,
    pub dropped_components: usize,
}
```

### 2.2 BasisProvenance (new)

```rust
pub enum BasisProvenance {
    /// Receiver derives basis from its own transaction history.
    /// No external attestation. Research baseline.
    SelfAnchored {
        history_window: u64,                            // Depth window for history-derived signatures
        min_history: usize,                             // Minimum history before receiver can operate (see I1-bootstrap)
    },

    /// Tenant admin supplies basis via configuration.
    /// SaaS default.
    TenantAnchored {
        tenant_id: TenantId,
        policy_ref: PolicyRef,                          // Reference to receiver's published policy envelope
        basis_signer: VerifyingKey,                     // Tenant admin key that signed the basis
    },

    /// Tenant-anchored mechanically, with an additional governance attestation
    /// on the basis provenance. Consortium/DAO mode. The membrane consumes
    /// governance output; it does not implement governance.
    GovernanceAttested {
        tenant_id: TenantId,
        policy_ref: PolicyRef,
        governance_root: Hash256,                       // Merkle root of governance attestation record
        attestation_epoch: u64,                         // Epoch at which attestation was produced
    },
}
```

*Rationale.* Mode selection is per-receiver, not per-deployment (see §4.4). A single node may host receivers in all three modes simultaneously — a `messaging/groupchat` receiver in `TenantAnchored`, a `governance/proposal` receiver in `GovernanceAttested`, and a researcher-private receiver in `SelfAnchored`.

### 2.3 TenantBasisMode (new)

```rust
pub enum TenantBasisMode {
    /// Each tenant's effective basis is exclusively the tenant's own signatures.
    /// Strict-isolation tenants (regulated industries with no-shared-compute
    /// requirements).
    Isolated,

    /// Tenant's effective basis is a union of (provider baseline ∩ applicable-to-tenant)
    /// and the tenant's own delta. Default for GIM SaaS.
    Hierarchical {
        baseline_ref: BaselineRef,                      // Handle to the provider baseline version in force
        min_tenant_admit: u32,                          // Minimum distinct tenants needed for a signature to enter baseline (see §5.1, §5.4)
    },
}
```

### 2.4 CapabilityMetadata (new; attaches to `disentangle-identity::Capability`)

```rust
pub struct MembraneMetadata {
    /// Whether filter failure is tagged (default) or hard-rejected pre-DAG.
    pub enforcement_mode: EnforcementMode,
    /// Whether capability-check runs before or after the filter.
    pub check_order: CheckOrder,
    /// Reference to the receiver's lambda-bounds policy for this capability class.
    pub policy_ref: PolicyRef,
}

pub enum EnforcementMode { Tagged, HardReject }
pub enum CheckOrder     { FilterFirst, CapabilityFirst }
```

*Placement.* The Capability struct in `disentangle-identity::Capability` gains an `Option<MembraneMetadata>` field. Capabilities without the field default to `MembraneMetadata { enforcement_mode: Tagged, check_order: FilterFirst, policy_ref: PolicyRef::Default }` at evaluation time (see §8 and §9). The default, in particular, is `Tagged` — a capability that was issued before the membrane existed, or issued without specifying membrane metadata, does not hard-reject. This is invariant I11.

### 2.5 AttackState attestation (new)

```rust
pub struct AttackState {
    /// Whether attack-mode tightening is currently active for this receiver/tenant.
    pub active: bool,
    /// Multiplier applied to baseline lambda when active. `1.0` means no tightening.
    pub tightening_multiplier: f64,
    /// When attack-mode began (depth-based, not wall-clock).
    pub activated_at_depth: u64,
    /// When attack-mode automatically returns to baseline.
    pub decays_at_depth: u64,
    /// Monotonically increasing counter of declared attack-mode activations,
    /// for ordering and replay protection.
    pub sequence: u64,
    /// Who declared the attack state — maps to Q3 BasisProvenance.
    pub authority: AttackAuthority,
    /// Human-readable signal provenance; recorded to observer channel.
    /// Not used by the algorithm, used by auditors.
    pub signal_provenance: String,
    /// Signature binding the attestation to the authority's key.
    pub signature: Signature,
}

pub enum AttackAuthority {
    Receiver(DID),                                      // Self-anchored → receiver itself
    TenantOperator { tenant_id: TenantId, key: VerifyingKey },
    Governance { governance_root: Hash256, attestation_epoch: u64 },
}
```

*Rationale for attack-state authority mapping.* Per Q4, the authority that can declare an attack state follows the receiver's `BasisProvenance` mode. A `SelfAnchored` receiver declares its own attack state. A `TenantAnchored` receiver accepts attack-state attestations signed by the tenant security operator key bound at `PolicyRef` time. A `GovernanceAttested` receiver accepts attack-state attestations carrying a governance epoch reference.

### 2.6 ObserverTier configuration (new)

```rust
pub struct ObserverConfig {
    /// Always-on aggregate-continuous tier.
    pub tier1: Tier1Config,
    /// Per-transaction tier, subpoena-gated.
    pub tier2: Tier2Config,
    /// Foliation surfacing (cross-cutting item 3).
    pub foliation: FoliationSurfacing,
}

pub struct Tier1Config {
    /// Aggregation window for histogram / rate emissions.
    pub window_depth: u64,
    /// Histogram bucket count for resonance distribution.
    pub histogram_buckets: u8,
    /// Whether basis-drift events (basis mutations) are emitted.
    pub emit_basis_drift: bool,
    /// Whether attack-mode activations are emitted.
    pub emit_attack_state: bool,
}

pub struct Tier2Config {
    /// Whether Tier 2 is active. Always false unless legal-process-attested
    /// attestation is present for the specific scope.
    pub active_scope: Option<LegalProcessScope>,
}

pub enum FoliationSurfacing {
    /// Foliation leaf identifiers and aggregate counts emitted via Tier 1.
    /// No per-transaction leaf assignment. Default.
    AggregateOnly,
    /// No foliation information in the observer channel.
    None,
    /// Per-transaction leaf assignment emitted. Tenant-opt-in; elevated-privacy
    /// tenants disable.
    PerTransaction,
}

pub struct LegalProcessScope {
    pub receiver_did: DID,                              // Specific receiver(s) named in legal process
    pub start_depth: u64,
    pub end_depth: u64,
    pub process_identifier: String,                     // Subpoena / warrant number
    pub attesting_authority: VerifyingKey,              // External legal-process attestation key
    pub attestation_signature: Signature,
}
```

### 2.7 Transaction metadata extension (composes with `disentangle-dag::Transaction`)

The membrane produces a per-transaction metadata record that the DAG transaction carries as a signed extension field:

```rust
pub struct MembraneRecord {
    pub resonance: f64,
    pub passed: bool,
    pub lambda_at_eval: f64,
    pub basis_version: u64,
    pub provenance_tag: ProvenanceTag,                  // Opaque handle to BasisProvenance (not the mode itself, per I9)
    pub check_order_applied: CheckOrder,
    pub enforcement_mode_applied: EnforcementMode,
    pub attack_state_active: bool,
    pub receiver_signature: Signature,                  // Receiver signs the record
}
```

`ProvenanceTag` is a 16-byte opaque identifier that is stable per-receiver-per-basis-version but does not disclose whether the receiver is self-anchored, tenant-anchored, or governance-attested (invariant I9). Auditors with appropriate authorization can resolve the tag to the provenance mode; senders and arbitrary observers cannot.

---

## 3. Core Filter Algorithm (SimHash Path)

### 3.1 High-level flow

```text
Input:
    payload: &[u8]                                      // Application payload bytes
    basis:   &CoherenceBasis                            // Receiver's effective basis (after §4 resolution)
    lambda:  f64                                        // Effective lambda (after §7 resolution)

Procedure filter(payload, basis, lambda) -> FilterResult:
    1. Compute payload_hash = simhash_from_bytes(payload)
    2. Compute min_distance = min_{s in basis.signatures} hamming(payload_hash, s)
    3. in_basis  := (min_distance <= basis.threshold)
    4. resonance := 1.0 - (min_distance as f64 / SimHash::BITS as f64)
    5. passed    := in_basis AND (resonance >= lambda)
    6. RETURN FilterResult { passed, resonance,
                             projected_payload = if passed Some(payload.to_vec()) else None,
                             dropped_components = if passed 0 else 1 }
```

The two-layer structure (step 3 basis-scope check, step 5 lambda check) is non-negotiable; it is the content of invariant I3. `lambda = 0.0` with an in-basis payload always admits; `lambda = 1.0` admits only exact-match payloads; payloads outside basis scope are always rejected.

### 3.2 Lambda-at-zero convention reconciliation (cross-cutting item 1)

The research crate has two callsites that use `lambda = 0.0` with opposite intents:

- `filter.rs` treats `lambda = 0.0` as *maximally open*: any in-basis payload passes regardless of resonance floor.
- `membrane.rs`'s `adapt_lambda(mutual_curvature)` when called with `mutual_curvature = 0.0` sets `lambda = 1.0` (maximum selectivity). The unknown-peer branch then calls `adapt_lambda(0.0)` — meaning unknown peers are treated *maximally selectively*.

These are consistent in each file but confusing in composition because two calls with `lambda = 0.0` on the `CoherenceFilter` produce different operational outcomes depending on whether the `Membrane` wrapper has been used.

**Reconciliation (final).** The v1 spec preserves the `CoherenceFilter` semantics (0.0 = open, 1.0 = closed) as the scalar convention, and renames the `Membrane` "unknown-peer" code path to make the intent explicit rather than a numeric coincidence.

```rust
// CoherenceFilter: lambda is the minimum resonance for passage.
//   lambda = 0.0 -> any in-basis payload admits (most permissive)
//   lambda = 1.0 -> only exact-resonance payloads admit (most restrictive)
// This is the sole scalar convention. All other code uses it consistently.

impl Membrane {
    fn on_unknown_peer(&mut self) {
        // Previously: self.filter.adapt_lambda(0.0)  -- interpreted as "mutual curvature = 0"
        //             which maps (via 1 - mutual_curvature) to lambda = 1.0 = maximally selective.
        // Replaced with: explicit call to the intended target.
        self.filter.set_lambda(1.0);                    // Explicit: maximally selective
    }
}
```

The `adapt_lambda(mutual_curvature)` signature is retained for the known-peer case where mutual curvature is meaningful. The unknown-peer case uses `set_lambda(1.0)` directly. This eliminates the double-convention hazard and makes audit trails easier to read.

Callers migrating from the research crate must not assume `adapt_lambda(0.0)` produces maximally selective behavior in the new API — that path is now equivalent to `set_lambda(1.0)` only if `mutual_curvature` is semantically zero. For "unknown peer, default to selective," use `on_unknown_peer()` or `set_lambda(1.0)` directly.

### 3.3 Worked numerical example (filter)

Assume:
- Receiver basis: three 128-bit SimHashes `s1, s2, s3`.
- Basis threshold: `T = 48` (hamming distance).
- Payload hash: `p = simhash_from_bytes(payload)`.
- `hamming(p, s1) = 72, hamming(p, s2) = 41, hamming(p, s3) = 96`.

Compute:
- `min_distance = 41`.
- `in_basis = (41 <= 48) = true`.
- `resonance = 1.0 - 41/128 = 0.6797`.

Case A: lambda = 0.5.
- `passed = true AND (0.6797 >= 0.5) = true`.
- Filter output: `{ passed: true, resonance: 0.6797, projected_payload: Some(payload), dropped_components: 0 }`.

Case B: lambda = 0.7.
- `passed = true AND (0.6797 >= 0.7) = false`.
- Filter output: `{ passed: false, resonance: 0.6797, projected_payload: None, dropped_components: 1 }`.

Case C: basis threshold tightened to `T = 32`.
- `in_basis = (41 <= 32) = false`.
- Regardless of lambda: `passed = false`, `resonance = 0.6797` recorded, `dropped_components = 1`.

This illustrates invariant I3: in Case C, even if lambda were 0.0, the payload is out of basis scope and rejected. Resonance is still recorded; the observer channel sees the value.

### 3.4 Algorithmic complexity

- Per-filter cost: O(|basis.signatures|) hamming comparisons, each O(1) via 128-bit XOR + popcount. Typical basis size: 50–5000 signatures; per-filter cost is sub-millisecond on contemporary hardware.
- SimHash derivation cost: one SHA3-256 compression over the payload. Cost is O(|payload|); for payloads up to ~10 KB, sub-millisecond.
- Memory: O(|basis.signatures|) basis storage. At 5000 signatures × 16 bytes, basis occupies ~80 KB per receiver.

Receivers with very large bases (>100,000 signatures) should consider pre-clustering the basis (offline) and running filter queries against cluster centroids with a two-stage threshold. This is an implementation optimization, not a specification change; the SPEC treats the basis as a flat set.

---

## 4. Basis Provenance (Q3)

### 4.1 The three modes

Every receiver declares one of three provenance modes at instantiation. The mode governs how the basis is computed and re-computed, who may mutate it, and who may attest to its correctness under audit.

### 4.2 Self-anchored (research baseline)

```text
Procedure basis_self_anchored(receiver, history_window, min_history) -> CoherenceBasis:
    1. Let H = receiver.history(depth_window = history_window)
    2. IF len(H) < min_history: RETURN CoherenceBasis::empty()       // Bootstrap: filter closed
    3. Let sigs = { simhash_from_bytes(h.payload) for h in H }
    4. Deduplicate sigs (hamming distance < DEDUP_THRESHOLD collapses to one)
    5. Choose threshold T_auto such that P(in_basis | random payload) <= target_false_admit_rate
    6. RETURN CoherenceBasis { signatures: sigs, threshold: T_auto, version: now_depth }
```

*Default parameters.*

| Parameter | Preferred value | Valid range | Rationale |
|---|---|---|---|
| `history_window` | 10,000 depth units | 1,000 – 1,000,000 | Matches PPA-1 bootstrap ramp (α ramps 0→3 over 1k–6k depth); 10k gives stable signal post-ramp. |
| `min_history` | 32 signatures | 8 – 1,024 | Below 32 the basis is noise-dominated; above 1,024 the bootstrap is slow for minimal marginal value. |
| `DEDUP_THRESHOLD` | 8 bits | 4 – 32 | Below 8 collapses near-identical-but-distinct signatures; above 32 retains near-duplicates. |
| `target_false_admit_rate` | 0.001 (0.1%) | 0.0001 – 0.01 | Random-payload admission rate under no lambda. 0.1% balances bootstrap usability against adversarial probing. |
| `T_auto` resolved from above | typically 32–48 bits | 16 – 64 | Auto-tuned per basis size; published in the observer channel (Tier 1). |

Self-anchored bootstrap property (new invariant I12): during bootstrap (len(H) < min_history) the filter is *closed*, not open. An empty basis has `signatures.len() == 0`; the filter returns `{ passed: false, resonance: 0.0, ... }` for any payload (see `filter.rs:69-76`). This is deliberate: a receiver with no history has no claim to what it is coherent with, and defaulting open would violate I3's "non-bypassability" spirit. Receivers in bootstrap can accept payloads through other application-layer paths (capability validation), but the membrane itself is effectively disabled until `min_history` is reached.

### 4.3 Tenant-anchored

```text
Procedure basis_tenant_anchored(tenant_id, policy_ref, basis_signer) -> CoherenceBasis:
    1. Let policy = resolve_policy(policy_ref)                       // Pulls receiver's published envelope
    2. Let basis_blob = policy.basis_blob                             // Signed by basis_signer
    3. Verify signature on basis_blob against basis_signer
    4. Parse basis_blob -> (sigs, threshold, version)
    5. Enforce policy.min_signatures <= len(sigs) <= policy.max_signatures
    6. Enforce policy.min_threshold <= threshold <= policy.max_threshold
    7. RETURN CoherenceBasis { signatures: sigs, threshold, version }
```

*Operational model.* The tenant operator publishes a policy envelope at `PolicyRef`. The envelope is versioned, signed, and immutable once published. To change basis the tenant publishes a new version; receivers re-resolve on startup and on a configured cadence.

*Change authority.* Only the `basis_signer` key may publish a new basis blob. Rotation of this key is a tenant-operator procedure, out of scope for this spec; reference to standard enterprise key-rotation (HSM + quorum) is sufficient. The GIM SaaS product layer will wrap this with a customer UI.

### 4.4 Governance-attested

```text
Procedure basis_governance_attested(tenant_id, policy_ref, governance_root, attestation_epoch) -> CoherenceBasis:
    1. Resolve tenant-anchored basis per §4.3     (tenant_anchored mechanically)
    2. Verify governance attestation:
       a. Load governance record at (governance_root, attestation_epoch)
       b. Verify record asserts the current basis_version is attested
       c. Verify attestation predates this receiver's startup
    3. IF attestation invalid or missing: RETURN CoherenceBasis::empty()   (closed)
    4. RETURN the tenant-anchored basis
```

*What the membrane does and does not do.* The membrane consumes a governance attestation as input. It does not implement governance, does not tally votes, does not weight by coherence tier. All of that is the responsibility of `disentangle-identity::governance` and, for tenant-specific consortium operations, the tenant's governance UI. The attestation format is a Merkle-rooted commitment that the attestation record exists at the claimed epoch; the spec requires only that the membrane can verify the commitment against the receiver's configured `governance_root`.

*Operational model.* A consortium (industry association, DAO, multi-party operator) runs its governance process (out-of-band or via `disentangle-identity::governance`) and produces an attestation at each epoch asserting "basis version X was approved." Receivers in `GovernanceAttested` mode accept only bases whose versions appear in the attestation. Stale attestations (older than a configured horizon) invalidate the basis until a fresh attestation is published.

### 4.5 Per-receiver selection

Per Q3 settled decision, `BasisProvenance` is per-receiver, not per-deployment. A receiver is a named endpoint (capability holder, topic subscriber, RPC handler) identified by `(node_did, receiver_id)`. Each receiver carries its own provenance mode. The node may host arbitrarily many receivers across the three modes simultaneously.

*Enumeration contract.* A node exposes (via the observer channel Tier 1 and via a standard RPC) the set of receivers and the provenance mode of each. This supports auditor access and regulatory review. It does not expose any basis contents, signers, or policy details — only the mode enumeration.

### 4.6 Provenance failure modes

| Failure | Cause | Handling |
|---|---|---|
| Tenant-anchored basis signature invalid | Key rotation race, tampered envelope, misconfiguration | Receiver filter closes (empty basis); observer channel emits `BasisUnavailable` event; alert is raised at Tier 1 |
| Governance attestation stale | Governance process lapsed, attestation key compromised | Same as above; recovery requires fresh attestation |
| Self-anchored below min_history | Bootstrap period | Filter closed during bootstrap (I12); no alert, expected behavior |
| Tenant-anchored policy envelope unreachable | Network partition to policy service | Fall back to last-known-good basis with exponential-backoff retry; observer emits `PolicyUnreachable` event; after configurable grace period, receiver closes filter |

---

## 5. Tenant Basis Scope (Q6)

### 5.1 Hierarchical bases as the shared-observability pattern

Before enumerating the two modes, this subsection names what `Hierarchical` actually is at the architectural level. It is not merely an enum variant and not merely a configuration option. It is the primitive's central commercial moat, expressed as a named pattern.

**Pattern name:** *Hierarchical bases as the shared-observability pattern* (equivalently: *coherence-substrate with shared observability*).

**Shape.** Three components held together structurally:

1. **Shared provider baseline.** A basis version derived by the SaaS operator from contributions that appear in at least `min_tenant_admit` distinct tenants. The baseline is published (including its Merkle root) so every tenant and every external auditor can verify its structure without reading its construction inputs.
2. **Per-tenant delta.** Each tenant maintains its own delta basis — signatures it has attested for its own bandwidth, distinct from the baseline. The delta is opaque to every other tenant. The tenant retains threshold authority over its own filter.
3. **Minimum-tenant-threshold admission.** A signature does not enter the baseline unless independently contributed by at least `min_tenant_admit` distinct tenants (default 5, range 3–50). This is the privacy gate (H1) and also the epistemic gate: a signal is promoted into the shared surface only when it has cross-tenant corroboration.

**Why the pattern produces signals no single deployment can derive.** A coordinated attacker operating against multiple GIM tenants simultaneously leaves structural fingerprints — SimHash signatures — in each tenant's contribution stream. Any single tenant sees only its own slice and cannot distinguish its local adversary from a cross-tenant campaign. The aggregator, seeing the same signature independently contributed by ≥5 tenants, promotes it into the baseline. Within one refresh cycle, every participating tenant's receiver becomes filter-sensitive to the cross-tenant pattern, even tenants not yet targeted. This is emergent observability: the defensive signal exists at the substrate level and does not exist at any single tenant's level. A self-hosted install, an isolated-mode deployment, and a privacy-maximal single-tenant OEM all operate without it. Hierarchical mode is the only configuration under which this class of signal is derivable, and the baseline is the cryptographic artifact that carries it.

**Why this is a pattern rather than a config flag.** The three components are co-dependent: the baseline's value relies on `min_tenant_admit`; the delta's usefulness relies on the baseline existing; the privacy invariants (H1–H4 in §5.4) only compose correctly when all three are present and configured to interlock. A deployment that claims "hierarchical bases" without `min_tenant_admit` enforcement, or without publishing the baseline's Merkle root, has not implemented the pattern; it has implemented a subset that does not produce the emergent signal. Vendors evaluating the primitive for integration should be led to this named pattern before the enum, because the pattern is what they are buying.

**Relation to PPA-4 claim anchors.** The shared-observability pattern is the load-bearing anchor behind Appendix B Anchor 7 (*Hierarchical basis construction with minimum-tenant-threshold admission for cross-tenant attack detection preserving per-tenant privacy*). It composes with Anchor 5 (*Two-tier observer channel with provenance binding*) to produce the commercial narrative: the membrane primitive plus the shared baseline plus the tiered observer channel is what GIM sells, and the hierarchical pattern is the keystone of the network-effect claim. Counsel should treat the pattern — not the enum — as the artifact being claimed.

**Relation to the `Isolated` alternative.** `Isolated` mode remains a first-class alternative for privacy-maximal tenants (healthcare HIE, defense-adjacent, regulated sectors declining cross-tenant aggregation, and early-onboarding tenants who have not yet agreed to the Hierarchical operating terms). It is architecturally complete on its own — all core filter invariants (I1–I12) hold unchanged — and it is supported on equal contractual footing. What it does not carry is the emergent cross-tenant signal that Hierarchical carries. That is the explicit tradeoff a tenant selects when choosing `Isolated`.

### 5.2 The two modes

A `TenantAnchored` or `GovernanceAttested` receiver additionally declares whether it operates in `Isolated` or `Hierarchical` tenant-basis scope. `SelfAnchored` receivers have no tenant, so this dimension is not applicable for them. `Hierarchical` is the default (§5.5); `Isolated` is a first-class opt-out selected by the receiver or the tenant policy.

### 5.3 Isolated mode

```text
Procedure effective_basis_isolated(tenant_delta_basis) -> CoherenceBasis:
    RETURN tenant_delta_basis
```

Equivalent to §4.3 / §4.4 directly. No provider-shared signatures. Suitable for:

- Regulated-industry tenants with no-shared-compute policies (certain healthcare HIE, defense-adjacent, nation-state-regulated sectors).
- Single-tenant on-prem deployments of the GIM product that do not participate in the SaaS operator's tenant pool.
- Tenants in early onboarding before they have agreed to the Hierarchical operating terms.

### 5.4 Hierarchical mode

```text
Procedure effective_basis_hierarchical(tenant_delta_basis, baseline_ref, min_tenant_admit) -> CoherenceBasis:
    1. Let baseline = resolve_baseline(baseline_ref)
    2. Let applicable = baseline.signatures that pass the tenant's applicability filter
       (tenant's policy may exclude categories of baseline signatures they declare N/A)
    3. Let effective_sigs = (applicable ∪ tenant_delta_basis.signatures) with dedup
    4. Effective threshold = tenant_delta_basis.threshold    (tenant retains threshold authority)
    5. RETURN CoherenceBasis { signatures: effective_sigs, threshold, version }
```

*Baseline construction (provider-side).* The SaaS operator runs this procedure offline on a cadence:

```text
Procedure construct_baseline(tenant_contributions, min_tenant_admit) -> Baseline:
    1. For each signature s in ∪ tenant_contributions: count distinct tenants that submitted s
    2. Admit s into baseline iff distinct_tenant_count(s) >= min_tenant_admit
    3. Publish baseline with version_id, signatures, and merkle_root commitment
```

*Privacy invariants for hierarchical mode:*

- **H1 Minimum-tenant admission.** A signature does not enter the baseline unless at least `min_tenant_admit` distinct tenants have contributed it. Default value: `min_tenant_admit = 5`. Valid range: 3 – 50. This bounds re-identification risk: a signature appearing in <5 tenants might identify the handful of contributors; a signature appearing in >=5 tenants cannot be attributed uniquely.
- **H2 Content opacity.** Tenant contributions carry only the 128-bit SimHash. No payload content, no sender/receiver identifiers, no timestamps finer than the contribution epoch.
- **H3 Auditable baseline.** The baseline's Merkle root is published publicly at each version. Tenants can verify baseline membership without determining contributor identity.
- **H4 Tenant exit.** A tenant leaving the SaaS pool does not retroactively remove its past contributions from the baseline (they are irrevocably committed to publicly-published versions) but future baseline versions no longer include the tenant's subsequent contributions.

*Cross-tenant attack detection — the value prop.* When a coordinated attacker operates across multiple GIM tenants simultaneously, the attacker's structural signatures appear in many tenants' contributions. The baseline picks these up after `min_tenant_admit` threshold crossings. Receivers in any tenant (not just the one under attack) become filter-sensitive to the pattern as soon as their next basis refresh pulls the new baseline. This is the single highest-leverage benefit of Hierarchical mode; it is the benefit that cannot be derived in any single-tenant deployment.

### 5.5 Default mode selection

Per settled Q6: `Hierarchical` is the default for `TenantAnchored` and `GovernanceAttested` receivers — it is the architectural pattern the primitive is built to express (§5.1). `Isolated` is a first-class opt-out selected by privacy-maximal tenants as described in §5.1 and §5.3. Both modes are claimable in PPA-4 as embodiments of the same primitive (see Appendix B), but the shared-observability pattern is the load-bearing commercial claim.

### 5.6 Worked example (hierarchical-mode admission)

Assume six tenants (`T1..T6`) each maintaining their delta basis. Aggregator observes the following signature frequencies over one baseline-refresh window:

| Signature | Distinct tenants contributing |
|---|---|
| sig_A | 1 (T3 only) |
| sig_B | 2 (T1, T5) |
| sig_C | 5 (T1, T2, T4, T5, T6) |
| sig_D | 6 (all six) |
| sig_E | 1 (T2 only) |

With `min_tenant_admit = 5`:
- `sig_A, sig_B, sig_E`: not admitted (below threshold).
- `sig_C, sig_D`: admitted.

Published baseline: `{signatures: [sig_C, sig_D], version_id, merkle_root, admission_epoch}`.

A seventh tenant (`T7`) onboarding in Hierarchical mode with an empty delta sees an effective basis of `{sig_C, sig_D}`. If `T7`'s traffic contains a payload whose SimHash falls near `sig_C`, it matches the baseline — even though `T7` never contributed `sig_C` and has no visibility into which tenants did. Cross-tenant attack detection operates without cross-tenant data disclosure.

---

## 6. Node Integration and Positioning (Q1)

### 6.1 Layer placement

The membrane is an *application-layer* concern. It sits after p2p transport has delivered and decrypted the message, after the receiver identity has been resolved (the RPC handler / topic subscriber / capability target is known), and *before* or *after* capability validation depending on the `CheckOrder` setting (§9). Placement is depicted:

```text
[wire] --> [Noise/PQ-TLS decryption] --> [payload bytes + receiver identity]
                                                     |
                                                     v
                               +------------------------------------+
                               |  Application dispatch              |
                               |     |                              |
                               |     +--> [membrane filter]         |  <- ingress membrane (§6.2)
                               |     +--> [capability check]        |
                               |     +--> [handler invocation]      |
                               |     +--> [DAG insertion]           |
                               |                                    |
                               |  [self-audit egress membrane]      |  <- optional (§6.3)
                               |     +--> [own outbound emissions]  |
                               +------------------------------------+
```

The membrane is *not* in the p2p transport path (ruled out by Q1 analysis in `DECISIONS.md` §Q1). It is *not* in the consensus validation path (§8 governs composition, not replacement). It is *not* in the deserialization path — the receiver identity must already be resolved.

### 6.2 Ingress membrane (default, always present when a receiver declares a membrane)

Every receiver that declares a membrane runs an ingress filter on each payload destined for it. The filter result is recorded on the transaction as a signed `MembraneRecord` (§2.7) regardless of outcome. What happens next depends on the capability's `enforcement_mode` (§8) and `check_order` (§9).

### 6.3 Self-audit egress (optional, opt-in per receiver)

A receiver may additionally declare an egress membrane: the same filter algorithm applied to the receiver's own outbound emissions. Purpose: self-drift detection — was my basis compromised? Is my emission pattern diverging from what I claim to be?

Egress is NOT the default. It is an opt-in per receiver. Reasons:

- Egress results can be interpreted as the receiver's "compliance with its own basis," which may create obligations (legal, regulatory, contractual) that tenants do not want by default.
- Egress doubles the filter compute per transaction; many receivers do not need it.
- The primary pitch ("measure coupling between content and receiver at the edge") points at ingress; egress is secondary.

When enabled, egress `MembraneRecord` entries are tagged with a `direction: Egress` field (ingress default is `direction: Ingress`) so observer aggregation can separate the two streams.

### 6.4 Non-path composition

The membrane does not touch:
- p2p transport (libp2p / Noise / PQ session). The membrane sees only decrypted, delivered payloads.
- Consensus validation. DAG transactions are validated independently (signature, parent references, payload well-formedness). The membrane record attaches to an already-validated transaction.
- Capability delegation record creation. The membrane only reads capability metadata at exercise time.

### 6.5 Observer-mode default

The membrane's default posture is **non-blocking**. For `EnforcementMode::Tagged` (default), a failing filter does not block the handler from running — it only tags the resulting transaction. For `EnforcementMode::HardReject` (opt-in), a failing filter does block. Per Q1 settled decision, the "measure coupling" pitch is preserved by keeping observer-mode as the default posture.

---

## 7. Lambda Dynamics (Q4)

### 7.1 Three layers

Effective lambda is computed at every transaction exercise by composing three layers:

1. **Baseline adaptive lambda** from `mutual_curvature` (known peer) or `set_lambda(1.0)` (unknown peer).
2. **Per-capability-class bounds** from the receiver's published policy (floor, ceiling).
3. **Attack-mode tightening** from the current `AttackState` attestation.

```text
Procedure resolve_lambda(peer_lt, receiver_policy, capability_class, attack_state) -> f64:
    1. IF peer_lt is known:
           // peer_lt and local_lt are CONSUMED from the consensus/DAG layers per §1.4.
           // The scalar named `mutual_curvature` here is a membrane-internal coupling
           // coefficient derived from those consumed LT gaps — NOT the consensus-layer
           // curvature primitive. Name retained for research-crate API compatibility.
           (level_gap, temporal_gap) = local_lt.gap(peer_lt)
           mutual_curvature = (1.0 / (1.0 + level_gap)) * (1.0 / (1.0 + temporal_gap))
           base = 1.0 - mutual_curvature                              // Research baseline
       ELSE:
           base = 1.0                                                  // Maximally selective (unknown peer)

    2. (floor, ceiling) = receiver_policy.bounds_for(capability_class)
       bounded = clamp(base, floor, ceiling)

    3. IF attack_state.active:
           effective = min(1.0, bounded * attack_state.tightening_multiplier)
       ELSE:
           effective = bounded

    4. RETURN effective
```

### 7.2 Per-capability-class bounds

Each capability class declares a `(floor, ceiling)` pair in the receiver's policy envelope. Examples:

| Capability class | floor | ceiling | Rationale |
|---|---|---|---|
| `governance/proposal` | 0.8 | 1.0 | High-stakes; selectivity must remain high regardless of adaptive baseline. |
| `treasury/transfer` | 0.85 | 1.0 | Very high-stakes. |
| `agent/delegation` | 0.6 | 0.95 | Medium-stakes; adaptive selectivity but bounded away from open. |
| `messaging/groupchat` | 0.15 | 0.5 | Low-stakes volume traffic; ceiling prevents over-restriction. |
| `messaging/direct` | 0.2 | 0.6 | Medium-low. |
| `oracle/query` | 0.4 | 0.8 | Tunable by tenant based on oracle sensitivity. |

These are illustrative. The spec does not ship a baked class map; tenant product layers configure them. The only structural contract is: `0.0 <= floor <= ceiling <= 1.0`.

*Why receiver-declared.* The receiver is the party whose integration capacity is at stake; they know whether they can tolerate open (ceiling high) or require closed (floor high). Tenant policy sets an envelope (min floor, max ceiling per class) within which the receiver may choose. This matches the tenant-anchored model: the tenant declares the envelope, receivers populate it, the sender has no say.

### 7.3 Attack-mode tightening

`AttackState` (§2.5) represents an externally-attested signal that attack-mode tightening should be in force. When `active == true`, the multiplier is applied to the bounded baseline. The multiplier decays to 1.0 at `decays_at_depth`, after which `active` transitions to false automatically.

Authority to declare attack-mode maps to provenance mode:

| Receiver BasisProvenance | AttackState authority |
|---|---|
| `SelfAnchored` | `AttackAuthority::Receiver(receiver_did)` — receiver attests to its own attack state |
| `TenantAnchored` | `AttackAuthority::TenantOperator { tenant_id, key }` — tenant security-operator key signs |
| `GovernanceAttested` | `AttackAuthority::Governance { governance_root, attestation_epoch }` — governance epoch attestation |

The observer channel (§10) records every attack-state activation at Tier 1 with: `activated_at_depth, decays_at_depth, sequence, authority type, signal_provenance` string. Tier 2 (subpoena-gated) additionally surfaces per-transaction `attack_state_active` flags.

### 7.4 Pitch-protection: attack-mode vs legitimate-burst

A regulated customer will ask *"what prevents a burst of genuine activity from being treated as an attack?"* The answer is explicit in this spec, not a footnote:

The membrane itself does not declare attack mode automatically. It does not have a "rate spike triggered tightening" built in — that would be rule-based, opaque, and would conflate legitimate bursts with attacks. Attack mode is only activated by an **externally-attested AttackState attestation** signed by the appropriate authority for the receiver's provenance mode. The authority is responsible for judging whether observed traffic is an attack or a legitimate burst. When they declare attack mode, they sign:

- the activation reason as a free-text `signal_provenance` field,
- the time window (`activated_at_depth`, `decays_at_depth`),
- a monotonically increasing sequence number for replay protection.

The observer channel records the signed attestation verbatim. Any receiver in the affected scope can audit after the fact whether the activation was justified: the signal_provenance tells them what the authority saw, the time window tells them which of their own transactions were affected, and the signature ties accountability to the authority's key.

If an authority repeatedly declares attack-mode for legitimate bursts, their customers (in tenant-anchored mode) or governance pool (in governance-attested mode) have recourse: revoke the authority's key or elect a new governance. The system is *auditable consequence*, not *automated gate*.

For `SelfAnchored` receivers, the authority is the receiver itself — they can only affect their own lambda. For the SaaS product shape, this customer question always resolves to tenant-anchored or governance-attested, and the answer is "the authority signs the attestation and you can see what they saw."

### 7.5 Worked example (lambda resolution)

Assume:
- Receiver in `TenantAnchored` mode.
- Capability class: `messaging/groupchat`, policy bounds `(0.15, 0.5)`.
- Peer known; `level_gap = 2, temporal_gap = 0.3`.
- Attack state: not active.

Compute:
- `mutual_curvature = (1 / (1 + 2)) * (1 / (1 + 0.3)) = 0.333 * 0.769 = 0.256`
- `base = 1.0 - 0.256 = 0.744`
- `bounded = clamp(0.744, 0.15, 0.5) = 0.5`
- Attack-mode: no change.
- `effective = 0.5`

The adaptive baseline wanted stricter (0.744) but the class ceiling enforced 0.5. Resonance needs to be >= 0.5 for this transaction to pass.

Same scenario, now attack mode active with `tightening_multiplier = 1.5`:
- `effective = min(1.0, 0.5 * 1.5) = 0.75`

Now resonance needs to be >= 0.75. More transactions will fail filter; the observer channel records both `attack_state_active = true` and the elevated effective lambda.

---

## 8. Composition with Consensus (Q2)

### 8.1 Default: tagged entry

Per settled Q2, the default composition is: **transactions enter the DAG regardless of filter outcome, carrying a `MembraneRecord` as signed metadata.** Consensus weight at inclusion is unchanged by filter outcome.

```text
Procedure on_payload_received_default(tx, receiver, basis, lambda):
    1. result = filter(tx.payload, basis, lambda)
    2. record = MembraneRecord { resonance, passed, lambda_at_eval, ... }
    3. tx.extensions.add(record)
    4. dag.insert(tx)                                                 // Consensus weight unchanged
    5. observer.emit(record)
    6. IF NOT result.passed:
           handler_execution = Skipped                                // Default Tagged: handler NOT run on fail
       ELSE:
           handler_execution = invoke_handler(tx)
```

This is `EnforcementMode::Tagged`. The transaction's presence in the DAG is preserved; the handler is skipped when the filter failed (so the transaction has no application-layer effect on the receiver). The resonance and pass-fail outcome are on the record for downstream consumption.

### 8.2 Opt-in: hard reject

Capabilities marked `enforcement_mode: HardReject` (in their `MembraneMetadata`) enable a different path:

```text
Procedure on_payload_received_hard_reject(tx, receiver, basis, lambda):
    1. result = filter(tx.payload, basis, lambda)
    2. IF NOT result.passed:
           reject_pre_dag(tx, reason = "membrane_filter_fail")
           observer.emit(MembraneRecord { ..., rejected_pre_dag: true })
           RETURN
    3. record = MembraneRecord { resonance, passed = true, ... }
    4. tx.extensions.add(record)
    5. dag.insert(tx)
    6. invoke_handler(tx)
    7. observer.emit(record)
```

In HardReject mode a filter-failed transaction does not enter the DAG. It is rejected at the application-layer ingress. The observer channel still records the rejection, so auditors can see that a transaction was seen and dropped. The dropped transaction's content is not retained.

### 8.3 Capability metadata determines mode

The `EnforcementMode` is a property of the capability, declared at capability issuance time, signed by the delegator. Receivers and dispatchers do not get to choose at exercise time — the capability carries the mode. This is invariant I11 (hard-reject explicitness).

| Declaration site | Contents |
|---|---|
| Capability delegation record | `MembraneMetadata { enforcement_mode, check_order, policy_ref }` |
| Capability exercise | Inherits from the delegation; cannot override |
| Default for capabilities without the field | `Tagged`, `FilterFirst`, `PolicyRef::Default` |

### 8.4 Pitch-protection: consensus-weight second-order dynamics

A regulated customer will ask: *"does the membrane alter consensus outcomes?"* The answer is explicit in this spec:

**The membrane does not alter consensus weights at the moment of transaction inclusion.** Every transaction that enters the DAG does so with its ordinary consensus weight, independent of `MembraneRecord.resonance`. The DAG consensus algorithms (`disentangle-consensus::compute_topological_mass`, `resolve_conflict`, `is_finalized`) do not read the membrane record.

Second-order effects on consensus weight arise from the sender's persistent failure to couple with their intended receivers, aggregated across emissions over time through tenant-configured revocation policies and the coherence-tier dynamics of PPA-1 and PPA-2. Concretely:

1. A sender's emissions are tagged with receiver-observed resonance values over time.
2. A tenant-configured revocation policy may fire when a sender's cumulative low-resonance rate crosses a threshold for a given capability or delegation edge.
3. The revocation is a separate transaction (`TransactionPayload::RevokeCapability` in PPA-2) that *does* affect the DAG state.
4. PPA-1's topological mass computation sees the revocation like any other transaction and updates the sender's coherence tier accordingly.

The composition is explicit and auditable:

- The resonance tag is visible on every transaction. Auditors can reconstruct the sender's observed-resonance history from the DAG.
- The tier computation is visible. PPA-1 defines exactly how mass is computed; nothing in the membrane alters that computation.
- The revocation policy is tenant-configurable. The tenant sees the policy, sees its thresholds, and is accountable for its behavior.

**No hidden pathway exists between membrane resonance and consensus weight.** The pathway that *does* exist — resonance → revocation policy → revocation transaction → topological mass — is a chain of explicit, auditable, tenant-configurable steps. This is consequence, not coupling. The pitch line "coupling, not gating" is preserved; the regulated customer sees a chain they can audit at each step.

### 8.5 Failure modes

| Scenario | Behavior |
|---|---|
| Filter fails, `Tagged` mode | Tx enters DAG; handler skipped; observer records pass=false |
| Filter fails, `HardReject` mode | Tx rejected pre-DAG; observer records rejection |
| Filter fails, sender retries with same capability | Same behavior; observer sees repeat; tenant revocation policy may fire |
| Capability valid, filter passes, handler throws | Ordinary handler error path; membrane record still present |
| Capability invalid, filter not yet run | See §9 CheckOrder semantics |
| Membrane record invalid signature | Treat as missing record; skip filter composition; log integrity violation to Tier 1 observer |

---

## 9. Capability-Check Ordering (Q7)

### 9.1 Both orderings first-class

Per settled Q7, the spec defines both orderings as first-class. The capability declares which order applies via `MembraneMetadata::check_order: CheckOrder`. Default is `FilterFirst`. No baked class map is shipped with the spec — tenant product layers ship opinionated defaults as UX convenience.

### 9.2 FilterFirst (default)

```text
Procedure on_payload_filter_first(tx, cap, receiver, basis, lambda):
    1. filter_result = filter(tx.payload, basis, lambda)
    2. record = MembraneRecord { ..., check_order_applied: FilterFirst }
    3. cap_ok = validate_capability(cap, tx)
    4. IF filter_result.passed AND cap_ok:
           outcome = Accepted
       ELSE IF NOT filter_result.passed AND cap_ok:
           outcome = FilterFailed
       ELSE IF filter_result.passed AND NOT cap_ok:
           outcome = CapabilityFailed                                  // Probing traffic signal retained
       ELSE:
           outcome = BothFailed
    5. observer.emit(record, outcome)
    6. Handle per outcome (§8 enforcement)
```

*Asymmetric claim-anchor value.* When `CheckOrder = FilterFirst`, the spec records `resonance` on transactions even when capability validation later fails (`CapabilityFailed` outcome). This is the distinguishable behavior: **coupling measurement prior to capability validation, resonance retained as a distinct auditable artifact regardless of capability outcome.** The probing-traffic signal — an unauthorized attacker whose payload happens to be high-resonance against the receiver's basis — is a detection signal that capability-first would discard. Call this out explicitly in the PPA-4 claim appendix (Appendix B, anchor 6).

### 9.3 CapabilityFirst (opt-in)

```text
Procedure on_payload_capability_first(tx, cap, receiver, basis, lambda):
    1. cap_ok = validate_capability(cap, tx)
    2. IF NOT cap_ok:
           outcome = CapabilityFailedEarly
           observer.emit(MembraneRecord { resonance: not_computed, check_order_applied: CapabilityFirst }, outcome)
           RETURN reject
    3. filter_result = filter(tx.payload, basis, lambda)
    4. record = MembraneRecord { ..., check_order_applied: CapabilityFirst }
    5. outcome = if filter_result.passed { Accepted } else { FilterFailed }
    6. observer.emit(record, outcome)
    7. Handle per outcome
```

Economic advantage: unauthorized traffic does not incur the SimHash computation. For receivers with cheap capability validation and expensive basis lookups (very large bases), this is a meaningful throughput saving. The cost is the lost signal on unauthorized-high-resonance probing.

### 9.4 Partial-success behavior

| Order | Filter | Capability | Outcome | Observer record |
|---|---|---|---|---|
| FilterFirst | pass | pass | Accepted | Full record |
| FilterFirst | pass | fail | CapabilityFailed | Full record (resonance retained — probing signal) |
| FilterFirst | fail | pass | FilterFailed | Full record (Tagged: handler skipped; HardReject: tx rejected) |
| FilterFirst | fail | fail | BothFailed | Full record |
| CapabilityFirst | — (not run) | fail | CapabilityFailedEarly | Partial record (no resonance) |
| CapabilityFirst | pass | pass | Accepted | Full record |
| CapabilityFirst | fail | pass | FilterFailed | Full record |

### 9.5 Observer records applied ordering

Every `MembraneRecord` carries `check_order_applied`. This lets auditors, tenant dashboards, and PPA-4 claim examiners see unambiguously which ordering was in force per transaction. In tenant deployments with mixed configurations across capability classes, the ordering is not inferable from the capability class alone (tenants may override defaults) — the per-transaction record is the source of truth.

---

## 10. Observer Channel (Q5)

### 10.1 Two tiers

Per settled Q5, the membrane specifies exactly two observer tiers:

- **Tier 1: aggregate-continuous, always-on, no per-transaction data.**
- **Tier 2: per-transaction, subpoena-gated, external legal process attested.**

The "authorized anomaly view" (an earlier design referenced in the decision doc) lives in the GIM SaaS product layer as a composition over Tier 1 aggregates and tenant-provided scope filters. It is not a separate membrane-level tier. This section specifies exactly what the membrane emits; higher-layer products compose from it.

**Content is never disclosed at any tier** (invariant I10). The observer channel does not surface decrypted payload bytes. Maximum per-transaction exposure at Tier 2 is the `MembraneRecord` (resonance, passed, lambda_at_eval, basis_version, provenance_tag, check_order_applied, enforcement_mode_applied, attack_state_active, receiver_signature) plus receiver/sender DIDs, timestamp, and capability identifier.

### 10.2 Tier 1 — aggregate-continuous

Always-on for every receiver that declares a membrane. Emitted to the tenant admin / auditor channel at the granularity configured in `Tier1Config.window_depth`.

Per-window emission payload:

```rust
pub struct Tier1Emission {
    pub receiver_did: DID,
    pub window_start_depth: u64,
    pub window_end_depth: u64,
    pub tx_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub attenuation_rate: f64,                          // fail_count / tx_count
    pub resonance_histogram: Vec<u32>,                  // Count per bucket; Tier1Config.histogram_buckets buckets over [0.0, 1.0]
    pub basis_drift_events: Vec<BasisDriftEvent>,       // Additions/removals from basis in window
    pub attack_state_activations: Vec<AttackStateEvent>,// Each activation in the window
    pub foliation_summary: Option<FoliationSummary>,    // See §10.4
    pub by_capability_class: HashMap<String, PerClassSummary>,  // Pass/fail/attenuation per class
}
```

`BasisDriftEvent` carries `(added_count, removed_count, version_before, version_after, timestamp)`. It does *not* carry the signatures themselves (those are not auditor-visible without authorization beyond Tier 1).

`AttackStateEvent` carries `(activated_at_depth, decays_at_depth, sequence, authority_type, signal_provenance, tightening_multiplier)` — the full signed attestation contents, supporting auditability per §7.4.

### 10.3 Tier 2 — per-transaction, subpoena-gated

Tier 2 is inactive by default. Activation requires a `LegalProcessScope` attestation:

```rust
pub struct LegalProcessScope {
    pub receiver_did: DID,
    pub start_depth: u64,
    pub end_depth: u64,
    pub process_identifier: String,                     // Subpoena / warrant number
    pub attesting_authority: VerifyingKey,
    pub attestation_signature: Signature,
}
```

When a valid scope is installed, Tier 2 surfaces per-transaction `MembraneRecord`s for transactions within the scope (receiver_did match, depth in [start, end]). The records carry full resonance, lambda_at_eval, basis_version, sender DID, capability identifier. No payload content.

*Jurisdictional escalation flip criterion (retained).* Some jurisdictions will require disclosure under legal process that does not match the schema's `LegalProcessScope` shape. The spec allows tenants to override the attestation-verification function via a configuration point; the expected override is to accept additional authorities (not to lower the content-opacity bar). If a jurisdiction requires the membrane to surface payload content under subpoena, that is an application-layer obligation outside this spec — the membrane emphatically does not retain or re-emit payload bytes, and tenant deployments requiring content disclosure must wire their own content-logging layer upstream of the membrane. This flip criterion is specifically documented so tenants and counsel can evaluate deployability per jurisdiction.

### 10.4 Foliation in the observer channel (cross-cutting item 3)

The seven-question decision doc did not address whether foliation surfaces to the observer channel. Decision:

- **Default: `FoliationSurfacing::AggregateOnly`.** Tier 1 emissions carry `FoliationSummary { leaf_count, largest_leaf_size, membership_change_rate }`. No per-transaction leaf assignment. This gives the auditor a coarse signal of coherence-neighborhood stability without surfacing which specific receiver is in which leaf.
- **Opt-out: `FoliationSurfacing::None`.** For privacy-aggressive tenants, foliation information does not appear in the observer channel at all. Tenant-configured.
- **Opt-in: `FoliationSurfacing::PerTransaction`.** Each `MembraneRecord` carries the receiver's current `LeafId`. Only available in tenant deployments where the observer audience is trusted with per-receiver clustering (e.g., tenant's internal security team auditing their own deployment). This is opt-in; it is not a default.

*Rationale.* Foliation is a useful signal for detecting coordination (a sudden spike in leaf count, a sudden shift of receivers between leaves, a leaf splitting into sub-leaves) but exposes clustering information that could be used to re-identify or profile receivers. Defaulting to `AggregateOnly` gives auditors the actionable signal without elevating re-identification risk. Tenants with specific needs opt out or in.

### 10.5 Emission path

```text
Procedure observer_emit(record, outcome):
    1. Tier 1: buffer the record into the current window bucket.
       Only aggregates are emitted; individual record not retained beyond window boundary.
    2. Tier 2: IF scope_active(record.receiver_did, record.depth):
           emit per-transaction record to Tier 2 sink.
       ELSE: drop.
    3. Foliation: per FoliationSurfacing setting, attach leaf info if applicable.
    4. Basis-drift and attack-state events are emitted regardless of Tier 2 status
       (they do not contain per-transaction data).
```

### 10.6 Observer sink configuration

The observer emissions are routed to a configured sink. The membrane spec does not dictate the sink implementation — it is a pluggable interface. Reference implementations include:

- `disentangle-node`'s event stream (SSE).
- Tenant-operated SIEM forwarders (Splunk, Sumo, Datadog).
- GIM SaaS product ingest pipeline.
- On-disk append-only log for air-gapped deployments.

---

## 11. SpectralFilter Path — Forward Reference (cross-cutting item 2)

The research crate includes a parallel `SpectralFilter` path using eigendecomposition of receiver-history feature covariance (`filter.rs` §"Spectral Path"). The v1 specification **scopes SpectralFilter out of productization.** It remains present in the crate for continued research use, but:

- It is not exposed in any public product API in v1.
- `BasisProvenance`, `TenantBasisMode`, `EnforcementMode`, `CheckOrder`, `AttackState`, and the observer channel are defined over the SimHash path only.
- Tenant configurations that reference SpectralFilter are rejected at configuration load time in v1.
- The `SpectralBasis`, `SpectralFilter` types continue to exist and their tests continue to run; the SimHash path does not depend on them, and they do not depend on any new v1 types.

### 11.1 When to re-open SpectralFilter scope

Decision criteria for v2:

- A concrete product use case requires continuous-valued feature vectors instead of byte-level payload hashes (e.g., a receiver that genuinely operates over continuous telemetry streams).
- Benchmark data demonstrates the spectral path meaningfully outperforms SimHash on the target use case (the two are not interchangeable — spectral captures variance-directed projection, SimHash captures set-based locality).
- PPA-4 claim-anchor analysis identifies a specific claim that the spectral path supports and the SimHash path does not.

Until then, treat the spectral path as internal research. Do not ship it in v1; do not claim it in PPA-4 v1; do not configure it in tenant deployments.

### 11.2 Forward-compatibility notes

When SpectralFilter enters scope in a future version:

- `BasisProvenance` will extend to `SelfAnchoredSpectral { feature_history_window, energy_threshold }`.
- `CoherenceBasis` will generalize to an enum `{ SimHash(CoherenceBasis), Spectral(SpectralBasis) }` — or the SpectralFilter path will gain an independent top-level primitive rather than folding into `CoherenceBasis`. The choice is deferred; either preserves v1 invariants.

---

## 12. Failure Modes

Consolidated list across all sections. Each failure has a documented behavior; no failure is "undefined."

| # | Failure | Section | Behavior |
|---|---|---|---|
| F1 | Basis empty (bootstrap) | §4.2 I12 | Filter closed; passed=false; filter result recorded |
| F2 | Basis signature set unsigned (self-anchored) | §4.2 | No signature required; self-anchored is trust-on-use-of-own-history |
| F3 | Tenant-anchored basis signature invalid | §4.3, §4.6 | Filter closed; observer emits `BasisUnavailable` |
| F4 | Governance attestation stale | §4.4, §4.6 | Filter closed; observer emits `GovernanceStale` |
| F5 | Policy service unreachable | §4.6 | Last-known-good basis; backoff retry; after grace period, filter closes |
| F6 | AttackState signature invalid | §7.3 | Reject attestation; observer logs integrity violation; lambda stays at bounded baseline |
| F7 | AttackState replay (sequence <= last seen) | §7.3 | Reject attestation; observer logs replay attempt |
| F8 | MembraneRecord signature invalid | §8.5 | Treat transaction as if record were missing; integrity violation logged |
| F9 | Tier 2 scope attestation invalid | §10.3 | Tier 2 remains inactive; attempt logged at Tier 1 |
| F10 | Payload SimHash collision with out-of-basis signature | §3 | Payload admits with elevated resonance (expected behavior — collision probability ~2^-128 per signature, acceptable) |
| F11 | Capability metadata field absent on delegation | §2.4 | Default applied: Tagged + FilterFirst + PolicyRef::Default |
| F12 | Unknown peer at `Membrane::transfer` time | §3.2 | `on_unknown_peer()` — lambda set to 1.0 explicitly; maximally selective |
| F13 | Hierarchical baseline version regression | §5.4 | Tenant configuration error; reject new basis; retain last known version; observer logs |
| F14 | Egress enabled but no outbound traffic | §6.3 | Normal; observer shows zero egress records |
| F15 | Capability class not in receiver policy | §7.2 | Reject at capability validation (not a membrane failure); observer emits `UnknownCapabilityClass` |

---

## 13. Embodiment Variations

This section describes deployment embodiments that compose the primitive with surrounding infrastructure. Each is a first-class supported configuration.

### 13.1 Research / permissionless embodiment

- BasisProvenance: SelfAnchored
- TenantBasisMode: not applicable
- EnforcementMode: Tagged (default)
- CheckOrder: FilterFirst (default)
- Observer: Tier 1 only; no Tier 2
- Egress: off

Matches the paper's reference model and the research crate's current behavior. This is what academic collaborators and public reference nodes run.

### 13.2 SaaS GIM tenant (tenant-isolated)

- BasisProvenance: TenantAnchored
- TenantBasisMode: Isolated
- EnforcementMode: Tagged for `messaging/*`; HardReject for `governance/*` and `treasury/*`
- CheckOrder: FilterFirst for most classes; CapabilityFirst for cheap-capability high-volume classes
- Observer: Tier 1 continuous; Tier 2 subpoena-gated
- Egress: off (unless tenant opts in for self-audit)

Matches healthcare / financial / defense-adjacent tenants with strict-isolation compliance postures.

### 13.3 SaaS GIM tenant (hierarchical)

- BasisProvenance: TenantAnchored
- TenantBasisMode: Hierarchical (default)
- EnforcementMode and CheckOrder: as per 13.2
- Observer: Tier 1 includes baseline version and cross-tenant pattern flags

Default GIM tenant shape. Gets cross-tenant attack detection benefit.

### 13.4 Consortium deployment

- BasisProvenance: GovernanceAttested
- TenantBasisMode: Hierarchical or Isolated per consortium agreement
- EnforcementMode: Tagged default; HardReject where consortium charter specifies
- Observer: Tier 1; Tier 2 gated by consortium legal framework

Matches industry-association operators, DAOs with sophisticated governance, and regulated consortiums.

### 13.5 PPA-4 Aspect 1 + membrane

Permissioned-consortium operational mode (PPA-4 Aspect 1) composed with membrane gives: consortium membership gated by external attestation (Aspect 1), and traffic between consortium members filtered by membrane (this spec). The membrane's `GovernanceAttested` provenance mode plugs directly into the consortium governance process. The observer channel's Tier 1 carries the compliance evidence the consortium auditor expects.

### 13.6 PPA-4 Aspect 7 + membrane

Coherence-bounded agent runtime (PPA-4 Aspect 7): agent delegation edges are monitored via membrane resonance. An agent's out-of-pattern delegation exercise produces low-resonance transactions; the receiver records them, tenant revocation policy fires, agent autonomy is throttled. The membrane is the runtime-monitoring primitive for Aspect 7.

---

## 14. Compatibility and Migration from the Research Crate

### 14.1 API changes vs. `filter.rs` / `membrane.rs`

| API element | Change | Migration |
|---|---|---|
| `CoherenceFilter::new(basis, lambda)` | Unchanged | No change |
| `CoherenceFilter::filter(payload)` | Unchanged | No change |
| `CoherenceFilter::adapt_lambda(mutual_curvature)` | Retained for known-peer path | Unchanged call sites |
| `Membrane::transfer(payload)` | Unchanged shape; internally uses `on_unknown_peer()` for missing peer_lt | Recompile; no call-site change |
| `Membrane::on_unknown_peer()` | New public method | Optional; `transfer()` already calls it internally |
| `CoherenceBasis` | Adds `version: u64` field | Default impl: `version = 0` on old bases; callers must set monotonically on mutation |
| `BasisProvenance` | New type | Tenants set; default SelfAnchored for research users |
| `TenantBasisMode` | New type | Tenants set; default Hierarchical in SaaS, not applicable in research |
| `MembraneMetadata` on `Capability` | New optional field | Defaulted when absent |
| `AttackState` | New type | No default; absent = no attack mode |
| Observer channel emissions | New | Tier 1 feature-flaggable in v1.0; recommend default-on |
| `FilterResult` | Unchanged | No change |
| `SpectralFilter*` | Retained, not surfaced | Unchanged; no product use in v1 |

### 14.2 Configuration migration

Existing research-mode callers (paper authors, academic collaborators) require no configuration change: unspecified fields default to the research-baseline behavior. Tenant deployments add configuration via policy envelopes.

### 14.3 Test suite changes

The existing 3597-line test suite (invariants I1–I7) continues to run unchanged. New tests are added for:

- I8 Receiver-governed bandwidth
- I9 Provenance opacity
- I10 Observer no-content
- I11 Hard-reject explicitness
- I12 Bootstrap closure
- H1–H4 Hierarchical mode privacy invariants
- Lambda-at-zero reconciliation (new `on_unknown_peer` path)
- AttackState verification, replay protection, decay
- Observer Tier 1 emission shapes
- Observer Tier 2 scope attestation path
- Capability metadata parsing and default resolution
- Check-order per-transaction observation

Target test coverage: maintain >=5× test-to-source ratio as the crate grows.

---

## Appendix A: Worked Numerical Examples

### A.1 Self-anchored bootstrap progression

Receiver starts with empty history. `min_history = 32`, `history_window = 10000`, `DEDUP_THRESHOLD = 8`.

| Depth | len(H) | Basis state | Filter behavior |
|---|---|---|---|
| 0 | 0 | empty | I12: closed |
| 500 | 3 | empty (below min_history) | I12: closed |
| 2000 | 18 | empty (below min_history) | I12: closed |
| 4000 | 35 | 29 signatures after dedup | operational; T_auto tuned for 29 sigs |
| 10000 | 210 | 178 after dedup | operational; T_auto retuned |
| 12000 | history_window slides; 168 after dedup | operational |
| 50000 | stable growth pattern | operational |

### A.2 Hierarchical baseline admission with small tenant pool

Six tenants (`T1..T6`), `min_tenant_admit = 5`. Admission computed at each baseline-refresh epoch.

Epoch E1:

| Signature | T1 | T2 | T3 | T4 | T5 | T6 | Count | Admit? |
|---|---|---|---|---|---|---|---|---|
| sig_α | 1 | 1 | 0 | 1 | 1 | 0 | 4 | no |
| sig_β | 1 | 1 | 1 | 1 | 1 | 0 | 5 | yes |
| sig_γ | 1 | 1 | 1 | 1 | 1 | 1 | 6 | yes |
| sig_δ | 0 | 0 | 1 | 0 | 1 | 0 | 2 | no |

Baseline E1: `{sig_β, sig_γ}`.

Epoch E2: T4 onboards a new attacker cluster with sig_ω that also appears in T2, T5, T6:

| Signature | T1 | T2 | T3 | T4 | T5 | T6 | Count | Admit? |
|---|---|---|---|---|---|---|---|---|
| sig_α | 1 | 1 | 1 | 1 | 1 | 0 | 5 | yes (newly admitted) |
| sig_β | 1 | 1 | 1 | 1 | 1 | 0 | 5 | yes |
| sig_γ | 1 | 1 | 1 | 1 | 1 | 1 | 6 | yes |
| sig_ω | 0 | 1 | 0 | 1 | 1 | 1 | 4 | no (still below threshold) |

Baseline E2: `{sig_α, sig_β, sig_γ}`. sig_ω is close but not yet admitted. If in epoch E3 a fifth tenant sees sig_ω, it will be admitted; all tenants will become filter-sensitive to the cross-tenant pattern. This is the cross-tenant attack-detection benefit realized over two refresh cycles.

### A.3 Lambda resolution under attack mode

Receiver `R`, `TenantAnchored`, class `messaging/groupchat` with bounds `(0.15, 0.5)`.

Scenario: `R` in attack mode declared at depth 40000, decays at 41800, multiplier 1.5.

Transaction at depth 40500:

- Peer LT known: `level_gap = 1, temporal_gap = 0.2`.
- `mutual_curvature = (1 / 2) * (1 / 1.2) = 0.417`.
- `base = 1 - 0.417 = 0.583`.
- `bounded = clamp(0.583, 0.15, 0.5) = 0.5`.
- `attack_active = true, multiplier = 1.5`.
- `effective = min(1, 0.5 * 1.5) = 0.75`.

Payload SimHash yields resonance 0.7 against basis.
- `passed = in_basis AND (0.7 >= 0.75) = false`.
- MembraneRecord: `passed=false, resonance=0.7, lambda_at_eval=0.75, attack_state_active=true, ...`.
- Observer Tier 1 counts this in the window's fail bucket, in the resonance histogram bucket covering 0.7, and flags attack state active for the window.
- Outcome per Tagged: handler skipped; transaction enters DAG; sender's observed-resonance history accumulates a sub-threshold entry.

Transaction at depth 41900 (after attack mode decays):

- Same peer, same payload.
- `attack_active = false`.
- `effective = 0.5`.
- `passed = true AND (0.7 >= 0.5) = true`.
- Payload now admits; handler runs.

Audit trail at Tier 1 shows: for the attack window 40000–41800, receiver R's attenuation rate was elevated; post-decay, it returned to baseline. Auditor can inspect the AttackStateEvent emitted at 40000 with its `signal_provenance` string to judge whether the activation was legitimate.

---

## Appendix B: PPA-4 Claim Anchor Enumeration (cross-cutting item 4)

This appendix enumerates distinguishable claim anchors that emerge from the seven settled decisions. For counsel-call reference. Not filing-ready; counsel drafts claim language, this appendix states anchors.

1. **Application-layer per-receiver coupling measurement against a coherence basis.** Distinguishable from PPA-1 (DAG-wide mass) and PPA-2 (identity/capability), from generic WAF/DLP (rule-based, not geometric), and from ML-based content classification (no structural-fingerprint basis with geometric threshold).

2. **Tagged-resonance DAG transaction metadata with consensus-weight independence at inclusion.** Distinguishable from PPA-1/PPA-2 (no metadata layer), from generic consensus-augmented audit logs (no coupling-coefficient primitive), and from graph-analytic fraud detection (not tied to DAG transaction inclusion).

3. **Three-mode basis provenance (self-anchored, tenant-anchored, governance-attested) as selectable per-receiver configuration, with the same filter algorithm operating over all three.** Distinguishable from tenant-provided content-moderation ML (not per-receiver, not geometric), from governance-voted content moderation (not tied to coherence-basis geometry), and from self-learned anomaly detection (no tenant/governance anchoring).

4. **Externally-attested time-bounded attack-mode tightening of geometric coupling selectivity, with authority mapped to basis provenance mode.** Distinguishable from WAF adaptive blocking (rule-based, not geometric), from ML anomaly tightening (not tied to coupling-coefficient primitive), and from rate-limit escalation (not tied to basis-geometry selectivity).

5. **Two-tier observer channel (aggregate-continuous, per-transaction-subpoena-gated) cryptographically bound to basis provenance and attestation records with content never disclosed.** Distinguishable from SIEM tier structures (not coupling-coefficient-based), from generic compliance-observability (not tied to frozen-curvature commitments per PPA-1/PPA-3), and composes directly with PPA-4 Aspect 6 attestation types.

6. **Filter-first capability-check ordering with resonance retained as a distinct auditable artifact regardless of capability-validation outcome.** Distinguishable from traditional policy-filter composition (which runs policy first and discards post-policy traffic), and supports a specific probing-detection semantics where unauthorized-but-high-resonance traffic is a detection signal rather than discarded noise.

7. **Hierarchical basis construction with minimum-tenant-threshold admission for cross-tenant attack detection preserving per-tenant privacy — the shared-observability pattern.** This is the commercial keystone anchor. See §5.1 for the named pattern. Distinguishable from federated learning (aggregates model weights, not basis signatures), from threat-intelligence-sharing (IOC rules, not geometric signatures), and composes with PPA-4 Aspect 2 (CaaS service architecture) and with Anchor 5 above (two-tier observer channel). The `Isolated` mode is an architectural alternative, not a subset: deployments selecting Isolated do not participate in this anchor's claim.

Counsel should verify FTO on each anchor independently; prior-art concerns per anchor are summarized in `DECISIONS.md` §Q1–Q7 alternative sections. Anchors 5 and 7 together carry the commercial moat; Anchors 1–4 and 6 carry the primitive's technical novelty.

---

## Appendix C: Conventions and Invariant Inventory

### C.1 Lambda convention (final, single source of truth)

Lambda is the **minimum resonance for passage**. `lambda = 0.0` is maximally open; `lambda = 1.0` is maximally closed. This convention applies uniformly across `CoherenceFilter`, `Membrane`, policy envelopes, AttackState tightening, and observer channel records. The `Membrane::on_unknown_peer()` path explicitly sets `lambda = 1.0` (§3.2).

### C.2 Depth vs wall-clock time

All durations in this spec are expressed in DAG depth units, not wall-clock time. `history_window`, `window_depth`, `activated_at_depth`, `decays_at_depth`, `start_depth`, `end_depth` — all depth-based. Wall-clock timestamps appear only in transaction records and observer emissions as diagnostic metadata; they do not drive any algorithmic decision.

### C.3 Invariant inventory

| # | Name | Source |
|---|---|---|
| I1 | Non-degradation | tests/safety_invariants.rs |
| I2 | Bandwidth monotonicity | tests/safety_invariants.rs |
| I3 | Basis scope non-bypassability | tests/safety_invariants.rs |
| I4 | Square-preservation symmetry | tests/safety_invariants.rs |
| I5 | Lambda bounds | tests/safety_invariants.rs |
| I6 | Bandwidth non-negativity | tests/safety_invariants.rs |
| I7 | Sybil resistance / idempotence | tests/safety_invariants.rs |
| I8 | Receiver-governed bandwidth | this spec §1.2 |
| I9 | Provenance opacity | this spec §1.2 |
| I10 | Observer no-content | this spec §1.2 |
| I11 | Hard-reject explicitness | this spec §1.2 |
| I12 | Bootstrap closure (self-anchored empty basis) | this spec §4.2 |
| H1 | Hierarchical minimum-tenant admission | this spec §5.1, §5.4 |
| H2 | Hierarchical content opacity | this spec §5.4 |
| H3 | Hierarchical auditable baseline | this spec §5.4 |
| H4 | Hierarchical tenant exit | this spec §5.4 |

---

## Appendix D: Glossary

- **Basis / CoherenceBasis.** A set of SimHash signatures plus a hamming-distance threshold defining the frequency band a receiver can integrate.
- **Basis scope.** The non-bypassable Layer 1 check: payload must be within `threshold` hamming distance of at least one basis signature.
- **Coupling coefficient / resonance.** A scalar in `[0.0, 1.0]` measuring how strongly a payload couples to a receiver's basis. `resonance = 1 - min_hamming / BITS`.
- **Effective bandwidth.** `max_bandwidth * level_factor * temporality_factor`, where factors are derived from level-temporality gaps to peer. Always governed by receiver.
- **Foliation.** A classification of nodes into level-temporality-coherent leaves. Local computation, not consensus.
- **GIM / Group Integrity Monitor.** The SaaS product layer consuming the membrane primitive, described in `PIVOT_AUDIT.md` §4.1 #2.
- **Governance-attested.** BasisProvenance mode where a governance process attests to the tenant-anchored basis version.
- **Hierarchical mode.** TenantBasisMode where tenant's effective basis unions a shared provider baseline with a per-tenant delta.
- **Hard reject.** EnforcementMode where filter failure rejects pre-DAG.
- **Isolated mode.** TenantBasisMode where tenant's effective basis is exclusively the tenant's own signatures.
- **Lambda.** Minimum resonance for passage. 0 = open, 1 = closed.
- **Leaf / LeafId.** A group of nodes with level-temporality within configured epsilons of each other.
- **Level-temporality / LT.** `(CoherenceLevel, TemporalSignature)` pair characterizing a node's coherence depth and integration speed.
- **Membrane.** The composition of `CoherenceFilter` with level-temporality gap-derived bandwidth adjustment. The primitive this spec defines.
- **MembraneRecord.** Signed per-transaction metadata carrying the filter's output and the configuration active at evaluation.
- **Mutual curvature (membrane-internal).** `(1 / (1 + level_gap)) * (1 / (1 + temporal_gap))`, a coupling scalar derived inside the membrane from consumed LT gaps. Distinct from the consensus-layer curvature primitive (see PPA-1; `disentangle-consensus`). The name is retained for research-crate API compatibility and is namespaced by its `adapt_lambda` usage.
- **Coherence tier (upstream).** Ordinal produced by `disentangle-consensus` from curvature-and-mass primitives (PPA-1). Consumed by the membrane via `LevelTemporality`. Not computed here.
- **Temporal signature (upstream).** Scalar produced by `disentangle-dag` from DAG-depth integration behavior (PPA-3). Consumed by the membrane via `LevelTemporality`. Not computed here.
- **Topological mass (upstream).** Quantity computed by `disentangle-consensus` (PPA-1). Not read at membrane filter time; reaches the membrane indirectly via coherence tier and revocation effects.
- **Observer channel.** The Tier 1 / Tier 2 emission stream from the membrane to auditors.
- **Policy envelope / PolicyRef.** A tenant-published, signed record declaring lambda bounds, basis signatures, EnforcementMode defaults, and CheckOrder defaults per capability class.
- **Provenance tag.** An opaque 16-byte handle appearing on MembraneRecord that stably identifies (receiver, basis-version) without disclosing basis provenance mode to unauthorized observers.
- **Receiver.** A named application-layer endpoint — handler, topic subscriber, capability holder — identified by `(node_did, receiver_id)`.
- **Resonance.** See coupling coefficient.
- **Self-anchored.** BasisProvenance mode where the receiver derives its own basis from transaction history.
- **SimHash.** A 128-bit locality-sensitive hash used as a structural fingerprint.
- **Tagged mode.** EnforcementMode where filter failure tags the transaction and skips the handler but does not reject pre-DAG.
- **Tenant-anchored.** BasisProvenance mode where the tenant operator publishes the basis.
- **Tier 1 / Tier 2.** Observer channel tiers: aggregate-continuous vs per-transaction-subpoena-gated.

End of specification.
