# disentangle-membrane — Productization Decision Document

**Status:** Pre-alignment decision document. Not a full spec. Seven open design questions requiring synchronous decision by Lars + cdesktop. Full SPEC expansion is a follow-up task once these seven calls are made.
**Scope:** Translate the `disentangle-membrane` research primitive (coherence-selective filtering over SimHash basis + spectral basis + level-temporality gap) into a productizable shape suitable for (a) preserving the research integrity of the filter, (b) fitting the Group Integrity Monitor SaaS product shape described in `PIVOT_AUDIT.md` §4.1, and (c) supporting the PPA-4 "coherence-selective membrane filtering for group integrity" claim surface.
**Audience:** Lars, cdesktop.
**Constraint:** Decision-doc depth only. Each answer is (i) recommended answer with justification, (ii) one or two most plausible alternatives, (iii) criterion that would flip the recommendation. No implementation code. No schemas. No full claim language.
**Last updated:** 2026-04-18.

---

## 0. Framing

The research crate today is a payload-agnostic coupling primitive: bytes → SimHash → hamming distance against a receiver's coherence basis → resonance coefficient in `[0.0, 1.0]` → `FilterResult { passed, resonance, projected_payload, dropped_components }`. Behavior is governed by two knobs:

- **Basis scope.** A set of SimHash signatures with a hamming-distance `threshold` defining the frequency band the receiver can integrate. Non-bypassable even at `lambda = 0.0` (Invariant 3 in `tests/safety_invariants.rs`).
- **Lambda sensitivity.** A scalar in `[0.0, 1.0]` controlling minimum coupling coefficient for passage. Adapts via `adapt_lambda(mutual_curvature) ⇒ lambda = 1 - mutual_curvature` when a peer's level-temporality is known; defaults to maximum selectivity (`lambda = 0.0`, wait — at the filter level `lambda = 0.0` is maximally open; at the `Membrane` level unknown peer sets `lambda = 0.0` because `adapt_lambda(0.0)` maps mutual curvature of zero to lambda one via the implementation inversion. Confirm this semantic flip in the SPEC expansion; the research code currently uses two different "maximally selective" conventions in `filter.rs` and `membrane.rs` which the spec should reconcile).

The productization question is not *what does the math do*. The math has been beaten on (5.4× test-to-source ratio, seven property-based invariants, adversarial/spectral-evolution/enlightenment test suites). The question is *where does the primitive sit, what does it produce, who sees it, and on whose basis does it run* — such that the resulting product is recognizably a Group Integrity Monitor rather than a research library.

### Evaluation axes used throughout

Every recommendation below is scored against three criteria:

- **(a) Research integrity.** Preserves the coupling-coefficient framing, preserves the two-layer basis/lambda separation, preserves the receiver-governed bandwidth invariant (Invariant 2), does not reduce the filter to a boolean gate.
- **(b) GIM SaaS fit.** Fits the product shape from `PIVOT_AUDIT.md` §4.1 #2: "Closed-source productized implementation of the `disentangle-membrane` math... delivered as an API plus a dashboard. Sells to: encrypted-messaging vendors, online-community platforms, financial-communications surveillance teams."
- **(c) PPA-4 claim surface.** Supports the "coherence-selective membrane filtering" aspect as a distinguishable claim from PPA-1 (mass/curvature), PPA-2 (capability/coherence identity), and PPA-3 (temporal ordering). Where possible, creates additional claim anchors by composition with PPA-4 Aspects 1 (permissioned consortium), 2 (CaaS hosted API), 6 (geometric compliance attestations), and 7 (coherence-bounded agent runtime).

### Anchor pitch line

> "Zero Trust today means allow/deny at the edge. We measure coupling between content and receiver at the edge."

Every decision below should make this line more defensible, not less. Concretely: the product must *measure a continuous quantity* (coupling), must sit *at the edge* (not deep in a consensus pipeline invisible to the buyer), must operate per-*receiver* (not per-sender, that's rate limiting), and must operate on *content* (not just metadata, that's a WAF). The worst failure mode for the pitch is a design that collapses into "allow/deny on a hash" — that is already available from every SIEM and next-gen firewall vendor and is not patentably distinguishable.

---

## Q1. Positioning in the Node

**Question.** Ingress, egress, or both? At the p2p transport layer (pre-deserialization), at the consensus layer (post-validation, pre-DAG-insertion), or at the application layer (per-RPC, per-topic, per-capability invocation)?

### (i) Recommendation: application-layer, ingress-dominant, observer-mode default, with optional symmetric egress for self-protection posture.

**Application layer.** The membrane must sit where *content and receiver identity are both legible in the same context*. The p2p transport layer sees encrypted bytes destined for a peer whose receiver-role is not yet known (a payload on the wire is not yet bound to an RPC handler, a topic subscriber, or a capability invocation). The consensus layer sees transactions that have already passed validation and are en route to DAG insertion — by then the receiver concept has dissolved into "the DAG" and coupling-between-content-and-receiver is no longer well-defined. Only at the application layer — per-RPC, per-gossipsub-topic, per-capability invocation — does the node have: (1) the decrypted payload, (2) the resolved receiver identity (the handler, the subscriber, the capability holder), (3) the receiver's coherence basis, and (4) the context to produce a useful `FilterResult`. This is the layer where the pitch-line phrase "coupling between content and receiver" has an operational referent.

**Ingress-dominant.** The pitch frames the receiver as the protected party. A membrane that measures *incoming* coupling protects the receiver from inauthentic or coordinated content. A membrane that measures *outgoing* coupling has a weaker pitch because it is measuring the node's own emissions against its own basis — which is structurally tautological unless the node is attempting self-audit for drift. Ingress-dominant also fits the SaaS product shape: the GIM customer wants visibility into what is *reaching* their users, not what their users are *saying* (though egress signal is useful for drift detection, see below).

**Observer mode default.** The product's default posture is non-blocking: the membrane runs on ingress traffic, emits resonance metadata into an observer channel (Q5), and does *not* hold up the traffic. This is the pitch's "measure coupling" — not "enforce coupling." Blocking modes are opt-in per tenant for capability classes the tenant has declared high-stakes. Observer mode preserves research integrity (the primitive is a measurement, not a gate), fits the SaaS shape (the SaaS sells a dashboard + API; a dashboard product cannot block traffic it does not control), and gives the PPA-4 claim surface its operative anchor (the attestation output is the claimable artifact, not the inline rejection).

**Symmetric egress for self-protection.** A node concerned about its *own* drift (was my basis compromised? have I been manipulated into accepting payloads I should not integrate?) benefits from a reflexive egress measurement. The recommended shape is: egress membrane uses the *same* basis as ingress, emits resonance values on outgoing payloads, and its attenuation rate is a first-class signal in the observer channel. This gives the product a story about "basis drift detection" (Q3) and connects to PPA-4 Aspect 6 Segment (c) "absence of negative curvature" attestations over a bounded time window.

### Justification against the three criteria

- **(a) Research integrity.** Application-layer positioning preserves the receiver-governed bandwidth invariant: each RPC handler / topic subscriber carries its own basis and lambda, and the `Membrane::effective_bandwidth()` calculation remains a pure function of the receiver's integration capacity and the peer's level-temporality gap. No coupling into the p2p transport or consensus pipeline compromises the math.
- **(b) GIM SaaS fit.** The GIM product described in §4.1 #2 is an API-plus-dashboard. An API-plus-dashboard product consumes application-layer signal by construction; it does not terminate TCP connections or validate DAG transactions. Observer-mode ingress measurement is precisely what the SaaS ingests and renders.
- **(c) PPA-4 claim surface.** Application-layer positioning creates the strongest distinguishability from PPA-1 and PPA-2 prior art: PPA-1 operates on the DAG as a whole, PPA-2 operates on capability and identity structure. A claim that bounds the invention to "per-receiver, per-capability-invocation, application-layer coupling measurement against a coherence basis" does not overlap PPA-1/PPA-2 and is also distinguishable from generic WAF / DLP / CASB prior art (those operate on rules, not on geometric coupling against a learned basis).

### (ii) Most plausible alternatives

**Alt 1: consensus-layer ingress (post-validation, pre-DAG-insertion).** Tighter coupling to the research. The filter runs on every valid transaction before it enters the DAG, producing a resonance value that is written into the DAG itself as transaction metadata. This has one real advantage: the resonance values become *part of the DAG* and are therefore subject to PPA-1's topological mass aggregation — you can do mass-weighted reasoning over resonance. It has two disadvantages. First, it couples the membrane inseparably to the DAG consensus pipeline, which makes it impossible to productize the membrane as a standalone SaaS that sits in front of Marmot / Matrix / MLS deployments that do not run the full Disentangle DAG. Second, it collapses the "edge" framing of the pitch — the filter is running inside the consensus engine, which is not what enterprise buyers call "the edge." This alternative remains viable for the permissioned-consortium embodiment (PPA-4 Aspect 1), which *does* run the full DAG and *does* want consensus-coupled coherence measurement.

**Alt 2: p2p transport-layer, pre-deserialization.** The most defensive possible position — filter on the wire before decryption / decode work is spent on adversarial payloads. This was probably the original research intuition. It fails on two counts. First, the SimHash is computed over decrypted bytes; on-the-wire bytes are a ciphertext and their SimHash is structurally unrelated to the receiver's basis. Second, the pitch evaporates: a transport-layer filter that rejects packets by hash similarity is a rate-limited WAF with extra steps, which is a commodity product. The research integrity also suffers: the "coupling between content and receiver" phrase requires content to be meaningfully typed, which ciphertext is not.

### (iii) Decision criterion that would flip the recommendation

If the productization target is a permissioned-consortium ledger (PPA-4 Aspect 1) rather than a SaaS observability layer, Alt 1 (consensus-layer) becomes the better fit because the consortium buyer *wants* the filter coupled to their DAG and wants resonance values to be DAG-mass-weighted. The criterion is concretely: *does the lead customer operate their own Disentangle DAG, or are they running a non-Disentangle messaging substrate (Marmot, Matrix, MLS, proprietary) that they want instrumented?* Consortium lead ⇒ consensus-layer. Messaging substrate lead ⇒ application-layer. The enterprise pivot in `PIVOT.md` currently reads as messaging-substrate-lead; the GIM product in §4.1 reads as messaging-substrate-lead; both support application-layer.

If the lead customer category changes to "consortium-operated DAG" (e.g., a healthcare HIE consortium that runs Disentangle as their ledger), revisit this decision.

---

## Q2. Composition with Consensus

**Question.** On coupling-threshold failure (`FilterResult.passed == false`), what happens? (a) Transaction is rejected pre-DAG. (b) Transaction enters the DAG with a low-resonance tag, weighted in consensus. (c) Transaction is routed around the low-resonance receiver.

### (i) Recommendation: (b) enters DAG with resonance value recorded as first-class transaction metadata; no hard pre-DAG rejection by default; consensus weights remain unchanged but downstream observers (auditors, operators, capability revocation logic) consume the resonance tag.

This is the research-faithful choice. The entire framing of the research — `coupling coefficient, not gate`, `frequency-selective coupler, not filter` (the crate is misnamed for historical reasons) — collapses the moment "failure" means "rejection." (b) preserves the continuous quantity and turns the resonance into an auditable record rather than an irreversible censorship decision.

### Detailed semantics

Every transaction that traverses an application-layer membrane acquires a `resonance: f64 in [0.0, 1.0]` metadata field, a `basis_version: u64` (which basis was used), and a `lambda_at_evaluation: f64` (which lambda was in force, relevant for audits of attack-mode tightening — Q4). These three fields are:

1. **Recorded in the DAG transaction as a signed extension field.** The receiver signs the resonance measurement; the sender cannot forge it. This is structurally analogous to how `disentangle-zkp::ReputationClaim` attaches to transactions but from the receiver side rather than the sender side.
2. **Not used as a consensus weight by default.** Topological mass continues to be governed by PPA-1's curvature mechanics; resonance is *observable*, not *consensus-operative*. This is critical for research integrity: the filter and consensus are compositional, not fused.
3. **Available to downstream consumers as a policy input.** A capability revocation policy may fire when cumulative low-resonance incidents cross a threshold for a given delegation edge. A governance proposal may include resonance-distribution histograms as evidence. A GIM SaaS dashboard renders resonance distributions per tenant, per topic, per capability class.

### Opt-in hard rejection

Tenants that require the membrane to be an enforcement point (PPA-4 Aspect 1 permissioned-consortium embodiments; regulated-industry deployments where low-resonance traffic is a compliance failure on its own) can opt into (a) pre-DAG rejection for specified capability classes. The opt-in is configured per-capability-class rather than globally, because global hard rejection reintroduces the "allow/deny" framing the pitch is trying to escape. A tenant might configure: `rejection mode = hard` for capability class `govern/treasury`, `rejection mode = tagged` for capability class `messaging/groupchat`. The math is unchanged; only the downstream action varies.

### Why not (c), route-around?

Routing around a low-resonance receiver is expensive to implement correctly in a DAG substrate. The DAG already has a mechanism for "this transaction did not achieve consensus weight" — it is PPA-1's topological mass computation. A separately-implemented route-around would either duplicate PPA-1 (bad, violates separation of concerns) or conflict with PPA-1 (worse, produces consensus oscillation). Route-around is also a poor fit for application-layer positioning (Q1): at the application layer the "route" is already resolved (the RPC is addressed to this handler, the subscriber is already on this topic); there is nowhere to reroute *to* without reconstructing a different dispatch layer, which is out of scope for a filter primitive.

### Justification against the three criteria

- **(a) Research integrity.** (b) preserves the coupling-coefficient framing. The filter remains a measurement, not a gate. The compositional separation from consensus (resonance does *not* modify topological mass) preserves the research claim that PPA-1 and the membrane are independent primitives composable in multiple configurations.
- **(b) GIM SaaS fit.** The GIM product sells observability, not enforcement. Its core value proposition to an encrypted-messaging vendor is: *"Here is a dashboard of coordinated-inauthentic-behavior signal on your traffic."* A SaaS dashboard product whose filter mode is "drop the traffic" is incompatible with customer requirements — messaging vendors cannot accept lost messages from a third-party observability layer. Tagged-and-observable is the only shape that lets the SaaS sit as a sidecar rather than inline.
- **(c) PPA-4 claim surface.** (b) opens multiple claim directions that (a) forecloses. The resonance tag is (i) a structural compliance-evidence artifact (PPA-4 Aspect 6, particularly attestation types (c) absence-of-negative-curvature and (e) consequence-closure), (ii) a capability-runtime-monitoring signal (PPA-4 Aspect 7 coherence-bounded agent runtime, where resonance on agent-delegation edges is the runtime throttle input), and (iii) a hosted-service observable (PPA-4 Aspect 2 CaaS, where the resonance-distribution API is the productized surface). (a) collapses all of these into "the filter blocked a transaction," which is patentably thin.

### (ii) Most plausible alternatives

**Alt 1: (a) hard pre-DAG rejection as default, (b) tagged mode as opt-in.** Inverts the default. Stronger security posture: by default, a low-resonance transaction does not enter the record. Fits the paranoid deployment model (finance, defense-adjacent). The cost is the research-integrity cost: with (a) as default, the primitive *is* a gate from the buyer's perspective, and the pitch-line distinction from next-gen firewalls narrows. Also harder to pitch to design partners because "this will drop some of your traffic" is a procurement-blocking clause in most MSA templates.

**Alt 2: (b) but with resonance feeding consensus weight.** Partial fusion: the resonance value is multiplied into the transaction's consensus contribution before topological mass is computed. Research appeal: ties the two primitives together more tightly, potentially stronger paper story. Product appeal: makes the membrane's output observable through mass directly, simplifies the downstream logic. Problem: this couples the filter and consensus in a way that makes them co-dependent (you cannot reason about PPA-1 mass without also reasoning about membrane resonance), which weakens both patent claims (neither is separately instantiable) and weakens the modularity that makes the membrane deployable as a SaaS sidecar on non-Disentangle substrates.

### (iii) Decision criterion that would flip the recommendation

If the lead enterprise buyer articulates a *hard compliance requirement* that low-resonance traffic must be rejected pre-DAG (not tagged-and-retained), flip to Alt 1. The concrete test: ask the first three serious design-partner prospects whether they need the filter to drop traffic or tag it. If two or more say "drop," Alt 1 is the better product default. If two or more say "tag and let our team review," the recommendation stands.

A weaker flip condition: if the `disentangle-consensus` team pushes back on shipping a resonance-metadata extension on DAG transactions (schema-evolution concern, signature complexity), Alt 1 becomes operationally simpler because it never touches the DAG.

---

## Q3. Basis Provenance

**Question.** Who computes the receiver's `CoherenceBasis`? Self-anchored (derived from the node's own transaction history), community-anchored (derived from governance-weighted network state), or tenant-anchored (provided by a Group Integrity Monitor operator)? The task framing suggests all three modes — name when each applies.

### (i) Recommendation: all three modes are first-class, deployment-selected by a `BasisProvenance` field on each receiver's membrane configuration. Self-anchored is the research baseline; tenant-anchored is the GIM SaaS default; community-anchored is the consortium / governance-operated mode.

### The three modes, named and bounded

**Self-anchored (research baseline, permissionless default).** The receiver computes its own `CoherenceBasis` from its observable history: SimHash signatures of its own recent transactions, its own capability exercises, the payloads it has successfully integrated in prior windows. This is what the research code does implicitly — `extend_basis(sig)` adds a new signature to the basis, presumed to be learned from a successful transfer. The provenance claim is *"receiver knows best what it is coherent with."* Suitable for:

- Individual Disentangle nodes in a permissionless deployment.
- Researchers and early adopters building against the protocol directly.
- Reference implementations in the paper and in open-source demos.

**Tenant-anchored (GIM SaaS default).** The receiver's `CoherenceBasis` is issued by a tenant administrator — in the SaaS case, by a customer organization who has configured the GIM product with its own definition of "what coherent content looks like for this community / group / channel." The tenant admin either (i) uploads a seed set of exemplar SimHashes, (ii) points the GIM to a training corpus of approved-coherent historical traffic, or (iii) approves / rejects candidate basis extensions on an ongoing review cadence. The provenance claim is *"the tenant defines coherence for its community; the GIM enforces the definition."* Suitable for:

- Encrypted-messaging vendor deployments (Signal-for-enterprise, Wickr-for-government, Marmot/Nostr-for-enterprise) where the vendor's trust-and-safety team is the tenant admin.
- Financial-services communications-surveillance deployments (FINRA-style archived-trader-comms surveillance).
- Healthcare HIE consortium deployments where the consortium operator defines clinically-coherent traffic.

**Community-anchored (consortium / DAO / governance-operated mode).** The `CoherenceBasis` is derived from governance — a coherence-weighted vote (PPA-2's governance mechanism) selects the basis signatures for a given receiver class. This is distinct from tenant-anchored in that no single admin is authoritative; the basis is the product of a collective decision that is itself subject to the protocol's coherence-weighted governance. Suitable for:

- Open-consortium deployments (industry-association networks, cooperative operators).
- DAO-like structures where community members collectively curate the definition of coherence.
- Research-protocol deployments where the academic community wants a stable, jointly-owned basis rather than a vendor-owned one.

### Mode selection is per-receiver, not per-deployment

A single Disentangle node may host receivers operating under different modes: a `messaging/groupchat` receiver runs tenant-anchored (the GIM defines basis for that group), while a `governance/proposal` receiver runs community-anchored (the protocol's governance layer defines basis for governance traffic). The `BasisProvenance` enum is attached to the membrane instance, not to the node.

### Hybrid composition

The three are not mutually exclusive. A practical deployment will often run a tenant-anchored basis augmented by self-learned extensions that the tenant admin approves on a cadence. This becomes: *tenant-anchored baseline + self-anchored candidate extensions + tenant-anchored admission of candidates into the baseline.* The research-integrity price is low (the math doesn't care where signatures come from) and the product-integrity value is high (the GIM tenant gets a dashboard of "candidate extensions awaiting approval" which is a natural review workflow).

### Justification against the three criteria

- **(a) Research integrity.** All three modes are consistent with the research framing: the basis is a set of SimHashes with a threshold, and the source of the signatures is a deployment choice. The paper should present self-anchored as the reference model (it is the simplest instantiation and closest to the research intuition), with tenant-anchored and community-anchored as embodiments.
- **(b) GIM SaaS fit.** Tenant-anchored is *necessary* for the GIM to be a product rather than a research tool. A customer buys the GIM because they want *their* definition of coherence enforced, not a receiver's self-derived definition. The tenant-anchored mode is the GIM-specific embodiment; without it, the GIM is a hosted inference service with no customer-controlled policy surface.
- **(c) PPA-4 claim surface.** Naming three modes creates three distinct claim anchors and three distinguishable prior-art positions:
  - Self-anchored: distinguishable from traditional DLP / SIEM rule systems by virtue of being *learned* rather than *specified*.
  - Tenant-anchored: distinguishable from traditional rule-based content filtering by virtue of the basis being a *set of structural fingerprints* with a *geometric threshold*, not a rule tree.
  - Community-anchored: distinguishable from consortium-authority content moderation by virtue of the basis being *coherence-weighted* rather than *voting-weighted*, which composes with PPA-2's governance claims.

This also creates the substrate for PPA-4 Aspect 1 (permissioned-consortium) to claim the tenant-anchored mode specifically, and for PPA-4 Aspect 6 to claim the community-anchored mode as the basis-provenance channel for structural compliance attestations.

### (ii) Most plausible alternatives

**Alt 1: two modes only — self-anchored and tenant-anchored — collapse community-anchored into governance-as-tenant.** Simpler spec. The collapse is defensible on the grounds that community governance can always appoint a delegate admin who runs the tenant-anchored path. The cost is that the three-mode story is *cleaner* in PPA-4 claims and in the paper — losing community-anchored-as-distinct loses one claim anchor.

**Alt 2: one mode — self-anchored only — with tenant/community provenance handled by out-of-band signing of basis signatures.** The mathematically cleanest option: there is one mode, and the "source" of basis signatures is just *who signed them before the receiver ingested them*. The basis is a set of signed SimHashes; who signed it is a deployment-layer question, not a membrane-layer question. This is elegant but hurts product legibility — the GIM tenant wants to see "tenant-anchored" in their configuration UI, not "self-anchored with signed-basis-extension log."

### (iii) Decision criterion that would flip the recommendation

If, during the SPEC expansion, it becomes evident that community-anchored mode cannot be specified without substantial governance coupling (pulling in `disentangle-identity::governance` and the coherence-weighted voting machinery), flip to Alt 1. The community-anchored mode is only worth carrying as first-class if it is nearly free to specify. If it requires spec'ing a full governance workflow inside the membrane doc, fold it into tenant-anchored.

A weaker flip condition: if counsel's PPA-4 prior-art sweep on "tenant-provided coherence basis for content filtering" returns close art (industrial content-moderation ML platforms with customer-provided training corpora), the tenant-anchored mode may need to be claimed more narrowly, in which case the three-mode framing becomes load-bearing as a way to distinguish the overall invention.

---

## Q4. Lambda Dynamics

**Question.** Fixed lambda per receiver/tenant/topic? Adaptive (tightens under attack)? Different lambda per capability type? Adaptive lambda is "where defense lives."

### (i) Recommendation: adaptive-by-default per-pair lambda (the research behavior, `lambda = 1 - mutual_curvature`), with per-capability-class floors and ceilings, and a time-bounded attack-mode tightening function that raises the effective lambda globally or per-tenant for a configured window when anomaly signals fire.

Three layers stack:

1. **Base adaptive lambda (research baseline).** `Membrane::transfer()` already computes `mutual_curvature = level_factor * temporality_factor` and sets `lambda = 1 - mutual_curvature`. This is the research behavior and the minimum the spec should specify.
2. **Per-capability-class bounds.** Each capability class (e.g., `messaging/groupchat`, `governance/proposal`, `agent/delegation`, `treasury/transfer`) carries a `(lambda_floor, lambda_ceiling)` pair that clamps the adaptive lambda to a configured range. High-stakes capabilities enforce a floor (cannot go below `lambda = 0.6`); low-stakes capabilities enforce a ceiling (cannot go above `lambda = 0.4`). The research code already clamps to `[0.0, 1.0]`; this extends the clamp.
3. **Attack-mode tightening.** When observer-channel signals (Q5) indicate elevated coordinated-inauthentic-behavior signal — resonance distribution skewing toward low-resonance, basis-extension rate spiking, foliation leaf count unstable — a tightening multiplier is applied to all receivers in the affected tenant/region for a time-bounded window. Concretely: `effective_lambda = min(1.0, base_lambda * tightening_multiplier)`, with `tightening_multiplier` decaying back to 1.0 over a configured window (e.g., 30 minutes post-last-anomaly).

### Why per-capability-class bounds matter

The research paper treats lambda as a per-filter scalar. In production, a single tenant operates many receivers across many capability classes. A uniform lambda across all classes either over-restricts routine traffic or under-restricts high-stakes traffic. Per-class bounds make the spec concrete for product deployment: the GIM tenant admin configures "admin/treasury requires lambda ≥ 0.8; messaging/general allows lambda ≤ 0.3" once, and the system handles the rest.

This also creates a PPA-4 claim anchor orthogonal to the base lambda: *"capability-class-scoped coupling-selectivity bounds with adaptive clamping"* distinguishes from generic policy-scoped filtering (which does not have a geometric selectivity parameter at all) and from PPA-2 (which has capability classes but no coupling selectivity).

### Attack-mode tightening is where defense lives

The research code has one form of adaptivity: `adapt_lambda(mutual_curvature)`. That adaptivity is defensive only in the weak sense of "peers with poor mutual curvature get higher selectivity." A real attacker does not present poor mutual curvature; an attacker presents *engineered* mutual curvature that looks coherent. Defense against engineered coherence requires:

- **Detecting the anomaly at the aggregate layer**, not at the per-transaction layer. A single low-resonance transaction is noise; a distribution shift in resonance across many transactions is signal.
- **Tightening the selectivity globally or per-tenant** once signal is detected, rather than waiting for the per-pair adaptivity to react.
- **Decaying the tightening** so the system returns to baseline after the anomaly window passes, rather than permanently over-restricting.

This is the mechanism by which the GIM product actually *defends* a customer, as opposed to merely reporting on them. It is also a distinguishable PPA-4 claim — adaptive time-bounded tightening of geometric coupling selectivity in response to aggregate anomaly signals — with no close prior art (WAF adaptive blocking is rule-based, not geometric; ML-based anomaly detection is not tied to a coupling-coefficient primitive).

### (ii) Most plausible alternatives

**Alt 1: base adaptive + per-class bounds; no attack-mode tightening.** Simpler spec, slightly weaker defense story. Acceptable if the product's defensive value is framed entirely through the observer channel (Q5) — i.e., the GIM *reports* anomalies to the tenant, and the tenant is responsible for manual tightening via API. This is a valid product shape, just less automated.

**Alt 2: fixed lambda per tenant, no adaptivity.** The absolute simplest shape. The tenant configures lambda at onboarding, and it does not change. Gives up the entire "adaptive lambda is where defense lives" story — but also makes the product *operationally trivial* to reason about. Appealing for a first shipping version if engineering resources are constrained.

### (iii) Decision criterion that would flip the recommendation

If Q2 is flipped to (a) hard pre-DAG rejection as default, attack-mode tightening becomes operationally dangerous (a false-positive anomaly that tightens lambda globally could reject a flood of legitimate traffic), and the recommendation should drop to Alt 1 or Alt 2. Observer-mode default (the Q2 recommendation) makes attack-mode tightening safe because the tightening only affects which transactions are tagged low-resonance, not which transactions are retained.

A secondary flip condition: if the spectral-filter path (`SpectralFilter`, currently parallel to `CoherenceFilter` in the research code) is declared in-scope for productization, the lambda mechanics for spectral filters differ from SimHash filters (lambda controls eigenvector energy retention rather than hamming-distance threshold), and this spec section will need a Q4.b addendum. Default assumption: only the SimHash path productizes in v1.

---

## Q5. Regulator-Observer Channel

**Question.** For the Group Integrity Monitor SaaS, what does the auditor/regulator observer see? Per-transaction resonance values, aggregate basis drift, attenuation rates? Connects to PPA-4 Aspect 6 (geometric compliance attestations).

### (i) Recommendation: three privacy-preserving observer tiers, configured per tenant per capability class, corresponding to baseline statistical view, authorized anomaly view, and incident-response view. Default baseline for all tenants; upper tiers opt-in with authorization gates.

### Tier 1 — Baseline (always-on, statistical)

What the observer sees, in all deployments at all times, with no authorization beyond being named the tenant's auditor:

- **Resonance histogram** per capability class per time window (e.g., hour buckets): the distribution of resonance values across traffic, without per-transaction data.
- **Attenuation rate**: fraction of transactions whose resonance fell below lambda threshold, stratified by capability class and time window.
- **Basis-extension rate**: how often the basis grew in the window; a proxy for basis drift.
- **Foliation leaf count + stability**: the number of level-temporality leaves currently active across the tenant's receivers and how much they are churning; a coarse anomaly signal.
- **Aggregate Merkle-rooted commitment** of the underlying transaction set, published on a cadence (per hour, per day), such that the auditor can later verify that Tier 2/3 evidence came from the committed set.

### Tier 2 — Authorized anomaly view (per-cluster, anomaly-triggered)

Available when a tenant admin explicitly authorizes an auditor to see anomaly-level detail. Activated when Tier 1 statistics cross configured thresholds or when a specific investigation is opened.

- **Per-cluster anomaly reports**: "This receiver DID, in this time window, saw a resonance-distribution shift of X." No transaction payloads; only receiver identifier, time window, and the statistical signature of the shift.
- **Basis-version diff logs**: what signatures were added or removed from a receiver's basis in the window, who (if tenant-anchored) authorized the change.
- **Cross-tenant correlation signal** (only if Q6 is resolved to hierarchical bases): "This cluster pattern also appears in N other tenants in the provider's customer base at the same time window," without naming the other tenants.

### Tier 3 — Incident-response view (per-transaction, legal-process-gated)

Available only on legal process (subpoena, regulatory order, court-authorized audit) and only for specific transactions already identified through Tier 1/2 analysis.

- **Per-transaction resonance value** with lambda-at-evaluation and basis-version-at-evaluation.
- **Receiver DID, sender DID (if known), capability class, timestamp.**
- **Still no payload content** — the membrane's observer channel never surfaces the payload itself. Payload access is a separate authorization path (the tenant's DLP / discovery product), not the GIM's.

The three-tier structure is the operationalization of PPA-4 Aspect 6's attestation catalog: Tier 1 produces attestations of type (a) tier membership proofs and (b) aggregate-coherence-tier proofs; Tier 2 produces attestations of type (c) absence-of-negative-curvature over a bounded subgraph; Tier 3 supplies the unit evidence underlying a specific investigation.

### Justification against the three criteria

- **(a) Research integrity.** The observer channel is *downstream of the filter computation*; the filter itself does not change shape based on who is observing. Research integrity is preserved because the observer is a projection of the existing `FilterResult` stream, with aggregation added at Tier 1.
- **(b) GIM SaaS fit.** The three-tier structure is exactly what a regulated-industry SaaS product looks like. Every major compliance-oriented SaaS (audit-board, identity-trust-as-a-service, SIEM) has a baseline-plus-authorized-plus-subpoena tier structure. Selling to finance, healthcare, and government markets requires this structure to exist; it is a procurement pattern, not an engineering choice.
- **(c) PPA-4 claim surface.** Connects directly to Aspect 6. The specific claim anchor is *"a layered observer channel for a coherence-selective filtering primitive wherein baseline statistical evidence, authorized anomaly evidence, and incident-response per-transaction evidence are separated by authorization gates and cryptographically bound to frozen-curvature commitments."* This is distinguishable from generic SIEM tiering (which does not operate on geometric coupling) and from generic compliance-observability (which does not have a frozen-curvature commitment anchor).

### (ii) Most plausible alternatives

**Alt 1: Tier 1 only, all-statistical, no per-cluster or per-transaction observer.** Simpler. Fits a product positioning that is explicitly "we do not store or surface per-transaction data, even under subpoena, because we architecturally cannot." This is a defensible position for privacy-aggressive products (Signal-style, end-to-end-encrypted messaging vendors) but rules out regulated-industry verticals (finance, healthcare, government) where the tenant has legal obligation to produce evidence. Not recommended as default but potentially the right shape for a "privacy edition" SKU.

**Alt 2: Always-on per-transaction observer, no tiering.** The simpler opposite: always expose everything, no authorization gates. This is a non-starter for the majority of the target market (data-privacy-sensitive verticals) and weakens the PPA-4 claim because the tiering structure is a first-class novelty.

### (iii) Decision criterion that would flip the recommendation

If counsel's FTO on Aspect 6 comes back clean and the tiered-observer structure is the key distinguishable element, the three-tier recommendation is load-bearing. If counsel's FTO is constrained (Aspect 6 is flagged HIGH-RISK in `PPA4_ASPECTS.md`), the three-tier structure may be the specific claim anchor that threads the needle — making the structure non-negotiable. In that case: do not reduce tiering for spec simplicity; keep all three and let SPEC expansion detail the authorization boundaries precisely.

If the initial design-partner cohort for the GIM product is dominated by privacy-aggressive messaging vendors (not regulated-industry), flip to Alt 1 as default with Tier 2/3 as a later addition for the regulated-industry SKU.

---

## Q6. Tenant-Isolated Bases

**Question.** Independent per-tenant bases or hierarchical (shared provider basis + tenant delta)? Hierarchical unlocks cross-tenant attack detection while preserving privacy.

### (i) Recommendation: hierarchical by default (shared provider basis + per-tenant delta), with a strict-isolation opt-out for tenants with regulatory requirements that prohibit any shared computation. The shared provider basis is computed over non-identifying structural signatures and never crosses tenant boundaries.

### Hierarchical structure

- **Provider baseline basis.** The GIM operator maintains a baseline `CoherenceBasis` derived from aggregated, non-identifying structural signatures across the provider's customer base. This is the "what coordinated-inauthentic-behavior looks like across many deployments" basis. It is read-only from the tenant's perspective; the tenant cannot see its contents or modify it.
- **Per-tenant delta basis.** Each tenant maintains a local delta: signatures specific to that tenant's deployment, signatures that the tenant has added through the Q3 tenant-anchored mode. The tenant owns, sees, and controls this.
- **Effective basis at a receiver.** Union of (provider baseline ∩ applicable-to-tenant) with tenant delta. The hamming-distance threshold is evaluated against the union.

### Privacy posture

The shared provider basis is not a collection of payloads — it is a collection of 128-bit SimHashes with no content recoverable. Its construction from the aggregated customer base follows these rules, which should be hard-specified in SPEC expansion:

1. No signature enters the provider baseline unless it appears in at least N distinct tenants (N ≥ 5 recommended). This prevents a single-tenant signature (which might carry identifying information) from reaching the baseline.
2. Provider baseline signatures are content-agnostic — they are derived from structural features of transaction graphs, not from payload semantics. SimHash's locality-sensitivity is computed over graph structure, not over message text.
3. The provider publishes a Merkle root of the current baseline on a public cadence, such that any tenant can audit the baseline (see which signatures exist) without tenants being able to determine *which tenants contributed*.

### Why hierarchical unlocks cross-tenant attack detection

An attacker operating across multiple GIM tenants (a coordinated-inauthentic-behavior operation targeting several encrypted-messaging vendors simultaneously) will produce traffic that looks locally-coherent at each individual tenant but that matches a provider-baseline pattern derived from seeing the same structure across multiple tenants. Pure-isolated bases cannot detect this; hierarchical bases can.

This is the single highest-leverage technical benefit of the GIM product to its customer base — it is a benefit that no individual tenant could derive on its own and that requires the SaaS operator's vantage across many tenants. It is also a strong PPA-4 claim anchor: *"hierarchical coherence-basis construction for cross-tenant coordinated-inauthentic-behavior detection with privacy-preserving minimum-tenant-threshold basis admission."*

### Strict-isolation opt-out

Some tenants (defense-adjacent, nation-state-regulated) will have compliance requirements that prohibit any shared computation with other tenants. For these, the `CoherenceBasis` is pure tenant-anchored with no provider baseline overlay. The cost to the tenant is the loss of cross-tenant detection; the cost to the provider is a SKU that has to document strict isolation guarantees.

### Justification against the three criteria

- **(a) Research integrity.** The hierarchical structure is a composition of bases; the math treats the effective basis identically regardless of how it was constructed. Union-of-bases with a single threshold is a well-defined operation on the existing `CoherenceBasis` type.
- **(b) GIM SaaS fit.** Cross-tenant attack detection is *the* feature a multi-tenant SaaS can deliver that no single-tenant deployment can. Without it, the GIM is a hosted single-tenant tool that could just as easily run in the tenant's VPC. With it, the GIM has a genuine multi-tenant value proposition that justifies the SaaS-tier pricing model.
- **(c) PPA-4 claim surface.** New claim anchor: hierarchical-basis construction with minimum-tenant-threshold admission. Distinguishable from federated-learning prior art (which aggregates model weights, not coherence-basis signatures) and from threat-intelligence-sharing prior art (which shares indicators-of-compromise as rules, not geometric signatures). Composes with PPA-4 Aspect 2 (CaaS service architecture) — the service-claim language can include hierarchical basis as a key element of the service.

### (ii) Most plausible alternatives

**Alt 1: pure per-tenant isolation, no shared basis.** Simpler privacy posture; easier to defend in regulated environments. Loses cross-tenant detection entirely. Appropriate for a first version if privacy-conservative messaging is the go-to-market anchor.

### (iii) Decision criterion that would flip the recommendation

If the initial design-partner cohort's privacy counsel raises objections to any shared computation, flip to Alt 1. The flip condition is concrete: if during the first three design-partner technical reviews, the customer's security team rules out hierarchical on principle, Alt 1 becomes the default and hierarchical becomes an opt-in upgrade.

---

## Q7. Capability-Check Ordering

**Question.** Capability validation before or after membrane filter? Semantics of both orders. Partial-success behavior.

### (i) Recommendation: membrane filter runs first in observer mode (the Q2 recommendation); capability validation runs first in enforcement mode. In observer mode, both checks produce independent signals — the observer records both resonance and capability-validation outcome, and downstream consumers decide what to do with each.

### Semantics, both orders

**Filter-first (observer-mode default):**

1. The payload arrives at the receiver.
2. The receiver's membrane computes `FilterResult { resonance, passed, ... }`.
3. The resonance and passed flag are recorded as transaction metadata regardless of outcome.
4. Capability validation runs on the payload.
5. If capability validation succeeds, the transaction proceeds; if it fails, it is rejected for capability reasons (independent of filter outcome).
6. The observer channel sees: resonance value, capability-validation outcome, and whether the transaction ultimately proceeded.

This gives the observer the full attack surface — including attack traffic that was rejected for capability reasons but that still carries a resonance signal revealing coordinated-inauthentic-behavior.

**Capability-first (enforcement-mode default):**

1. The payload arrives at the receiver.
2. Capability validation runs.
3. If capability validation fails, transaction rejected; filter does not run. No resonance recorded.
4. If capability validation succeeds, filter runs.
5. If filter fails (resonance < lambda), transaction rejected pre-DAG (Q2=a opt-in) or tagged (Q2=b default).
6. The observer channel sees: capability-validation outcome, and (if succeeded) resonance value.

This is operationally cheaper — unauthorized traffic does not incur the SimHash computation. It also produces a cleaner audit log (every recorded resonance value is for an authorized action).

**Partial-success behavior:**

- Filter-first + filter fails + capability succeeds: transaction enters DAG with low-resonance tag (Q2=b default). Capability exercise is recorded. Observer sees both signals. Resonance-triggered capability revocation logic may fire later.
- Filter-first + filter succeeds + capability fails: transaction rejected for capability reasons. Resonance is still recorded. This is where filter-first's value shows: an attacker's probing traffic (high-resonance but unauthorized) is captured as a signal.
- Capability-first + filter fails: transaction rejected or tagged. Observer sees both.
- Capability-first + capability fails: transaction rejected. No filter signal captured.

### Why filter-first is the right observer-mode default

The pitch line — *"we measure coupling between content and receiver at the edge"* — puts measurement ahead of authorization. If capability-first is the default, the product's observability surface is bounded by what is already authorized, which is the subset of traffic least interesting to a coordinated-inauthentic-behavior detection product (the attacker's most dangerous signal is *probing* traffic, not traffic the attacker has already gained authorization for).

PPA-4 claim value: filter-first enables a distinguishable claim — *"coupling measurement prior to capability validation, with the resulting resonance signal retained as a distinct auditable artifact regardless of capability-validation outcome."* This is narrower than the full three-mode spec but more defensible against prior art (most authorization-filtering systems run authorization first).

### (ii) Most plausible alternatives

**Alt 1: always capability-first.** Simpler; cheaper; cleaner audit log. The loss is the probing-traffic observability described above and the claim-value from the distinction. Acceptable if the product's first-version scope is "observe authorized traffic only" and probing-detection is deferred to a later release.

**Alt 2: configurable per-capability-class.** The most flexible option: each capability class declares its preferred order, and the tenant admin configures per class. `governance/proposal` might be capability-first (cheap and strict); `messaging/groupchat` might be filter-first (rich observability). This is the operationally-correct answer if engineering budget permits; the concern is it adds a configuration knob that could easily be misconfigured.

### (iii) Decision criterion that would flip the recommendation

If the membrane filter computation is measured (at SPEC-expansion time) to be expensive enough that filter-first imposes a meaningful latency cost on unauthorized-but-high-volume probing traffic (e.g., > 10× the capability-validation cost and the expected unauthorized-traffic volume is > 20% of total), flip to Alt 1. The criterion is concretely: benchmark the filter at realistic traffic shapes against the capability-validation cost; if the ratio is worse than 10×, capability-first wins on economics.

If configuration flexibility is considered a feature by initial design partners (rather than a risk), flip to Alt 2.

---

## Decision summary (one-line form for synchronous review)

- **Q1. Positioning:** application-layer, ingress-dominant, observer-mode default, symmetric egress for self-protection.
- **Q2. Composition with consensus:** (b) — enter DAG with resonance metadata tag; consensus weight unchanged; opt-in hard rejection per capability class.
- **Q3. Basis provenance:** all three modes (self-anchored research baseline, tenant-anchored SaaS default, community-anchored consortium mode) as first-class deployment choices.
- **Q4. Lambda dynamics:** adaptive per-pair (research baseline) + per-capability-class floors/ceilings + time-bounded attack-mode tightening on aggregate anomaly signal.
- **Q5. Regulator-observer channel:** three privacy-preserving tiers — baseline statistical (always-on), authorized anomaly (opt-in), incident-response per-transaction (legal-process-gated).
- **Q6. Tenant-isolated bases:** hierarchical by default (shared provider baseline + per-tenant delta) with strict-isolation opt-out; minimum-tenant-threshold admission rule for baseline signatures.
- **Q7. Capability-check ordering:** filter-first in observer mode, capability-first in enforcement mode; observer records both signals in both orders.

## Cross-cutting notes for SPEC expansion

- **Lambda-at-zero convention ambiguity.** `filter.rs` treats `lambda = 0.0` as maximally open; `membrane.rs` treats unknown-peer as `lambda = 0.0` with intent of maximum selectivity. SPEC expansion must reconcile: either invert the convention in one file or add an explicit `unknown_peer_policy` field so the two behaviors are decoupled.
- **SimHash vs spectral path.** This decision doc addresses only the SimHash path. The `SpectralFilter` path has separate lambda semantics and should be declared either in-scope or deferred in SPEC expansion; default assumption is deferred.
- **Foliation role.** `Foliation` is not addressed in the seven questions. SPEC expansion must decide whether foliation leaves become a first-class product surface (visible to the observer channel as a coherence-neighborhood structure) or remain an internal classifier used only in lambda adaptation.
- **PPA-4 claim harvest.** The recommendations above generate at least six distinguishable claim anchors: (1) application-layer coupling measurement, (2) tagged-resonance DAG metadata, (3) three-mode basis provenance, (4) time-bounded attack-mode tightening, (5) three-tier observer channel, (6) hierarchical basis construction with minimum-tenant-threshold admission. SPEC expansion should include a short appendix enumerating these for counsel.
- **Scope discipline for SPEC expansion follow-up task.** This decision doc does not commit to any of the above as final; the synchronous Lars + cdesktop review decides. Expansion is on adopted decisions only.

End of decision document.
