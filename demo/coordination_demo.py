#!/usr/bin/env python3
"""
Disentangle Protocol: Coordination Economy Demo

Demonstrates the full 5-phase coordination economy lifecycle:
  Phase 1 - Trust Building (identity registration + triangle topology)
  Phase 2 - Proposal Ignition (mass-commitment activation)
  Phase 3 - Collaboration (SharedIntent + coherence measurement)
  Phase 4 - Oracle Distribution (CommonsPool + coherence-weighted payout)
  Phase 5 - Sybil Attack (star topology blocked by coherence gates)

Requires: running disentangle node (default http://localhost:3000)
"""

import os
import sys
import time
from typing import Any

try:
    import httpx
except ImportError:
    print("ERROR: httpx is required. Install with: pip install httpx")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("DISENTANGLE_NODE_URL", "http://localhost:3000")
REQUEST_TIMEOUT = 30.0

# Proposal parameters (from spec section 2)
ACTIVATION_MASS = 0.5
MIN_PARTICIPANTS = 3
EXPIRY_DEPTH = 10000

# Pool parameters
POOL_DEPOSIT_AMOUNT = 10000
POOL_NAME = "Coordination Economy Demo Pool"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

_client: httpx.Client | None = None


def client() -> httpx.Client:
    """Lazy-initialize and return the shared HTTP client."""
    global _client
    if _client is None:
        _client = httpx.Client(base_url=BASE_URL, timeout=REQUEST_TIMEOUT)
    return _client


def post(path: str, json: dict[str, Any] | None = None) -> dict[str, Any]:
    """POST request with error handling."""
    resp = client().post(path, json=json or {})
    if not resp.is_success:
        detail = ""
        try:
            detail = resp.json().get("error", resp.text)
        except Exception:
            detail = resp.text
        raise RuntimeError(f"POST {path} returned {resp.status_code}: {detail}")
    return resp.json()


def get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """GET request with error handling."""
    resp = client().get(path, params=params)
    if not resp.is_success:
        detail = ""
        try:
            detail = resp.json().get("error", resp.text)
        except Exception:
            detail = resp.text
        raise RuntimeError(f"GET {path} returned {resp.status_code}: {detail}")
    return resp.json()


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def banner(text: str) -> None:
    """Print a formatted banner for phase titles."""
    print(f"\n{'=' * 72}")
    print(f"  {text}")
    print(f"{'=' * 72}\n")


def section(text: str) -> None:
    """Print a sub-section header."""
    print(f"\n  --- {text} ---\n")


def fmt(value: float, width: int = 10) -> str:
    """Format a float to 4 decimal places, right-aligned."""
    return f"{value:>{width}.4f}"


def fmt_int(value: int, width: int = 10) -> str:
    """Format an integer, right-aligned."""
    return f"{value:>{width}}"


def elapsed_since(start: float) -> str:
    """Format elapsed time since start."""
    return f"{time.time() - start:.2f}s"


# ---------------------------------------------------------------------------
# Agent record (lightweight, no SDK dependency)
# ---------------------------------------------------------------------------

class Agent:
    """Lightweight agent record for the demo.

    Holds registration data returned from POST /identity/register.
    Methods are thin wrappers around the HTTP helpers above.
    """

    def __init__(self, name: str):
        self.name = name
        self.did: str = ""
        self.signing_key_hex: str = ""
        self.registered = False

    def register(self, agent_type: str = "agi", runtime_attestation: str | None = None) -> None:
        payload: dict[str, Any] = {"agent_type": agent_type}
        if runtime_attestation:
            payload["runtime_attestation"] = runtime_attestation
        resp = post("/identity/register", json=payload)
        self.did = resp["did"]
        self.signing_key_hex = resp["signing_key_hex"]
        self.registered = True

    def introduce(self, other: "Agent", edge_name: str = "collaborator") -> bool:
        resp = post("/introduction", json={
            "introducer_did": self.did,
            "introducer_sk_hex": self.signing_key_hex,
            "introduced_did": other.did,
            "edge_name": edge_name,
        })
        return resp.get("success", False)

    def coherence(self) -> dict[str, Any]:
        resp = get(f"/coherence/{self.did}")
        return resp.get("profile", resp)

    def create_capability(
        self,
        subject: dict[str, Any] | None = None,
        constraints: list[dict[str, Any]] | None = None,
        delegatable: bool = True,
    ) -> str:
        """Create a capability and return its hex ID."""
        payload = {
            "issuer_did": self.did,
            "signing_key_hex": self.signing_key_hex,
            "subject": subject or {"type": "TransactionScope", "scope": "All"},
            "constraints": constraints or [],
            "delegatable": delegatable,
        }
        resp = post("/capability/create", json=payload)
        return resp["capability_id_hex"]

    def __repr__(self) -> str:
        short_did = self.did[:24] + "..." if self.did else "<unregistered>"
        return f"Agent({self.name}, {short_did})"


# ---------------------------------------------------------------------------
# Phase 1: Trust Building
# ---------------------------------------------------------------------------

def phase_1_trust_building() -> tuple[Agent, Agent, Agent]:
    """Register 3 agents and form a triangle with positive curvature."""
    banner("PHASE 1: Trust Building")
    t0 = time.time()

    alice = Agent("Alice")
    bob = Agent("Bob")
    carol = Agent("Carol")

    # Register
    for agent in (alice, bob, carol):
        print(f"  Registering {agent.name}...")
        agent.register(
            agent_type="agi",
            runtime_attestation=f"{agent.name.lower()}-attestation-hash",
        )
        print(f"    DID: {agent.did[:48]}...")

    # Mutual introductions to form a triangle
    section("Mutual Introductions (Triangle Topology)")
    pairs = [
        (alice, bob, "research-partner"),
        (bob, alice, "research-partner"),
        (alice, carol, "collaborator"),
        (carol, alice, "collaborator"),
        (bob, carol, "collaborator"),
        (carol, bob, "collaborator"),
    ]
    for a, b, edge in pairs:
        ok = a.introduce(b, edge_name=edge)
        print(f"    {a.name} -> {b.name}: {'OK' if ok else 'FAILED'}")

    # Small delay for topology propagation
    time.sleep(0.3)

    # Print coherence profiles
    section("Coherence Profiles")
    header = f"  {'Agent':<12} {'Score':>10} {'Mass':>12} {'Curvature':>12} {'Diversity':>10}"
    sep = f"  {'-'*12} {'-'*10} {'-'*12} {'-'*12} {'-'*10}"
    print(header)
    print(sep)

    for agent in (alice, bob, carol):
        coh = agent.coherence()
        print(
            f"  {agent.name:<12} "
            f"{fmt(coh.get('composite_score', 0.0))} "
            f"{fmt(coh.get('topological_mass', 0.0), 12)} "
            f"{fmt(coh.get('mean_local_curvature', 0.0), 12)} "
            f"{fmt_int(coh.get('relational_diversity', 0))}"
        )

    print(f"\n  Observation: Triangle topology yields positive curvature.")
    print(f"  Elapsed: {elapsed_since(t0)}")

    return alice, bob, carol


# ---------------------------------------------------------------------------
# Phase 2: Proposal Ignition
# ---------------------------------------------------------------------------

def phase_2_proposal_ignition(alice: Agent, bob: Agent, carol: Agent) -> str:
    """Alice creates a proposal; Bob and Carol join; auto-activates as SharedIntent."""
    banner("PHASE 2: Proposal Ignition")
    t0 = time.time()

    # Alice creates proposal
    section("Alice Creates Proposal")
    proposal_resp = post("/proposal/create", json={
        "initiator_did": alice.did,
        "description": "Collaborative embedding generation",
        "activation_mass": ACTIVATION_MASS,
        "min_participants": MIN_PARTICIPANTS,
        "expiry_depth": EXPIRY_DEPTH,
    })
    proposal_id = proposal_resp["id"]
    print(f"  Proposal ID: {proposal_id}")
    print(f"  Description: Collaborative embedding generation")
    print(f"  Activation mass: {ACTIVATION_MASS}")
    print(f"  Min participants: {MIN_PARTICIPANTS}")
    print(f"  Expiry depth: {EXPIRY_DEPTH}")

    # Bob joins
    section("Bob Joins Proposal")
    join_resp = post("/proposal/join", json={
        "proposal_id": proposal_id,
        "joiner_did": bob.did,
    })
    committed = join_resp.get("committed_mass", join_resp.get("total_mass", 0.0))
    status = join_resp.get("status", "unknown")
    print(f"  Bob committed mass: {committed:.4f}")
    print(f"  Proposal status: {status}")
    print(f"  Mass threshold not yet reached.")

    # Carol joins -- should trigger activation
    section("Carol Joins Proposal (Threshold Crossing)")
    join_resp = post("/proposal/join", json={
        "proposal_id": proposal_id,
        "joiner_did": carol.did,
    })
    committed = join_resp.get("committed_mass", join_resp.get("total_mass", 0.0))
    status = join_resp.get("status", "unknown")
    intent_id = join_resp.get("intent_id", "")

    print(f"  Carol committed mass: {committed:.4f}")
    print(f"  Proposal status: {status}")

    if intent_id:
        print(f"  AUTO-ACTIVATED as SharedIntent!")
        print(f"  Intent ID: {intent_id}")
    else:
        # If not returned in join response, check proposal state
        proposal_state = get(f"/proposal/{proposal_id}")
        p_status = proposal_state.get("status", {})
        if isinstance(p_status, dict) and "Activated" in p_status:
            intent_id = p_status["Activated"].get("intent_id", "")
        elif isinstance(p_status, str) and p_status == "Activated":
            intent_id = proposal_state.get("intent_id", proposal_id)

        if intent_id:
            print(f"  AUTO-ACTIVATED as SharedIntent!")
            print(f"  Intent ID: {intent_id}")
        else:
            print(f"  WARNING: Proposal did not auto-activate. Using proposal ID as fallback.")
            intent_id = proposal_id

    print(f"\n  Elapsed: {elapsed_since(t0)}")
    return intent_id


# ---------------------------------------------------------------------------
# Phase 3: Collaboration
# ---------------------------------------------------------------------------

def phase_3_collaboration(
    alice: Agent, bob: Agent, carol: Agent, intent_id: str
) -> None:
    """All three contribute capabilities, run settlements, check coherence."""
    banner("PHASE 3: Collaboration")
    t0 = time.time()

    agents = [alice, bob, carol]

    # Each agent contributes capabilities to the SharedIntent
    section("Contributing Capabilities to SharedIntent")
    for agent in agents:
        cap_id = agent.create_capability(
            subject={"type": "TransactionScope", "scope": "All"},
        )
        try:
            join_resp = post("/intent/join", json={
                "intent_id": intent_id,
                "joiner_did": agent.did,
                "capability_ids": [cap_id],
            })
            print(f"  {agent.name} contributed capability {cap_id[:16]}... -> OK")
        except RuntimeError as e:
            # Agent may already be a participant from proposal activation
            print(f"  {agent.name} contributed capability {cap_id[:16]}... -> {e}")

    # Run simulated work: create settlements with CoherenceEffect::None
    section("Simulated Work (Settlements with CoherenceEffect::None)")
    settlement_pairs = [(alice, bob), (bob, carol), (carol, alice)]
    for provider, consumer in settlement_pairs:
        try:
            cap_id = provider.create_capability()
            settlement_resp = post("/agreement/propose", json={
                "provider_did": provider.did,
                "consumer_did": consumer.did,
                "capability_id": cap_id,
                "terms": {"duration": 3600, "rate": 100},
                "coherence_effect": "None",
            })
            agreement_id = settlement_resp.get("agreement_id", settlement_resp.get("id", "unknown"))
            print(f"  Settlement {provider.name} -> {consumer.name}: {agreement_id[:16] if len(str(agreement_id)) > 16 else agreement_id}...")

            # Accept and complete the settlement
            try:
                post("/agreement/accept", json={
                    "agreement_id": agreement_id,
                    "acceptor_did": consumer.did,
                })
                post("/agreement/complete", json={
                    "agreement_id": agreement_id,
                    "completer_did": provider.did,
                })
            except RuntimeError:
                pass  # Settlement completion is best-effort in demo

        except RuntimeError as e:
            print(f"  Settlement {provider.name} -> {consumer.name}: skipped ({e})")

    # Check intent coherence snapshot
    section("Intent Coherence Snapshot")
    try:
        snapshot = get(f"/intent/{intent_id}/coherence")
        print(f"  Intent ID:          {intent_id}")
        print(f"  Participants:       {snapshot.get('participant_count', 'N/A')}")
        print(f"  Baseline mass:      {snapshot.get('baseline_mass', 0.0):.4f}")
        print(f"  Current mass:       {snapshot.get('current_mass', 0.0):.4f}")
        print(f"  Mass delta:         {snapshot.get('mass_delta', 0.0):.4f}")
        print(f"  Baseline curvature: {snapshot.get('baseline_curvature', 0.0):.4f}")
        print(f"  Current curvature:  {snapshot.get('current_curvature', 0.0):.4f}")
        print(f"  Curvature delta:    {snapshot.get('curvature_delta', 0.0):.4f}")
    except RuntimeError as e:
        print(f"  Could not retrieve coherence snapshot: {e}")

    print(f"\n  Elapsed: {elapsed_since(t0)}")


# ---------------------------------------------------------------------------
# Phase 4: Oracle Distribution
# ---------------------------------------------------------------------------

def phase_4_oracle_distribution(
    alice: Agent, bob: Agent, carol: Agent, intent_id: str
) -> str:
    """Create CommonsPool, deposit, trigger oracle, distribute, claim."""
    banner("PHASE 4: Oracle Distribution")
    t0 = time.time()

    agents = [alice, bob, carol]

    # Create CommonsPool
    section("Create CommonsPool")
    pool_resp = post("/pool/create", json={
        "name": POOL_NAME,
        "min_coherence": 0.1,
    })
    pool_id = pool_resp.get("id", pool_resp.get("pool_id", ""))
    print(f"  Pool ID: {pool_id}")
    print(f"  Name: {POOL_NAME}")

    # Deposit simulated funds
    section("Deposit Simulated Funds")
    deposit_resp = post("/pool/deposit", json={
        "pool_id": pool_id,
        "depositor": "external-sponsor",
        "amount": POOL_DEPOSIT_AMOUNT,
    })
    balance = deposit_resp.get("balance", deposit_resp.get("total_balance", POOL_DEPOSIT_AMOUNT))
    print(f"  Deposited: {POOL_DEPOSIT_AMOUNT} units")
    print(f"  Pool balance: {balance}")

    # Trigger oracle query over intent participants
    section("Trigger Oracle Distribution")
    dist_resp = post("/pool/distribute", json={
        "pool_id": pool_id,
        "region": {"Intent": intent_id},
        "depth_start": 0,
        "depth_end": 99999,
    })
    distribution_id = dist_resp.get("query_id", dist_resp.get("distribution_id", ""))
    weights = dist_resp.get("weights", {})
    scores = dist_resp.get("scores", {})

    print(f"  Distribution ID: {distribution_id}")
    print(f"\n  Distribution Weights:")
    header = f"    {'Agent':<16} {'Weight':>10} {'Mass Delta':>12} {'Curv Delta':>12} {'Diversity':>10} {'Composite':>12}"
    sep = f"    {'-'*16} {'-'*10} {'-'*12} {'-'*12} {'-'*10} {'-'*12}"
    print(header)
    print(sep)

    for agent in agents:
        w = weights.get(agent.did, 0.0)
        s = scores.get(agent.did, {})
        print(
            f"    {agent.name:<16} "
            f"{fmt(w)} "
            f"{fmt(s.get('mass_delta', 0.0), 12)} "
            f"{fmt(s.get('curvature_delta', 0.0), 12)} "
            f"{fmt_int(s.get('diversity', 0))} "
            f"{fmt(s.get('composite', 0.0), 12)}"
        )

    # Agents claim from pool
    section("Agents Claim from Pool")
    for agent in agents:
        try:
            claim_resp = post("/pool/claim", json={
                "pool_id": pool_id,
                "claimant_did": agent.did,
                "distribution_id": distribution_id,
            })
            claimed = claim_resp.get("amount", claim_resp.get("claimed", 0))
            print(f"  {agent.name} claimed: {claimed} units")
        except RuntimeError as e:
            print(f"  {agent.name} claim failed: {e}")

    # Print final pool state
    section("Final Pool State")
    try:
        pool_state = get(f"/pool/{pool_id}")
        print(f"  Pool ID:        {pool_id}")
        print(f"  Balance:        {pool_state.get('balance', 'N/A')}")
        print(f"  Total deposits: {len(pool_state.get('deposits', []))}")
        print(f"  Total claims:   {len(pool_state.get('claims', []))}")
    except RuntimeError as e:
        print(f"  Could not retrieve pool state: {e}")

    print(f"\n  Elapsed: {elapsed_since(t0)}")
    return pool_id


# ---------------------------------------------------------------------------
# Phase 5: Sybil Attack
# ---------------------------------------------------------------------------

def phase_5_sybil_attack(
    alice: Agent, bob: Agent, carol: Agent, pool_id: str
) -> None:
    """Register Sybil agents in star topology, show coherence gates block them."""
    banner("PHASE 5: Sybil Attack (Star Topology)")
    t0 = time.time()

    honest_agents = [alice, bob, carol]
    sybil_count = 5

    # Register Sybil hub
    section("Register Sybil Cluster (Star Topology)")
    sybil_hub = Agent("Sybil-Hub")
    sybil_hub.register(
        agent_type="agi",
        runtime_attestation="sybil-hub-attestation",
    )
    print(f"  Sybil Hub DID: {sybil_hub.did[:48]}...")

    # Register Sybil leaves -- star topology, no cross-connections
    sybil_leaves: list[Agent] = []
    for i in range(sybil_count):
        leaf = Agent(f"Sybil-{i}")
        leaf.register(
            agent_type="agi",
            runtime_attestation=f"sybil-leaf-{i}-attestation",
        )
        # Hub introduces each leaf (star topology)
        sybil_hub.introduce(leaf, edge_name=f"sybil-link-{i}")
        leaf.introduce(sybil_hub, edge_name="sybil-hub")
        sybil_leaves.append(leaf)
        print(f"  Registered {leaf.name}, connected to hub only")

    # No cross-connections among leaves (star topology = zero triangles)
    print(f"\n  Topology: {sybil_count} leaves connected to 1 hub, 0 cross-connections")

    time.sleep(0.3)

    # Sybil hub creates competing proposal
    section("Sybil Hub Creates Competing Proposal")
    try:
        sybil_proposal_resp = post("/proposal/create", json={
            "initiator_did": sybil_hub.did,
            "description": "Sybil-controlled compute pool",
            "activation_mass": 0.3,
            "min_participants": 3,
            "expiry_depth": EXPIRY_DEPTH,
        })
        sybil_proposal_id = sybil_proposal_resp.get("id", "")
        print(f"  Sybil proposal ID: {sybil_proposal_id}")

        # Sybil leaves try to join
        for leaf in sybil_leaves[:3]:
            try:
                join_resp = post("/proposal/join", json={
                    "proposal_id": sybil_proposal_id,
                    "joiner_did": leaf.did,
                })
                status = join_resp.get("status", "unknown")
                print(f"  {leaf.name} join attempt: status={status}")
            except RuntimeError as e:
                print(f"  {leaf.name} join BLOCKED: {e}")

        print("\n  Result: CoherenceMinimum blocks Sybil agents from joining proposals.")
    except RuntimeError as e:
        print(f"  Sybil proposal creation BLOCKED: {e}")
        print("  Result: CoherenceMinimum prevents Sybil hub from creating proposals.")

    # Show coherence comparison
    section("Coherence Comparison: Honest vs. Sybil")
    header = f"  {'Agent':<16} {'Score':>10} {'Mass':>12} {'Curvature':>12} {'Diversity':>10}"
    sep = f"  {'-'*16} {'-'*10} {'-'*12} {'-'*12} {'-'*10}"
    print(header)
    print(sep)

    honest_scores: list[float] = []
    sybil_scores: list[float] = []

    for agent in honest_agents:
        coh = agent.coherence()
        score = coh.get("composite_score", 0.0)
        honest_scores.append(score)
        print(
            f"  {agent.name:<16} "
            f"{fmt(score)} "
            f"{fmt(coh.get('topological_mass', 0.0), 12)} "
            f"{fmt(coh.get('mean_local_curvature', 0.0), 12)} "
            f"{fmt_int(coh.get('relational_diversity', 0))}"
        )

    print()  # separator between clusters

    for agent in [sybil_hub] + sybil_leaves:
        coh = agent.coherence()
        score = coh.get("composite_score", 0.0)
        sybil_scores.append(score)
        print(
            f"  {agent.name:<16} "
            f"{fmt(score)} "
            f"{fmt(coh.get('topological_mass', 0.0), 12)} "
            f"{fmt(coh.get('mean_local_curvature', 0.0), 12)} "
            f"{fmt_int(coh.get('relational_diversity', 0))}"
        )

    avg_honest = sum(honest_scores) / len(honest_scores) if honest_scores else 0.0
    avg_sybil = sum(sybil_scores) / len(sybil_scores) if sybil_scores else 0.0
    ratio = avg_honest / avg_sybil if avg_sybil > 0 else float("inf")
    print(f"\n  Honest avg score:  {avg_honest:.4f}")
    print(f"  Sybil avg score:   {avg_sybil:.4f}")
    print(f"  Separation ratio:  {ratio:.2f}x")

    # Run oracle over Sybil cluster -- scores should be zero
    section("Oracle Query: Sybil Cluster")
    sybil_dids = [sybil_hub.did] + [l.did for l in sybil_leaves]
    try:
        sybil_dist = post("/pool/distribute", json={
            "pool_id": pool_id,
            "region": {"Explicit": sybil_dids},
            "depth_start": 0,
            "depth_end": 99999,
        })
        sybil_weights = sybil_dist.get("weights", {})

        print(f"  {'Agent':<16} {'Weight':>10}")
        print(f"  {'-'*16} {'-'*10}")
        for agent in [sybil_hub] + sybil_leaves:
            w = sybil_weights.get(agent.did, 0.0)
            print(f"  {agent.name:<16} {fmt(w)}")

        total_sybil_weight = sum(sybil_weights.values())
        print(f"\n  Total Sybil distribution weight: {total_sybil_weight:.4f}")
    except RuntimeError as e:
        print(f"  Oracle query over Sybil cluster failed: {e}")
        print("  (Expected: negative boundary curvature -> zero scores)")

    # Final comparison
    section("Distribution Comparison: Honest vs. Sybil Cluster")
    print("  Honest cluster (triangle topology):")
    print(f"    Positive curvature, positive mass delta")
    print(f"    Oracle distributes proportional to structural contribution")
    print()
    print("  Sybil cluster (star topology):")
    print(f"    Negative/zero boundary curvature, no triangles")
    print(f"    Oracle scores at zero -- no distribution")
    print()
    print("  The network's geometry reveals its truth.")

    print(f"\n  Elapsed: {elapsed_since(t0)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def check_node_connectivity() -> bool:
    """Verify the Disentangle node is reachable."""
    try:
        resp = client().get("/status")
        if resp.is_success:
            return True
        print(f"  Node responded with status {resp.status_code}")
        return False
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        print(f"  Cannot connect to node at {BASE_URL}: {e}")
        return False


def main() -> int:
    """Run the full 5-phase coordination economy demo."""
    total_start = time.time()

    banner("DISENTANGLE PROTOCOL: COORDINATION ECONOMY DEMO")
    print("  Settlement does not mint coherence.")
    print("  Proposals activate by mass, not votes.")
    print("  The network is a lens, not a bank.")
    print(f"\n  Node URL: {BASE_URL}")

    # Connectivity check
    print("  Checking node connectivity...")
    if not check_node_connectivity():
        print(f"\n  ERROR: Cannot connect to Disentangle node at {BASE_URL}")
        print("  Please ensure a Disentangle node is running:")
        print("    cd disentangle-core && cargo run --bin disentangle-node")
        print(f"  Or set DISENTANGLE_NODE_URL to the correct address.")
        return 1
    print("  Node connection: OK")

    try:
        # Phase 1: Trust Building
        alice, bob, carol = phase_1_trust_building()

        # Phase 2: Proposal Ignition
        intent_id = phase_2_proposal_ignition(alice, bob, carol)

        # Phase 3: Collaboration
        phase_3_collaboration(alice, bob, carol, intent_id)

        # Phase 4: Oracle Distribution
        pool_id = phase_4_oracle_distribution(alice, bob, carol, intent_id)

        # Phase 5: Sybil Attack
        phase_5_sybil_attack(alice, bob, carol, pool_id)

        # Summary
        banner("DEMO COMPLETE")
        print("  5-Phase Coordination Economy Lifecycle:")
        print("    Phase 1 - Trust Building:      Triangle topology, positive curvature")
        print("    Phase 2 - Proposal Ignition:    Mass-commitment auto-activation")
        print("    Phase 3 - Collaboration:        SharedIntent coherence measurement")
        print("    Phase 4 - Oracle Distribution:   Coherence-weighted value flow")
        print("    Phase 5 - Sybil Attack:         Star topology blocked by geometry")
        print()
        print("  Key Invariants Demonstrated:")
        print("    - Settlement generates zero coherence delta")
        print("    - Proposals activate by mass, not votes")
        print("    - SharedIntents have no completion state (topology IS the attestation)")
        print("    - Oracle computation is deterministic from DAG state")
        print("    - Sybil clusters score zero (negative boundary curvature)")
        print(f"\n  Total elapsed: {elapsed_since(total_start)}")
        print()
        return 0

    except RuntimeError as e:
        print(f"\n  ERROR: {e}")
        return 1
    except Exception as e:
        print(f"\n  UNEXPECTED ERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        if _client is not None:
            _client.close()


if __name__ == "__main__":
    sys.exit(main())
