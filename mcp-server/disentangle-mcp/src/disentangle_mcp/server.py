from fastmcp import FastMCP
import httpx
import os

mcp = FastMCP("Disentangle Protocol")
NODE_URL = os.environ.get("DISENTANGLE_NODE_URL", "http://localhost:8000")

# --- Identity Tools ---

@mcp.tool()
def register_identity(agent_type: str = "agi") -> dict:
    """Register a new DID on the Disentangle network.
    Returns the DID and signing key for future operations.
    agent_type: 'agi' for AI agents, 'human' for human participants."""
    r = httpx.post(f"{NODE_URL}/identity/register", json={"agent_type": agent_type})
    return r.json()

@mcp.tool()
def lookup_identity(did: str) -> dict:
    """Look up a DID's document and registration details."""
    r = httpx.get(f"{NODE_URL}/identity/{did}")
    return r.json()

# --- Coherence Tools ---

@mcp.tool()
def check_coherence(did: str) -> dict:
    """Get an agent's coherence profile: topological mass, mean curvature,
    relational diversity, and composite score. Use this to assess
    trustworthiness before delegating capabilities or entering agreements."""
    r = httpx.get(f"{NODE_URL}/coherence/{did}")
    return r.json()

@mcp.tool()
def check_curvature(did_a: str, did_b: str) -> dict:
    """Get the curvature between two DIDs. Positive = structurally integrated.
    Negative = weak connection (potential Sybil or new relationship)."""
    r = httpx.get(f"{NODE_URL}/coherence/curvature/{did_a}/{did_b}")
    return r.json()

@mcp.tool()
def get_neighbors(did: str) -> dict:
    """Get the DIDs that a given identity is connected to in the identity graph."""
    r = httpx.get(f"{NODE_URL}/coherence/neighbors/{did}")
    return r.json()

# --- Capability Tools ---

@mcp.tool()
def create_capability(
    issuer_did: str,
    signing_key_hex: str,
    subject_type: str = "access",
    scope: str = "all",
    delegatable: bool = True,
    constraints: list[dict] | None = None,
) -> dict:
    """Create a new capability. The issuer grants permission for an action type.
    subject_type: 'transact', 'access', 'govern', 'custom'
    constraints: optional list like [{"type": "coherence_minimum", "min_mass": 10}]"""
    payload = {
        "issuer_did": issuer_did,
        "signing_key_hex": signing_key_hex,
        "subject": {"type": subject_type, "scope": scope},
        "constraints": constraints or [],
        "delegatable": delegatable,
    }
    r = httpx.post(f"{NODE_URL}/capability/create", json=payload)
    return r.json()

@mcp.tool()
def delegate_capability(
    capability_id_hex: str,
    delegator_did: str,
    delegator_sk_hex: str,
    delegatee_did: str,
) -> dict:
    """Delegate a capability to another agent. The delegatee can then invoke it.
    Check their coherence first with check_coherence()."""
    payload = {
        "capability_id_hex": capability_id_hex,
        "delegator_did": delegator_did,
        "delegator_sk_hex": delegator_sk_hex,
        "delegatee_did": delegatee_did,
    }
    r = httpx.post(f"{NODE_URL}/capability/delegate", json=payload)
    return r.json()

@mcp.tool()
def invoke_capability(capability_id_hex: str, invoker_did: str) -> dict:
    """Attempt to invoke a capability. Returns whether the invocation is allowed.
    Checks delegation chain validity, constraint satisfaction (including
    coherence minimums), and revocation status."""
    payload = {"capability_id_hex": capability_id_hex, "invoker_did": invoker_did}
    r = httpx.post(f"{NODE_URL}/capability/invoke", json=payload)
    return r.json()

@mcp.tool()
def list_capabilities(did: str) -> dict:
    """List all capabilities held by or issued to a DID."""
    r = httpx.get(f"{NODE_URL}/capability/by-did/{did}")
    return r.json()

# --- Social Graph Tools ---

@mcp.tool()
def introduce(
    introducer_did: str,
    introducer_sk_hex: str,
    introduced_did: str,
    edge_name: str = "collaborator",
) -> dict:
    """Introduce yourself to another agent. Builds the identity graph.
    Mutual introductions create positive curvature (trust signal).
    One-directional introductions from a single source create negative
    curvature (introduction mill / Sybil signal)."""
    payload = {
        "introducer_did": introducer_did,
        "introducer_sk_hex": introducer_sk_hex,
        "introduced_did": introduced_did,
        "edge_name": edge_name,
    }
    r = httpx.post(f"{NODE_URL}/introduction", json=payload)
    return r.json()

# --- Agreement Tools ---

@mcp.tool()
def propose_agreement(
    provider_did: str,
    consumer_did: str,
    description: str,
    success_criteria: list[str],
    signing_key_hex: str,
    deadline_depth: int | None = None,
) -> dict:
    """Propose a service agreement between two agents. The consumer must accept.
    Completed agreements build coherence for both parties."""
    payload = {
        "provider_did": provider_did,
        "consumer_did": consumer_did,
        "terms": {
            "description": description,
            "success_criteria": success_criteria,
            "deadline_depth": deadline_depth,
        },
        "signing_key_hex": signing_key_hex,
    }
    r = httpx.post(f"{NODE_URL}/agreement/propose", json=payload)
    return r.json()

@mcp.tool()
def accept_agreement(agreement_id: str, consumer_sk_hex: str) -> dict:
    """Accept a proposed service agreement."""
    payload = {"agreement_id": agreement_id, "consumer_sk_hex": consumer_sk_hex}
    r = httpx.post(f"{NODE_URL}/agreement/accept", json=payload)
    return r.json()

@mcp.tool()
def complete_agreement(
    agreement_id: str, success: bool, outcome_hash: str, signing_key_hex: str
) -> dict:
    """Mark a service agreement as completed. Both parties should call this.
    Successful completion builds coherence; failure degrades it."""
    payload = {
        "agreement_id": agreement_id,
        "success": success,
        "outcome_hash": outcome_hash,
        "signing_key_hex": signing_key_hex,
    }
    r = httpx.post(f"{NODE_URL}/agreement/complete", json=payload)
    return r.json()

# --- Network Tools ---

@mcp.tool()
def network_health() -> dict:
    """Get network health: peer count, DAG size, registered DIDs,
    active capabilities, mean curvature, and more."""
    r = httpx.get(f"{NODE_URL}/network/health")
    return r.json()

@mcp.tool()
def node_status() -> dict:
    """Get basic node status (peers, DAG size, tips)."""
    r = httpx.get(f"{NODE_URL}/status")
    return r.json()
