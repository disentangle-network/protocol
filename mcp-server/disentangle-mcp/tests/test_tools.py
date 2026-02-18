"""Tests for Disentangle MCP server tools."""


def test_all_tools_registered():
    """Verify all 34 tools are registered."""
    from disentangle_mcp.server import mcp

    tools = mcp._tool_manager._tools
    expected = [
        "register_identity", "lookup_identity",
        "check_coherence", "check_curvature", "get_neighbors",
        "curvature_gradient", "excitability", "gradient_map",
        "create_capability", "delegate_capability", "invoke_capability", "list_capabilities",
        "introduce",
        "propose_agreement", "accept_agreement", "complete_agreement",
        "network_health", "node_status",
        "create_proposal", "join_proposal", "list_proposals",
        "create_intent", "join_intent", "archive_intent", "intent_coherence", "list_intents",
        "query_oracle", "get_distribution",
        "neighborhoods",
        "pool_status", "pool_claim", "create_pool", "pool_deposit", "pool_distribute",
    ]

    tool_names = list(tools.keys())
    for name in expected:
        assert name in tool_names, f"Missing tool: {name}"

    assert len(tool_names) == 34, f"Expected 34 tools, got {len(tool_names)}"


def test_tool_descriptions():
    """Verify all tools have docstrings."""
    from disentangle_mcp.server import mcp

    tools = mcp._tool_manager._tools

    for name, tool in tools.items():
        assert tool.description, f"Tool {name} missing description"
        assert len(tool.description) > 10, f"Tool {name} has too short description"


def test_identity_tools_present():
    """Check identity management tools."""
    from disentangle_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools.keys())

    assert "register_identity" in tool_names
    assert "lookup_identity" in tool_names


def test_coherence_tools_present():
    """Check coherence analysis tools."""
    from disentangle_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools.keys())

    assert "check_coherence" in tool_names
    assert "check_curvature" in tool_names
    assert "get_neighbors" in tool_names


def test_gradient_tools_present():
    """Check excitability gradient tools."""
    from disentangle_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools.keys())

    assert "curvature_gradient" in tool_names
    assert "excitability" in tool_names
    assert "gradient_map" in tool_names


def test_capability_tools_present():
    """Check capability management tools."""
    from disentangle_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools.keys())

    assert "create_capability" in tool_names
    assert "delegate_capability" in tool_names
    assert "invoke_capability" in tool_names
    assert "list_capabilities" in tool_names


def test_agreement_tools_present():
    """Check service agreement tools."""
    from disentangle_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools.keys())

    assert "propose_agreement" in tool_names
    assert "accept_agreement" in tool_names
    assert "complete_agreement" in tool_names


def test_network_tools_present():
    """Check network monitoring tools."""
    from disentangle_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools.keys())

    assert "network_health" in tool_names
    assert "node_status" in tool_names


def test_social_graph_tools_present():
    """Check social graph tools."""
    from disentangle_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools.keys())

    assert "introduce" in tool_names


def test_proposal_tools_present():
    """Check proposal coordination tools."""
    from disentangle_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools.keys())

    assert "create_proposal" in tool_names
    assert "join_proposal" in tool_names
    assert "list_proposals" in tool_names


def test_intent_tools_present():
    """Check SharedIntent collaboration tools."""
    from disentangle_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools.keys())

    assert "create_intent" in tool_names
    assert "join_intent" in tool_names
    assert "archive_intent" in tool_names
    assert "intent_coherence" in tool_names
    assert "list_intents" in tool_names


def test_oracle_tools_present():
    """Check CoherenceOracle tools."""
    from disentangle_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools.keys())

    assert "query_oracle" in tool_names
    assert "get_distribution" in tool_names


def test_topology_tools_present():
    """Check topology neighborhood tools."""
    from disentangle_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools.keys())

    assert "neighborhoods" in tool_names


def test_pool_tools_present():
    """Check CommonsPool tools."""
    from disentangle_mcp.server import mcp

    tool_names = set(mcp._tool_manager._tools.keys())

    assert "pool_status" in tool_names
    assert "pool_claim" in tool_names
    assert "create_pool" in tool_names
    assert "pool_deposit" in tool_names
    assert "pool_distribute" in tool_names
