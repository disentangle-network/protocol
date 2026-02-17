"""Tests for Disentangle MCP server tools."""


def test_all_tools_registered():
    """Verify all 15 tools are registered."""
    from disentangle_mcp.server import mcp

    tools = mcp._tool_manager._tools
    expected = [
        "register_identity", "lookup_identity",
        "check_coherence", "check_curvature", "get_neighbors",
        "create_capability", "delegate_capability", "invoke_capability", "list_capabilities",
        "introduce",
        "propose_agreement", "accept_agreement", "complete_agreement",
        "network_health", "node_status",
    ]

    tool_names = list(tools.keys())
    for name in expected:
        assert name in tool_names, f"Missing tool: {name}"

    assert len(tool_names) == 15, f"Expected 15 tools, got {len(tool_names)}"


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
