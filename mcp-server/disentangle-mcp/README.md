# Disentangle MCP Server

Model Context Protocol (MCP) server for the Disentangle Protocol, providing 15 tools for agent coordination and trust management.

## Overview

This MCP server exposes Disentangle Protocol capabilities to AI agents (Claude, custom agents, etc.) through a standardized interface. It wraps the Disentangle node RPC API and provides tools for identity management, coherence checking, capability delegation, service agreements, and network monitoring.

## Installation

```bash
cd /Users/lclose/DISENTANGLE-NETWORK/protocol/mcp-server/disentangle-mcp
uv sync
```

## Usage

### Stdio Mode (for Claude Desktop, etc.)

```bash
uv run python -m disentangle_mcp
```

### With Custom Node URL

```bash
DISENTANGLE_NODE_URL=http://localhost:8000 uv run python -m disentangle_mcp
```

### Claude Desktop Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "disentangle": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/mcp-server/disentangle-mcp", "python", "-m", "disentangle_mcp"],
      "env": {
        "DISENTANGLE_NODE_URL": "http://localhost:8000"
      }
    }
  }
}
```

## Available Tools

### Identity Tools (2)
- `register_identity` - Register a new DID on the network
- `lookup_identity` - Look up a DID's document

### Coherence Tools (3)
- `check_coherence` - Get an agent's coherence profile (mass, curvature, diversity)
- `check_curvature` - Get curvature between two DIDs
- `get_neighbors` - Get connected DIDs in the identity graph

### Capability Tools (4)
- `create_capability` - Create a new capability
- `delegate_capability` - Delegate a capability to another agent
- `invoke_capability` - Attempt to invoke a capability
- `list_capabilities` - List capabilities for a DID

### Social Graph Tools (1)
- `introduce` - Introduce yourself to another agent

### Agreement Tools (3)
- `propose_agreement` - Propose a service agreement
- `accept_agreement` - Accept a proposed agreement
- `complete_agreement` - Mark agreement as completed

### Network Tools (2)
- `network_health` - Get network health metrics
- `node_status` - Get basic node status

## Testing

```bash
uv run pytest -v
```

All tests verify:
- All 15 tools are registered
- All tools have proper docstrings
- Tools are categorized correctly

## Architecture

This server is part of the Disentangle Protocol's agent coordination surface (WS-B). It:
- Wraps the existing Disentangle node RPC API (20+ endpoints)
- Provides type-safe tool definitions via FastMCP
- Works with any MCP-compatible agent framework
- Defaults to `http://localhost:8000` for the node URL

## Development

Project structure:
```
disentangle-mcp/
├── src/
│   └── disentangle_mcp/
│       ├── __init__.py
│       ├── __main__.py      # Entry point
│       └── server.py         # Tool definitions
├── tests/
│   └── test_tools.py
├── pyproject.toml
└── README.md
```

## Related

- Node RPC API: `/Users/lclose/DISENTANGLE-NETWORK/protocol`
- Python SDK: `/Users/lclose/DISENTANGLE-NETWORK/sdk-python`
- Spec: `CC_SPEC_COORDINATION_SURFACE.md`
