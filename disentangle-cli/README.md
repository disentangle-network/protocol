# Disentangle CLI

Command-line interface for the Disentangle Protocol.

## Installation

```bash
cargo install --path .
```

## Usage

```bash
# Connect to default node (http://localhost:3000)
disentangle node status

# Connect to custom node
disentangle --node http://192.168.1.100:3000 node status

# Submit a transaction
disentangle tx submit --sender alice --parents <parent-tx-id> --data "hello"

# Get DAG graph structure
disentangle node graph

# Use JSON output
disentangle --format json node status
```

## Available Commands

### Node Operations
- `node status` - Get node status (peer count, DAG size, tips)
- `node graph` - Get full DAG graph structure
- `node trigger-conflict` - Debug: trigger a conflict scenario

### Transaction Operations
- `tx submit` - Submit a new transaction (requires running node)
- `tx get` - Get transaction by ID (not yet implemented on node)
- `tx list` - List recent transactions (not yet implemented on node)

### Identity Operations (Planned)
- `identity create` - Register a new DID
- `identity show` - Show identity info
- `identity list` - List local identities

### Curvature Operations (Planned)
- `curvature compute` - Compute curvature between two transactions
- `curvature stats` - Show curvature distribution statistics

### Capability Operations (Planned)
- `cap grant` - Grant a capability
- `cap revoke` - Revoke a capability
- `cap list` - List capabilities

### Petname Operations (Planned)
- `petname set` - Set a petname for a DID
- `petname get` - Get DID by petname
- `petname list` - List all petnames

### Governance Operations (Planned)
- `gov propose` - Submit a governance proposal
- `gov vote` - Vote on a proposal
- `gov list` - List governance proposals

## Implementation Status

**Working Now:**
- Node status endpoint
- DAG graph visualization
- Transaction submission
- Conflict triggering (debug)

**Planned:**
- Identity management (local keystore)
- Petname system (local storage)
- Curvature queries
- Capability system
- Governance
- Transaction history lookup

## Architecture

The CLI uses a simple HTTP client to communicate with the node's RPC endpoints. It does not import any Rust types from other crates - all communication is via JSON over HTTP.

- `client.rs` - HTTP request wrapper
- `output.rs` - Human vs JSON formatting
- `commands/` - Subcommand implementations

## Output Formats

**Human** (default):
```
peer_id: 12D3KooWXYZ...
peer_count: 3
dag_size: 142
```

**JSON** (`--format json`):
```json
{
  "peer_id": "12D3KooWXYZ...",
  "peer_count": 3,
  "dag_size": 142
}
```
