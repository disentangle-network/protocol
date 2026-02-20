# Disentangle Protocol

[![CI](https://github.com/disentangle-network/protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/disentangle-network/protocol/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/disentangle-network/protocol/branch/main/graph/badge.svg)](https://codecov.io/gh/disentangle-network/protocol)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Topological consensus for post-quantum networks.**

Disentangle implements Proof of Entanglement (PoE), a consensus mechanism that derives security from information theory and topology rather than game theory or thermodynamics.

## Overview

Traditional consensus protocols answer: "who has authority to append blocks?" Proof of Work selects by computational expenditure; Proof of Stake selects by collateral. Both reduce consensus to a leader-election problem and inherit the game-theoretic assumptions that follow.

Proof of Entanglement asks a different question: "which state is structurally coherent with the network's history?" Transactions form a directed acyclic graph (DAG), and consensus emerges from measuring the topological curvature of that graph using discrete Ollivier-Ricci curvature (Jaccard variant). Blocks whose local geometry is consistent with the global structure are accepted; blocks that distort it are rejected. There is no mining, no staking, and no committee selection.

The protocol uses post-quantum cryptographic primitives throughout: ML-DSA-87 (Dilithium5) for signatures, ML-KEM-1024 (Kyber1024) for key encapsulation, and SHA3-256 for hashing. All consensus-critical arithmetic uses fixed-point representation (i32, SCALE=65536) to ensure deterministic cross-platform computation.

## Architecture

Disentangle is implemented as a Rust workspace of nine crates:

| Crate | Purpose |
|---|---|
| `disentangle-dag` | Core DAG structure and transaction graph |
| `disentangle-consensus` | Curvature-based consensus logic, confirmation rules |
| `disentangle-simhash` | Locality-sensitive hashing for Proof of Entanglement |
| `disentangle-crypto` | Post-quantum primitives (ML-DSA, ML-KEM, SHA3) |
| `disentangle-p2p` | libp2p networking layer, peer discovery |
| `disentangle-node` | Node binary and RPC server |
| `disentangle-cli` | Command-line interface |
| `disentangle-identity` | Decentralized identifiers, capabilities, petname system |
| `disentangle-zkp` | Zero-knowledge proofs (Plonky3 STARKs) |

## Quick Start

### Build

```bash
cargo build --release
```

### Test

```bash
cargo test
```

### Run a Local Testnet

```bash
docker compose up
```

This starts a five-node local testnet with pre-configured peer discovery.

### Run a Single Node

```bash
disentangle-node <p2p-port> <rpc-port> [bootstrap-peer]
```

## Protocol Highlights

**Topological consensus.** Finality is determined by the curvature of the DAG, not by vote counting or chain weight. Discrete Ollivier-Ricci curvature (Jaccard variant) measures structural coherence at each vertex, providing a mathematical criterion for accepting or rejecting state transitions.

**Curvature freezing.** Once a transaction reaches `CONFIRMATION_DEPTH=6`, its curvature score is frozen. This provides deterministic finality without probabilistic guarantees.

**Bootstrap ramping.** During the network bootstrap phase (blocks 1000 through 6000), the curvature weighting parameter alpha ramps linearly from zero to its steady-state value. This prevents cliff attacks during early-network conditions when the graph is sparse.

**Post-quantum from day one.** All cryptographic operations use NIST-standardized post-quantum algorithms at their highest security levels (NIST Level 5). No classical fallbacks are used in production paths.

**SimHash binding.** Locality-sensitive hashing binds each transaction to the structural context in which it was created, making retroactive graph manipulation detectable.

**Privacy-preserving identity.** Ephemeral keys and nullifiers provide transaction unlinkability while maintaining Sybil resistance through zero-knowledge reputation proofs.

## Specification

The full protocol specification is available in [SPEC.md](SPEC.md) (v0.3).

## Status

Disentangle is in **alpha**. The protocol specification is stabilizing, core crates compile and pass tests, and a Docker-based local testnet is operational. The protocol is not yet suitable for production use.

**Current work includes:**
- Testnet hardening and observability
- ZK reputation proof integration
- SDK development (Python, TypeScript)
- Formal verification of curvature properties

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

---

[GitHub](https://github.com/disentangle-network) | [Specification](SPEC.md)
