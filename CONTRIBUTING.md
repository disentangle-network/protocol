# Contributing to Disentangle Protocol

Thank you for your interest in contributing to the Disentangle Protocol.

## Getting Started

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run the test suite: `cargo test`
5. Ensure your code compiles without warnings: `cargo build --release`
6. Submit a pull request

## Development Setup

**Requirements:**
- Rust 1.85+ (stable)
- Docker and Docker Compose (for testnet)

**Build and test:**

```bash
cargo build --release
cargo test
```

**Run a local testnet:**

```bash
docker compose up
```

## Code Style

- Follow standard Rust formatting: `cargo fmt`
- Address all clippy warnings: `cargo clippy`
- All consensus-critical computation must use fixed-point arithmetic (i32, SCALE=65536)
- No floating-point in consensus paths

## Pull Request Process

1. PRs must target the `main` branch
2. All tests must pass
3. Include tests for new functionality
4. Update SPEC.md if the change affects protocol behavior
5. One approval required for merge

## Architecture Notes

- The workspace contains 9 crates; see README.md for the crate map
- Post-quantum cryptographic primitives only (ML-DSA-87, ML-KEM-1024, SHA3-256)
- DAG-based transaction graph with Jaccard discrete curvature
- See SPEC.md for the full protocol specification

## Reporting Issues

Open an issue on GitHub with:
- Clear description of the problem or feature request
- Steps to reproduce (for bugs)
- Expected vs actual behavior

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
