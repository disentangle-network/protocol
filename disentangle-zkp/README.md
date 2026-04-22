# disentangle-zkp

Zero-knowledge reputation proofs for the Entangle Protocol, built on
Plonky3 STARKs.

The headline surface of this crate is `ReputationProver` /
`ReputationVerifier`: a verifier learns only that a claimant's
reputation falls into a public bucket, never the exact score.

## What this crate gives you

- `ReputationProver` / `ReputationVerifier` — bucketed STARK proofs that
  an account's reputation meets a threshold, without revealing the
  account or the exact score.
- `AccountMerkleTree` / `MerkleProof` — SHA3-256 Merkle commitments over
  account state.
- `ReputationBucket` / `BUCKET_WEIGHTS` — discretized reputation classes
  used by the protocol's mass computation.
- `AccountStateLeaf`, `ReputationClaim`, `DiversityAwareReputationClaim`,
  `SupporterTag` — the core types threaded through prover, verifier, and
  consensus.

## How reputation proofs work

```text
AccountState[] --> MerkleTree --> root
                       |
                       v
ReputationCircuit(private: account, path; public: root, bucket)
                       |
                       v
                  ZkProof --> verify() --> bool
```

To bridge the gap between ZK predicates (which prove statements) and
mass computation (which needs comparable values), reputation is
discretized into buckets. Each bucket has a public weight. The circuit
proves bucket membership without revealing the underlying score, so the
verifier can assign the correct weight without learning anything more.

Target proving time: under 500ms on commodity hardware. A criterion
bench (`benches/reputation_proof.rs`) tracks this.

## Default build

```toml
[dependencies]
disentangle-zkp = { path = "../disentangle-zkp" }
```

The default feature set ships only the reputation-proof surface. This
is what enterprise deployments of the protocol actually link against.

## Primitives available for future applications

This crate also contains a collection of privacy primitives that are
**not load-bearing for the current enterprise positioning**. They remain
available, behind a Cargo feature flag, for applications that later
need privacy-preserving payments, stealth addressing, or confidential
transaction circuits.

- `stealth` — stealth addresses derived from a Kyber1024 KEM shared
  secret, so a sender can pay a recipient without revealing the
  recipient's public key on-chain.
- `confidential` — hash-based amount commitments with blinding factors
  (`AmountCommitment`, `Blinding`, `ConfidentialAmount`).
- `balance_circuit` — a STARK AIR proving
  `sum(inputs) == sum(outputs)` without revealing amounts.
- `range_circuit` — a STARK AIR proving `0 <= amount < 2^64` via bit
  decomposition.

These modules and their re-exports are gated behind the
`primitives-future` Cargo feature. The feature is off by default and
activates no other crates. To use any of the primitives, enable it
explicitly:

```toml
[dependencies]
disentangle-zkp = { path = "../disentangle-zkp", features = ["primitives-future"] }
```

Framing: these primitives are kept in-tree because they have already
been built and are tested end-to-end by
`tests/confidential_integration.rs` (also feature-gated). They are not
part of the default public surface because the current positioning of
the protocol does not depend on confidential payments. An application
that needs them can opt in without forking the crate; an enterprise
deployment that does not need them pays no compile-time cost for their
presence.
