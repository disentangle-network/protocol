//! Benchmark for reputation proof generation and verification.
//!
//! Target: Proving time < 500ms

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use disentangle_zkp::{AccountMerkleTree, AccountStateLeaf, ReputationProver, ReputationVerifier};

fn make_test_accounts(count: usize) -> Vec<AccountStateLeaf> {
    (0..count)
        .map(|i| {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            AccountStateLeaf::new(id, (i as u64 + 1) * 100, i as u64 + 1, i as u64 * 100)
        })
        .collect()
}

fn benchmark_proof_generation(c: &mut Criterion) {
    let accounts = make_test_accounts(1024);
    let prover = ReputationProver::new(&accounts);

    c.bench_function("reputation_proof_generate_1024_accounts", |b| {
        b.iter(|| {
            let claim = prover.prove(
                black_box(0),
                black_box(&accounts[0]),
                black_box(50),
                black_box(1),
            );
            black_box(claim)
        })
    });
}

fn benchmark_proof_verification(c: &mut Criterion) {
    let accounts = make_test_accounts(1024);
    let prover = ReputationProver::new(&accounts);
    let verifier = ReputationVerifier::new();
    let claim = prover.prove(0, &accounts[0], 50, 1).unwrap();
    let root = prover.merkle_root();

    c.bench_function("reputation_proof_verify_1024_accounts", |b| {
        b.iter(|| {
            let result = verifier.verify(black_box(&claim), black_box(&root), black_box(1));
            black_box(result)
        })
    });
}

fn benchmark_merkle_tree_construction(c: &mut Criterion) {
    let accounts = make_test_accounts(1024);

    c.bench_function("merkle_tree_construct_1024_accounts", |b| {
        b.iter(|| {
            let tree = AccountMerkleTree::new(black_box(&accounts));
            black_box(tree.root())
        })
    });
}

criterion_group!(
    benches,
    benchmark_proof_generation,
    benchmark_proof_verification,
    benchmark_merkle_tree_construction
);
criterion_main!(benches);
