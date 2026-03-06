//! Plonky3 STARK configuration for BabyBear field.
//!
//! Provides a deterministic configuration suitable for proof serialization:
//! the same config can be reconstructed on both prover and verifier sides
//! using a fixed RNG seed for the Poseidon2 permutation.

use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Fixed seed for deterministic Poseidon2 permutation generation.
/// Both prover and verifier must use the same seed to produce matching configs.
const POSEIDON2_RNG_SEED: u64 = 0xD15E_07A9_61E0_2401;

type Val = BabyBear;

/// Poseidon2 permutation over BabyBear with width 16 and S-box degree 7.
pub type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;

/// Hash function: padding-free sponge over Poseidon2.
pub type StarkHash = PaddingFreeSponge<Perm, 16, 8, 8>;

/// Compression function: truncated Poseidon2 permutation.
pub type StarkCompress = TruncatedPermutation<Perm, 2, 8, 16>;

/// Merkle tree commitment scheme over BabyBear field packings.
pub type ValMmcs = FieldMerkleTreeMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    StarkHash,
    StarkCompress,
    8,
>;

/// Degree-4 extension of BabyBear for challenge values.
pub type Challenge = BinomialExtensionField<Val, 4>;

/// Extension MMCS for challenges.
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

/// Duplex challenger using Poseidon2.
pub type StarkChallenger = DuplexChallenger<Val, Perm, 16, 8>;

/// Radix-2 DIT parallel DFT.
pub type Dft = Radix2DitParallel;

/// FRI-based polynomial commitment scheme.
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

/// Complete STARK configuration type.
pub type StarkConfigType = StarkConfig<Pcs, Challenge, StarkChallenger>;

/// Create the deterministic Poseidon2 permutation from the fixed seed.
fn create_perm() -> Perm {
    let mut rng = StdRng::seed_from_u64(POSEIDON2_RNG_SEED);
    Perm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixBabyBear::default(),
        &mut rng,
    )
}

/// Create the STARK configuration and the permutation instance.
///
/// The permutation is returned separately because it is also needed
/// to construct challengers. Both prover and verifier call this
/// function to obtain identical configurations.
pub fn create_stark_config() -> (StarkConfigType, Perm) {
    let perm = create_perm();
    let hash = StarkHash::new(perm.clone());
    let compress = StarkCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft {};
    let fri_config = FriConfig {
        log_blowup: 2,
        num_queries: 28,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    let config = StarkConfigType::new(pcs);
    (config, perm)
}

/// Create a fresh challenger from the given permutation.
///
/// Each prove/verify call requires its own fresh challenger instance.
pub fn create_challenger(perm: &Perm) -> StarkChallenger {
    StarkChallenger::new(perm.clone())
}
