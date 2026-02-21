use std::sync::LazyLock;

use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;

/// Width of the Poseidon2 state (number of Goldilocks field elements).
pub const WIDTH: usize = 12;

/// Number of full (external) rounds.
pub const ROUNDS_F: usize = 8;

/// Number of partial (internal) rounds.
pub const ROUNDS_P: usize = 22;

/// Deterministic seed for round constant generation.
///
/// This seed is used with ChaCha20Rng to produce the same round constants
/// on every platform. Changing this value changes the hash function entirely.
/// The value is the Goldilocks prime p = 2^64 - 2^32 + 1 truncated to 64 bits,
/// chosen as a nothing-up-my-sleeve number.
const FIXED_SEED: u64 = 0xFFFF_FFFF_0000_0001;

/// Global singleton Poseidon2 permutation instance.
static POSEIDON2: LazyLock<Poseidon2Goldilocks<WIDTH>> = LazyLock::new(|| {
    let mut rng = ChaCha20Rng::seed_from_u64(FIXED_SEED);
    Poseidon2Goldilocks::new_from_rng(ROUNDS_F, ROUNDS_P, &mut rng)
});

/// Apply the Poseidon2 permutation in-place.
pub(crate) fn permute(state: &mut [Goldilocks; WIDTH]) {
    POSEIDON2.permute_mut(state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_goldilocks::Goldilocks;

    #[test]
    fn permutation_is_deterministic() {
        let mut s1 = [Goldilocks::new(0); WIDTH];
        let mut s2 = [Goldilocks::new(0); WIDTH];
        permute(&mut s1);
        permute(&mut s2);
        assert_eq!(s1, s2);
    }

    #[test]
    fn permutation_changes_state() {
        let mut state = [Goldilocks::new(0); WIDTH];
        let original = state;
        permute(&mut state);
        assert_ne!(state, original);
    }

    #[test]
    fn different_inputs_different_outputs() {
        let mut s1 = [Goldilocks::new(0); WIDTH];
        let mut s2 = [Goldilocks::new(0); WIDTH];
        s2[0] = Goldilocks::new(1);
        permute(&mut s1);
        permute(&mut s2);
        assert_ne!(s1, s2);
    }
}
