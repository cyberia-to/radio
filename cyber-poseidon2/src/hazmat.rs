//! Low-level primitives for BAO-style Merkle tree construction.
//!
//! These functions mirror the blake3 "hazmat" API: `chunk_cv` for hashing
//! leaf data into a chaining value, and `parent_cv` for combining two
//! child chaining values into a parent node.

use p3_goldilocks::Goldilocks;

use crate::encoding::{OUTPUT_ELEMENTS, RATE, bytes_to_cv, hash_to_bytes};
use crate::params::{self, WIDTH};
use crate::sponge::Hash;

/// Flags encoded in the capacity for BAO operations.
const FLAG_ROOT: u64 = 1 << 0;
const FLAG_PARENT: u64 = 1 << 1;
const FLAG_CHUNK: u64 = 1 << 2;

/// Capacity index for BAO flags.
const CAPACITY_FLAGS_IDX: usize = RATE + 1; // state[9]

/// Compute the chaining value for a leaf chunk.
///
/// This hashes the chunk data using the Poseidon2 sponge with a
/// dedicated CHUNK flag in the capacity, and optionally the ROOT flag.
pub fn chunk_cv(chunk: &[u8], is_root: bool) -> Hash {
    let mut hasher = crate::sponge::Hasher::new();
    hasher.update(chunk);
    // We finalize normally and then XOR the chunk/root flags into the
    // result via a keyed re-hash. This is simpler than exposing internal
    // sponge state.
    //
    // Alternative: we build the CV directly with the flags in capacity.
    // This is the approach we take for correctness — a dedicated
    // finalization that includes the BAO flags.
    let base_hash = hasher.finalize();

    // Re-derive with flags via parent_cv-style single-permutation.
    let base_elems = bytes_to_cv(base_hash.as_bytes());
    let mut state = [Goldilocks::new(0); WIDTH];
    state[..OUTPUT_ELEMENTS].copy_from_slice(&base_elems);

    let mut flags = FLAG_CHUNK;
    if is_root {
        flags |= FLAG_ROOT;
    }
    state[CAPACITY_FLAGS_IDX] = Goldilocks::new(flags);

    params::permute(&mut state);

    let output: [Goldilocks; OUTPUT_ELEMENTS] = state[..OUTPUT_ELEMENTS].try_into().unwrap();
    Hash::from_bytes(hash_to_bytes(&output))
}

/// Combine two child chaining values into a parent chaining value.
///
/// This is optimally efficient: `left` (4 elements) + `right` (4 elements) = 8 elements,
/// which exactly fills one rate block. A single permutation produces the result.
///
/// The `is_root` flag domain-separates the tree root from interior nodes.
pub fn parent_cv(left: &Hash, right: &Hash, is_root: bool) -> Hash {
    let left_elems = bytes_to_cv(left.as_bytes());
    let right_elems = bytes_to_cv(right.as_bytes());

    let mut state = [Goldilocks::new(0); WIDTH];

    // Fill rate with left || right (8 elements total).
    state[..OUTPUT_ELEMENTS].copy_from_slice(&left_elems);
    state[OUTPUT_ELEMENTS..RATE].copy_from_slice(&right_elems);

    // Set flags in capacity.
    let mut flags = FLAG_PARENT;
    if is_root {
        flags |= FLAG_ROOT;
    }
    state[CAPACITY_FLAGS_IDX] = Goldilocks::new(flags);

    params::permute(&mut state);

    let output: [Goldilocks; OUTPUT_ELEMENTS] = state[..OUTPUT_ELEMENTS].try_into().unwrap();
    Hash::from_bytes(hash_to_bytes(&output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_cv_non_commutative() {
        let left = Hash::from_bytes([1u8; 32]);
        let right = Hash::from_bytes([2u8; 32]);
        let lr = parent_cv(&left, &right, false);
        let rl = parent_cv(&right, &left, false);
        assert_ne!(lr, rl);
    }

    #[test]
    fn parent_cv_root_differs() {
        let left = Hash::from_bytes([1u8; 32]);
        let right = Hash::from_bytes([2u8; 32]);
        let non_root = parent_cv(&left, &right, false);
        let root = parent_cv(&left, &right, true);
        assert_ne!(non_root, root);
    }

    #[test]
    fn chunk_cv_root_differs() {
        let data = b"chunk data";
        let non_root = chunk_cv(data, false);
        let root = chunk_cv(data, true);
        assert_ne!(non_root, root);
    }

    #[test]
    fn parent_cv_deterministic() {
        let left = Hash::from_bytes([0xAA; 32]);
        let right = Hash::from_bytes([0xBB; 32]);
        let h1 = parent_cv(&left, &right, false);
        let h2 = parent_cv(&left, &right, false);
        assert_eq!(h1, h2);
    }

    #[test]
    fn chunk_cv_different_data() {
        let h1 = chunk_cv(b"data1", false);
        let h2 = chunk_cv(b"data2", false);
        assert_ne!(h1, h2);
    }

    #[test]
    fn chunk_cv_empty() {
        let h = chunk_cv(b"", false);
        assert_ne!(h.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn chunk_cv_vs_plain_hash() {
        // chunk_cv should differ from a plain hash of the same data
        // because of the CHUNK flag domain separation.
        let data = b"test data";
        let plain = crate::sponge::Hasher::new().update(data).finalize();
        let cv = chunk_cv(data, false);
        assert_ne!(plain, cv);
    }
}
