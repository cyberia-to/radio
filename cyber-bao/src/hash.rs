//! Hash backend trait and Poseidon2 implementation.
//!
//! The `HashBackend` trait abstracts the hash function used in BAO tree
//! construction, making the tree machinery hash-agnostic. The `Poseidon2Backend`
//! provides the concrete implementation using cyber-poseidon2.

use cyber_poseidon2::Hash;

/// Trait for pluggable hash functions in BAO tree operations.
///
/// Implementations must provide:
/// - Leaf hashing: hash a data chunk at a position in the file
/// - Parent hashing: combine two child hashes into a parent hash
pub trait HashBackend {
    /// The hash output type.
    type Hash: AsRef<[u8]> + Clone + Eq + std::fmt::Debug;

    /// Hash a data chunk (leaf node).
    ///
    /// - `data`: the chunk data
    /// - `counter`: 0-based position index in the file
    /// - `is_root`: true if this is the only chunk (root finalization)
    fn chunk_hash(&self, data: &[u8], counter: u64, is_root: bool) -> Self::Hash;

    /// Combine two child hashes into a parent hash.
    ///
    /// - `left`: left child hash
    /// - `right`: right child hash
    /// - `is_root`: true if this is the tree root
    fn parent_hash(
        &self,
        left: &Self::Hash,
        right: &Self::Hash,
        is_root: bool,
    ) -> Self::Hash;

    /// Size of the hash output in bytes.
    fn hash_size(&self) -> usize;

    /// A zero hash (used for empty/placeholder nodes).
    fn zero_hash(&self) -> Self::Hash;

    /// Construct a hash from its raw byte representation.
    fn hash_from_bytes(&self, bytes: &[u8]) -> Self::Hash;
}

/// Poseidon2 hash backend using cyber-poseidon2.
#[derive(Debug, Clone, Copy, Default)]
pub struct Poseidon2Backend;

impl HashBackend for Poseidon2Backend {
    type Hash = Hash;

    fn chunk_hash(&self, data: &[u8], counter: u64, is_root: bool) -> Hash {
        cyber_poseidon2::hazmat::chunk_cv(data, counter, is_root)
    }

    fn parent_hash(&self, left: &Hash, right: &Hash, is_root: bool) -> Hash {
        cyber_poseidon2::hazmat::parent_cv(left, right, is_root)
    }

    fn hash_size(&self) -> usize {
        32
    }

    fn zero_hash(&self) -> Hash {
        Hash::from_bytes([0u8; 32])
    }

    fn hash_from_bytes(&self, bytes: &[u8]) -> Hash {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Hash::from_bytes(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon2_backend_basic() {
        let backend = Poseidon2Backend;
        let h1 = backend.chunk_hash(b"hello", 0, false);
        let h2 = backend.chunk_hash(b"hello", 0, false);
        assert_eq!(h1, h2); // deterministic

        let h3 = backend.chunk_hash(b"world", 0, false);
        assert_ne!(h1, h3); // different data
    }

    #[test]
    fn poseidon2_backend_counter() {
        let backend = Poseidon2Backend;
        let h0 = backend.chunk_hash(b"data", 0, false);
        let h1 = backend.chunk_hash(b"data", 1, false);
        assert_ne!(h0, h1); // different counter
    }

    #[test]
    fn poseidon2_backend_parent() {
        let backend = Poseidon2Backend;
        let left = backend.chunk_hash(b"left", 0, false);
        let right = backend.chunk_hash(b"right", 1, false);
        let parent = backend.parent_hash(&left, &right, false);
        assert_ne!(parent, left);
        assert_ne!(parent, right);

        // Non-commutative
        let parent_rev = backend.parent_hash(&right, &left, false);
        assert_ne!(parent, parent_rev);
    }

    #[test]
    fn poseidon2_backend_root_differs() {
        let backend = Poseidon2Backend;
        let left = backend.chunk_hash(b"left", 0, false);
        let right = backend.chunk_hash(b"right", 1, false);
        let non_root = backend.parent_hash(&left, &right, false);
        let root = backend.parent_hash(&left, &right, true);
        assert_ne!(non_root, root);
    }

    #[test]
    fn hash_size() {
        let backend = Poseidon2Backend;
        assert_eq!(backend.hash_size(), 32);
    }
}
