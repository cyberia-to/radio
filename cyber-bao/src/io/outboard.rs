//! Outboard computation — build the hash tree from data.
//!
//! The outboard is a flat array of parent hashes stored in pre-order.
//! This is the core "hash the data" step that produces the root hash
//! and all intermediate chaining values.

use std::collections::HashMap;

use crate::hash::HashBackend;
use crate::tree::{BaoChunk, BaoTree, BlockSize, CHUNK_SIZE};

/// Result of computing the outboard for a blob.
#[derive(Debug, Clone)]
pub struct Outboard<H: Clone> {
    /// The root hash of the entire tree.
    pub root: H,
    /// Parent hashes in pre-order (each parent = left_hash || right_hash).
    /// Empty if the data fits in a single block.
    pub data: Vec<u8>,
    /// Tree geometry.
    pub tree: BaoTree,
}

/// Compute the outboard (hash tree) for the given data.
///
/// Returns the root hash and serialized parent hashes in pre-order.
pub fn outboard<B: HashBackend>(
    backend: &B,
    data: &[u8],
    block_size: BlockSize,
) -> Outboard<B::Hash> {
    let tree = BaoTree::new(data.len() as u64, block_size);
    let blocks = tree.blocks();

    if blocks <= 1 {
        let root = super::hash_group(backend, data, 0, true);
        return Outboard {
            root,
            data: Vec::new(),
            tree,
        };
    }

    let post_order = tree.post_order_chunks();

    // Bottom-up computation: hash leaves, then combine parents.
    // Track child hashes for each parent to serialize in pre-order later.
    let mut hash_stack: Vec<B::Hash> = Vec::new();
    let mut node_to_children: HashMap<u64, (B::Hash, B::Hash)> = HashMap::new();

    for chunk in &post_order {
        match chunk {
            BaoChunk::Leaf {
                start_chunk,
                size,
                is_root,
            } => {
                let byte_start = *start_chunk * CHUNK_SIZE as u64;
                let byte_end = (byte_start + *size as u64).min(data.len() as u64);
                let chunk_data = if byte_start < data.len() as u64 {
                    &data[byte_start as usize..byte_end as usize]
                } else {
                    &[]
                };
                let block_cv = super::hash_group(backend, chunk_data, *start_chunk, *is_root);
                hash_stack.push(block_cv);
            }
            BaoChunk::Parent { node, is_root, .. } => {
                let right = hash_stack.pop().expect("missing right child hash");
                let left = hash_stack.pop().expect("missing left child hash");
                node_to_children.insert(node.0, (left.clone(), right.clone()));
                let parent = backend.parent_hash(&left, &right, *is_root);
                hash_stack.push(parent);
            }
        }
    }

    let root = hash_stack
        .pop()
        .expect("hash stack should have root after traversal");
    debug_assert!(hash_stack.is_empty());

    // Serialize child-hash pairs in pre-order
    let pre_order = tree.pre_order_chunks();
    let mut outboard_data = Vec::with_capacity(node_to_children.len() * backend.hash_size() * 2);

    for chunk in &pre_order {
        if let BaoChunk::Parent { node, .. } = chunk
            && let Some((left, right)) = node_to_children.get(&node.0)
        {
            outboard_data.extend_from_slice(left.as_ref());
            outboard_data.extend_from_slice(right.as_ref());
        }
    }

    Outboard {
        root,
        data: outboard_data,
        tree,
    }
}

#[cfg(test)]
mod tests {
    use hemera::OUTPUT_BYTES;

    use super::*;
    use crate::hash::Poseidon2Backend;

    const PAIR_SIZE: usize = OUTPUT_BYTES * 2;

    #[test]
    fn outboard_single_block() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; CHUNK_SIZE];
        let ob = outboard(&backend, &data, BlockSize::ZERO);
        assert!(ob.data.is_empty());
        assert_eq!(ob.root, backend.chunk_hash(&data, 0, true));
    }

    #[test]
    fn outboard_two_blocks() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; CHUNK_SIZE * 2];
        let ob = outboard(&backend, &data, BlockSize::ZERO);
        assert_eq!(ob.data.len(), PAIR_SIZE);

        let left = backend.chunk_hash(&data[..CHUNK_SIZE], 0, false);
        let right = backend.chunk_hash(&data[CHUNK_SIZE..], 1, false);
        let expected_root = backend.parent_hash(&left, &right, true);
        assert_eq!(ob.root, expected_root);
        assert_eq!(&ob.data[..OUTPUT_BYTES], left.as_ref());
        assert_eq!(&ob.data[OUTPUT_BYTES..PAIR_SIZE], right.as_ref());
    }

    #[test]
    fn outboard_four_blocks() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; CHUNK_SIZE * 4];
        let ob = outboard(&backend, &data, BlockSize::ZERO);
        // 4 blocks -> 3 parents -> 3 * PAIR_SIZE bytes
        assert_eq!(ob.data.len(), 3 * PAIR_SIZE);
    }

    #[test]
    fn outboard_empty() {
        let backend = Poseidon2Backend;
        let ob = outboard(&backend, &[], BlockSize::ZERO);
        assert!(ob.data.is_empty());
        assert_eq!(ob.root, backend.chunk_hash(&[], 0, true));
    }

    #[test]
    fn outboard_deterministic() {
        let backend = Poseidon2Backend;
        let data = vec![0xABu8; 3000];
        let ob1 = outboard(&backend, &data, BlockSize::ZERO);
        let ob2 = outboard(&backend, &data, BlockSize::ZERO);
        assert_eq!(ob1.root, ob2.root);
        assert_eq!(ob1.data, ob2.data);
    }

    #[test]
    fn outboard_different_data_different_root() {
        let backend = Poseidon2Backend;
        let ob1 = outboard(&backend, &[1u8; 2048], BlockSize::ZERO);
        let ob2 = outboard(&backend, &[2u8; 2048], BlockSize::ZERO);
        assert_ne!(ob1.root, ob2.root);
    }

    #[test]
    fn outboard_partial_last_block() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; CHUNK_SIZE + 500];
        let ob = outboard(&backend, &data, BlockSize::ZERO);
        assert_eq!(ob.data.len(), PAIR_SIZE);

        let left = backend.chunk_hash(&data[..CHUNK_SIZE], 0, false);
        let right = backend.chunk_hash(&data[CHUNK_SIZE..], 1, false);
        let expected_root = backend.parent_hash(&left, &right, true);
        assert_eq!(ob.root, expected_root);
    }
}
