//! Outboard computation — build the hash tree from data.
//!
//! The outboard is a flat array of parent hashes stored in pre-order.
//! This is the core "hash the data" step that produces the root hash
//! and all intermediate chaining values.

use std::collections::HashMap;

use hemera::OUTPUT_BYTES;

use crate::hash::HashBackend;
use crate::tree::{BaoChunk, BaoTree, BlockSize, CHUNK_SIZE};

/// Size of a hash pair (two hashes concatenated).
const PAIR_SIZE: usize = OUTPUT_BYTES * 2;

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
    let bs = block_size.bytes();

    if blocks <= 1 {
        let root = hash_block(backend, data, 0, true, bs);
        return Outboard {
            root,
            data: Vec::new(),
            tree,
        };
    }

    let post_order = tree.post_order_chunks();
    let (root, node_to_children) = fold_post_order(backend, data, &post_order, bs);

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

/// Bottom-up fold of a post-order chunk sequence into a single root hash.
///
/// Hashes each leaf and combines parents as they are reached, tracking each
/// parent's child-hash pair for pre-order serialization by the caller. A
/// well-formed post-order traversal of `tree` always folds to exactly one
/// value on `hash_stack`; anything else means the traversal handed to this
/// function does not describe a single tree over `data`.
fn fold_post_order<B: HashBackend>(
    backend: &B,
    data: &[u8],
    post_order: &[BaoChunk],
    bs: usize,
) -> (B::Hash, HashMap<u64, (B::Hash, B::Hash)>) {
    let mut hash_stack: Vec<B::Hash> = Vec::new();
    let mut node_to_children: HashMap<u64, (B::Hash, B::Hash)> = HashMap::new();

    for chunk in post_order {
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
                let block_cv = hash_block(backend, chunk_data, *start_chunk, *is_root, bs);
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
    assert!(
        hash_stack.is_empty(),
        "post-order traversal did not fold to a single root: {} chunk(s) left over",
        hash_stack.len()
    );
    (root, node_to_children)
}

/// Hash a single block of data (may contain multiple chunks).
///
/// For BlockSize::ZERO (1 chunk per block), this is just `chunk_hash`.
/// For larger blocks, we hash individual chunks and combine them into
/// a mini-tree within the block.
fn hash_block<B: HashBackend>(
    backend: &B,
    data: &[u8],
    start_chunk: u64,
    is_root: bool,
    block_bytes: usize,
) -> B::Hash {
    if data.is_empty() {
        return backend.chunk_hash(&[], start_chunk, is_root);
    }

    let mut chunk_hashes: Vec<B::Hash> = Vec::new();
    let mut offset = 0usize;
    let mut counter = start_chunk;
    while offset < data.len() {
        let end = (offset + CHUNK_SIZE).min(data.len());
        let chunk_data = &data[offset..end];
        let is_single_chunk = data.len() <= CHUNK_SIZE && is_root;
        chunk_hashes.push(backend.chunk_hash(chunk_data, counter, is_single_chunk));
        offset += CHUNK_SIZE;
        counter += 1;
    }

    if chunk_hashes.len() == 1 {
        return chunk_hashes.into_iter().next().unwrap();
    }

    // Combine into a mini-tree (bottom-up)
    let _ = block_bytes;
    let mut level = chunk_hashes;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let parent = backend.parent_hash(&level[i], &level[i + 1], false);
                next.push(parent);
            } else {
                next.push(level[i].clone());
            }
            i += 2;
        }
        level = next;
    }

    level.into_iter().next().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Poseidon2Backend;
    use crate::tree::TreeNode;

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

    #[test]
    fn fold_post_order_two_blocks_folds_to_one_root() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; CHUNK_SIZE * 2];
        let post_order = vec![
            BaoChunk::Leaf { start_chunk: 0, size: CHUNK_SIZE, is_root: false },
            BaoChunk::Leaf { start_chunk: 1, size: CHUNK_SIZE, is_root: false },
            BaoChunk::Parent { node: TreeNode(0), is_root: true, left: true, right: true },
        ];
        let (root, children) = fold_post_order(&backend, &data, &post_order, 0);
        assert_eq!(children.len(), 1);
        let left = backend.chunk_hash(&data[..CHUNK_SIZE], 0, false);
        let right = backend.chunk_hash(&data[CHUNK_SIZE..], 1, false);
        assert_eq!(root, backend.parent_hash(&left, &right, true));
    }

    #[test]
    #[should_panic(expected = "post-order traversal did not fold to a single root")]
    fn fold_post_order_rejects_a_dangling_leaf() {
        // A post-order sequence with a leaf never combined into a parent —
        // the same shape a mismatched or corrupted BaoTree traversal would
        // produce. This must never silently return a root computed over
        // only part of the tree.
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; CHUNK_SIZE * 2];
        let post_order = vec![
            BaoChunk::Leaf { start_chunk: 0, size: CHUNK_SIZE, is_root: false },
            BaoChunk::Leaf { start_chunk: 1, size: CHUNK_SIZE, is_root: false },
        ];
        let _ = fold_post_order(&backend, &data, &post_order, 0);
    }
}
