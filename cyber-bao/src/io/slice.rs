//! Slice extraction and verification.
//!
//! A slice is a minimal subset of the combined encoding that proves
//! a requested byte range. It includes only the parent hashes on the
//! path from the requested chunks to the root, plus the chunk data
//! in the range. Verification is O(log N) in the file size.

use std::ops::Range;

use crate::hash::HashBackend;
use crate::io::outboard;
use crate::tree::{BaoChunk, BaoTree, BlockSize, ChunkNum};
use crate::{ChunkRanges, ChunkRangesRef};

/// Extract a slice (proof + data) for the given byte range.
///
/// Returns the root hash and the encoded slice that can be verified
/// against it.
pub fn extract_slice<B: HashBackend>(
    backend: &B,
    data: &[u8],
    range: Range<u64>,
    block_size: BlockSize,
) -> (B::Hash, Vec<u8>) {
    let chunk_ranges = crate::io::round_up_to_chunks(&crate::ByteRanges::from(range));
    extract_slice_ranges(backend, data, &chunk_ranges, block_size)
}

/// Extract a slice for multiple chunk ranges (multi-range query).
///
/// Returns the root hash and the encoded slice containing only the
/// parent hashes on the verification path and the leaf data for
/// requested ranges.
pub fn extract_slice_ranges<B: HashBackend>(
    backend: &B,
    data: &[u8],
    ranges: &ChunkRangesRef,
    block_size: BlockSize,
) -> (B::Hash, Vec<u8>) {
    let ob = outboard::outboard(backend, data, block_size);
    let tree = ob.tree;

    let mut slice_data = Vec::new();
    slice_data.extend_from_slice(&(data.len() as u64).to_le_bytes());

    if tree.blocks() <= 1 {
        slice_data.extend_from_slice(data);
        return (ob.root, slice_data);
    }

    let hash_size = backend.hash_size();
    let pair_size = hash_size * 2;
    let pre_order = tree.pre_order_chunks();
    let mut outboard_offset = 0usize;

    for chunk in &pre_order {
        match chunk {
            BaoChunk::Parent { node, .. } => {
                let actual_range = tree.node_actual_chunk_range(*node);
                let node_chunks = ChunkRanges::from(actual_range.start..actual_range.end);
                if !node_chunks.is_disjoint(ranges) {
                    slice_data
                        .extend_from_slice(&ob.data[outboard_offset..outboard_offset + pair_size]);
                }
                outboard_offset += pair_size;
            }
            BaoChunk::Leaf {
                start_chunk,
                size,
                ..
            } => {
                let chunks_per_block = 1u64 << block_size.chunk_log();
                let block_idx = *start_chunk / chunks_per_block;
                let leaf_start = block_idx * chunks_per_block;
                let leaf_end = leaf_start + chunks_per_block;
                let leaf_range =
                    ChunkRanges::from(ChunkNum(leaf_start)..ChunkNum(leaf_end));
                if !leaf_range.is_disjoint(ranges) {
                    let byte_start = (*start_chunk * 1024) as usize;
                    let byte_end = (byte_start + *size).min(data.len());
                    if byte_start < data.len() {
                        slice_data.extend_from_slice(&data[byte_start..byte_end]);
                    }
                }
            }
        }
    }

    (ob.root, slice_data)
}

/// Decode and verify a slice against a trusted root hash.
///
/// Returns a vec of `(offset, data)` pairs for each verified leaf.
pub fn decode_slice<B: HashBackend>(
    backend: &B,
    slice: &[u8],
    root_hash: &B::Hash,
    ranges: &ChunkRangesRef,
    block_size: BlockSize,
) -> Result<Vec<(u64, Vec<u8>)>, SliceDecodeError> {
    if slice.len() < 8 {
        return Err(SliceDecodeError::Truncated);
    }

    let declared_size = u64::from_le_bytes(slice[..8].try_into().unwrap());
    let tree = BaoTree::new(declared_size, block_size);
    let hash_size = backend.hash_size();
    let pair_size = hash_size * 2;
    let bs = block_size.bytes();

    let mut cursor = 8usize;
    let mut results = Vec::new();

    if tree.blocks() <= 1 {
        let leaf_data = &slice[cursor..];
        let computed = hash_block_for_verify(backend, leaf_data, 0, true, bs);
        if computed != *root_hash {
            return Err(SliceDecodeError::LeafMismatch { start_chunk: 0 });
        }
        results.push((0u64, leaf_data.to_vec()));
        return Ok(results);
    }

    let pre_order = tree.pre_order_chunks();
    let mut expected_stack: Vec<B::Hash> = vec![root_hash.clone()];

    for chunk in &pre_order {
        match chunk {
            BaoChunk::Parent { node, is_root, .. } => {
                let actual_range = tree.node_actual_chunk_range(*node);
                let node_chunks = ChunkRanges::from(actual_range.start..actual_range.end);
                let included = !node_chunks.is_disjoint(ranges);

                if included {
                    if cursor + pair_size > slice.len() {
                        return Err(SliceDecodeError::Truncated);
                    }
                    let left_bytes = &slice[cursor..cursor + hash_size];
                    let right_bytes = &slice[cursor + hash_size..cursor + pair_size];
                    cursor += pair_size;

                    let left_hash = backend.hash_from_bytes(left_bytes);
                    let right_hash = backend.hash_from_bytes(right_bytes);

                    let computed = backend.parent_hash(&left_hash, &right_hash, *is_root);
                    let expected = expected_stack.pop().ok_or(SliceDecodeError::Truncated)?;
                    if computed != expected {
                        return Err(SliceDecodeError::ParentMismatch { node: node.0 });
                    }

                    expected_stack.push(right_hash);
                    expected_stack.push(left_hash);
                } else {
                    let _ = expected_stack.pop();
                }
            }
            BaoChunk::Leaf {
                start_chunk,
                size,
                is_root,
            } => {
                let chunks_per_block = 1u64 << block_size.chunk_log();
                let block_idx = *start_chunk / chunks_per_block;
                let leaf_start = block_idx * chunks_per_block;
                let leaf_end = leaf_start + chunks_per_block;
                let leaf_range =
                    ChunkRanges::from(ChunkNum(leaf_start)..ChunkNum(leaf_end));
                let included = !leaf_range.is_disjoint(ranges);

                if included {
                    if cursor + *size > slice.len() {
                        return Err(SliceDecodeError::Truncated);
                    }
                    let leaf_data = &slice[cursor..cursor + *size];
                    cursor += *size;

                    let computed =
                        hash_block_for_verify(backend, leaf_data, *start_chunk, *is_root, bs);
                    let expected = expected_stack.pop().ok_or(SliceDecodeError::Truncated)?;
                    if computed != expected {
                        return Err(SliceDecodeError::LeafMismatch {
                            start_chunk: *start_chunk,
                        });
                    }

                    let byte_offset = *start_chunk * 1024;
                    results.push((byte_offset, leaf_data.to_vec()));
                } else {
                    let _ = expected_stack.pop();
                }
            }
        }
    }

    Ok(results)
}

/// Error during slice decoding / verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SliceDecodeError {
    Truncated,
    ParentMismatch { node: u64 },
    LeafMismatch { start_chunk: u64 },
}

impl std::fmt::Display for SliceDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SliceDecodeError::Truncated => write!(f, "truncated slice"),
            SliceDecodeError::ParentMismatch { node } => {
                write!(f, "parent hash mismatch at node {node}")
            }
            SliceDecodeError::LeafMismatch { start_chunk } => {
                write!(f, "leaf hash mismatch at chunk {start_chunk}")
            }
        }
    }
}

impl std::error::Error for SliceDecodeError {}

fn hash_block_for_verify<B: HashBackend>(
    backend: &B,
    data: &[u8],
    start_chunk: u64,
    is_root: bool,
    _block_bytes: usize,
) -> B::Hash {
    if data.is_empty() {
        return backend.chunk_hash(&[], start_chunk, is_root);
    }

    let mut chunk_hashes: Vec<B::Hash> = Vec::new();
    let mut offset = 0usize;
    let mut counter = start_chunk;
    while offset < data.len() {
        let end = (offset + 1024).min(data.len());
        let chunk_data = &data[offset..end];
        let is_single_chunk = data.len() <= 1024 && is_root;
        chunk_hashes.push(backend.chunk_hash(chunk_data, counter, is_single_chunk));
        offset += 1024;
        counter += 1;
    }

    if chunk_hashes.len() == 1 {
        return chunk_hashes.into_iter().next().unwrap();
    }

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

    #[test]
    fn slice_full_range_matches_encode() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 2048];
        let (root, slice) = extract_slice(&backend, &data, 0..2048, BlockSize::ZERO);

        assert_eq!(slice.len(), 8 + 64 + 2048);

        let left = backend.chunk_hash(&data[..1024], 0, false);
        let right = backend.chunk_hash(&data[1024..], 1, false);
        let expected_root = backend.parent_hash(&left, &right, true);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn slice_partial_range_is_smaller() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 4096];
        let (root_full, full_slice) = extract_slice(&backend, &data, 0..4096, BlockSize::ZERO);
        let (root_partial, partial_slice) =
            extract_slice(&backend, &data, 0..1024, BlockSize::ZERO);

        assert_eq!(root_full, root_partial);
        assert!(partial_slice.len() < full_slice.len());
    }

    #[test]
    fn slice_root_hash_independent_of_range() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 4096];
        let (root1, _) = extract_slice(&backend, &data, 0..1024, BlockSize::ZERO);
        let (root2, _) = extract_slice(&backend, &data, 1024..2048, BlockSize::ZERO);
        let (root3, _) = extract_slice(&backend, &data, 0..4096, BlockSize::ZERO);
        assert_eq!(root1, root2);
        assert_eq!(root2, root3);
    }

    #[test]
    fn decode_slice_full_range_roundtrip() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 2048];
        let ranges = ChunkRanges::from(ChunkNum(0)..ChunkNum(2));
        let (root, slice) = extract_slice_ranges(&backend, &data, &ranges, BlockSize::ZERO);

        let results = decode_slice(&backend, &slice, &root, &ranges, BlockSize::ZERO)
            .expect("decode should succeed");

        let mut decoded = vec![0u8; 2048];
        for (offset, chunk) in &results {
            decoded[*offset as usize..*offset as usize + chunk.len()].copy_from_slice(chunk);
        }
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_slice_partial_range() {
        let backend = Poseidon2Backend;
        let data = vec![0xABu8; 4096];
        let ranges = ChunkRanges::from(ChunkNum(0)..ChunkNum(1));
        let (root, slice) = extract_slice_ranges(&backend, &data, &ranges, BlockSize::ZERO);

        let results = decode_slice(&backend, &slice, &root, &ranges, BlockSize::ZERO)
            .expect("decode should succeed");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 0);
        assert_eq!(results[0].1, data[..1024]);
    }

    #[test]
    fn decode_slice_wrong_root_fails() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 2048];
        let ranges = ChunkRanges::from(ChunkNum(0)..ChunkNum(2));
        let (_, slice) = extract_slice_ranges(&backend, &data, &ranges, BlockSize::ZERO);

        let wrong_root = backend.chunk_hash(b"wrong", 0, true);
        let result = decode_slice(&backend, &slice, &wrong_root, &ranges, BlockSize::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn multi_range_slice_extract_and_verify() {
        let backend = Poseidon2Backend;
        let data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        // Request chunks 0 and 3 (non-contiguous)
        let ranges = ChunkRanges::from(ChunkNum(0)..ChunkNum(1))
            | ChunkRanges::from(ChunkNum(3)..ChunkNum(4));
        let (root, slice) = extract_slice_ranges(&backend, &data, &ranges, BlockSize::ZERO);

        let results = decode_slice(&backend, &slice, &root, &ranges, BlockSize::ZERO)
            .expect("decode should succeed");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, 0);
        assert_eq!(results[0].1, data[..1024]);
        assert_eq!(results[1].0, 3072);
        assert_eq!(results[1].1, data[3072..4096]);
    }

    #[test]
    fn single_block_slice_roundtrip() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 500];
        let ranges = ChunkRanges::from(ChunkNum(0)..ChunkNum(1));
        let (root, slice) = extract_slice_ranges(&backend, &data, &ranges, BlockSize::ZERO);

        let results = decode_slice(&backend, &slice, &root, &ranges, BlockSize::ZERO)
            .expect("decode should succeed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, data);
    }

    #[test]
    fn slice_roundtrip_block_size_nonzero() {
        let backend = Poseidon2Backend;
        let bs = BlockSize::from_chunk_log(1); // 2KB blocks
        // 8KB → 4 blocks of 2KB
        let data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
        let ranges = ChunkRanges::all();
        let (root, slice) = extract_slice_ranges(&backend, &data, &ranges, bs);

        let results = decode_slice(&backend, &slice, &root, &ranges, bs)
            .expect("decode should succeed");

        let mut decoded = vec![0u8; 8192];
        for (offset, chunk) in &results {
            decoded[*offset as usize..*offset as usize + chunk.len()].copy_from_slice(chunk);
        }
        assert_eq!(decoded, data);
    }
}
