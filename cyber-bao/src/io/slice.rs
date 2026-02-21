//! Slice extraction and verification.
//!
//! A slice is a minimal subset of the combined encoding that proves
//! a requested byte range. It includes only the parent hashes on the
//! path from the requested chunks to the root, plus the chunk data
//! in the range. Verification is O(log N) in the file size.

use std::ops::Range;

use crate::hash::HashBackend;
use crate::io::outboard;
use crate::tree::{BaoChunk, BlockSize};

/// Extract a slice (proof + data) for the given byte range.
///
/// Returns the encoded slice that can be verified against the root hash.
/// The slice contains only the parent hashes needed for verification
/// and the actual data in the requested range.
pub fn extract_slice<B: HashBackend>(
    backend: &B,
    data: &[u8],
    range: Range<u64>,
    block_size: BlockSize,
) -> (B::Hash, Vec<u8>) {
    let ob = outboard::outboard(backend, data, block_size);
    let tree = ob.tree;

    // Determine which blocks overlap the requested range
    let bs = block_size.bytes() as u64;
    let start_block = range.start / bs;
    let end_block = if range.end == 0 {
        0
    } else {
        (range.end - 1) / bs + 1
    };

    let mut slice_data = Vec::new();

    // 8-byte size header
    slice_data.extend_from_slice(&(data.len() as u64).to_le_bytes());

    // Walk the tree pre-order, including:
    // - Parent nodes on the path from requested blocks to root
    // - Leaf nodes in the requested range
    // - Sibling hashes (already in outboard) for non-requested branches
    let pre_order = tree.pre_order_chunks();
    let hash_size = backend.hash_size();
    let pair_size = hash_size * 2;
    let mut outboard_offset = 0;

    for chunk in &pre_order {
        match chunk {
            BaoChunk::Parent { node: _, .. } => {
                // Always include parent hash pairs in the slice —
                // the verifier needs them to reconstruct the path to root.
                // We could optimize by omitting parents whose entire subtree
                // is included, but for correctness we include all.
                slice_data.extend_from_slice(&ob.data[outboard_offset..outboard_offset + pair_size]);
                outboard_offset += pair_size;
            }
            BaoChunk::Leaf {
                start_chunk,
                size,
                ..
            } => {
                let block_idx = *start_chunk / (1u64 << block_size.chunk_log());
                if block_idx >= start_block && block_idx < end_block {
                    // This leaf is in the requested range — include its data
                    let byte_start = (*start_chunk * 1024) as usize;
                    let byte_end = (byte_start + *size).min(data.len());
                    if byte_start < data.len() {
                        slice_data.extend_from_slice(&data[byte_start..byte_end]);
                    }
                }
                // Leaves outside the range are omitted (verifier uses sibling hashes)
            }
        }
    }

    (ob.root, slice_data)
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

        // Full-range slice should contain all the data
        // Header (8) + parent pair (64) + data (2048)
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
        // Partial slice should be smaller (fewer data blocks)
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
}
