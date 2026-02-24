//! Pre-order combined encoding — data interleaved with hash tree.
//!
//! Format:
//! ```text
//! [8-byte little-endian data size]
//! [pre-order tree: parent hash-pairs interleaved with leaf data]
//! ```
//!
//! Parent nodes appear before their children, so the decoder can verify
//! each piece as it arrives without buffering the entire file.

use crate::hash::HashBackend;
use crate::io::outboard;
use crate::tree::{BaoChunk, BlockSize};

/// Encode data into the combined (pre-order) format.
///
/// Returns the root hash and the full encoded blob (header + tree + data).
pub fn encode<B: HashBackend>(
    backend: &B,
    data: &[u8],
    block_size: BlockSize,
) -> (B::Hash, Vec<u8>) {
    let ob = outboard::outboard(backend, data, block_size);
    let tree = ob.tree;

    // Estimate output size: 8 (header) + outboard + data
    let mut encoded = Vec::with_capacity(8 + ob.data.len() + data.len());

    // 8-byte little-endian length header
    encoded.extend_from_slice(&(data.len() as u64).to_le_bytes());

    // Walk pre-order, emitting parent hash pairs and leaf data
    let pre_order = tree.pre_order_chunks();
    let hash_size = backend.hash_size();
    let mut outboard_offset = 0;

    for chunk in &pre_order {
        match chunk {
            BaoChunk::Parent { .. } => {
                // Emit the two child hashes (left || right)
                let pair_size = hash_size * 2;
                encoded.extend_from_slice(&ob.data[outboard_offset..outboard_offset + pair_size]);
                outboard_offset += pair_size;
            }
            BaoChunk::Leaf {
                start_chunk, size, ..
            } => {
                let byte_start = (*start_chunk * 1024) as usize;
                let byte_end = (byte_start + *size).min(data.len());
                if byte_start < data.len() {
                    encoded.extend_from_slice(&data[byte_start..byte_end]);
                }
            }
        }
    }

    (ob.root, encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Poseidon2Backend;

    #[test]
    fn encode_single_block() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 1024];
        let (root, encoded) = encode(&backend, &data, BlockSize::ZERO);

        // Header (8 bytes) + data (1024 bytes), no parents
        assert_eq!(encoded.len(), 8 + 1024);
        assert_eq!(u64::from_le_bytes(encoded[..8].try_into().unwrap()), 1024);
        assert_eq!(&encoded[8..], &data[..]);
        assert_eq!(root, backend.chunk_hash(&data, 0, true));
    }

    #[test]
    fn encode_two_blocks() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 2048];
        let (root, encoded) = encode(&backend, &data, BlockSize::ZERO);

        // Header (8) + parent pair (64) + leaf0 (1024) + leaf1 (1024) = 3120
        assert_eq!(encoded.len(), 8 + 64 + 2048);

        // Verify header
        let size = u64::from_le_bytes(encoded[..8].try_into().unwrap());
        assert_eq!(size, 2048);

        // Verify root hash
        let left = backend.chunk_hash(&data[..1024], 0, false);
        let right = backend.chunk_hash(&data[1024..], 1, false);
        let expected_root = backend.parent_hash(&left, &right, true);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn encode_empty() {
        let backend = Poseidon2Backend;
        let (root, encoded) = encode(&backend, &[], BlockSize::ZERO);
        assert_eq!(encoded.len(), 8); // just the header
        assert_eq!(u64::from_le_bytes(encoded[..8].try_into().unwrap()), 0);
        assert_eq!(root, backend.chunk_hash(&[], 0, true));
    }

    #[test]
    fn encode_partial_block() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 500];
        let (root, encoded) = encode(&backend, &data, BlockSize::ZERO);
        // Single block, no parents
        assert_eq!(encoded.len(), 8 + 500);
        assert_eq!(root, backend.chunk_hash(&data, 0, true));
    }

    #[test]
    fn encode_deterministic() {
        let backend = Poseidon2Backend;
        let data = vec![0xABu8; 3000];
        let (r1, e1) = encode(&backend, &data, BlockSize::ZERO);
        let (r2, e2) = encode(&backend, &data, BlockSize::ZERO);
        assert_eq!(r1, r2);
        assert_eq!(e1, e2);
    }

    #[test]
    fn encode_block_size_nonzero() {
        let backend = Poseidon2Backend;
        let bs = BlockSize::from_chunk_log(1); // 2KB blocks
        // 8KB data → 4 blocks of 2KB → 3 parents
        let data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
        let (root, encoded) = encode(&backend, &data, bs);
        // Header (8) + 3 parent pairs (3×64) + 8192 data = 8392
        assert_eq!(encoded.len(), 8 + 3 * 64 + 8192);
        // Root hash should be non-zero
        assert_ne!(root, backend.chunk_hash(&[], 0, true));
    }

    #[test]
    fn encode_block_size_default() {
        let backend = Poseidon2Backend;
        let bs = BlockSize::DEFAULT; // 16KiB blocks
        // 32KB data → 2 blocks of 16KB → 1 parent
        let data: Vec<u8> = (0..32768).map(|i| (i % 256) as u8).collect();
        let (root, encoded) = encode(&backend, &data, bs);
        // Header (8) + 1 parent pair (64) + 32768 data
        assert_eq!(encoded.len(), 8 + 64 + 32768);
        assert_ne!(root, backend.chunk_hash(&[], 0, true));
    }
}
