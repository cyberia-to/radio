//! Streaming decode with verification.
//!
//! The decoder reads a combined-encoded stream (header + pre-order tree)
//! and verifies every hash against the trusted root. Invalid data is
//! rejected immediately.

use crate::hash::HashBackend;
use crate::tree::{BaoChunk, BaoTree, BlockSize};

/// Error during decoding / verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The encoded data is truncated or malformed.
    Truncated,
    /// A parent hash pair didn't match the expected parent CV.
    ParentMismatch { node: u64 },
    /// A leaf chunk's hash didn't match the expected CV.
    LeafMismatch { start_chunk: u64 },
    /// The declared size in the header doesn't match actual data.
    SizeMismatch { declared: u64, actual: u64 },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "truncated or malformed encoded data"),
            DecodeError::ParentMismatch { node } => {
                write!(f, "parent hash mismatch at node {node}")
            }
            DecodeError::LeafMismatch { start_chunk } => {
                write!(f, "leaf hash mismatch at chunk {start_chunk}")
            }
            DecodeError::SizeMismatch { declared, actual } => {
                write!(f, "size mismatch: declared {declared}, actual {actual}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decode and verify a combined-encoded blob.
///
/// Takes the encoded bytes and the trusted root hash. Returns the
/// original data on success or a `DecodeError` on verification failure.
pub fn decode<B: HashBackend>(
    backend: &B,
    encoded: &[u8],
    root_hash: &B::Hash,
    block_size: BlockSize,
) -> Result<Vec<u8>, DecodeError> {
    if encoded.len() < 8 {
        return Err(DecodeError::Truncated);
    }

    let declared_size = u64::from_le_bytes(encoded[..8].try_into().unwrap());
    let tree = BaoTree::new(declared_size, block_size);
    let pre_order = tree.pre_order_chunks();
    let hash_size = backend.hash_size();
    let bs = block_size.bytes();

    let mut cursor = 8usize;
    let mut data = Vec::with_capacity(declared_size as usize);

    // Stack of expected hashes. Push root first; as we encounter parent nodes,
    // we verify them and push their children (right first, so left is popped first).
    let mut expected_stack: Vec<B::Hash> = vec![root_hash.clone()];

    for chunk in &pre_order {
        match chunk {
            BaoChunk::Parent { node, is_root, .. } => {
                let pair_size = hash_size * 2;
                if cursor + pair_size > encoded.len() {
                    return Err(DecodeError::Truncated);
                }

                let left_bytes = &encoded[cursor..cursor + hash_size];
                let right_bytes = &encoded[cursor + hash_size..cursor + pair_size];
                cursor += pair_size;

                let left_hash = backend.hash_from_bytes(left_bytes);
                let right_hash = backend.hash_from_bytes(right_bytes);

                // Verify: parent_hash(left, right) must equal expected
                let computed_parent = backend.parent_hash(&left_hash, &right_hash, *is_root);
                let expected = expected_stack.pop().ok_or(DecodeError::Truncated)?;
                if computed_parent != expected {
                    return Err(DecodeError::ParentMismatch { node: node.0 });
                }

                // Push children onto expected stack: right first (popped after left)
                let blocks = tree.blocks();
                if let Some(right_child) = node.right_child() {
                    let right_block_start = right_child.chunk_range().start.0 / 2;
                    if right_block_start < blocks {
                        expected_stack.push(right_hash);
                    }
                }
                expected_stack.push(left_hash);
            }
            BaoChunk::Leaf {
                start_chunk,
                size,
                is_root,
            } => {
                if cursor + *size > encoded.len() {
                    return Err(DecodeError::Truncated);
                }

                let leaf_data = &encoded[cursor..cursor + *size];
                cursor += *size;

                let computed =
                    hash_block_for_verify(backend, leaf_data, *start_chunk, *is_root, bs);
                let expected = expected_stack.pop().ok_or(DecodeError::Truncated)?;
                if computed != expected {
                    return Err(DecodeError::LeafMismatch {
                        start_chunk: *start_chunk,
                    });
                }

                data.extend_from_slice(leaf_data);
            }
        }
    }

    if data.len() as u64 != declared_size {
        return Err(DecodeError::SizeMismatch {
            declared: declared_size,
            actual: data.len() as u64,
        });
    }

    Ok(data)
}

/// Hash a block of data for verification (same logic as outboard's hash_block).
fn hash_block_for_verify<B: HashBackend>(
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
    use crate::io::encode;

    #[test]
    fn decode_single_block() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 1024];
        let (root, encoded) = encode::encode(&backend, &data, BlockSize::ZERO);
        let decoded = decode(&backend, &encoded, &root, BlockSize::ZERO).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_two_blocks() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 2048];
        let (root, encoded) = encode::encode(&backend, &data, BlockSize::ZERO);
        let decoded = decode(&backend, &encoded, &root, BlockSize::ZERO).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_four_blocks() {
        let backend = Poseidon2Backend;
        let data = vec![0xABu8; 4096];
        let (root, encoded) = encode::encode(&backend, &data, BlockSize::ZERO);
        let decoded = decode(&backend, &encoded, &root, BlockSize::ZERO).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_partial_block() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 500];
        let (root, encoded) = encode::encode(&backend, &data, BlockSize::ZERO);
        let decoded = decode(&backend, &encoded, &root, BlockSize::ZERO).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_empty() {
        let backend = Poseidon2Backend;
        let (root, encoded) = encode::encode(&backend, &[], BlockSize::ZERO);
        let decoded = decode(&backend, &encoded, &root, BlockSize::ZERO).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_wrong_root_fails() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 2048];
        let (_, encoded) = encode::encode(&backend, &data, BlockSize::ZERO);
        let wrong_root = backend.chunk_hash(b"wrong", 0, true);
        let result = decode(&backend, &encoded, &wrong_root, BlockSize::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn decode_truncated_fails() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 2048];
        let (root, encoded) = encode::encode(&backend, &data, BlockSize::ZERO);
        let truncated = &encoded[..encoded.len() - 100];
        let result = decode(&backend, truncated, &root, BlockSize::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn decode_tampered_data_fails() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 2048];
        let (root, mut encoded) = encode::encode(&backend, &data, BlockSize::ZERO);
        // Tamper with leaf data (after 8-byte header + 64-byte parent pair)
        if encoded.len() > 80 {
            encoded[80] ^= 0xFF;
        }
        let result = decode(&backend, &encoded, &root, BlockSize::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_various_sizes() {
        let backend = Poseidon2Backend;
        for size in [0, 1, 512, 1024, 1025, 2048, 3000, 4096, 5000, 8192] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let (root, encoded) = encode::encode(&backend, &data, BlockSize::ZERO);
            let decoded = decode(&backend, &encoded, &root, BlockSize::ZERO).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for size {size}");
        }
    }

    #[test]
    fn roundtrip_block_size_nonzero() {
        let backend = Poseidon2Backend;
        let bs = BlockSize::from_chunk_log(1); // 2KB blocks
        for size in [0, 1024, 2048, 3000, 4096, 8192, 10000] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let (root, encoded) = encode::encode(&backend, &data, bs);
            let decoded = decode(&backend, &encoded, &root, bs).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for size {size} with BlockSize(1)");
        }
    }

    #[test]
    fn roundtrip_block_size_default() {
        let backend = Poseidon2Backend;
        let bs = BlockSize::DEFAULT; // 16KiB blocks
        for size in [0, 1024, 16384, 32768, 50000] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let (root, encoded) = encode::encode(&backend, &data, bs);
            let decoded = decode(&backend, &encoded, &root, bs).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for size {size} with BlockSize::DEFAULT");
        }
    }
}
