//! Encoding, decoding, outboard creation, and slice extraction.
//!
//! All operations are parameterized by a `HashBackend`, making the
//! serialization format hash-agnostic.

pub mod content;
pub mod decode;
pub mod encode;
pub mod error;
pub mod mixed;
pub mod outboard;
pub mod pre_order;
pub mod slice;
pub mod sync;
pub mod traits;

#[cfg(feature = "tokio_fsm")]
pub mod fsm;

// Re-export commonly used types at the io level.
pub use content::{BaoContentItem, Leaf, Parent};
pub use error::{DecodeError, EncodeError};
pub use traits::{Outboard, OutboardMut, ReadAt, ReadBytesAt, Size, WriteAt};

use range_collections::range_set::RangeSetRange;

use crate::hash::{HashBackend, Poseidon2Backend};
use crate::tree::{BlockSize, ChunkNum, CHUNK_SIZE};
use crate::{ByteRanges, ChunkRanges};

/// Compute the root hash for a single block (possibly multi-chunk).
///
/// Hashes each chunk individually, then reduces via parent_hash
/// to produce the block's root. Used by both sync and async encode/decode paths.
/// When `is_root` is true, only the final node receives ROOT finalization;
/// otherwise the result is an internal chaining value. Chunk counters are absolute.
pub fn hash_block(
    backend: &Poseidon2Backend,
    data: &[u8],
    start_chunk: u64,
    is_root: bool,
    block_bytes: usize,
) -> hemera::Hash {
    let _ = block_bytes;
    hash_group(backend, data, start_chunk, is_root)
}

/// Reduce a group with ROOT applied only when it is the complete file.
fn hash_group<B: HashBackend>(
    backend: &B,
    data: &[u8],
    start_chunk: u64,
    is_root: bool,
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

    let mut level = chunk_hashes;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let parent =
                    backend.parent_hash(&level[i], &level[i + 1], is_root && level.len() == 2);
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

/// Round byte ranges up to chunk ranges.
pub fn round_up_to_chunks(ranges: &ByteRanges) -> ChunkRanges {
    let mut result = ChunkRanges::empty();
    for range in ranges.iter() {
        let (start, end) = match range.cloned() {
            RangeSetRange::Range(r) => {
                let start = ChunkNum(r.start / CHUNK_SIZE as u64);
                let end = ChunkNum(r.end.div_ceil(CHUNK_SIZE as u64));
                (start, Some(end))
            }
            RangeSetRange::RangeFrom(r) => {
                let start = ChunkNum(r.start / CHUNK_SIZE as u64);
                (start, None)
            }
        };
        match end {
            Some(end) if start < end => {
                result |= ChunkRanges::from(start..end);
            }
            None => {
                result |= ChunkRanges::from(start..);
            }
            _ => {}
        }
    }
    result
}

/// Round chunk ranges up to full chunk groups (block-aligned).
pub fn round_up_to_chunks_groups(ranges: &ChunkRanges, block_size: BlockSize) -> ChunkRanges {
    if block_size.chunk_log() == 0 {
        return ranges.clone();
    }
    let group_size = 1u64 << block_size.chunk_log();
    let mut result = ChunkRanges::empty();
    for range in ranges.iter() {
        let (start, end) = match range.cloned() {
            RangeSetRange::Range(r) => {
                let start = ChunkNum((r.start.0 / group_size) * group_size);
                let end = ChunkNum(r.end.0.div_ceil(group_size) * group_size);
                (start, Some(end))
            }
            RangeSetRange::RangeFrom(r) => {
                let start = ChunkNum((r.start.0 / group_size) * group_size);
                (start, None)
            }
        };
        match end {
            Some(end) if start < end => {
                result |= ChunkRanges::from(start..end);
            }
            None => {
                result |= ChunkRanges::from(start..);
            }
            _ => {}
        }
    }
    result
}

#[cfg(test)]
mod root_policy_tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Default)]
    struct Recording {
        leaves: RefCell<Vec<(u64, usize, bool)>>,
        parents: RefCell<Vec<bool>>,
    }

    fn leaf(counter: u64, root: bool) -> Vec<u8> {
        let mut result = vec![u8::from(root)];
        result.extend_from_slice(&counter.to_le_bytes());
        result
    }

    fn pair(left: &[u8], right: &[u8], root: bool) -> Vec<u8> {
        let mut result = vec![u8::from(root)];
        result.extend_from_slice(&(left.len() as u64).to_le_bytes());
        result.extend_from_slice(left);
        result.extend_from_slice(right);
        result
    }

    impl HashBackend for Recording {
        // Deliberately non-Copy to exercise the generic backend contract.
        type Hash = Vec<u8>;

        fn chunk_hash(&self, data: &[u8], counter: u64, root: bool) -> Self::Hash {
            self.leaves.borrow_mut().push((counter, data.len(), root));
            leaf(counter, root)
        }

        fn parent_hash(&self, left: &Self::Hash, right: &Self::Hash, root: bool) -> Self::Hash {
            self.parents.borrow_mut().push(root);
            pair(left, right, root)
        }

        fn hash_size(&self) -> usize {
            unreachable!("group reduction does not serialize hashes")
        }

        fn zero_hash(&self) -> Self::Hash {
            unreachable!("group reduction does not use placeholder hashes")
        }

        fn hash_from_bytes(&self, _: &[u8]) -> Self::Hash {
            unreachable!("group reduction does not deserialize hashes")
        }
    }

    #[test]
    fn empty_and_single_leaf_preserve_absolute_counter_and_root() {
        for root in [false, true] {
            for len in [0, 1, CHUNK_SIZE] {
                let backend = Recording::default();
                assert_eq!(
                    hash_group(&backend, &vec![0; len], 37, root),
                    leaf(37, root)
                );
                assert_eq!(*backend.leaves.borrow(), [(37, len, root)]);
                assert!(backend.parents.borrow().is_empty());
            }
        }
    }

    #[test]
    fn finalization_and_odd_promotion_are_independent_of_group_position() {
        for root in [false, true] {
            for count in [2, 3, 5] {
                let backend = Recording::default();
                let data = vec![0; (count - 1) * CHUNK_SIZE + 1];
                let hashes: Vec<_> = (37..37 + count as u64).map(|n| leaf(n, false)).collect();
                let expected = match count {
                    2 => pair(&hashes[0], &hashes[1], root),
                    3 => pair(&pair(&hashes[0], &hashes[1], false), &hashes[2], root),
                    5 => pair(
                        &pair(
                            &pair(&hashes[0], &hashes[1], false),
                            &pair(&hashes[2], &hashes[3], false),
                            false,
                        ),
                        &hashes[4],
                        root,
                    ),
                    _ => unreachable!(),
                };
                assert_eq!(hash_group(&backend, &data, 37, root), expected);
                let leaves: Vec<_> = (0..count)
                    .map(|i| {
                        (
                            37 + i as u64,
                            if i + 1 == count { 1 } else { CHUNK_SIZE },
                            false,
                        )
                    })
                    .collect();
                assert_eq!(*backend.leaves.borrow(), leaves);
                let mut parents = vec![false; count - 1];
                *parents.last_mut().unwrap() = root;
                assert_eq!(*backend.parents.borrow(), parents);
            }
        }
    }
}
