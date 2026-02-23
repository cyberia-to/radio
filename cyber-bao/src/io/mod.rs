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
use crate::tree::{BlockSize, ChunkNum};
use crate::{ByteRanges, ChunkRanges};

/// Compute the root hash for a single block (possibly multi-chunk).
///
/// Hashes each 1024-byte chunk individually, then reduces via parent_hash
/// to produce the block's root. Used by both sync and async encode/decode paths.
pub(crate) fn hash_block(
    backend: &Poseidon2Backend,
    data: &[u8],
    start_chunk: u64,
    is_root: bool,
    block_bytes: usize,
) -> cyber_poseidon2::Hash {
    if data.is_empty() {
        return backend.chunk_hash(&[], start_chunk, is_root);
    }

    let mut chunk_hashes: Vec<cyber_poseidon2::Hash> = Vec::new();
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

/// Round byte ranges up to chunk ranges.
pub fn round_up_to_chunks(ranges: &ByteRanges) -> ChunkRanges {
    let mut result = ChunkRanges::empty();
    for range in ranges.iter() {
        let (start, end) = match range.cloned() {
            RangeSetRange::Range(r) => {
                let start = ChunkNum(r.start / 1024);
                let end = ChunkNum(r.end.div_ceil(1024));
                (start, Some(end))
            }
            RangeSetRange::RangeFrom(r) => {
                let start = ChunkNum(r.start / 1024);
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
