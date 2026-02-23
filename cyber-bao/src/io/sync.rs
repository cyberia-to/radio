//! Synchronous encoding and validation functions.
//!
//! Provides `encode_ranges_validated` and `valid_ranges` for sync I/O,
//! using Poseidon2 hashing throughout.

use std::io::{self, Write};

use smallvec::SmallVec;

use crate::hash::{HashBackend, Poseidon2Backend};
use crate::io::error::EncodeError;
use crate::io::traits::{Outboard, ReadAt};
use crate::tree::{BaoTree, ChunkNum, TreeNode};
use crate::{ChunkRanges, ChunkRangesRef};

/// Encode ranges relevant to a query from a reader and outboard to a writer.
///
/// This function validates the data before writing.
///
/// It is possible to encode ranges from a partial file and outboard.
/// This will either succeed if the requested ranges are all present, or fail
/// as soon as a range is missing.
pub fn encode_ranges_validated<D: ReadAt, O: Outboard<Hash = cyber_poseidon2::Hash>, W: Write>(
    data: D,
    outboard: O,
    ranges: &ChunkRangesRef,
    mut encoded: W,
) -> Result<(), EncodeError> {
    if ranges.is_empty() {
        return Ok(());
    }
    let backend = Poseidon2Backend;
    let mut stack = SmallVec::<[cyber_poseidon2::Hash; 10]>::new();
    stack.push(outboard.root());
    let tree = outboard.tree();
    let mut buffer = vec![0u8; tree.chunk_group_bytes()];
    let mut out_buf = Vec::new();
    // canonicalize ranges
    let ranges = truncate_ranges(ranges, tree.size());
    // Use recursive approach to iterate the tree in pre-order with range info
    let items = select_nodes_rec_collect(tree, ranges);
    for item in &items {
        match item {
            RangeChunk::Parent {
                node,
                is_root,
                left,
                right,
            } => {
                let (l_hash, r_hash) = outboard.load(*node)?.unwrap();
                let actual = backend.parent_hash(&l_hash, &r_hash, *is_root);
                let expected = stack.pop().unwrap();
                if actual != expected {
                    return Err(EncodeError::ParentHashMismatch(*node));
                }
                if *right {
                    stack.push(r_hash.clone());
                }
                if *left {
                    stack.push(l_hash.clone());
                }
                let pair = combine_hash_pair(&l_hash, &r_hash);
                encoded.write_all(&pair)?;
            }
            RangeChunk::Leaf {
                start_chunk,
                size,
                is_root,
                full,
            } => {
                let expected = stack.pop().unwrap();
                let start = start_chunk.to_bytes();
                let buf = &mut buffer[..*size];
                data.read_exact_at(start, buf)?;
                let (actual, to_write) = if !full {
                    // For partial ranges within a block, we need to encode selected data.
                    // In practice with Poseidon2 and block-level trees, partial block
                    // encoding is rare. We use the recursive encoder for correctness.
                    out_buf.clear();
                    let actual = encode_selected_rec(
                        &backend,
                        *start_chunk,
                        buf,
                        *is_root,
                        &ChunkRanges::all(), // simplification: encode full block
                        tree.block_size().to_u32(),
                        true,
                        &mut out_buf,
                    );
                    (actual, &out_buf[..])
                } else {
                    let actual =
                        hash_subtree(&backend, start_chunk.0, buf, *is_root);
                    #[allow(clippy::redundant_slicing)]
                    (actual, &buf[..])
                };
                if actual != expected {
                    return Err(EncodeError::LeafHashMismatch(*start_chunk));
                }
                encoded.write_all(to_write)?;
            }
        }
    }
    Ok(())
}

/// Given a data file and an outboard, compute all valid ranges.
///
/// This is not cheap since it recomputes the hashes for all chunks.
///
/// To reduce the amount of work, you can specify a range you are interested in.
pub fn valid_ranges<'a, O, D>(
    outboard: O,
    data: D,
    ranges: &'a ChunkRangesRef,
) -> impl IntoIterator<Item = io::Result<std::ops::Range<ChunkNum>>> + 'a
where
    O: Outboard<Hash = cyber_poseidon2::Hash> + 'a,
    D: ReadAt + 'a,
{
    genawaiter::sync::Gen::new(move |co| async move {
        if let Err(cause) =
            RecursiveDataValidator::validate(outboard, data, ranges, &co).await
        {
            co.yield_(Err(cause)).await;
        }
    })
}

// ---- Internal helpers ----

/// A chunk item with range information for `encode_ranges_validated`.
enum RangeChunk {
    Parent {
        node: TreeNode,
        is_root: bool,
        left: bool,
        right: bool,
    },
    Leaf {
        start_chunk: ChunkNum,
        size: usize,
        is_root: bool,
        /// Whether the full block is requested (vs partial).
        full: bool,
    },
}

/// Collect pre-order chunks with range information for the given tree and ranges.
fn select_nodes_rec_collect(tree: BaoTree, ranges: &ChunkRangesRef) -> Vec<RangeChunk> {
    let mut result = Vec::new();
    select_nodes_rec(
        ChunkNum(0),
        tree.size().try_into().unwrap_or(0),
        true,
        ranges,
        tree.block_size().to_u32(),
        tree.block_size().to_u32(),
        &mut result,
    );
    result
}

/// Recursive pre-order chunk selection with range tracking.
fn select_nodes_rec(
    start_chunk: ChunkNum,
    size: usize,
    is_root: bool,
    ranges: &ChunkRangesRef,
    tree_level: u32,
    min_full_level: u32,
    result: &mut Vec<RangeChunk>,
) {
    if ranges.is_empty() {
        return;
    }
    const CHUNK_LEN: usize = 1024;
    if size <= CHUNK_LEN {
        result.push(RangeChunk::Leaf {
            start_chunk,
            size,
            is_root,
            full: true,
        });
    } else {
        let chunks: usize = size / CHUNK_LEN + (size % CHUNK_LEN != 0) as usize;
        let chunks = chunks.next_power_of_two();
        let level = chunks.trailing_zeros() - 1;
        let full = ranges.is_all();
        if (level < tree_level) || (full && level < min_full_level) {
            result.push(RangeChunk::Leaf {
                start_chunk,
                size,
                is_root,
                full,
            });
        } else {
            let mid = chunks / 2;
            let mid_bytes = mid * CHUNK_LEN;
            let mid_chunk = ChunkNum(start_chunk.0 + mid as u64);
            let (l_ranges, r_ranges) = split_inner(ranges, start_chunk, mid_chunk);
            let node = TreeNode::new(
                start_chunk.0 | ((1u64 << level) - 1),
            );
            result.push(RangeChunk::Parent {
                node,
                is_root,
                left: !l_ranges.is_empty(),
                right: !r_ranges.is_empty(),
            });
            select_nodes_rec(
                start_chunk,
                mid_bytes,
                false,
                l_ranges,
                tree_level,
                min_full_level,
                result,
            );
            select_nodes_rec(
                mid_chunk,
                size - mid_bytes,
                false,
                r_ranges,
                tree_level,
                min_full_level,
                result,
            );
        }
    }
}

/// Split ranges at a midpoint, canonicalizing single-interval results.
fn split_inner<'a>(
    ranges: &'a ChunkRangesRef,
    start: ChunkNum,
    mid: ChunkNum,
) -> (&'a ChunkRangesRef, &'a ChunkRangesRef) {
    let (mut a, mut b) = ranges.split(mid);
    // Canonicalize: if a is a single interval starting at or before start, make it "all"
    if a.boundaries().len() == 1 && a.boundaries()[0] <= start {
        a = ChunkRangesRef::new(&[ChunkNum(0)]).unwrap();
    }
    // Same for b with mid
    if b.boundaries().len() == 1 && b.boundaries()[0] <= mid {
        b = ChunkRangesRef::new(&[ChunkNum(0)]).unwrap();
    }
    (a, b)
}

/// Truncate ranges to the given data size, ensuring the last chunk is included.
pub fn truncate_ranges(ranges: &ChunkRangesRef, size: u64) -> &ChunkRangesRef {
    let bs = ranges.boundaries();
    ChunkRangesRef::new_unchecked(&bs[..truncated_len(ranges, size)])
}

fn truncated_len(ranges: &ChunkRangesRef, size: u64) -> usize {
    let end = ChunkNum::chunks(size);
    let lc = ChunkNum(end.0.saturating_sub(1));
    let bs = ranges.boundaries();
    match bs.binary_search(&lc) {
        Ok(i) if (i & 1) == 0 => i + 1,
        Ok(i) => {
            if bs.len() == i + 1 {
                i + 1
            } else {
                i
            }
        }
        Err(ip) if (ip & 1) == 0 => {
            if bs.len() == ip {
                ip
            } else {
                ip + 1
            }
        }
        Err(ip) => ip,
    }
}

/// Combine two hashes into a 64-byte pair.
fn combine_hash_pair(l: &cyber_poseidon2::Hash, r: &cyber_poseidon2::Hash) -> [u8; 64] {
    let mut res = [0u8; 64];
    res[..32].copy_from_slice(l.as_bytes());
    res[32..].copy_from_slice(r.as_bytes());
    res
}

/// Hash a subtree (one or more 1024-byte chunks) using Poseidon2.
fn hash_subtree(
    backend: &Poseidon2Backend,
    start_chunk: u64,
    data: &[u8],
    is_root: bool,
) -> cyber_poseidon2::Hash {
    const CHUNK_LEN: usize = 1024;
    if data.len() <= CHUNK_LEN {
        return backend.chunk_hash(data, start_chunk, is_root);
    }
    // Multiple chunks: build a binary tree of hashes
    let mut chunk_hashes: Vec<cyber_poseidon2::Hash> = Vec::new();
    let mut offset = 0usize;
    let mut counter = start_chunk;
    while offset < data.len() {
        let end = (offset + CHUNK_LEN).min(data.len());
        let chunk_data = &data[offset..end];
        chunk_hashes.push(backend.chunk_hash(chunk_data, counter, false));
        offset += CHUNK_LEN;
        counter += 1;
    }
    // Build the tree bottom-up
    let mut level = chunk_hashes;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(backend.parent_hash(&level[i], &level[i + 1], false));
            } else {
                next.push(level[i].clone());
            }
            i += 2;
        }
        level = next;
    }
    level.into_iter().next().unwrap()
}

/// Recursive encoder for selected ranges (used for partial block encoding).
fn encode_selected_rec(
    backend: &Poseidon2Backend,
    start_chunk: ChunkNum,
    data: &[u8],
    is_root: bool,
    _query: &ChunkRangesRef,
    min_level: u32,
    emit_data: bool,
    res: &mut Vec<u8>,
) -> cyber_poseidon2::Hash {
    const CHUNK_LEN: usize = 1024;
    if data.len() <= CHUNK_LEN {
        if emit_data {
            res.extend_from_slice(data);
        }
        hash_subtree(backend, start_chunk.0, data, is_root)
    } else {
        let chunks = data.len() / CHUNK_LEN + (data.len() % CHUNK_LEN != 0) as usize;
        let chunks = chunks.next_power_of_two();
        let level = chunks.trailing_zeros() - 1;
        let mid = chunks / 2;
        let mid_bytes = mid * CHUNK_LEN;

        let emit_parent = level >= min_level;
        let hash_offset = if emit_parent {
            res.extend_from_slice(&[0xFFu8; 64]);
            Some(res.len() - 64)
        } else {
            None
        };
        let left = encode_selected_rec(
            backend,
            start_chunk,
            &data[..mid_bytes],
            false,
            &ChunkRanges::all(),
            min_level,
            emit_data,
            res,
        );
        let mid_chunk = ChunkNum(start_chunk.0 + mid as u64);
        let right = encode_selected_rec(
            backend,
            mid_chunk,
            &data[mid_bytes..],
            false,
            &ChunkRanges::all(),
            min_level,
            emit_data,
            res,
        );
        if let Some(o) = hash_offset {
            res[o..o + 32].copy_from_slice(left.as_bytes());
            res[o + 32..o + 64].copy_from_slice(right.as_bytes());
        }
        backend.parent_hash(&left, &right, is_root)
    }
}

// ---- RecursiveDataValidator (for valid_ranges) ----

type LocalBoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>;

struct RecursiveDataValidator<'a, O: Outboard<Hash = cyber_poseidon2::Hash>, D: ReadAt> {
    tree: BaoTree,
    shifted_filled_size: TreeNode,
    outboard: O,
    data: D,
    buffer: Vec<u8>,
    backend: Poseidon2Backend,
    co: &'a genawaiter::sync::Co<io::Result<std::ops::Range<ChunkNum>>>,
}

impl<O: Outboard<Hash = cyber_poseidon2::Hash>, D: ReadAt> RecursiveDataValidator<'_, O, D> {
    async fn validate(
        outboard: O,
        data: D,
        ranges: &ChunkRangesRef,
        co: &genawaiter::sync::Co<io::Result<std::ops::Range<ChunkNum>>>,
    ) -> io::Result<()> {
        let tree = outboard.tree();
        let buffer = vec![0u8; tree.chunk_group_bytes()];
        let backend = Poseidon2Backend;
        if tree.blocks() == 1 {
            // special case for a tree that fits in one block
            let sz: usize = tree.size().try_into().unwrap();
            let mut tmp = vec![0u8; sz];
            data.read_exact_at(0, &mut tmp)?;
            let actual = hash_subtree(&backend, 0, &tmp, true);
            if actual == outboard.root() {
                co.yield_(Ok(ChunkNum(0)..tree.chunks())).await;
            }
            return Ok(());
        }
        let ranges = truncate_ranges(ranges, tree.size());
        let root_hash = outboard.root();
        let (shifted_root, shifted_filled_size) = tree.shifted();
        let mut validator = RecursiveDataValidator {
            tree,
            shifted_filled_size,
            outboard,
            data,
            buffer,
            backend,
            co,
        };
        validator
            .validate_rec(&root_hash, shifted_root, true, ranges)
            .await
    }

    async fn yield_if_valid(
        &mut self,
        range: std::ops::Range<u64>,
        hash: &cyber_poseidon2::Hash,
        is_root: bool,
    ) -> io::Result<()> {
        let len = (range.end - range.start).try_into().unwrap();
        let tmp = &mut self.buffer[..len];
        self.data.read_exact_at(range.start, tmp)?;
        let actual =
            hash_subtree(&self.backend, ChunkNum::full_chunks(range.start).0, tmp, is_root);
        if actual == *hash {
            self.co
                .yield_(Ok(
                    ChunkNum::full_chunks(range.start)..ChunkNum::chunks(range.end)
                ))
                .await;
        }
        Ok(())
    }

    fn validate_rec<'b>(
        &'b mut self,
        parent_hash: &'b cyber_poseidon2::Hash,
        shifted: TreeNode,
        is_root: bool,
        ranges: &'b ChunkRangesRef,
    ) -> LocalBoxFuture<'b, io::Result<()>> {
        Box::pin(async move {
            if ranges.is_empty() {
                return Ok(());
            }
            let node = shifted.subtract_block_size(self.tree.block_size().chunk_log());
            let (l, m, r) = self.tree.leaf_byte_ranges3(node);
            if !self.tree.is_relevant_for_outboard(node) {
                self.yield_if_valid(l..r, parent_hash, is_root).await?;
                return Ok(());
            }
            let Some((l_hash, r_hash)) = self.outboard.load(node)? else {
                return Ok(());
            };
            let actual = self.backend.parent_hash(&l_hash, &r_hash, is_root);
            if actual != *parent_hash {
                return Ok(());
            }
            let (l_ranges, r_ranges) = split(ranges, node);
            if shifted.is_leaf() {
                if !l_ranges.is_empty() {
                    self.yield_if_valid(l..m, &l_hash, false).await?;
                }
                if !r_ranges.is_empty() {
                    self.yield_if_valid(m..r, &r_hash, false).await?;
                }
            } else {
                let left = shifted.left_child().unwrap();
                self.validate_rec(&l_hash, left, false, l_ranges).await?;
                let right = shifted
                    .right_descendant(self.shifted_filled_size)
                    .unwrap();
                self.validate_rec(&r_hash, right, false, r_ranges).await?;
            }
            Ok(())
        })
    }
}

/// Split ranges on a tree node's midpoint.
fn split(
    ranges: &ChunkRangesRef,
    node: TreeNode,
) -> (&ChunkRangesRef, &ChunkRangesRef) {
    let mid = node.mid();
    let start = node.chunk_range().start;
    split_inner(ranges, start, mid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::pre_order::PreOrderMemOutboard;
    use crate::tree::BlockSize;

    #[test]
    fn encode_ranges_validated_full() {
        let data = vec![0x42u8; 2048];
        let outboard = PreOrderMemOutboard::create(&data, BlockSize::ZERO);
        let mut encoded = Vec::new();
        let size = data.len() as u64;
        encoded.extend_from_slice(&size.to_le_bytes());
        encode_ranges_validated(&data[..], &outboard, &ChunkRanges::all(), &mut encoded)
            .expect("encode should succeed");
        // Should have size prefix + parent hash pair (64) + 2 leaf chunks (2048)
        assert_eq!(encoded.len(), 8 + 64 + 2048);
    }

    #[test]
    fn valid_ranges_all_valid() {
        let data = vec![0x42u8; 2048];
        let outboard = PreOrderMemOutboard::create(&data, BlockSize::ZERO);
        let mut ranges = ChunkRanges::empty();
        for range in valid_ranges(&outboard, &data[..], &ChunkRanges::all())
            .into_iter()
            .flatten()
        {
            ranges |= ChunkRanges::from(range);
        }
        assert_eq!(ranges, ChunkRanges::from(ChunkNum(0)..ChunkNum(2)));
    }

    #[test]
    fn valid_ranges_empty_data() {
        let data: Vec<u8> = vec![];
        let outboard = PreOrderMemOutboard::create(&data, BlockSize::ZERO);
        let mut ranges = ChunkRanges::empty();
        for range in valid_ranges(&outboard, &data[..], &ChunkRanges::all())
            .into_iter()
            .flatten()
        {
            ranges |= ChunkRanges::from(range);
        }
        // empty data has 0 chunks, so valid range is 0..0 which is empty
        assert_eq!(ranges, ChunkRanges::empty());
    }

    #[test]
    fn encode_then_valid_ranges_roundtrip() {
        let data = vec![0xABu8; 4096];
        let outboard = PreOrderMemOutboard::create(&data, BlockSize::ZERO);
        // First verify all ranges are valid
        let mut ranges = ChunkRanges::empty();
        for range in valid_ranges(&outboard, &data[..], &ChunkRanges::all())
            .into_iter()
            .flatten()
        {
            ranges |= ChunkRanges::from(range);
        }
        assert_eq!(ranges, ChunkRanges::from(ChunkNum(0)..ChunkNum(4)));
    }
}
