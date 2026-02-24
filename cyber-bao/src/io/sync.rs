//! Synchronous encoding and validation functions.
//!
//! Provides `encode_ranges_validated` and `valid_ranges` for sync I/O,
//! using Poseidon2 hashing throughout.

use std::io::{self, Write};

use smallvec::SmallVec;

use crate::hash::{HashBackend, Poseidon2Backend};
use crate::io::error::EncodeError;
use crate::io::traits::{Outboard, ReadAt};
use crate::tree::ChunkNum;
use crate::ChunkRangesRef;

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
    let tree = outboard.tree();
    let block_size = tree.block_size();

    // Use the same tree traversal as the decoder (pre_order_chunks_filtered)
    // to ensure encoder and decoder agree on the stream structure.
    let pre_order = tree.pre_order_chunks_filtered(ranges);

    let mut stack = SmallVec::<[cyber_poseidon2::Hash; 10]>::new();
    stack.push(outboard.root());

    for chunk in &pre_order {
        match chunk {
            crate::tree::BaoChunk::Parent { node, is_root, left, right } => {
                let (l_hash, r_hash) = outboard.load(*node)?.unwrap();
                let actual = backend.parent_hash(&l_hash, &r_hash, *is_root);
                let expected = stack.pop().unwrap();
                if actual != expected {
                    return Err(EncodeError::ParentHashMismatch(*node));
                }
                // Only push hashes for children that will be visited
                if *right {
                    stack.push(r_hash.clone());
                }
                if *left {
                    stack.push(l_hash.clone());
                }
                let pair = combine_hash_pair(&l_hash, &r_hash);
                encoded.write_all(&pair)?;
            }
            crate::tree::BaoChunk::Leaf {
                start_chunk,
                size,
                is_root,
            } => {
                let byte_start = *start_chunk * 1024;
                let mut buf = vec![0u8; *size];
                data.read_exact_at(byte_start, &mut buf)?;

                let computed =
                    super::hash_block(&backend, &buf, *start_chunk, *is_root, block_size.bytes());
                let expected = stack.pop().unwrap();
                if computed != expected {
                    return Err(EncodeError::LeafHashMismatch(ChunkNum(*start_chunk)));
                }
                encoded.write_all(&buf)?;
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
            validate_ranges_impl(outboard, data, ranges, &co).await
        {
            co.yield_(Err(cause)).await;
        }
    })
}

// ---- Internal helpers ----

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

// ---- valid_ranges implementation ----

/// Validate ranges by recursively walking the tree.
///
/// For each leaf whose hash matches, yield the corresponding chunk range.
/// When an outboard entry is missing or a parent hash doesn't match,
/// the subtree is skipped (not the entire scan).
async fn validate_ranges_impl<O, D>(
    outboard: O,
    data: D,
    ranges: &ChunkRangesRef,
    co: &genawaiter::sync::Co<io::Result<std::ops::Range<ChunkNum>>>,
) -> io::Result<()>
where
    O: Outboard<Hash = cyber_poseidon2::Hash>,
    D: ReadAt,
{
    let backend = Poseidon2Backend;
    let tree = outboard.tree();

    if tree.blocks() == 0 {
        return Ok(());
    }

    if tree.blocks() == 1 {
        let sz: usize = tree.size().try_into().unwrap();
        let mut tmp = vec![0u8; sz];
        if data.read_exact_at(0, &mut tmp).is_err() {
            return Ok(());
        }
        let actual = hash_subtree(&backend, 0, &tmp, true);
        if actual == outboard.root() {
            co.yield_(Ok(ChunkNum(0)..tree.chunks())).await;
        }
        return Ok(());
    }

    let ranges = truncate_ranges(ranges, tree.size());
    validate_node_rec(
        &outboard, &data, &backend, &tree, tree.root(), outboard.root(),
        true, ranges, co,
    ).await;

    Ok(())
}

/// Recursively validate a node and its subtree.
async fn validate_node_rec<O, D>(
    outboard: &O,
    data: &D,
    backend: &Poseidon2Backend,
    tree: &crate::tree::BaoTree,
    node: crate::tree::TreeNode,
    expected_hash: cyber_poseidon2::Hash,
    is_root: bool,
    ranges: &ChunkRangesRef,
    co: &genawaiter::sync::Co<io::Result<std::ops::Range<ChunkNum>>>,
)
where
    O: Outboard<Hash = cyber_poseidon2::Hash>,
    D: ReadAt,
{
    use range_collections::RangeSet2;

    // Check if this node's subtree overlaps the ranges
    let actual_range = tree.node_actual_chunk_range(node);
    let node_chunks = RangeSet2::from(actual_range.start..actual_range.end);
    if node_chunks.is_disjoint(ranges) {
        return;
    }

    let level = node.level();
    if level == 0 {
        // Leaf node — verify hash
        let block_idx = node.0 / 2;
        let block_bytes = tree.block_size().bytes() as u64;
        let start_byte = block_idx * block_bytes;
        let end_byte = ((block_idx + 1) * block_bytes).min(tree.size());
        let size = if start_byte >= tree.size() {
            0
        } else {
            (end_byte - start_byte) as usize
        };
        let start_chunk = block_idx * (1u64 << tree.block_size().0);
        let mut buf = vec![0u8; size];
        if data.read_exact_at(start_byte, &mut buf).is_err() {
            return; // Can't read data — skip this leaf
        }
        let actual = hash_subtree(backend, start_chunk, &buf, is_root);
        if actual == expected_hash {
            let chunks_per_block = 1u64 << tree.block_size().chunk_log();
            let leaf_end_chunk = start_chunk + chunks_per_block;
            co.yield_(Ok(ChunkNum(start_chunk)..ChunkNum(leaf_end_chunk))).await;
        }
        return;
    }

    // Check if right child exists
    let right_exists = node.right_child().is_some_and(|rc| {
        let right_block_start = rc.chunk_range().start.0 / 2;
        right_block_start < tree.blocks()
    });

    if !right_exists {
        // No right child — skip parent, recurse left with inherited is_root
        if let Some(left) = node.left_child() {
            Box::pin(validate_node_rec(
                outboard, data, backend, tree, left, expected_hash,
                is_root, ranges, co,
            )).await;
        }
        return;
    }

    // Load outboard hash pair
    let pair = match outboard.load(node) {
        Ok(Some(pair)) => pair,
        _ => return, // Missing outboard entry — skip this subtree
    };

    let (l_hash, r_hash) = pair;
    let actual = backend.parent_hash(&l_hash, &r_hash, is_root);
    if actual != expected_hash {
        return; // Hash mismatch — skip this subtree
    }

    // Recurse into children
    if let Some(left) = node.left_child() {
        Box::pin(validate_node_rec(
            outboard, data, backend, tree, left, l_hash,
            false, ranges, co,
        )).await;
    }
    if let Some(right) = node.right_child() {
        Box::pin(validate_node_rec(
            outboard, data, backend, tree, right, r_hash,
            false, ranges, co,
        )).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::pre_order::PreOrderMemOutboard;
    use crate::tree::{BlockSize, ChunkNum};
    use crate::ChunkRanges;

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

    #[test]
    fn encode_ranges_block_size_nonzero() {
        // BlockSize(1) = 2KB blocks (2 chunks per block)
        let bs = BlockSize::from_chunk_log(1);
        let data = vec![0x42u8; 8192]; // 4 blocks × 2KB
        let outboard = PreOrderMemOutboard::create(&data, bs);
        let mut encoded = Vec::new();
        encode_ranges_validated(&data[..], &outboard, &ChunkRanges::all(), &mut encoded)
            .expect("encode should succeed");
        // outboard has 3 parents × 64 + 8192 data
        assert_eq!(encoded.len(), 3 * 64 + 8192);
    }

    #[test]
    fn encode_ranges_partial_large_block() {
        // Test partial range encoding: 100KB data, chunks 16..32, block_log=4 (16KB blocks)
        let bs = BlockSize::from_chunk_log(4);
        let data: Vec<u8> = (0..100000u64).map(|i| (i % 251) as u8).collect();
        let outboard = PreOrderMemOutboard::create(&data, bs);
        let ranges = ChunkRanges::from(ChunkNum(16)..ChunkNum(32));
        let mut encoded = Vec::new();
        encode_ranges_validated(&data[..], &outboard, &ranges, &mut encoded)
            .expect("encode should succeed for partial ranges");
        assert!(!encoded.is_empty());
    }

    #[test]
    fn valid_ranges_block_size_nonzero() {
        let bs = BlockSize::from_chunk_log(1);
        let data = vec![0x42u8; 8192];
        let outboard = PreOrderMemOutboard::create(&data, bs);
        let mut ranges = ChunkRanges::empty();
        for range in valid_ranges(&outboard, &data[..], &ChunkRanges::all())
            .into_iter()
            .flatten()
        {
            ranges |= ChunkRanges::from(range);
        }
        // 8KB with 2KB blocks = 4 blocks, each block = 2 chunks
        // So 8 total chunks: 0..8
        assert_eq!(ranges, ChunkRanges::from(ChunkNum(0)..ChunkNum(8)));
    }
}
