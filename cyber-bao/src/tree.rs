//! BAO tree geometry — pure math, no hashing.
//!
//! This module provides the tree structure used for verified streaming.
//! The tree uses in-order indexing (same as bao-tree): leaves at
//! even positions, parents at odd positions, level = trailing ones count.

use core::fmt;
use core::ops::Range;

use hemera::OUTPUT_BYTES;

#[cfg(feature = "std")]
mod traversal;
#[cfg(feature = "std")]
pub use traversal::PostOrderChunkIter;

/// Size of a single chunk in bytes (Hemera spec: 4 KiB).
pub const CHUNK_SIZE: usize = 4096;

/// Size of a hash pair (two hashes concatenated).
const PAIR_SIZE: usize = OUTPUT_BYTES * 2;

/// A node position in the in-order binary tree.
///
/// Leaves are at even indices (0, 2, 4, ...).
/// Parents are at odd indices with level = trailing_ones count.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TreeNode(pub(crate) u64);

impl TreeNode {
    /// Create a tree node from a raw in-order index.
    pub fn new(index: u64) -> Self {
        Self(index)
    }

    /// The level of this node (0 for leaves).
    pub fn level(self) -> u32 {
        self.0.trailing_ones()
    }

    /// Whether this is a leaf node.
    pub fn is_leaf(self) -> bool {
        (self.0 & 1) == 0
    }

    /// The midpoint chunk number (boundary between left and right subtrees).
    pub fn mid(self) -> ChunkNum {
        ChunkNum(self.0 + 1)
    }

    /// The left child of this node, if it has one.
    pub fn left_child(self) -> Option<Self> {
        let level = self.level();
        if level == 0 {
            return None;
        }
        Some(Self(self.0 - (1 << (level - 1))))
    }

    /// The right child of this node, if it has one.
    pub fn right_child(self) -> Option<Self> {
        let level = self.level();
        if level == 0 {
            return None;
        }
        Some(Self(self.0 + (1 << (level - 1))))
    }

    /// The parent of this node.
    pub fn parent(self) -> Option<Self> {
        let level = self.level();
        let span = 1u64 << level;
        let offset = self.0;
        if offset & (span << 1) == 0 {
            Some(Self(offset + span))
        } else {
            offset.checked_sub(span).map(Self)
        }
    }

    /// Range of chunks covered by this node's subtree.
    pub fn chunk_range(self) -> Range<ChunkNum> {
        let level = self.level();
        let span = 1u64 << level;
        let mid = self.0 + 1;
        ChunkNum(mid - span)..ChunkNum(mid + span)
    }

    /// Range of bytes covered by this node's subtree.
    pub fn byte_range(self) -> Range<u64> {
        let range = self.chunk_range();
        range.start.to_bytes()..range.end.to_bytes()
    }

    /// The right descendant of this node that is within the tree bounds.
    ///
    /// Starts at right child, then walks left until within `len`.
    pub fn right_descendant(self, len: Self) -> Option<Self> {
        let mut node = self.right_child()?;
        while node >= len {
            node = node.left_child()?;
        }
        Some(node)
    }

    /// Count of nodes below this node in the subtree (excluding self).
    pub fn count_below(self) -> u64 {
        let level = self.level();
        if level == 0 {
            return 0;
        }
        (1u64 << (level + 1)) - 2
    }

    /// Post-order offset of this node (closed-form).
    pub fn post_order_offset(self) -> u64 {
        let level = self.level();
        let span = 1u64 << level;
        let mid = self.0 + 1;
        let start = mid - span;
        // In a complete binary tree, post-order offset = start + count_below
        start + self.count_below()
    }

    /// Shift the node index by removing the block_size lowest bits.
    ///
    /// Returns `None` if the node's level is below the block size
    /// (i.e., it's an intra-block node that doesn't appear in the block-level tree).
    pub const fn add_block_size(self, n: u8) -> Option<Self> {
        let mask = (1u64 << n) - 1;
        if self.0 & mask == mask {
            Some(Self(self.0 >> n))
        } else {
            None
        }
    }

    /// The inverse of `add_block_size` — expand back to the unshifted index.
    pub const fn subtract_block_size(self, n: u8) -> Self {
        let shifted = !(!self.0 << n);
        Self(shifted)
    }
}

impl fmt::Debug for TreeNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TreeNode({}, level={})", self.0, self.level())
    }
}

impl fmt::Display for TreeNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Count of chunks (each CHUNK_SIZE bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChunkNum(pub u64);

impl ChunkNum {
    /// Number of chunks needed for `size` bytes (rounds up).
    pub fn chunks(size: u64) -> Self {
        Self(size.div_ceil(CHUNK_SIZE as u64))
    }

    /// Number of full chunks in `size` bytes (rounds down).
    pub fn full_chunks(size: u64) -> Self {
        Self(size / CHUNK_SIZE as u64)
    }

    /// Convert chunks back to bytes.
    pub fn to_bytes(self) -> u64 {
        self.0 * CHUNK_SIZE as u64
    }
}

impl fmt::Debug for ChunkNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkNum({})", self.0)
    }
}

impl fmt::Display for ChunkNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl core::ops::Add for ChunkNum {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl core::ops::Add<u64> for ChunkNum {
    type Output = Self;
    fn add(self, rhs: u64) -> Self {
        Self(self.0 + rhs)
    }
}

impl core::ops::Sub for ChunkNum {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl core::ops::Sub<u64> for ChunkNum {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self {
        Self(self.0 - rhs)
    }
}

#[cfg(feature = "std")]
impl range_collections::range_set::RangeSetEntry for ChunkNum {
    fn min_value() -> Self {
        ChunkNum(0)
    }

    fn is_min_value(&self) -> bool {
        self.0 == 0
    }
}

/// Block size for chunk groups — log2 of the number of chunks per block.
///
/// `BlockSize(0)` = CHUNK_SIZE bytes (one chunk per block).
/// `BlockSize(2)` = 4 × CHUNK_SIZE bytes (4 chunks per block, recommended default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockSize(pub u8);

impl BlockSize {
    /// One chunk per block.
    pub const ZERO: Self = Self(0);

    /// Default 16 KiB blocks (4 × 4096-byte chunks, recommended for production).
    pub const DEFAULT: Self = Self(2);

    /// Create from the log2 of chunks per block.
    pub const fn from_chunk_log(log: u8) -> Self {
        Self(log)
    }

    /// Create from a byte size (must be a power of 2 >= CHUNK_SIZE).
    pub fn from_bytes(bytes: u64) -> Option<Self> {
        if bytes < CHUNK_SIZE as u64 || !bytes.is_power_of_two() {
            return None;
        }
        let log = (bytes / CHUNK_SIZE as u64).trailing_zeros() as u8;
        Some(Self(log))
    }

    /// Block size in bytes.
    pub fn bytes(self) -> usize {
        CHUNK_SIZE << self.0
    }

    /// Log2 of chunks per block.
    pub fn chunk_log(self) -> u8 {
        self.0
    }

    /// Log2 of chunks per block as u32.
    pub fn to_u32(self) -> u32 {
        self.0 as u32
    }
}

/// The BAO tree geometry descriptor.
///
/// Contains no actual data or hashes — purely describes the tree shape
/// for a blob of a given size and block size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaoTree {
    size: u64,
    block_size: BlockSize,
}

impl BaoTree {
    /// Create a new tree for the given data size and block size.
    pub fn new(size: u64, block_size: BlockSize) -> Self {
        Self { size, block_size }
    }

    /// Total data size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Block size configuration.
    pub fn block_size(&self) -> BlockSize {
        self.block_size
    }

    /// Number of chunks (CHUNK_SIZE bytes each).
    pub fn chunks(&self) -> ChunkNum {
        ChunkNum::chunks(self.size)
    }

    /// Number of blocks (chunk groups). Minimum 1 even for empty data.
    pub fn blocks(&self) -> u64 {
        let chunk_count = self.chunks().0;
        let chunks_per_block = 1u64 << self.block_size.0;
        chunk_count.div_ceil(chunks_per_block).max(1)
    }

    /// Root node of the tree (at the block level).
    ///
    /// In the in-order binary tree, the root of N leaves is at
    /// index `next_power_of_two(N) - 1`.
    pub fn root(&self) -> TreeNode {
        let blocks = self.blocks();
        if blocks <= 1 {
            return TreeNode(0);
        }
        TreeNode(blocks.next_power_of_two() - 1)
    }

    /// Size of the outboard (hash pairs only, no size prefix).
    /// Each internal node is a hash pair (two OUTPUT_BYTES hashes).
    pub fn outboard_size(&self) -> u64 {
        let blocks = self.blocks();
        if blocks <= 1 {
            return 0;
        }
        (blocks - 1) * PAIR_SIZE as u64
    }

    /// Block size in bytes (chunk group size).
    pub fn chunk_group_bytes(&self) -> usize {
        self.block_size.bytes()
    }

    /// Compute the shifted tree representation (block-level tree).
    ///
    /// Returns `(root_node, filled_size)` in the shifted coordinate system.
    pub fn shifted(&self) -> (TreeNode, TreeNode) {
        let level = self.block_size.0;
        let size = self.size;
        let shift = CHUNK_SIZE.trailing_zeros() + level as u32;
        let mask = (1u64 << shift) - 1;
        let full_blocks = size >> shift;
        let open_block = u64::from((size & mask) != 0);
        let blocks = (full_blocks + open_block).max(1);
        let n = blocks.div_ceil(2);
        let root = n.next_power_of_two() - 1;
        let filled_size = n + n.saturating_sub(1);
        (TreeNode(root), TreeNode(filled_size))
    }

    /// Compute the left, mid, and right byte boundaries for a leaf node.
    ///
    /// `(start, mid.min(size), end.min(size))`
    pub fn leaf_byte_ranges3(&self, node: TreeNode) -> (u64, u64, u64) {
        let Range { start, end } = node.byte_range();
        let mid = node.mid().to_bytes();
        (start, mid.min(self.size), end.min(self.size))
    }

    /// Convert a node's in-order chunk_range to actual chunk numbers.
    ///
    /// `TreeNode::chunk_range()` returns values in the in-order index space
    /// where leaf at index 2k covers range 2k..2k+2. Actual chunk numbers
    /// are: block_idx * chunks_per_block, where block_idx = leaf_index / 2.
    /// This method performs that conversion for use with `ChunkRanges`.
    pub fn node_actual_chunk_range(&self, node: TreeNode) -> Range<ChunkNum> {
        let raw = node.chunk_range();
        let cpb = 1u64 << self.block_size.0;
        // In-order index space → block space: divide by 2
        // Block space → chunk space: multiply by chunks_per_block
        ChunkNum((raw.start.0 / 2) * cpb)..ChunkNum((raw.end.0 / 2) * cpb)
    }

    /// Whether a node is relevant for the outboard (i.e., tracked at this block size).
    pub fn is_relevant_for_outboard(&self, node: TreeNode) -> bool {
        let level = node.level();
        let bs = self.block_size.to_u32();
        if level < bs {
            false
        } else if level > bs {
            true
        } else {
            node.mid().to_bytes() < self.size
        }
    }
}

/// Items yielded during tree traversal.
#[derive(Debug, Clone)]
pub enum BaoChunk {
    /// A parent node — contains two child hashes (PAIR_SIZE bytes).
    Parent {
        node: TreeNode,
        is_root: bool,
        /// Whether the left child will be visited in this traversal.
        left: bool,
        /// Whether the right child will be visited in this traversal.
        right: bool,
    },
    /// A leaf node — contains actual data.
    Leaf {
        start_chunk: u64,
        size: usize,
        is_root: bool,
    },
}

#[cfg(test)]
mod tests;
