//! BAO tree geometry — pure math, no hashing.
//!
//! This module provides the tree structure used for verified streaming.
//! The tree uses in-order indexing (same as bao-tree): leaves at
//! even positions, parents at odd positions, level = trailing ones count.

use std::fmt;
use std::ops::Range;

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

/// Count of 1024-byte chunks (or chunk groups).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChunkNum(pub u64);

impl ChunkNum {
    /// Number of chunks needed for `size` bytes (rounds up).
    pub fn chunks(size: u64) -> Self {
        Self(size.div_ceil(1024))
    }

    /// Number of full chunks in `size` bytes (rounds down).
    pub fn full_chunks(size: u64) -> Self {
        Self(size / 1024)
    }

    /// Convert chunks back to bytes.
    pub fn to_bytes(self) -> u64 {
        self.0 * 1024
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

impl std::ops::Add for ChunkNum {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Add<u64> for ChunkNum {
    type Output = Self;
    fn add(self, rhs: u64) -> Self {
        Self(self.0 + rhs)
    }
}

impl std::ops::Sub for ChunkNum {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl std::ops::Sub<u64> for ChunkNum {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self {
        Self(self.0 - rhs)
    }
}

impl range_collections::range_set::RangeSetEntry for ChunkNum {
    fn min_value() -> Self {
        ChunkNum(0)
    }

    fn is_min_value(&self) -> bool {
        self.0 == 0
    }
}

/// Block size for chunk groups — log2 of the number of 1024-byte chunks per block.
///
/// `BlockSize(0)` = 1024 bytes (one chunk per block, original bao behavior).
/// `BlockSize(4)` = 16384 bytes (16 chunks per block, recommended default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockSize(pub u8);

impl BlockSize {
    /// Standard 1024-byte blocks (one chunk per block).
    pub const ZERO: Self = Self(0);

    /// Default 16 KiB blocks (recommended for production).
    pub const DEFAULT: Self = Self(4);

    /// Create from the log2 of chunks per block.
    pub const fn from_chunk_log(log: u8) -> Self {
        Self(log)
    }

    /// Create from a byte size (must be a power of 2 >= 1024).
    pub fn from_bytes(bytes: u64) -> Option<Self> {
        if bytes < 1024 || !bytes.is_power_of_two() {
            return None;
        }
        let log = (bytes / 1024).trailing_zeros() as u8;
        Some(Self(log))
    }

    /// Block size in bytes.
    pub fn bytes(self) -> usize {
        1024 << self.0
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

    /// Number of 1024-byte chunks.
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
    /// Each internal node is a 64-byte hash pair (two 32-byte hashes).
    pub fn outboard_size(&self) -> u64 {
        let blocks = self.blocks();
        if blocks <= 1 {
            return 0;
        }
        (blocks - 1) * 64
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
        let shift = 10 + level as u32;
        let mask = (1u64 << shift) - 1;
        let full_blocks = size >> shift;
        let open_block = u64::from((size & mask) != 0);
        let blocks = (full_blocks + open_block).max(1);
        let n = blocks.div_ceil(2);
        let root = n.next_power_of_two() - 1;
        let filled_size = n + n.saturating_sub(1);
        (TreeNode(root), TreeNode(filled_size))
    }

    /// The offset of the given node's hash pair in the pre-order outboard.
    ///
    /// Returns `None` if the node is not a parent in the pre-order traversal.
    /// Returns the 0-based index among parents in pre-order.
    pub fn pre_order_offset(&self, node: TreeNode) -> Option<u64> {
        let pre_order = self.pre_order_chunks();
        let mut parent_idx = 0u64;
        for chunk in &pre_order {
            if let BaoChunk::Parent { node: n, .. } = chunk {
                if *n == node {
                    return Some(parent_idx);
                }
                parent_idx += 1;
            }
        }
        None
    }

    /// Post-order offset of a node in the block-level tree.
    ///
    /// Returns the 0-based index of this parent node among all parent nodes
    /// when traversed in post-order. Leaves are not counted (they are not
    /// stored in the outboard).
    ///
    /// Returns `None` if the node is a leaf (not stored in outboard).
    pub fn post_order_offset(&self, node: TreeNode) -> Option<u64> {
        // Walk the post-order chunks and count parents until we find this node.
        let post_order = self.post_order_chunks();
        let mut parent_idx = 0u64;
        for chunk in &post_order {
            if let BaoChunk::Parent { node: n, .. } = chunk {
                if *n == node {
                    return Some(parent_idx);
                }
                parent_idx += 1;
            }
        }
        None
    }

    /// Iterator over chunks in post-order (lazy version compatible with bao-tree).
    pub fn post_order_chunks_iter(&self) -> PostOrderChunkIter {
        PostOrderChunkIter {
            chunks: self.post_order_chunks(),
            pos: 0,
        }
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

/// Iterator over `BaoChunk` items (wraps the Vec returned by `post_order_chunks`).
#[derive(Debug)]
pub struct PostOrderChunkIter {
    chunks: Vec<BaoChunk>,
    pos: usize,
}

impl Iterator for PostOrderChunkIter {
    type Item = BaoChunk;
    fn next(&mut self) -> Option<BaoChunk> {
        if self.pos < self.chunks.len() {
            let item = self.chunks[self.pos].clone();
            self.pos += 1;
            Some(item)
        } else {
            None
        }
    }
}

/// Items yielded during tree traversal.
#[derive(Debug, Clone)]
pub enum BaoChunk {
    /// A parent node — contains two child hashes (64 bytes).
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

impl BaoTree {
    /// Iterate over the tree in pre-order (root first, then left, then right).
    ///
    /// Yields `BaoChunk` items suitable for combined encoding/decoding.
    /// Parent nodes appear before their children; leaf data appears at the
    /// position where it will be verified.
    pub fn pre_order_chunks(&self) -> Vec<BaoChunk> {
        let blocks = self.blocks();
        if blocks == 0 {
            return vec![];
        }
        if blocks == 1 {
            let chunk_bytes = self.size.min(self.block_size.bytes() as u64) as usize;
            return vec![BaoChunk::Leaf {
                start_chunk: 0,
                size: chunk_bytes,
                is_root: true,
            }];
        }
        let root = self.root();
        let mut items = Vec::new();
        self.pre_order_recurse(root, true, blocks, &mut items);
        items
    }

    fn pre_order_recurse(
        &self,
        node: TreeNode,
        is_root: bool,
        total_blocks: u64,
        out: &mut Vec<BaoChunk>,
    ) {
        let level = node.level();
        if level == 0 {
            // Leaf (block) node
            let block_idx = node.0 / 2;
            let block_bytes = self.block_size.bytes() as u64;
            let start_byte = block_idx * block_bytes;
            let end_byte = ((block_idx + 1) * block_bytes).min(self.size);
            let size = if start_byte >= self.size {
                0
            } else {
                (end_byte - start_byte) as usize
            };
            out.push(BaoChunk::Leaf {
                start_chunk: block_idx * (1u64 << self.block_size.0),
                size,
                is_root,
            });
            return;
        }

        // Check if the right subtree has any actual blocks
        let right_exists = node.right_child().is_some_and(|rc| {
            let right_block_start = rc.chunk_range().start.0 / 2;
            right_block_start < total_blocks
        });

        if !right_exists {
            // Right subtree is empty — skip this parent and recurse left,
            // inheriting the is_root flag (standard BAO incomplete tree behavior).
            if let Some(left) = node.left_child() {
                self.pre_order_recurse(left, is_root, total_blocks, out);
            }
            return;
        }

        // Both children exist — emit parent, then recurse left and right
        out.push(BaoChunk::Parent { node, is_root, left: true, right: true });

        if let Some(left) = node.left_child() {
            self.pre_order_recurse(left, false, total_blocks, out);
        }
        if let Some(right) = node.right_child() {
            self.pre_order_recurse(right, false, total_blocks, out);
        }
    }

    /// Iterate over the tree in post-order (children first, then parent).
    ///
    /// Used for computing the tree bottom-up (hash all leaves, then parents).
    pub fn post_order_chunks(&self) -> Vec<BaoChunk> {
        let blocks = self.blocks();
        if blocks == 0 {
            return vec![];
        }
        if blocks == 1 {
            let chunk_bytes = self.size.min(self.block_size.bytes() as u64) as usize;
            return vec![BaoChunk::Leaf {
                start_chunk: 0,
                size: chunk_bytes,
                is_root: true,
            }];
        }
        let root = self.root();
        let mut items = Vec::new();
        self.post_order_recurse(root, true, blocks, &mut items);
        items
    }

    fn post_order_recurse(
        &self,
        node: TreeNode,
        is_root: bool,
        total_blocks: u64,
        out: &mut Vec<BaoChunk>,
    ) {
        let level = node.level();
        if level == 0 {
            let block_idx = node.0 / 2;
            let block_bytes = self.block_size.bytes() as u64;
            let start_byte = block_idx * block_bytes;
            let end_byte = ((block_idx + 1) * block_bytes).min(self.size);
            let size = if start_byte >= self.size {
                0
            } else {
                (end_byte - start_byte) as usize
            };
            out.push(BaoChunk::Leaf {
                start_chunk: block_idx * (1u64 << self.block_size.0),
                size,
                is_root,
            });
            return;
        }

        // Check if right subtree has actual blocks
        let right_exists = node.right_child().is_some_and(|rc| {
            let right_block_start = rc.chunk_range().start.0 / 2;
            right_block_start < total_blocks
        });

        if !right_exists {
            // Right subtree is empty — skip this parent, recurse left with inherited is_root
            if let Some(left) = node.left_child() {
                self.post_order_recurse(left, is_root, total_blocks, out);
            }
            return;
        }

        // Both children exist
        if let Some(left) = node.left_child() {
            self.post_order_recurse(left, false, total_blocks, out);
        }
        if let Some(right) = node.right_child() {
            self.post_order_recurse(right, false, total_blocks, out);
        }

        // Parent after children
        out.push(BaoChunk::Parent { node, is_root, left: true, right: true });
    }
}

impl BaoTree {
    /// Iterate over the tree in pre-order, filtered by chunk ranges.
    ///
    /// Only yields parent nodes whose subtree overlaps the given ranges,
    /// and leaf nodes whose block overlaps the given ranges. This matches
    /// the set of items a sender would transmit for a range query.
    pub fn pre_order_chunks_filtered(
        &self,
        ranges: &range_collections::RangeSetRef<ChunkNum>,
    ) -> Vec<BaoChunk> {
        let blocks = self.blocks();
        if blocks == 0 || ranges.is_empty() {
            return vec![];
        }
        if blocks == 1 {
            let chunk_bytes = self.size.min(self.block_size.bytes() as u64) as usize;
            let leaf_range = range_collections::RangeSet2::from(ChunkNum(0)..ChunkNum(1u64 << self.block_size.0));
            if leaf_range.is_disjoint(ranges) {
                return vec![];
            }
            return vec![BaoChunk::Leaf {
                start_chunk: 0,
                size: chunk_bytes,
                is_root: true,
            }];
        }
        let root = self.root();
        let mut items = Vec::new();
        self.pre_order_filtered_recurse(root, true, blocks, ranges, &mut items);
        items
    }

    fn pre_order_filtered_recurse(
        &self,
        node: TreeNode,
        is_root: bool,
        total_blocks: u64,
        ranges: &range_collections::RangeSetRef<ChunkNum>,
        out: &mut Vec<BaoChunk>,
    ) {
        // Check if this node's subtree overlaps the ranges (actual chunk space)
        let actual_range = self.node_actual_chunk_range(node);
        let node_chunks =
            range_collections::RangeSet2::from(actual_range.start..actual_range.end);
        if node_chunks.is_disjoint(ranges) {
            return;
        }

        let level = node.level();
        if level == 0 {
            let block_idx = node.0 / 2;
            let block_bytes = self.block_size.bytes() as u64;
            let start_byte = block_idx * block_bytes;
            let end_byte = ((block_idx + 1) * block_bytes).min(self.size);
            let size = if start_byte >= self.size {
                0
            } else {
                (end_byte - start_byte) as usize
            };
            out.push(BaoChunk::Leaf {
                start_chunk: block_idx * (1u64 << self.block_size.0),
                size,
                is_root,
            });
            return;
        }

        let right_exists = node.right_child().is_some_and(|rc| {
            let right_block_start = rc.chunk_range().start.0 / 2;
            right_block_start < total_blocks
        });

        if !right_exists {
            // Right subtree doesn't exist — skip parent, inherit is_root
            if let Some(left) = node.left_child() {
                self.pre_order_filtered_recurse(left, is_root, total_blocks, ranges, out);
            }
            return;
        }

        // Check which children actually overlap the requested ranges
        let left_child = node.left_child();
        let right_child = node.right_child();

        let left_overlaps = left_child.is_some_and(|lc| {
            let lr = self.node_actual_chunk_range(lc);
            let lcs = range_collections::RangeSet2::from(lr.start..lr.end);
            !lcs.is_disjoint(ranges)
        });
        let right_overlaps = right_child.is_some_and(|rc| {
            let rr = self.node_actual_chunk_range(rc);
            let rcs = range_collections::RangeSet2::from(rr.start..rr.end);
            !rcs.is_disjoint(ranges)
        });

        if !left_overlaps && !right_overlaps {
            // Neither child overlaps — shouldn't happen since we checked above
            return;
        }

        // Emit the parent — the hash pair is needed to verify children
        out.push(BaoChunk::Parent { node, is_root, left: left_overlaps, right: right_overlaps });

        // Only recurse into children that overlap the ranges
        if left_overlaps {
            if let Some(left) = left_child {
                self.pre_order_filtered_recurse(left, false, total_blocks, ranges, out);
            }
        }
        if right_overlaps {
            if let Some(right) = right_child {
                self.pre_order_filtered_recurse(right, false, total_blocks, ranges, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_node_level() {
        assert_eq!(TreeNode(0).level(), 0); // leaf
        assert_eq!(TreeNode(1).level(), 1); // level 1 parent
        assert_eq!(TreeNode(2).level(), 0); // leaf
        assert_eq!(TreeNode(3).level(), 2); // level 2 parent
        assert_eq!(TreeNode(7).level(), 3); // level 3 parent
    }

    #[test]
    fn tree_node_is_leaf() {
        assert!(TreeNode(0).is_leaf());
        assert!(!TreeNode(1).is_leaf());
        assert!(TreeNode(2).is_leaf());
        assert!(!TreeNode(3).is_leaf());
    }

    #[test]
    fn tree_node_children() {
        let parent = TreeNode(1);
        assert_eq!(parent.left_child(), Some(TreeNode(0)));
        assert_eq!(parent.right_child(), Some(TreeNode(2)));

        let leaf = TreeNode(0);
        assert_eq!(leaf.left_child(), None);
        assert_eq!(leaf.right_child(), None);

        let l2_parent = TreeNode(3);
        assert_eq!(l2_parent.left_child(), Some(TreeNode(1)));
        assert_eq!(l2_parent.right_child(), Some(TreeNode(5)));
    }

    #[test]
    fn tree_node_chunk_range() {
        assert_eq!(TreeNode(0).chunk_range(), ChunkNum(0)..ChunkNum(2));
        assert_eq!(TreeNode(1).chunk_range(), ChunkNum(0)..ChunkNum(4));
        assert_eq!(TreeNode(3).chunk_range(), ChunkNum(0)..ChunkNum(8));
    }

    #[test]
    fn block_size_bytes() {
        assert_eq!(BlockSize::ZERO.bytes(), 1024);
        assert_eq!(BlockSize::DEFAULT.bytes(), 16384);
        assert_eq!(BlockSize::from_chunk_log(1).bytes(), 2048);
    }

    #[test]
    fn block_size_from_bytes() {
        assert_eq!(BlockSize::from_bytes(1024), Some(BlockSize::ZERO));
        assert_eq!(BlockSize::from_bytes(16384), Some(BlockSize::DEFAULT));
        assert_eq!(BlockSize::from_bytes(512), None);
        assert_eq!(BlockSize::from_bytes(3000), None);
    }

    #[test]
    fn bao_tree_basic() {
        let tree = BaoTree::new(1024, BlockSize::ZERO);
        assert_eq!(tree.chunks(), ChunkNum(1));
        assert_eq!(tree.blocks(), 1);
        assert_eq!(tree.outboard_size(), 0);
    }

    #[test]
    fn bao_tree_two_blocks() {
        let tree = BaoTree::new(2048, BlockSize::ZERO);
        assert_eq!(tree.chunks(), ChunkNum(2));
        assert_eq!(tree.blocks(), 2);
        assert_eq!(tree.outboard_size(), 64); // one parent pair
    }

    #[test]
    fn bao_tree_empty() {
        let tree = BaoTree::new(0, BlockSize::ZERO);
        assert_eq!(tree.blocks(), 1); // min 1
        assert_eq!(tree.outboard_size(), 0);
    }

    #[test]
    fn bao_tree_large() {
        let tree = BaoTree::new(1_000_000, BlockSize::DEFAULT);
        assert!(tree.blocks() > 0);
        assert!(tree.outboard_size() > 0);
    }

    #[test]
    fn pre_order_single_block() {
        let tree = BaoTree::new(1024, BlockSize::ZERO);
        let chunks = tree.pre_order_chunks();
        assert_eq!(chunks.len(), 1);
        assert!(matches!(
            chunks[0],
            BaoChunk::Leaf {
                start_chunk: 0,
                size: 1024,
                is_root: true,
            }
        ));
    }

    #[test]
    fn pre_order_two_blocks() {
        let tree = BaoTree::new(2048, BlockSize::ZERO);
        let chunks = tree.pre_order_chunks();
        // Should be: Parent(root), Leaf(0), Leaf(1)
        assert_eq!(chunks.len(), 3);
        assert!(matches!(chunks[0], BaoChunk::Parent { is_root: true, .. }));
        assert!(matches!(
            chunks[1],
            BaoChunk::Leaf {
                start_chunk: 0,
                is_root: false,
                ..
            }
        ));
        assert!(matches!(
            chunks[2],
            BaoChunk::Leaf {
                start_chunk: 1,
                is_root: false,
                ..
            }
        ));
    }

    #[test]
    fn post_order_two_blocks() {
        let tree = BaoTree::new(2048, BlockSize::ZERO);
        let chunks = tree.post_order_chunks();
        // Should be: Leaf(0), Leaf(1), Parent(root)
        assert_eq!(chunks.len(), 3);
        assert!(matches!(
            chunks[0],
            BaoChunk::Leaf {
                start_chunk: 0,
                is_root: false,
                ..
            }
        ));
        assert!(matches!(
            chunks[1],
            BaoChunk::Leaf {
                start_chunk: 1,
                is_root: false,
                ..
            }
        ));
        assert!(matches!(chunks[2], BaoChunk::Parent { is_root: true, .. }));
    }

    #[test]
    fn pre_order_four_blocks() {
        let tree = BaoTree::new(4096, BlockSize::ZERO);
        let chunks = tree.pre_order_chunks();
        // Root parent, left parent, leaf 0, leaf 1, right parent, leaf 2, leaf 3
        assert_eq!(chunks.len(), 7);
        // First item is root parent
        assert!(matches!(chunks[0], BaoChunk::Parent { is_root: true, .. }));
        // All leaves are non-root
        let leaf_count = chunks
            .iter()
            .filter(|c| matches!(c, BaoChunk::Leaf { .. }))
            .count();
        assert_eq!(leaf_count, 4);
    }
}
