//! Existing allocation-backed tree traversals.
use super::*;

impl BaoTree {
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
        out.push(BaoChunk::Parent {
            node,
            is_root,
            left: true,
            right: true,
        });

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
        out.push(BaoChunk::Parent {
            node,
            is_root,
            left: true,
            right: true,
        });
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
            let leaf_range = range_collections::RangeSet2::from(
                ChunkNum(0)..ChunkNum(1u64 << self.block_size.0),
            );
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
        let node_chunks = range_collections::RangeSet2::from(actual_range.start..actual_range.end);
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
        out.push(BaoChunk::Parent {
            node,
            is_root,
            left: left_overlaps,
            right: right_overlaps,
        });

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
