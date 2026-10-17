//! Checked, allocation-free preorder geometry for one byte range.
//!
//! This cursor emits geometry only. It does not parse a proof or authenticate
//! a particle, root, payload or empty request.

use core::{fmt, iter::FusedIterator, ops::Range};

use crate::{BaoChunk, BlockSize, CHUNK_SIZE, TreeNode};

/// Invalid geometry supplied to [`RangeTraversal::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeTraversalError {
    /// The group width cannot be represented by both u64 and usize.
    InvalidBlockSize,
    /// The byte range is reversed or extends beyond the file.
    InvalidRange,
}

impl fmt::Display for RangeTraversalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidBlockSize => "invalid traversal block size",
            Self::InvalidRange => "invalid traversal byte range",
        })
    }
}

impl core::error::Error for RangeTraversalError {}

#[derive(Debug, Clone, Copy)]
struct Frame {
    first: u64,
    count: u64,
    is_root: bool,
}

/// Preorder cursor over whole groups intersecting a half-open byte range.
///
/// Construction uses fixed storage for 53 frames. Each pending [`Iterator::next`]
/// pops one frame, pushes at most two children and returns one item, without
/// allocation, recursion, scanning or hashing. Pausing requires no extra state:
/// simply retain the cursor without calling `next`.
///
/// ROOT belongs to the complete file tree, even when the request selects only
/// one leaf. Parent flags identify children visited by this request; a parent
/// still describes a pair of hashes. An empty request is immediately complete
/// and emits no item; it makes no authentication claim.
pub struct RangeTraversal {
    size: u64,
    group_bytes: u64,
    selected: Range<u64>,
    frames: [Frame; 53],
    pending: usize,
}

impl fmt::Debug for RangeTraversal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RangeTraversal")
            .field("size", &self.size)
            .field("group_bytes", &self.group_bytes)
            .field("selected", &self.selected)
            .field("pending", &self.pending)
            .finish()
    }
}

impl RangeTraversal {
    /// Admit a file size, group width and half-open requested byte interval.
    ///
    /// Block geometry is validated before the request: the block log must be at
    /// most 51, and its byte width must fit usize. This admits logs 0..=51 on
    /// 64-bit targets and 0..=19 on 32-bit targets, even for a short or empty file.
    /// Width admission concerns integer geometry, not allocation layout validity.
    /// The request must satisfy `start <= end <= size`; an empty interval at EOF
    /// is valid. Only the final file group is clipped to its actual byte length.
    pub fn new(
        size: u64,
        block_size: BlockSize,
        request: Range<u64>,
    ) -> Result<Self, RangeTraversalError> {
        if block_size.0 > 51 {
            return Err(RangeTraversalError::InvalidBlockSize);
        }
        let group_bytes = (CHUNK_SIZE as u64) << block_size.0;
        usize::try_from(group_bytes).map_err(|_| RangeTraversalError::InvalidBlockSize)?;
        if request.start > request.end || request.end > size {
            return Err(RangeTraversalError::InvalidRange);
        }
        let mut result = Self {
            size,
            group_bytes,
            selected: 0..0,
            frames: [Frame {
                first: 0,
                count: 0,
                is_root: false,
            }; 53],
            pending: 0,
        };
        if request.start < request.end {
            result.selected = request.start / group_bytes..(request.end - 1) / group_bytes + 1;
            result.push(Frame {
                first: 0,
                count: size.div_ceil(group_bytes),
                is_root: true,
            });
        }
        Ok(result)
    }

    /// Whether no item remains, including immediately after the last emission.
    pub fn is_complete(&self) -> bool {
        self.pending == 0
    }

    fn push(&mut self, frame: Frame) {
        // N <= 2^52: at depth d <= 52, at most d deferred siblings plus
        // one current frame exist. Pop before pushing children preserves 53.
        self.frames[self.pending] = frame;
        self.pending += 1;
    }
}

impl Iterator for RangeTraversal {
    type Item = BaoChunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_complete() {
            return None;
        }
        self.pending -= 1;
        let frame = self.frames[self.pending];
        if frame.count == 1 {
            // first < N implies first * group_bytes <= size - 1. Subtract
            // before clipping: the next group's byte end need not fit u64.
            let start = frame.first * self.group_bytes;
            return Some(BaoChunk::Leaf {
                start_chunk: start / CHUNK_SIZE as u64,
                size: self.group_bytes.min(self.size - start) as usize,
                is_root: frame.is_root,
            });
        }
        let left_count = 1u64 << (frame.count - 1).ilog2();
        let middle = frame.first + left_count;
        let end = frame.first + frame.count;
        let left = self.selected.start < middle && frame.first < self.selected.end;
        let right = self.selected.start < end && middle < self.selected.end;
        if right {
            self.push(Frame {
                first: middle,
                count: frame.count - left_count,
                is_root: false,
            });
        }
        if left {
            self.push(Frame {
                first: frame.first,
                count: left_count,
                is_root: false,
            });
        }
        // middle < N <= 2^52, so this group-based index is below 2^53.
        Some(BaoChunk::Parent {
            node: TreeNode::new(2 * middle - 1),
            is_root: frame.is_root,
            left,
            right,
        })
    }
}

impl FusedIterator for RangeTraversal {}
