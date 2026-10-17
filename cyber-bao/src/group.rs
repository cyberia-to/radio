//! Incremental fixed-chunk group hashing with a fixed frontier.
//!
//! This computes a hash only; it does not authenticate data or a particle/root
//! association. Each pending step calls one backend kernel, on at most 4096 input
//! bytes or two child hashes. Arbitrary backend code and hash destructors retain
//! their own cost and allocation behavior.

use core::fmt;

use crate::{CHUNK_SIZE, HashBackend};

/// A group cannot be represented by the backend's absolute chunk counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupHashError {
    /// The input length does not fit in a u64 (unreachable on <=64-bit targets).
    InputTooLarge,
    /// The last absolute chunk counter would exceed u64::MAX.
    CounterOverflow,
}

impl fmt::Display for GroupHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InputTooLarge => "group input length exceeds u64",
            Self::CounterOverflow => "group chunk counter overflows u64",
        })
    }
}

impl core::error::Error for GroupHashError {}

fn leaf_count(len: u64) -> u64 {
    (len / CHUNK_SIZE as u64 + u64::from(!len.is_multiple_of(CHUNK_SIZE as u64))).max(1)
}

fn validate_counter(len: u64, start: u64) -> Result<u64, GroupHashError> {
    let leaves = leaf_count(len);
    start
        .checked_add(leaves - 1)
        .ok_or(GroupHashError::CounterOverflow)?;
    Ok(leaves)
}

/// A resumable complete-left binary reduction over fixed 4096-byte chunks.
///
/// Construction and completed polls call no backend method. Every pending
/// [`step`](Self::step) performs exactly one leaf or parent kernel: for N chunks
/// (at least one, even for empty input), completion takes exactly 2*N-1 steps.
/// Only the completing kernel receives the requested root flag.
///
/// The caller owns scheduling: check [`is_complete`](Self::is_complete), admit
/// one unit from its persistent budget, then step. Intermediate steps return
/// `None` while `is_complete` is false; count kernel entries, not returned hashes.
/// No internal quota is renewed by polling. Backend panics have no recovery
/// contract. Hashes are moved, never cloned.
///
/// The frontier uses 53 slots: a u64 byte length needs at most 2^52 leaves;
/// before a leaf there are at most 52 complete peaks, plus the incoming leaf.
/// This fixed storage does not require allocation or a placeholder hash.
pub struct GroupHasher<'a, B: HashBackend> {
    backend: &'a B,
    remaining: &'a [u8],
    next_counter: u64,
    leaves: u64,
    processed: u64,
    frontier: [Option<B::Hash>; 53],
    occupied: usize,
    reductions: u32,
    root: bool,
    complete: bool,
}

impl<B: HashBackend> fmt::Debug for GroupHasher<'_, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupHasher")
            .field("remaining_bytes", &self.remaining.len())
            .field("processed_leaves", &self.processed)
            .field("leaves", &self.leaves)
            .field("occupied", &self.occupied)
            .field("is_complete", &self.complete)
            .finish_non_exhaustive()
    }
}

impl<'a, B: HashBackend> GroupHasher<'a, B> {
    /// Borrow a group and validate every counter before any hashing.
    ///
    /// Empty input is a single empty leaf. A sole leaf at u64::MAX is valid;
    /// two leaves starting there return [`GroupHashError::CounterOverflow`].
    pub fn new(
        backend: &'a B,
        data: &'a [u8],
        start_chunk: u64,
        is_root: bool,
    ) -> Result<Self, GroupHashError> {
        let len = u64::try_from(data.len()).map_err(|_| GroupHashError::InputTooLarge)?;
        let leaves = validate_counter(len, start_chunk)?;
        Ok(Self {
            backend,
            remaining: data,
            next_counter: start_chunk,
            leaves,
            processed: 0,
            frontier: core::array::from_fn(|_| None),
            occupied: 0,
            reductions: 0,
            root: is_root,
            complete: false,
        })
    }

    /// Whether the final hash has already been returned.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Perform one pending kernel and return the hash only on the final step.
    ///
    /// Intermediate steps return None with `is_complete() == false`. Completed
    /// polls return None with `is_complete() == true` and perform no kernel.
    pub fn step(&mut self) -> Option<B::Hash> {
        if self.complete {
            return None;
        }
        if self.reductions != 0 {
            let right = self.frontier[self.occupied - 1]
                .take()
                .expect("occupied right peak");
            let left = self.frontier[self.occupied - 2]
                .take()
                .expect("occupied left peak");
            let final_parent = self.processed == self.leaves && self.occupied == 2;
            let hash = self
                .backend
                .parent_hash(&left, &right, self.root && final_parent);
            self.occupied -= 1;
            self.reductions -= 1;
            if final_parent {
                self.complete = true;
                return Some(hash);
            }
            self.frontier[self.occupied - 1] = Some(hash);
        } else {
            let take = self.remaining.len().min(CHUNK_SIZE);
            let hash = self.backend.chunk_hash(
                &self.remaining[..take],
                self.next_counter,
                self.root && self.leaves == 1,
            );
            self.remaining = &self.remaining[take..];
            self.processed += 1;
            if self.leaves == 1 {
                self.complete = true;
                return Some(hash);
            }
            self.frontier[self.occupied] = Some(hash);
            self.occupied += 1;
            if self.processed == self.leaves {
                // Fold remaining complete peaks from right to left.
                self.reductions = (self.occupied - 1) as u32;
            } else {
                // Merge equal-size complete peaks before accepting another leaf.
                self.reductions = self.processed.trailing_zeros();
                self.next_counter += 1; // all used counters were validated in new
            }
        }
        None
    }
}

#[cfg(test)]
mod tests;
