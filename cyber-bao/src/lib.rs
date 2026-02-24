//! Poseidon2-BAO: verified streaming with Poseidon2 hash over Goldilocks.
//!
//! This crate provides BAO-style content-verified streaming using the
//! Poseidon2 algebraic hash function. The tree structure
//! and encoding formats are compatible with the original bao specification,
//! differing only in the hash function used.
//!
//! # Architecture
//!
//! - **`tree`**: Pure geometry — tree node indexing, chunk counting, block sizes
//! - **`hash`**: Pluggable hash backend trait with Poseidon2 implementation
//! - **`io`**: Encoding, decoding, outboard creation, and slice extraction

pub mod hash;
pub mod io;
pub mod tree;

pub use hash::{HashBackend, Poseidon2Backend};
pub use tree::{BaoChunk, BaoTree, BlockSize, ChunkNum, PostOrderChunkIter, TreeNode};

/// A set of chunk ranges (used for partial downloads, range requests, etc.).
pub type ChunkRanges = range_collections::RangeSet2<ChunkNum>;

/// Borrowed reference to chunk ranges.
pub type ChunkRangesRef = range_collections::RangeSetRef<ChunkNum>;

/// A set of byte ranges.
pub type ByteRanges = range_collections::RangeSet2<u64>;
