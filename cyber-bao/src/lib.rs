//! Poseidon2-BAO: verified streaming with Poseidon2 hash over Goldilocks.
//!
//! This crate provides BAO-style content-verified streaming using the
//! Poseidon2 algebraic hash function instead of BLAKE3. The tree structure
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
pub use tree::{BaoChunk, BaoTree, BlockSize, ChunkNum, TreeNode};
