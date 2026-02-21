//! Encoding, decoding, outboard creation, and slice extraction.
//!
//! All operations are parameterized by a `HashBackend`, making the
//! serialization format hash-agnostic.

pub mod decode;
pub mod encode;
pub mod outboard;
pub mod slice;
