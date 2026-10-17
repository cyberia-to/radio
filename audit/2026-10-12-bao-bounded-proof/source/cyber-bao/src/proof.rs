//! Strict complete-buffer proofs for the canonical fixed-4096 Hemera tree.
//!
//! Concrete Poseidon2 kernels, counters and domains are those of Hemera d5f0a095.
//! A proof is an LE u64 complete length, then selected preorder child pairs and
//! whole group payloads. Every hash is four canonical LE field words. Grouping
//! changes the carrier, not the complete ROOT; historical internal CVs are not
//! roots. Legacy std carrier APIs have their own, unchanged admission behavior.

use core::{fmt, ops::Range};
use hemera::{Hash, OUTPUT_BYTES, OUTPUT_ELEMENTS, field::P};

use crate::{
    BaoChunk, BlockSize, CHUNK_SIZE, HashBackend, Poseidon2Backend, TreeNode,
    group::GroupHasher,
    traversal::{RangeTraversal, RangeTraversalError},
};

mod output;
pub use output::{ProofItem, ProofItems, VerifiedProof};

static BACKEND: Poseidon2Backend = Poseidon2Backend;
const _: () = assert!(CHUNK_SIZE == 4096 && OUTPUT_BYTES == 32 && OUTPUT_ELEMENTS == 4);
const PAIR_BYTES: usize = 2 * OUTPUT_BYTES;

/// First failed admission or proof action; coordinates name the encoded proof
/// except for TreeNode indexes and absolute file chunk counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    Geometry(RangeTraversalError),
    EmptyRequest,
    NonCanonicalRoot { word: u8 },
    Truncated { offset: usize, needed: usize },
    SizeMismatch { expected: u64, declared: u64 },
    NonCanonicalHash { offset: usize },
    ParentMismatch { node: TreeNode },
    LeafMismatch { start_chunk: u64 },
    TrailingBytes { offset: usize },
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Geometry(e) => e.fmt(f),
            Self::EmptyRequest => f.write_str("empty request for nonempty file"),
            Self::NonCanonicalRoot { word } => write!(f, "noncanonical expected root word {word}"),
            Self::Truncated { offset, needed } => {
                write!(f, "truncated proof at {offset}: need {needed} bytes")
            }
            Self::SizeMismatch { expected, declared } => {
                write!(f, "proof size {declared} differs from expected {expected}")
            }
            Self::NonCanonicalHash { offset } => {
                write!(f, "noncanonical proof hash word at {offset}")
            }
            Self::ParentMismatch { node } => write!(f, "proof parent mismatch at node {}", node.0),
            Self::LeafMismatch { start_chunk } => {
                write!(f, "proof leaf mismatch at chunk {start_chunk}")
            }
            Self::TrailingBytes { offset } => write!(f, "trailing proof bytes at {offset}"),
        }
    }
}
impl core::error::Error for ProofError {}

struct Pending<'a> {
    reducer: GroupHasher<'a, Poseidon2Backend>,
    expected: Hash,
    start_chunk: u64,
}

/// Resumable verification against an externally trusted complete root and size.
///
/// A returned view authenticates selected bytes only relative to those supplied
/// inputs. This API establishes no particle/root association or Kadek authority.
/// It borrows the immutable encoded proof, acquires no owner and allocates nothing.
/// Cancellation is dropping the verifier; no byte-feeding/reset API is provided.
///
/// Each pending step performs one bounded action: header; one parent pair and
/// kernel; one group setup; one GroupHasher kernel (<=4096 bytes or two hashes);
/// or final EOF commit. For P visited parents and C selected fixed chunks, a valid
/// nonempty proof takes 2+P+2*C actions; empty file takes 4. Constructor/fixed-array
/// setup is bounded. These are work units, not constant wall time.
///
/// The caller checks is_finished, charges one persistent unit, then steps. Yields,
/// completed groups and subsequent output/copy must not renew its total allowance.
/// No exact-total planning scan or budget is hidden here. There are three separate
/// fixed frontiers: traversal, expected hashes, and the current group reducer.
pub struct ProofVerifier<'a> {
    proof: &'a [u8],
    root: [u8; OUTPUT_BYTES],
    size: u64,
    block: BlockSize,
    request: Range<u64>,
    traversal: RangeTraversal,
    expected: [Option<Hash>; 53],
    occupied: usize,
    cursor: usize,
    header: bool,
    empty_pending: bool,
    group: Option<Pending<'a>>,
    complete: bool,
    error: Option<ProofError>,
}

impl<'a> ProofVerifier<'a> {
    /// Admit geometry, reject empty requests for nonempty files, then check all
    /// expected-root words. Reads no proof bytes and performs no hash kernel.
    ///
    /// Geometry admits logs 0..=51 on 64-bit and 0..=19 on 32-bit, even for empty
    /// files. This concerns integer geometry, not allocation Layout or the safety
    /// of the same BlockSize in unchecked BaoTree helpers. Range requires
    /// start <= end <= size. Empty file 0..0 still requires its canonical ROOT.
    pub fn new(
        proof: &'a [u8],
        root: [u8; OUTPUT_BYTES],
        size: u64,
        block: BlockSize,
        request: Range<u64>,
    ) -> Result<Self, ProofError> {
        let traversal =
            RangeTraversal::new(size, block, request.clone()).map_err(ProofError::Geometry)?;
        if size != 0 && request.is_empty() {
            return Err(ProofError::EmptyRequest);
        }
        if let Some(word) = noncanonical(&root) {
            return Err(ProofError::NonCanonicalRoot { word });
        }
        Ok(Self {
            proof,
            root,
            size,
            block,
            request,
            traversal,
            expected: [None; 53],
            occupied: 0,
            cursor: 0,
            header: false,
            empty_pending: size == 0,
            group: None,
            complete: false,
            error: None,
        })
    }

    /// True after either exact EOF completion or a sticky processing error.
    pub fn is_finished(&self) -> bool {
        self.complete || self.error.is_some()
    }

    /// Perform one action. Pending returns None; only the separate EOF action
    /// emits Some(view). Successful terminal polls return None without work;
    /// failed terminal polls return the identical error without work.
    pub fn step(&mut self) -> Result<Option<VerifiedProof<'a>>, ProofError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.complete {
            return Ok(None);
        }
        let result = self.advance();
        if let Err(error) = result {
            self.error = Some(error);
            self.group = None;
        }
        result
    }

    fn advance(&mut self) -> Result<Option<VerifiedProof<'a>>, ProofError> {
        if !self.header {
            let declared = u64::from_le_bytes(self.take(8)?.try_into().expect("eight-byte header"));
            if declared != self.size {
                return Err(ProofError::SizeMismatch {
                    expected: self.size,
                    declared,
                });
            }
            self.expected[0] = Some(Hash::from_bytes(self.root));
            self.occupied = 1;
            self.header = true;
            return Ok(None);
        }
        if let Some(group) = self.group.as_mut() {
            if let Some(hash) = group.reducer.step() {
                if hash != group.expected {
                    return Err(ProofError::LeafMismatch {
                        start_chunk: group.start_chunk,
                    });
                }
                self.group = None;
            }
            return Ok(None);
        }
        if self.empty_pending {
            self.empty_pending = false;
            self.start_group(0, 0, true)?;
            return Ok(None);
        }
        if let Some(item) = self.traversal.next() {
            match item {
                BaoChunk::Parent {
                    node,
                    is_root,
                    left,
                    right,
                } => {
                    let offset = self.cursor;
                    let bytes = self.take(PAIR_BYTES)?;
                    let l = wire_hash(&bytes[..OUTPUT_BYTES], offset)?;
                    let r = wire_hash(&bytes[OUTPUT_BYTES..], offset + OUTPUT_BYTES)?;
                    let expected = self.pop();
                    if BACKEND.parent_hash(&l, &r, is_root) != expected {
                        return Err(ProofError::ParentMismatch { node });
                    }
                    if right {
                        self.push(r);
                    }
                    if left {
                        self.push(l);
                    }
                }
                BaoChunk::Leaf {
                    start_chunk,
                    size,
                    is_root,
                } => self.start_group(start_chunk, size, is_root)?,
            }
            return Ok(None);
        }
        assert_eq!(self.occupied, 0, "geometry consumes every expected hash");
        if self.cursor != self.proof.len() {
            return Err(ProofError::TrailingBytes {
                offset: self.cursor,
            });
        }
        self.complete = true;
        Ok(Some(VerifiedProof::new(
            self.proof,
            self.root,
            self.size,
            self.block,
            self.request.clone(),
        )))
    }

    fn take(&mut self, needed: usize) -> Result<&'a [u8], ProofError> {
        if needed > self.proof.len() - self.cursor {
            return Err(ProofError::Truncated {
                offset: self.cursor,
                needed,
            });
        }
        let start = self.cursor;
        self.cursor += needed;
        Ok(&self.proof[start..self.cursor])
    }

    fn start_group(&mut self, start_chunk: u64, size: usize, root: bool) -> Result<(), ProofError> {
        let data = self.take(size)?;
        let expected = self.pop();
        // Checked geometry bounds final counters by 2^52-1; admitted group sizes
        // fit usize/u64. Empty file is one zero-length leaf at counter zero.
        let reducer =
            GroupHasher::new(&BACKEND, data, start_chunk, root).expect("admitted group geometry");
        self.group = Some(Pending {
            reducer,
            expected,
            start_chunk,
        });
        Ok(())
    }
    fn pop(&mut self) -> Hash {
        self.occupied -= 1;
        self.expected[self.occupied]
            .take()
            .expect("expected hash follows geometry")
    }
    fn push(&mut self, hash: Hash) {
        // At most 52 deferred right siblings plus the current expectation.
        self.expected[self.occupied] = Some(hash);
        self.occupied += 1;
    }
}

fn noncanonical(bytes: &[u8; OUTPUT_BYTES]) -> Option<u8> {
    bytes
        .chunks_exact(8)
        .position(|word| u64::from_le_bytes(word.try_into().expect("eight-byte word")) >= P)
        .map(|word| word as u8)
}
fn wire_hash(bytes: &[u8], offset: usize) -> Result<Hash, ProofError> {
    let array = bytes.try_into().expect("one complete child hash");
    if let Some(word) = noncanonical(&array) {
        return Err(ProofError::NonCanonicalHash {
            offset: offset + usize::from(word) * 8,
        });
    }
    Ok(Hash::from_bytes(array))
}

impl fmt::Debug for ProofVerifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProofVerifier")
            .field("proof_bytes", &self.proof.len())
            .field("size", &self.size)
            .field("request", &self.request)
            .field("cursor", &self.cursor)
            .field("expected", &self.occupied)
            .field("group_pending", &self.group.is_some())
            .field("finished", &self.is_finished())
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
