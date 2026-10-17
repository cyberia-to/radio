use core::{fmt, iter::FusedIterator, ops::Range};

use crate::{BaoChunk, BlockSize, CHUNK_SIZE, traversal::RangeTraversal};

/// Complete proof validation relative to the supplied root and complete size.
/// This sealed view does not establish a particle/root association. It retains
/// only immutable proof bytes and the admitted root/size/block/request tuple;
/// successful validation establishes the fixed eight-byte header for replay.
/// It can outlive its verifier, but cannot outlive or mutate the proof storage.
pub struct VerifiedProof<'a> {
    proof: &'a [u8],
    root: [u8; 32],
    size: u64,
    block: BlockSize,
    request: Range<u64>,
}
impl<'a> VerifiedProof<'a> {
    pub(super) fn new(
        proof: &'a [u8],
        root: [u8; 32],
        size: u64,
        block: BlockSize,
        request: Range<u64>,
    ) -> Self {
        Self {
            proof,
            root,
            size,
            block,
            request,
        }
    }
    pub fn root(&self) -> [u8; 32] {
        self.root
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn block_size(&self) -> BlockSize {
        self.block
    }
    /// The original half-open requested byte interval, independent of group cover.
    pub fn request(&self) -> Range<u64> {
        self.request.clone()
    }

    /// Start bounded geometry replay without scanning, rehashing or copying bytes.
    /// Each pending next is one separately chargeable parent/leaf action. A caller
    /// copies only the requested intersection of each whole leaf under its own
    /// persistent work/storage limits. An empty verified file emits no items.
    pub fn items(&self) -> ProofItems<'a> {
        ProofItems {
            proof: self.proof,
            cursor: 8,
            traversal: RangeTraversal::new(self.size, self.block, self.request.clone())
                .expect("sealed geometry"),
        }
    }
}

/// One output action. Public slice/coordinate values are not sealed authority;
/// obtain them through a completed view and its externally trusted root.
pub enum ProofItem<'a> {
    /// Opaque parent skip, exactly 64 encoded bytes. Count it positionally and
    /// charge its action; replay does not scan across it to find a payload.
    Parent,
    /// Whole selected group (only the final file group may be short).
    Leaf {
        file_offset: u64,
        proof_offset: usize,
        bytes: &'a [u8],
    },
}

/// Fixed-frontier output cursor. Every pending next returns one item; terminal
/// polls are fused, with no hashing, allocation or copying in any action.
pub struct ProofItems<'a> {
    proof: &'a [u8],
    cursor: usize,
    traversal: RangeTraversal,
}
impl ProofItems<'_> {
    /// True immediately after the final emission, or for an empty verified file.
    pub fn is_complete(&self) -> bool {
        self.traversal.is_complete()
    }
}
impl<'a> Iterator for ProofItems<'a> {
    type Item = ProofItem<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.traversal.next()? {
            BaoChunk::Parent { .. } => {
                self.cursor += super::PAIR_BYTES;
                Some(ProofItem::Parent)
            }
            BaoChunk::Leaf {
                start_chunk, size, ..
            } => {
                let proof_offset = self.cursor;
                self.cursor += size;
                // The sealed immutable proof already passed these exact extents;
                // checked traversal bounds start_chunk*4096 by the file length.
                Some(ProofItem::Leaf {
                    file_offset: start_chunk * CHUNK_SIZE as u64,
                    proof_offset,
                    bytes: &self.proof[proof_offset..self.cursor],
                })
            }
        }
    }
}
impl FusedIterator for ProofItems<'_> {}

impl fmt::Debug for VerifiedProof<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedProof")
            .field("proof_bytes", &self.proof.len())
            .field("root", &self.root)
            .field("size", &self.size)
            .field("block", &self.block)
            .field("request", &self.request)
            .finish()
    }
}
impl fmt::Debug for ProofItems<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProofItems")
            .field("proof_bytes", &self.proof.len())
            .field("cursor", &self.cursor)
            .field("complete", &self.is_complete())
            .finish()
    }
}
impl fmt::Debug for ProofItem<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parent => f.write_str("Parent"),
            Self::Leaf {
                file_offset,
                proof_offset,
                bytes,
            } => f
                .debug_struct("Leaf")
                .field("file_offset", file_offset)
                .field("proof_offset", proof_offset)
                .field("bytes", &bytes.len())
                .finish(),
        }
    }
}
