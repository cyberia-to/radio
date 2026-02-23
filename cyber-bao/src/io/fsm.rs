//! Async finite state machine for streaming BAO decode.
//!
//! `ResponseDecoder` reads from an async stream and yields verified
//! `BaoContentItem` chunks, allowing incremental download+verify.

use std::io;

use smallvec::SmallVec;

use crate::hash::HashBackend;
use crate::io::content::{BaoContentItem, Leaf, Parent};
use crate::io::error::DecodeError;
use crate::tree::{BaoChunk, BaoTree, ChunkNum, TreeNode};
use crate::ChunkRanges;

/// Async outboard mutation trait (for writing hash pairs during decode).
pub trait OutboardMut: Sized {
    /// Save a hash pair at the given node.
    fn save(
        &mut self,
        node: TreeNode,
        hash_pair: &(cyber_poseidon2::Hash, cyber_poseidon2::Hash),
    ) -> impl std::future::Future<Output = io::Result<()>> + '_;

    /// Flush pending writes.
    fn sync(&mut self) -> impl std::future::Future<Output = io::Result<()>> + '_;
}

/// Implements async OutboardMut for any sync OutboardMut.
impl<T: crate::io::traits::OutboardMut<Hash = cyber_poseidon2::Hash>> OutboardMut for T {
    fn save(
        &mut self,
        node: TreeNode,
        hash_pair: &(cyber_poseidon2::Hash, cyber_poseidon2::Hash),
    ) -> impl std::future::Future<Output = io::Result<()>> + '_ {
        let result = crate::io::traits::OutboardMut::save(self, node, hash_pair);
        std::future::ready(result)
    }

    fn sync(&mut self) -> impl std::future::Future<Output = io::Result<()>> + '_ {
        let result = crate::io::traits::OutboardMut::sync(self);
        std::future::ready(result)
    }
}

/// The state of the response decoder after calling `next()`.
#[derive(Debug)]
pub enum ResponseDecoderNext<R> {
    /// More items available. Contains the decoder and the next item/error.
    More(
        (
            ResponseDecoder<R>,
            Result<BaoContentItem<cyber_poseidon2::Hash>, DecodeError>,
        ),
    ),
    /// Decoding is complete.
    Done(R),
}

/// Async streaming BAO response decoder.
///
/// Reads encoded BAO data from an async reader, verifies each item
/// against the root hash, and yields `BaoContentItem` chunks.
pub struct ResponseDecoder<R> {
    inner: ResponseDecoderInner<R>,
}

struct ResponseDecoderInner<R> {
    hash: cyber_poseidon2::Hash,
    tree: BaoTree,
    encoded: R,
    stack: SmallVec<[cyber_poseidon2::Hash; 10]>,
    /// Pre-computed list of chunks to iterate
    items: Vec<BaoChunk>,
    /// Current position in the items list
    pos: usize,
}

impl<R> std::fmt::Debug for ResponseDecoder<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseDecoder")
            .field("tree", &self.inner.tree)
            .finish()
    }
}

impl<R: iroh_io::AsyncStreamReader> ResponseDecoder<R> {
    /// Create a new decoder for the given root hash, tree, and reader.
    pub fn new(
        hash: cyber_poseidon2::Hash,
        _ranges: ChunkRanges,
        tree: BaoTree,
        encoded: R,
    ) -> Self {
        let items = tree.pre_order_chunks();
        let mut stack = SmallVec::new();
        stack.push(hash.clone());
        Self {
            inner: ResponseDecoderInner {
                hash,
                tree,
                encoded,
                stack,
                items,
                pos: 0,
            },
        }
    }

    /// Get the tree geometry.
    pub fn tree(&self) -> BaoTree {
        self.inner.tree
    }

    /// Get the root hash.
    pub fn hash(&self) -> &cyber_poseidon2::Hash {
        &self.inner.hash
    }

    /// Consume the decoder and return the inner reader.
    pub fn finish(self) -> R {
        self.inner.encoded
    }

    /// Decode the next item from the stream.
    pub async fn next(mut self) -> ResponseDecoderNext<R> {
        match self.next0().await {
            Some(result) => ResponseDecoderNext::More((self, result)),
            None => ResponseDecoderNext::Done(self.inner.encoded),
        }
    }

    async fn next0(
        &mut self,
    ) -> Option<Result<BaoContentItem<cyber_poseidon2::Hash>, DecodeError>> {
        let inner = &mut self.inner;
        if inner.pos >= inner.items.len() {
            return None;
        }

        let chunk = inner.items[inner.pos].clone();
        inner.pos += 1;

        let backend = crate::hash::Poseidon2Backend;
        let block_bytes = inner.tree.block_size().bytes();

        match chunk {
            BaoChunk::Parent { node, is_root } => {
                // Read 64 bytes (hash pair)
                let pair_buf: [u8; 64] = match inner.encoded.read().await {
                    Ok(buf) => buf,
                    Err(e) => return Some(Err(DecodeError::Io(e))),
                };

                let left =
                    cyber_poseidon2::Hash::from_bytes(pair_buf[..32].try_into().unwrap());
                let right =
                    cyber_poseidon2::Hash::from_bytes(pair_buf[32..].try_into().unwrap());

                let computed = backend.parent_hash(&left, &right, is_root);
                let expected = match inner.stack.pop() {
                    Some(h) => h,
                    None => return Some(Err(DecodeError::ParentNotFound(node))),
                };

                if computed != expected {
                    return Some(Err(DecodeError::ParentHashMismatch(node)));
                }

                // Push children: right first, then left (left popped first)
                inner.stack.push(right.clone());
                inner.stack.push(left.clone());

                Some(Ok(BaoContentItem::Parent(Parent {
                    node,
                    pair: (left, right),
                })))
            }
            BaoChunk::Leaf {
                start_chunk,
                size,
                is_root,
            } => {
                // Read leaf data
                let leaf_data = match inner.encoded.read_bytes(size).await {
                    Ok(data) => {
                        if data.len() < size {
                            return Some(Err(DecodeError::Io(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "short read for leaf data",
                            ))));
                        }
                        data
                    }
                    Err(e) => return Some(Err(DecodeError::Io(e))),
                };

                let computed =
                    hash_block(&backend, &leaf_data, start_chunk, is_root, block_bytes);
                let expected = match inner.stack.pop() {
                    Some(h) => h,
                    None => {
                        return Some(Err(DecodeError::LeafNotFound(ChunkNum(start_chunk))));
                    }
                };

                if computed != expected {
                    return Some(Err(DecodeError::LeafHashMismatch(ChunkNum(start_chunk))));
                }

                let offset = start_chunk * 1024;
                Some(Ok(BaoContentItem::Leaf(Leaf {
                    offset,
                    data: leaf_data,
                })))
            }
        }
    }
}

use super::hash_block;

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use crate::hash::Poseidon2Backend;
    use crate::io::encode;
    use crate::tree::BlockSize;

    #[tokio::test]
    async fn fsm_decode_two_blocks() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 2048];
        let (root, encoded) = encode::encode(&backend, &data, BlockSize::ZERO);

        let tree = BaoTree::new(2048, BlockSize::ZERO);
        // Skip the 8-byte header (ResponseDecoder expects raw tree data)
        let encoded_bytes = Bytes::from(encoded[8..].to_vec());
        let decoder =
            ResponseDecoder::new(root, ChunkRanges::all(), tree, encoded_bytes);

        assert_eq!(decoder.tree(), tree);
        assert_eq!(*decoder.hash(), root);

        // Decode all items
        let mut current = decoder;
        let mut leaf_data = Vec::new();
        loop {
            match current.next().await {
                ResponseDecoderNext::More((dec, result)) => {
                    let item = result.expect("decode should succeed");
                    if let BaoContentItem::Leaf(leaf) = item {
                        leaf_data.extend_from_slice(&leaf.data);
                    }
                    current = dec;
                }
                ResponseDecoderNext::Done(_) => break,
            }
        }
        assert_eq!(leaf_data, data);
    }
}
