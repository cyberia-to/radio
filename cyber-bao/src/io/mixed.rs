//! Mixed I/O: sync read + async send for streaming BAO transfer.
//!
//! This module provides the server-side streaming encode path, where
//! outboard and data are read synchronously but items are sent
//! asynchronously over the network.

use std::future::Future;

use smallvec::SmallVec;

use crate::hash::HashBackend;
use crate::io::content::{Leaf, Parent};
use crate::io::error::EncodeError;
use crate::io::traits::{Outboard, ReadBytesAt};
use crate::tree::{BaoChunk, BaoTree, ChunkNum, CHUNK_SIZE};
use crate::ChunkRanges;

/// An item in the encoded BAO stream.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EncodedItem {
    /// The total size of the blob.
    Size(u64),
    /// A parent hash pair.
    Parent(Parent<hemera::Hash>),
    /// A leaf data chunk.
    Leaf(Leaf),
    /// An encoding error occurred.
    Error(EncodeError),
    /// Stream is complete.
    Done,
}

impl From<EncodeError> for EncodedItem {
    fn from(e: EncodeError) -> Self {
        EncodedItem::Error(e)
    }
}

/// Trait for sending encoded items (async).
pub trait Sender {
    /// Error type for send failures.
    type Error;

    /// Send an encoded item.
    fn send(&mut self, item: EncodedItem) -> impl Future<Output = Result<(), Self::Error>> + '_;
}

/// Walk the tree in pre-order, validate parent/leaf hashes, and send
/// `EncodedItem`s through the sender.
///
/// This is the core server-side streaming encode function.
pub async fn traverse_ranges_validated<D, O, S>(
    data: D,
    outboard: O,
    ranges: &ChunkRanges,
    send: &mut S,
) -> Result<(), S::Error>
where
    D: ReadBytesAt,
    O: Outboard<Hash = hemera::Hash>,
    S: Sender,
{
    let tree = outboard.tree();
    send.send(EncodedItem::Size(tree.size())).await?;
    let res = match traverse_impl(&data, &outboard, ranges, send, tree).await {
        Ok(Ok(())) => EncodedItem::Done,
        Err(send_err) => return Err(send_err),
        Ok(Err(encode_err)) => EncodedItem::Error(encode_err),
    };
    send.send(res).await
}

async fn traverse_impl<D, O, S>(
    data: &D,
    outboard: &O,
    ranges: &ChunkRanges,
    send: &mut S,
    tree: BaoTree,
) -> Result<Result<(), EncodeError>, S::Error>
where
    D: ReadBytesAt,
    O: Outboard<Hash = hemera::Hash>,
    S: Sender,
{
    use crate::hash::Poseidon2Backend;
    let backend = Poseidon2Backend;

    let pre_order = tree.pre_order_chunks_filtered(ranges);
    let mut stack: SmallVec<[hemera::Hash; 10]> = SmallVec::new();
    stack.push(outboard.root());

    let block_size = tree.block_size();

    for chunk in &pre_order {
        match chunk {
            BaoChunk::Parent { node, is_root, left, right } => {
                let pair = match outboard.load(*node) {
                    Ok(Some(pair)) => pair,
                    Ok(None) => {
                        return Ok(Err(EncodeError::ParentHashMismatch(*node)));
                    }
                    Err(e) => return Ok(Err(EncodeError::Io(e))),
                };
                let computed = backend.parent_hash(&pair.0, &pair.1, *is_root);
                let expected = match stack.pop() {
                    Some(h) => h,
                    None => return Ok(Err(EncodeError::ParentHashMismatch(*node))),
                };
                if computed != expected {
                    return Ok(Err(EncodeError::ParentHashMismatch(*node)));
                }
                // Only push hashes for children that will be visited
                if *right {
                    stack.push(pair.1.clone());
                }
                if *left {
                    stack.push(pair.0.clone());
                }

                send.send(EncodedItem::Parent(Parent {
                    node: *node,
                    pair,
                }))
                .await?;
            }
            BaoChunk::Leaf {
                start_chunk,
                size,
                is_root,
            } => {
                let byte_start = *start_chunk * CHUNK_SIZE as u64;
                let leaf_data = match data.read_bytes_at(byte_start, *size) {
                    Ok(d) => d,
                    Err(e) => return Ok(Err(EncodeError::Io(e))),
                };

                let chunk_num = ChunkNum(*start_chunk);
                let computed =
                    hash_block(&backend, &leaf_data, *start_chunk, *is_root, block_size.bytes());
                let expected = match stack.pop() {
                    Some(h) => h,
                    None => return Ok(Err(EncodeError::LeafHashMismatch(chunk_num))),
                };
                if computed != expected {
                    return Ok(Err(EncodeError::LeafHashMismatch(chunk_num)));
                }

                send.send(EncodedItem::Leaf(Leaf {
                    offset: byte_start,
                    data: leaf_data,
                }))
                .await?;
            }
        }
    }

    Ok(Ok(()))
}

use super::hash_block;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::pre_order::PreOrderMemOutboard;
    use crate::tree::BlockSize;

    struct VecSender(Vec<EncodedItem>);

    impl Sender for VecSender {
        type Error = std::convert::Infallible;

        async fn send(&mut self, item: EncodedItem) -> Result<(), Self::Error> {
            self.0.push(item);
            Ok(())
        }
    }

    #[tokio::test]
    async fn traverse_sends_size_then_items_then_done() {
        let data: Vec<u8> = (0..CHUNK_SIZE * 2).map(|i| (i % 251) as u8).collect();
        let outboard = PreOrderMemOutboard::create(&data, BlockSize::ZERO);
        let mut sender = VecSender(Vec::new());

        traverse_ranges_validated(&data[..], &outboard, &ChunkRanges::all(), &mut sender)
            .await
            .expect("VecSender::send never fails");

        let items = sender.0;
        assert!(
            matches!(items.first(), Some(EncodedItem::Size(n)) if *n == data.len() as u64),
            "first item should announce the total size"
        );
        assert!(
            matches!(items.last(), Some(EncodedItem::Done)),
            "last item should be Done on a clean traversal"
        );

        let mut leaf_data = Vec::new();
        for item in &items {
            if let EncodedItem::Leaf(leaf) = item {
                leaf_data.extend_from_slice(&leaf.data);
            }
        }
        assert_eq!(leaf_data, data, "leaves should reassemble the original bytes");
    }

    #[tokio::test]
    async fn traverse_reports_root_mismatch_as_error_item_not_a_send_error() {
        let data: Vec<u8> = (0..CHUNK_SIZE * 2).map(|i| (i % 251) as u8).collect();
        let mut outboard = PreOrderMemOutboard::create(&data, BlockSize::ZERO);
        // Corrupt the root only; the children hashes loaded from `outboard`
        // are still genuine, so the top parent's recomputed hash no longer
        // matches the (wrong) expected root popped off the stack.
        outboard.root = hemera::Hash::from_bytes([0u8; hemera::OUTPUT_BYTES]);
        let mut sender = VecSender(Vec::new());

        traverse_ranges_validated(&data[..], &outboard, &ChunkRanges::all(), &mut sender)
            .await
            .expect("a hash mismatch is a protocol error, not a transport error");

        let items = sender.0;
        assert!(
            matches!(
                items.last(),
                Some(EncodedItem::Error(EncodeError::ParentHashMismatch(_)))
            ),
            "expected the final item to report the mismatch, got {:?}",
            items.last()
        );
        assert!(
            !items.iter().any(|i| matches!(i, EncodedItem::Done)),
            "a mismatched traversal must not report Done"
        );
    }
}
