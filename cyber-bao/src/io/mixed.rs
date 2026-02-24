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
use crate::tree::{BaoChunk, BaoTree, ChunkNum};
use crate::ChunkRanges;

/// An item in the encoded BAO stream.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EncodedItem {
    /// The total size of the blob.
    Size(u64),
    /// A parent hash pair.
    Parent(Parent<cyber_poseidon2::Hash>),
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
    O: Outboard<Hash = cyber_poseidon2::Hash>,
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
    O: Outboard<Hash = cyber_poseidon2::Hash>,
    S: Sender,
{
    use crate::hash::Poseidon2Backend;
    let backend = Poseidon2Backend;

    let pre_order = tree.pre_order_chunks_filtered(ranges);
    let mut stack: SmallVec<[cyber_poseidon2::Hash; 10]> = SmallVec::new();
    stack.push(outboard.root());

    let block_size = tree.block_size();

    for chunk in &pre_order {
        match chunk {
            BaoChunk::Parent { node, is_root } => {
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
                // Push right then left (left will be popped first)
                stack.push(pair.1.clone());
                stack.push(pair.0.clone());

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
                let byte_start = *start_chunk * 1024;
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
