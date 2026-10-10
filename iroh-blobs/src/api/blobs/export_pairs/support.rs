use std::io;

use bytes::Bytes;
use cyber_bao::{io::Parent, ChunkNum, ChunkRanges, TreeNode, CHUNK_SIZE};
use hemera::tree::{chunk_cv, parent_cv};
use iroh::endpoint::VarInt;
use iroh_io::AsyncStreamWriter;
use irpc::channel::mpsc;

use super::super::{EncodedItem, ExportBaoProgress, Leaf, WriteProgress};
use crate::{
    provider::events::{AbortReason, ClientResult},
    store::IROH_BLOCK_SIZE,
    util::SendStream,
    Hash,
};

/// Independent affected-length root and parent-free wire, not an encoder oracle.
pub(super) fn root_policy_fixture() -> (Vec<u8>, crate::Hash, Vec<u8>) {
    let data = body(8192);
    let left = chunk_cv(&data[..4096], 0, false);
    let right = chunk_cv(&data[4096..], 1, false);
    let root = parent_cv(&left, &right, true);
    assert_eq!(
        root.to_string(),
        "2abf65dd26465a7352707d79d18ff3aab9ee5d97614a774619c79ed527e20190"
    );
    assert_eq!(root, hemera::tree::fixed_chunk_root(&data));
    let mut wire = 8192u64.to_le_bytes().to_vec();
    wire.extend_from_slice(&data);
    (data, root.into(), wire)
}

pub(super) const INDEX: u64 = 7;
pub(super) const OFFSET: u64 = 19;
pub(super) const PAYLOAD: &[u8] = b"payload";

pub(super) fn identity() -> Hash {
    hemera::Hash::from_bytes([0xa5; 32]).into()
}

pub(super) fn literal_items() -> Vec<EncodedItem> {
    vec![
        EncodedItem::Size(100),
        EncodedItem::Parent(Parent {
            node: TreeNode::new(1),
            pair: (
                hemera::Hash::from_bytes(core::array::from_fn(|i| i as u8)),
                hemera::Hash::from_bytes(core::array::from_fn(|i| (32 + i) as u8)),
            ),
        }),
        EncodedItem::Leaf(Leaf {
            offset: OFFSET,
            data: Bytes::from_static(PAYLOAD),
        }),
        EncodedItem::Done,
    ]
}

pub(super) fn literal_wire() -> Vec<u8> {
    let mut wire = 100u64.to_le_bytes().to_vec();
    wire.extend(0u8..64);
    wire.extend_from_slice(PAYLOAD);
    wire
}

pub(super) async fn scripted(items: Vec<EncodedItem>) -> ExportBaoProgress {
    let (tx, rx) = mpsc::channel(items.len());
    for item in items {
        tx.send(item).await.unwrap();
    }
    drop(tx);
    ExportBaoProgress::new(async move { Ok(rx) })
}

pub(super) fn geometry() -> (usize, usize) {
    assert_eq!(CHUNK_SIZE, 4096, "pinned Hemera chunk geometry");
    let bytes = IROH_BLOCK_SIZE.bytes();
    assert_eq!(bytes, 65536, "pinned provider block geometry");
    (bytes, bytes / CHUNK_SIZE)
}

pub(super) fn body(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i * 31 + i / CHUNK_SIZE) % 256) as u8)
        .collect()
}

pub(super) fn ranges(start: usize, end: usize) -> ChunkRanges {
    ChunkRanges::from(ChunkNum(start as u64)..ChunkNum(end as u64))
}

// Four explicit levels, independent of radio's outboard/tree traversal.
fn half_root(leaves: &[hemera::Hash]) -> hemera::Hash {
    assert_eq!(leaves.len(), 16);
    let p: [_; 8] = core::array::from_fn(|i| parent_cv(&leaves[2 * i], &leaves[2 * i + 1], false));
    let q: [_; 4] = core::array::from_fn(|i| parent_cv(&p[2 * i], &p[2 * i + 1], false));
    let r: [_; 2] = core::array::from_fn(|i| parent_cv(&q[2 * i], &q[2 * i + 1], false));
    parent_cv(&r[0], &r[1], false)
}

pub(super) fn right_fixture() -> (Vec<u8>, hemera::Hash, Vec<u8>) {
    let (block, chunks) = geometry();
    let data = body(2 * block);
    let leaves: Vec<_> = data
        .chunks_exact(CHUNK_SIZE)
        .enumerate()
        .map(|(i, bytes)| chunk_cv(bytes, i as u64, false))
        .collect();
    let left = half_root(&leaves[..chunks]);
    let right = half_root(&leaves[chunks..]);
    let root = parent_cv(&left, &right, true);
    let mut wire = (data.len() as u64).to_le_bytes().to_vec();
    wire.extend_from_slice(left.as_bytes());
    wire.extend_from_slice(right.as_bytes());
    wire.extend_from_slice(&data[block..]);
    (data, root, wire)
}

#[derive(Debug, Default)]
pub(super) struct Sink {
    pub bytes: Vec<u8>,
    pub calls: usize,
    pub fail_call: Option<usize>,
    pub partial: usize,
}

impl Sink {
    fn accept(&mut self, data: &[u8]) -> io::Result<()> {
        let call = self.calls;
        self.calls += 1;
        if self.fail_call == Some(call) {
            self.bytes
                .extend_from_slice(&data[..self.partial.min(data.len())]);
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "pair sink failure",
            ));
        }
        self.bytes.extend_from_slice(data);
        Ok(())
    }
}

impl AsyncStreamWriter for Sink {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.accept(data)
    }
    async fn write_bytes(&mut self, data: Bytes) -> io::Result<()> {
        self.accept(&data)
    }
    async fn sync(&mut self) -> io::Result<()> {
        panic!("exporter unexpectedly synced")
    }
}

impl SendStream for Sink {
    async fn send_bytes(&mut self, bytes: Bytes) -> io::Result<()> {
        self.accept(&bytes)
    }
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.accept(bytes)
    }
    async fn sync(&mut self) -> io::Result<()> {
        panic!("exporter unexpectedly synced")
    }
    fn reset(&mut self, _: VarInt) -> io::Result<()> {
        panic!("exporter unexpectedly reset")
    }
    async fn stopped(&mut self) -> io::Result<Option<VarInt>> {
        panic!("exporter unexpectedly queried stop")
    }
    fn id(&self) -> u64 {
        panic!("exporter unexpectedly queried id")
    }
}

#[derive(Debug, Default)]
pub(super) struct Progress {
    pub starts: Vec<(u64, Hash, u64)>,
    pub overhead: usize,
    pub payloads: Vec<(u64, u64, usize)>,
    pub reject_payload: bool,
}

impl WriteProgress for Progress {
    async fn notify_payload_write(&mut self, index: u64, offset: u64, len: usize) -> ClientResult {
        self.payloads.push((index, offset, len));
        if self.reject_payload {
            return Err(AbortReason::Permission.into());
        }
        Ok(())
    }
    fn log_other_write(&mut self, len: usize) {
        self.overhead += len;
    }
    async fn send_transfer_started(&mut self, index: u64, hash: &Hash, size: u64) {
        self.starts.push((index, *hash, size));
    }
}
