mod fixtures;

use std::{future::Future, io, time::Duration};

use bytes::Bytes;
use cyber_bao::{
    io::{BaoContentItem, Outboard, Parent},
    BaoTree, ChunkRanges, TreeNode,
};
use fixtures::{body, ranges, three_groups, two_groups, Fixture, GROUP};

use super::{BaoFileHandle, CompleteStorage, MemStore, OutboardReader};
use crate::{
    api::{
        blobs::{BlobStatus, Blobs},
        Error, RequestError,
    },
    store::{util::PartialMemStorage, IROH_BLOCK_SIZE},
};

async fn bounded(test: impl Future<Output = ()>) {
    n0_future::time::timeout(Duration::from_secs(30), test)
        .await
        .expect("parent-pair workflow exceeded 30 seconds");
}

async fn complete(blobs: &Blobs, fixture: &Fixture) {
    assert_eq!(
        blobs.status(fixture.root).await.unwrap(),
        BlobStatus::Complete {
            size: fixture.data.len() as u64
        }
    );
    assert_eq!(
        blobs.get_bytes(fixture.root).await.unwrap().as_ref(),
        fixture.data
    );
    assert_eq!(
        blobs
            .export_bao(fixture.root, ChunkRanges::all())
            .bao_to_vec()
            .await
            .unwrap(),
        fixture.full()
    );
    assert_eq!(
        blobs
            .export_bao(fixture.root, ranges(16, 32))
            .bao_to_vec()
            .await
            .unwrap(),
        fixture.middle()
    );
}

#[tokio::test]
async fn right_partial_then_complete_and_repeat() {
    bounded(async {
        let fixture = two_groups();
        let store = MemStore::new();
        store
            .import_bao_bytes(fixture.root, ranges(16, 32), fixture.middle())
            .await
            .unwrap();
        assert_eq!(
            store.status(fixture.root).await.unwrap(),
            BlobStatus::Partial { size: Some(131072) }
        );
        assert_eq!(
            store
                .export_bao(fixture.root, ranges(16, 32))
                .bao_to_vec()
                .await
                .unwrap(),
            fixture.middle()
        );
        store
            .import_bao_bytes(
                fixture.root,
                ranges(0, 16),
                fixture.wire(&fixture.data[..GROUP]),
            )
            .await
            .unwrap();
        complete(&store, &fixture).await;
        store
            .import_bao_bytes(fixture.root, ChunkRanges::all(), fixture.full())
            .await
            .unwrap();
        complete(&store, &fixture).await;
        store.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn three_group_nonzero_parent_ordinal() {
    bounded(async {
        let fixture = three_groups();
        let store = MemStore::new();
        store
            .import_bao_bytes(fixture.root, ChunkRanges::all(), fixture.full())
            .await
            .unwrap();
        complete(&store, &fixture).await;
        store.shutdown().await.unwrap();
    })
    .await;
}

async fn corruption(offset: usize, detail: &str) {
    let fixture = two_groups();
    let store = MemStore::new();
    let mut corrupt = fixture.middle();
    corrupt[offset] ^= 1;
    let error = store
        .import_bao_bytes(fixture.root, ranges(16, 32), corrupt)
        .await
        .unwrap_err();
    let RequestError::Inner {
        source: Error::Io(error),
        ..
    } = error
    else {
        panic!("expected verified input error: {error:?}");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), detail);
    assert_eq!(
        store.status(fixture.root).await.unwrap(),
        BlobStatus::Partial { size: None }
    );
    store
        .import_bao_bytes(fixture.root, ranges(16, 32), fixture.middle())
        .await
        .unwrap();
    assert_eq!(
        store.status(fixture.root).await.unwrap(),
        BlobStatus::Partial { size: Some(131072) }
    );
    assert_eq!(
        store
            .export_bao(fixture.root, ranges(16, 32))
            .bao_to_vec()
            .await
            .unwrap(),
        fixture.middle()
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn corrupted_parent_rejected_then_valid_retry() {
    bounded(corruption(8, "parent hash mismatch at node 1")).await;
}

#[tokio::test]
async fn corrupted_leaf_rejected_then_valid_retry() {
    bounded(corruption(72, "leaf hash mismatch at chunk 16")).await;
}

#[tokio::test]
async fn parent_free_control() {
    bounded(async {
        let data = body(4096);
        let root = hemera::tree::chunk_cv(&data, 0, true).into();
        let mut wire = 4096u64.to_le_bytes().to_vec();
        wire.extend_from_slice(&data);
        let store = MemStore::new();
        store
            .import_bao_bytes(root, ranges(0, 1), wire.clone())
            .await
            .unwrap();
        assert_eq!(
            store.status(root).await.unwrap(),
            BlobStatus::Complete { size: 4096 }
        );
        assert_eq!(store.get_bytes(root).await.unwrap().as_ref(), data);
        assert_eq!(
            store
                .export_bao(root, ranges(0, 1))
                .bao_to_vec()
                .await
                .unwrap(),
            wire
        );
        store.shutdown().await.unwrap();
    })
    .await;
}

#[cfg(feature = "fs-store")]
#[tokio::test]
async fn fs_complete_memory_batch_and_reopen() {
    use crate::store::fs::{options::Options, FsStore};
    bounded(async {
        let fixture = three_groups();
        let dir = tempfile::tempdir().unwrap();
        let mut options = Options::new(dir.path());
        options.inline.max_data_inlined = 196608;
        options.inline.max_outboard_inlined = 128;
        assert!(options.is_inlined_data(196608));
        assert!(!options.is_inlined_data(196609));
        assert!(options.is_inlined_outboard(128));
        assert!(!options.is_inlined_outboard(129));
        assert_eq!(BaoTree::new(196608, IROH_BLOCK_SIZE).outboard_size(), 128);
        let db = dir.path().join("blobs.db");
        let store = FsStore::load_with_opts(db.clone(), options.clone())
            .await
            .unwrap();
        // Parent(3), Parent(1), Leaf(A), Leaf(B), Leaf(C): one complete batch.
        store
            .import_bao_bytes(fixture.root, ChunkRanges::all(), fixture.full())
            .await
            .unwrap();
        complete(&store, &fixture).await;
        store.shutdown().await.unwrap();
        drop(store);
        let store = FsStore::load_with_opts(db, options).await.unwrap();
        complete(&store, &fixture).await;
        store.shutdown().await.unwrap();
    })
    .await;
}

#[test]
fn literal_pair_storage() {
    let pair = (
        hemera::Hash::from_bytes(core::array::from_fn(|i| i as u8)),
        hemera::Hash::from_bytes(core::array::from_fn(|i| (32 + i) as u8)),
    );
    let mut storage = PartialMemStorage::default();
    storage
        .write_batch(
            131072,
            &[BaoContentItem::Parent(Parent {
                node: TreeNode::new(1),
                pair,
            })],
        )
        .unwrap();
    assert_eq!(storage.outboard.as_ref(), (0u8..64).collect::<Vec<_>>());
}

#[test]
fn short_pair_reader_error() {
    let hash = hemera::Hash::from_bytes([0; 32]);
    let data = BaoFileHandle::new_partial(hash.into());
    data.0
        .state
        .send_replace(CompleteStorage::new(Bytes::new(), Bytes::from(vec![0; 63])).into());
    let reader = OutboardReader {
        hash,
        tree: BaoTree::new(131072, IROH_BLOCK_SIZE),
        data,
    };
    let error = reader.load(TreeNode::new(1)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(error.to_string(), "short read");
}

#[test]
fn diagnostic_one_pair() {
    super::print_outboard(&[0; 64]);
}

#[test]
fn diagnostic_two_pairs() {
    super::print_outboard(&[0; 128]);
}

#[test]
#[should_panic(expected = "assertion failed: hashes.len().is_multiple_of(HASH_PAIR_BYTES)")]
fn diagnostic_rejects_partial_pair() {
    super::print_outboard(&[0; 96]);
}
