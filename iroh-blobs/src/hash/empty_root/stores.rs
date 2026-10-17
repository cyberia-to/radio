use std::io;

use bytes::Bytes;
use cyber_bao::ChunkRanges;
use tokio::io::AsyncReadExt;

use super::{bounded, hello_wire, root, EMPTY_HEX, HELLO_HEX};
use crate::{
    api::{
        blobs::{Bitfield, BlobStatus, Blobs},
        Error, RequestError,
    },
    store::{mem::MemStore, readonly_mem::ReadonlyMemStore},
    BlobFormat, Hash,
};

async fn complete(blobs: &Blobs) {
    let hash = root(EMPTY_HEX);
    assert_eq!(
        blobs.status(hash).await.unwrap(),
        BlobStatus::Complete { size: 0 }
    );
    assert!(blobs.get_bytes(hash).await.unwrap().is_empty());
    let mut bytes = Vec::new();
    assert_eq!(blobs.reader(hash).read_to_end(&mut bytes).await.unwrap(), 0);
    assert!(bytes.is_empty());
    assert_eq!(blobs.observe(hash).await.unwrap(), Bitfield::complete(0));
    assert_eq!(
        blobs.observe(hash).await_completion().await.unwrap(),
        Bitfield::complete(0)
    );
    let wire = blobs
        .export_bao(hash, ChunkRanges::all())
        .bao_to_vec()
        .await
        .unwrap();
    assert_eq!(wire.len(), 8);
    assert_eq!(wire, [0; 8]);
}

#[tokio::test]
async fn memory_add_read_observe_export() {
    bounded(async {
        let store = MemStore::new();
        let tag = store.add_bytes(Bytes::new()).temp_tag().await.unwrap();
        assert_eq!(tag.hash(), root(EMPTY_HEX));
        complete(&store).await;
        drop(tag);
        for format in [BlobFormat::Raw, BlobFormat::HashSeq] {
            let tag = store
                .add_bytes_with_opts((Bytes::new(), format))
                .temp_tag()
                .await
                .unwrap();
            assert_eq!(tag.hash(), root(EMPTY_HEX));
            assert_eq!(tag.format(), format);
            complete(&store).await;
            drop(tag);
        }
        store.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn readonly_computed_key_control() {
    bounded(async {
        let store = ReadonlyMemStore::new([b"".as_slice()]);
        assert_eq!(store.list().hashes().await.unwrap(), [root(EMPTY_HEX)]);
        complete(&store).await;
        store.shutdown().await.unwrap();
    })
    .await;
}

#[cfg(feature = "fs-store")]
#[tokio::test]
async fn fs_add_formats_and_synthetic_reopen() {
    use crate::store::fs::FsStore;
    bounded(async {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("blobs.db");
        let store = FsStore::load(&db).await.unwrap();
        for format in [BlobFormat::Raw, BlobFormat::HashSeq] {
            let tag = store
                .add_bytes_with_opts((Bytes::new(), format))
                .temp_tag()
                .await
                .unwrap();
            assert_eq!(tag.hash(), root(EMPTY_HEX));
            assert_eq!(tag.format(), format);
            complete(&store).await;
            drop(tag);
        }
        let exported = dir.path().join("empty.bin");
        store.export(root(EMPTY_HEX), &exported).await.unwrap();
        assert_eq!(std::fs::read(exported).unwrap(), b"");
        store.shutdown().await.unwrap();
        drop(store);
        // Empty is synthetic on both opens; this does not prove persistence.
        let store = FsStore::load(&db).await.unwrap();
        complete(&store).await;
        store.shutdown().await.unwrap();
    })
    .await;
}

#[cfg(feature = "fs-store")]
#[tokio::test]
async fn fs_synthetic_status_enumeration_and_nonempty_control() {
    use crate::{api::blobs::DeleteOptions, store::fs::FsStore};
    bounded(async {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("blobs.db");
        let store = FsStore::load(&db).await.unwrap();
        let empty = root(EMPTY_HEX);
        let hello = root(HELLO_HEX);
        let zero = Hash::from_bytes([0; 32]);
        // Measured before the status repair: fresh and after-empty-add lists are empty.
        assert!(store.list().hashes().await.unwrap().is_empty());
        complete(&store).await;
        assert!(store.has(empty).await.unwrap());
        for absent in [zero, hello] {
            assert_eq!(store.status(absent).await.unwrap(), BlobStatus::NotFound);
            assert!(!store.has(absent).await.unwrap());
        }
        let tag = store.add_bytes(Bytes::new()).temp_tag().await.unwrap();
        assert_eq!(tag.hash(), empty);
        assert!(store.list().hashes().await.unwrap().is_empty());
        drop(tag);
        let tag = store
            .add_bytes(Bytes::from_static(b"hello"))
            .temp_tag()
            .await
            .unwrap();
        assert_eq!(tag.hash(), hello);
        hello_complete(&store).await;
        assert_eq!(store.list().hashes().await.unwrap(), [hello]);
        drop(tag);
        store.shutdown().await.unwrap();
        drop(store);

        let store = FsStore::load(&db).await.unwrap();
        complete(&store).await;
        assert!(store.has(empty).await.unwrap());
        hello_complete(&store).await;
        assert_eq!(store.list().hashes().await.unwrap(), [hello]);
        // The crate-private GC deletion route cannot remove synthetic availability.
        store
            .delete_with_opts(DeleteOptions {
                hashes: vec![empty],
                force: true,
            })
            .await
            .unwrap();
        complete(&store).await;
        assert_eq!(store.list().hashes().await.unwrap(), [hello]);
        assert_eq!(store.status(zero).await.unwrap(), BlobStatus::NotFound);
        assert!(!store.has(zero).await.unwrap());
        store.shutdown().await.unwrap();
    })
    .await;
}

#[cfg(feature = "fs-store")]
async fn hello_complete(blobs: &Blobs) {
    let hello = root(HELLO_HEX);
    assert_eq!(
        blobs.status(hello).await.unwrap(),
        BlobStatus::Complete { size: 5 }
    );
    assert!(blobs.has(hello).await.unwrap());
    assert_eq!(blobs.get_bytes(hello).await.unwrap().as_ref(), b"hello");
    assert_eq!(
        blobs
            .export_bao(hello, ChunkRanges::all())
            .bao_to_vec()
            .await
            .unwrap(),
        hello_wire()
    );
}

#[tokio::test]
async fn local_canonical_zero_header_admission() {
    bounded(async {
        let store = MemStore::new();
        let rest = store
            .import_bao_reader(
                root(EMPTY_HEX),
                ChunkRanges::all(),
                Bytes::from_static(&[0; 8]),
            )
            .await
            .unwrap();
        assert!(rest.is_empty()); // Guard-only; no claim of actor publication.
        store.shutdown().await.unwrap();
    })
    .await;
}

fn assert_io(error: RequestError, kind: io::ErrorKind, detail: Option<&str>) {
    let RequestError::Inner {
        source: Error::Io(error),
        ..
    } = error
    else {
        panic!("expected wrapped input IO error: {error:?}");
    };
    assert_eq!(error.kind(), kind);
    if let Some(detail) = detail {
        assert_eq!(error.to_string(), detail);
    }
}

#[tokio::test]
async fn local_zero_header_rejects_wrong_keys() {
    bounded(async {
        let store = MemStore::new();
        for hash in [Hash::from_bytes([0; 32]), root(HELLO_HEX)] {
            let error = store
                .import_bao_reader(hash, ChunkRanges::all(), Bytes::from_static(&[0; 8]))
                .await
                .unwrap_err();
            assert_io(error, io::ErrorKind::Other, Some("invalid size for hash"));
        }
        store.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn local_short_header_is_unexpected_eof() {
    bounded(async {
        let store = MemStore::new();
        let error = store
            .import_bao_reader(
                root(EMPTY_HEX),
                ChunkRanges::all(),
                Bytes::from_static(&[0; 7]),
            )
            .await
            .unwrap_err();
        assert_io(error, io::ErrorKind::UnexpectedEof, None);
        store.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn local_hello_runs_actual_decoder_and_import() {
    bounded(async {
        let store = MemStore::new();
        let hash = root(HELLO_HEX);
        let rest = store
            .import_bao_reader(hash, ChunkRanges::all(), Bytes::from(hello_wire()))
            .await
            .unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            store.status(hash).await.unwrap(),
            BlobStatus::Complete { size: 5 }
        );
        assert_eq!(store.get_bytes(hash).await.unwrap().as_ref(), b"hello");
        assert_eq!(
            store
                .export_bao(hash, ChunkRanges::all())
                .bao_to_vec()
                .await
                .unwrap(),
            hello_wire()
        );
        store.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn zero_key_has_no_empty_alias() {
    bounded(async {
        let store = MemStore::new();
        let zero = Hash::from_bytes([0; 32]);
        assert_eq!(store.status(zero).await.unwrap(), BlobStatus::NotFound);
        let observation = store.observe(zero).await.unwrap();
        assert_eq!(observation, Bitfield::empty());
        assert!(!observation.is_complete());
        // Observation creates a partial handle; do not demand NotFound afterward.
        store.shutdown().await.unwrap();
    })
    .await;
}
