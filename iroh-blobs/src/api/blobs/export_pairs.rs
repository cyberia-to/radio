//! Exercise the actual exporter with literal pairs and an independent store proof.
mod support;

use std::io;

use cyber_bao::{
    io::{slice::decode_slice, EncodeError},
    Poseidon2Backend, CHUNK_SIZE,
};
use n0_future::StreamExt;
use support::*;

use super::{EncodedItem, ExportBaoProgress};
use crate::{
    api::{Error, ExportBaoError},
    provider::events::ProgressError,
    store::{readonly_mem::ReadonlyMemStore, IROH_BLOCK_SIZE},
};

async fn chunks(export: ExportBaoProgress) -> Vec<Vec<u8>> {
    let mut stream = export.into_byte_stream();
    let mut chunks = Vec::new();
    while let Some(item) = stream.next().await {
        chunks.push(item.unwrap().to_vec());
    }
    chunks
}

#[test]
fn geometry_pins() {
    assert_eq!(geometry(), (65536, 16));
}

#[tokio::test]
async fn root_policy_readonly_memory_key_and_wire() {
    let (data, root, wire) = root_policy_fixture();
    let store = ReadonlyMemStore::new([&data]);
    let keys = store.list().hashes().await.unwrap();
    assert_eq!(keys, [root]);
    assert_eq!(root, crate::Hash::new(&data));
    assert_eq!(
        store
            .export_bao(keys[0], ranges(0, 2))
            .bao_to_vec()
            .await
            .unwrap(),
        wire
    );
    assert_eq!(store.get_bytes(keys[0]).await.unwrap().as_ref(), data);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn root_policy_mutable_memory_key_and_wire() {
    let (data, root, wire) = root_policy_fixture();
    let store = crate::store::mem::MemStore::new();
    let added = store.add_bytes(data.clone()).await.unwrap();
    assert_eq!(added.hash, root);
    assert_eq!(store.list().hashes().await.unwrap(), [root]);
    assert_eq!(root, crate::Hash::new(&data));
    assert_eq!(
        store
            .export_bao(added.hash, ranges(0, 2))
            .bao_to_vec()
            .await
            .unwrap(),
        wire
    );
    assert_eq!(store.get_bytes(added.hash).await.unwrap().as_ref(), data);
    store.shutdown().await.unwrap();
}

#[cfg(feature = "fs-store")]
#[tokio::test]
async fn root_policy_tiny_and_streamed_fs_import_agree() {
    use crate::store::fs::{options::Options, FsStore};

    let (data, root, wire) = root_policy_fixture();
    let mut keys = Vec::new();
    for (max_data_inlined, inlined) in [(32768, true), (4096, false)] {
        let dir = tempfile::tempdir().unwrap();
        let mut options = Options::new(dir.path());
        options.inline.max_data_inlined = max_data_inlined;
        options.inline.max_outboard_inlined = 16384;
        assert_eq!(options.is_inlined_all(8192), inlined);
        let store = FsStore::load_with_opts(dir.path().join("blobs.db"), options)
            .await
            .unwrap();
        let added = store.add_bytes(data.clone()).await.unwrap();
        keys.push(added.hash);
        assert_eq!(added.hash, root);
        assert_eq!(store.get_bytes(added.hash).await.unwrap().as_ref(), data);
        assert_eq!(
            store
                .export_bao(added.hash, ranges(0, 2))
                .bao_to_vec()
                .await
                .unwrap(),
            wire
        );
        store.shutdown().await.unwrap();
    }
    assert_eq!(keys, [root, root]);
    assert_eq!(root, crate::Hash::new(&data));
}

#[tokio::test]
async fn literal_parent_write() {
    let mut bytes = Vec::new();
    scripted(literal_items())
        .await
        .write(&mut bytes)
        .await
        .unwrap();
    assert_eq!(bytes, literal_wire());
}

#[tokio::test]
async fn literal_parent_progress() {
    let mut sink = Sink::default();
    let mut progress = Progress::default();
    scripted(literal_items())
        .await
        .write_with_progress(&mut sink, &mut progress, &identity(), INDEX)
        .await
        .unwrap();
    assert_eq!(sink.bytes, literal_wire());
    assert_eq!(progress.starts, [(INDEX, identity(), 100)]);
    assert_eq!(progress.overhead, 72);
    assert_eq!(progress.payloads, [(INDEX, OFFSET, PAYLOAD.len())]);
}

#[tokio::test]
async fn literal_parent_byte_stream() {
    let chunks = chunks(scripted(literal_items()).await).await;
    assert_eq!(
        chunks.iter().map(Vec::len).collect::<Vec<_>>(),
        [8, 64, PAYLOAD.len()]
    );
    assert_eq!(chunks.concat(), literal_wire());
}

#[tokio::test]
async fn readonly_store_right_block() {
    let (data, root, expected) = right_fixture();
    let (block, count) = geometry();
    assert_eq!(expected.len(), 8 + 2 * hemera::OUTPUT_BYTES + block);
    // Optional evidence output is only enabled by the isolated audit command.
    if let Some(dir) = std::env::var_os("RADIO_EXPORT_PAIRS_FIXTURE_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::write(dir.join("right-proof.bin"), &expected).unwrap();
        std::fs::write(dir.join("right-root.txt"), root.to_string()).unwrap();
    }
    let store = ReadonlyMemStore::new([&data]);
    let query = ranges(count, 2 * count);
    let mut written = Vec::new();
    store
        .export_bao(root, query.clone())
        .write(&mut written)
        .await
        .unwrap();
    assert_eq!(written, expected);
    let mut sink = Sink::default();
    let mut progress = Progress::default();
    store
        .export_bao(root, query.clone())
        .write_with_progress(&mut sink, &mut progress, &root.into(), INDEX)
        .await
        .unwrap();
    assert_eq!(sink.bytes, expected);
    assert_eq!(progress.starts, [(INDEX, root.into(), data.len() as u64)]);
    assert_eq!(progress.overhead, 72);
    assert_eq!(progress.payloads, [(INDEX, block as u64, block)]);
    let chunks = chunks(store.export_bao(root, query.clone())).await;
    assert_eq!(
        chunks.iter().map(Vec::len).collect::<Vec<_>>(),
        [8, 64, block]
    );
    assert_eq!(chunks.concat(), expected);
    let decoded =
        decode_slice(&Poseidon2Backend, &written, &root, &query, IROH_BLOCK_SIZE).unwrap();
    assert_eq!(decoded, [(block as u64, data[block..].to_vec())]);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn readonly_store_parent_free() {
    geometry();
    let data = body(CHUNK_SIZE);
    let root = hemera::tree::chunk_cv(&data, 0, true);
    let mut expected = (CHUNK_SIZE as u64).to_le_bytes().to_vec();
    expected.extend_from_slice(&data);
    let store = ReadonlyMemStore::new([&data]);
    let mut written = Vec::new();
    store
        .export_bao(root, ranges(0, 1))
        .write(&mut written)
        .await
        .unwrap();
    assert_eq!(written, expected);
    let mut sink = Sink::default();
    let mut progress = Progress::default();
    store
        .export_bao(root, ranges(0, 1))
        .write_with_progress(&mut sink, &mut progress, &root.into(), INDEX)
        .await
        .unwrap();
    assert_eq!(sink.bytes, expected);
    assert_eq!(progress.overhead, 8);
    assert_eq!(progress.payloads, [(INDEX, 0, CHUNK_SIZE)]);
    let chunks = chunks(store.export_bao(root, ranges(0, 1))).await;
    assert_eq!(
        chunks.iter().map(Vec::len).collect::<Vec<_>>(),
        [8, CHUNK_SIZE]
    );
    assert_eq!(chunks.concat(), expected);
    store.shutdown().await.unwrap();
}

fn check_inner(error: ExportBaoError, kind: io::ErrorKind, detail: &str) {
    let ExportBaoError::ExportBaoInner {
        source: EncodeError::Io(source),
        ..
    } = error
    else {
        panic!("expected encoded I/O error: {error:?}");
    };
    assert_eq!(source.kind(), kind);
    assert_eq!(source.to_string(), detail);
}

fn check_sink(error: ExportBaoError) {
    let ExportBaoError::ExportBaoIo { source, .. } = error else {
        panic!("expected sink I/O error: {error:?}");
    };
    assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(source.to_string(), "pair sink failure");
}

fn error_items() -> Vec<EncodedItem> {
    let mut items = literal_items();
    items.truncate(2);
    items.push(EncodedItem::Error(EncodeError::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        "encoded sentinel",
    ))));
    items
}

#[tokio::test]
async fn encoded_error_propagates() {
    let mut bytes = Vec::new();
    check_inner(
        scripted(error_items())
            .await
            .write(&mut bytes)
            .await
            .unwrap_err(),
        io::ErrorKind::InvalidData,
        "encoded sentinel",
    );
    assert_eq!(bytes, literal_wire()[..72]);
    let mut sink = Sink::default();
    let mut progress = Progress::default();
    check_inner(
        scripted(error_items())
            .await
            .write_with_progress(&mut sink, &mut progress, &identity(), INDEX)
            .await
            .unwrap_err(),
        io::ErrorKind::InvalidData,
        "encoded sentinel",
    );
    assert_eq!(sink.bytes, bytes);
    assert_eq!(progress.overhead, 72);
    assert!(progress.payloads.is_empty());
    let mut stream = scripted(error_items()).await.into_byte_stream();
    let mut prefix = Vec::new();
    for _ in 0..2 {
        prefix.extend_from_slice(&stream.next().await.unwrap().unwrap());
    }
    let Error::Io(source) = stream.next().await.unwrap().unwrap_err();
    assert_eq!(prefix, bytes);
    assert_eq!(source.kind(), io::ErrorKind::InvalidData);
    assert_eq!(source.to_string(), "encoded sentinel");
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn readonly_store_missing() {
    let store = ReadonlyMemStore::new([b"present"]);
    let detail = "export task ended unexpectedly";
    let mut bytes = Vec::new();
    check_inner(
        store
            .export_bao(identity(), ranges(0, 1))
            .write(&mut bytes)
            .await
            .unwrap_err(),
        io::ErrorKind::UnexpectedEof,
        detail,
    );
    assert!(bytes.is_empty());
    let mut sink = Sink::default();
    let mut progress = Progress::default();
    check_inner(
        store
            .export_bao(identity(), ranges(0, 1))
            .write_with_progress(&mut sink, &mut progress, &identity(), INDEX)
            .await
            .unwrap_err(),
        io::ErrorKind::UnexpectedEof,
        detail,
    );
    assert!(sink.bytes.is_empty());
    assert!(progress.starts.is_empty());
    assert_eq!(progress.overhead, 0);
    assert!(progress.payloads.is_empty());
    let mut stream = store
        .export_bao(identity(), ranges(0, 1))
        .into_byte_stream();
    let Error::Io(source) = stream.next().await.unwrap().unwrap_err();
    assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(source.to_string(), detail);
    assert!(stream.next().await.is_none());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn writer_failure_accounting() {
    for (call, overhead) in [(0, 0), (1, 8), (2, 72)] {
        let mut sink = Sink {
            fail_call: Some(call),
            ..Sink::default()
        };
        check_sink(
            scripted(literal_items())
                .await
                .write(&mut sink)
                .await
                .unwrap_err(),
        );
        assert_eq!(sink.calls, call + 1);
        assert_eq!(sink.bytes, literal_wire()[..overhead]);
        let mut sink = Sink {
            fail_call: Some(call),
            ..Sink::default()
        };
        let mut progress = Progress::default();
        check_sink(
            scripted(literal_items())
                .await
                .write_with_progress(&mut sink, &mut progress, &identity(), INDEX)
                .await
                .unwrap_err(),
        );
        assert_eq!(sink.calls, call + 1);
        assert_eq!(sink.bytes, literal_wire()[..overhead]);
        assert_eq!(progress.overhead, overhead);
        assert_eq!(progress.starts, [(INDEX, identity(), 100)]);
        assert!(progress.payloads.is_empty());
    }
}

#[tokio::test]
async fn partial_parent_failure() {
    for use_progress in [false, true] {
        let mut sink = Sink {
            fail_call: Some(1),
            partial: 17,
            ..Sink::default()
        };
        let mut progress = Progress::default();
        let export = scripted(literal_items()).await;
        let error = if use_progress {
            export
                .write_with_progress(&mut sink, &mut progress, &identity(), INDEX)
                .await
                .unwrap_err()
        } else {
            export.write(&mut sink).await.unwrap_err()
        };
        check_sink(error);
        assert_eq!(sink.bytes, literal_wire()[..25]);
        assert_eq!(sink.calls, 2);
        assert_eq!(progress.overhead, if use_progress { 8 } else { 0 });
        assert!(progress.payloads.is_empty());
    }
}

#[tokio::test]
async fn payload_progress_failure() {
    let mut items = literal_items();
    items.pop();
    items.extend(literal_items().into_iter().skip(2));
    let mut sink = Sink::default();
    let mut progress = Progress {
        reject_payload: true,
        ..Progress::default()
    };
    let error = scripted(items)
        .await
        .write_with_progress(&mut sink, &mut progress, &identity(), INDEX)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ExportBaoError::ClientError {
            source: ProgressError::Permission { .. },
            ..
        }
    ));
    assert_eq!(sink.bytes, literal_wire());
    assert_eq!(sink.calls, 3);
    assert_eq!(progress.overhead, 72);
    assert_eq!(progress.payloads, [(INDEX, OFFSET, PAYLOAD.len())]);
}
