use std::{
    io,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use cyber_bao::ChunkNum;
use iroh::endpoint::VarInt;

use super::{bounded, hello_wire, root, EMPTY_HEX, HELLO_HEX};
use crate::{
    get::{
        fsm::{AtBlobHeaderNextError, DecodeError},
        GetError, GetResult, Stats, StreamPair,
    },
    protocol::{GetRequest, Request},
    store::mem::MemStore,
    util::SendStream,
    Hash,
};

#[derive(Default)]
struct Sent {
    bytes: Vec<u8>,
    syncs: usize,
}

struct Capture(Arc<Mutex<Sent>>);

impl SendStream for Capture {
    async fn send_bytes(&mut self, bytes: Bytes) -> io::Result<()> {
        self.send(&bytes).await
    }
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.lock().unwrap().bytes.extend_from_slice(bytes);
        Ok(())
    }
    async fn sync(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().syncs += 1;
        Ok(())
    }
    fn reset(&mut self, _: VarInt) -> io::Result<()> {
        panic!("unexpected reset")
    }
    async fn stopped(&mut self) -> io::Result<Option<VarInt>> {
        panic!("unexpected stopped")
    }
    fn id(&self) -> u64 {
        0
    }
}

async fn get(store: &MemStore, hash: Hash, wire: impl Into<Bytes>) -> GetResult<Stats> {
    let sent = Arc::new(Mutex::new(Sent::default()));
    let conn = StreamPair::new(7, wire.into(), Capture(sent.clone()));
    let result = store
        .remote()
        .execute_get(conn, GetRequest::blob(hash))
        .await;
    let sent = sent.lock().unwrap();
    assert_eq!(sent.syncs, 1);
    let request: Request = postcard::from_bytes(&sent.bytes).unwrap();
    assert_eq!(request, Request::Get(GetRequest::blob(hash)));
    result
}

#[tokio::test]
async fn canonical_zero_header_drains_empty_leaf() {
    bounded(async {
        let store = MemStore::new();
        let stats = get(&store, root(EMPTY_HEX), Bytes::from_static(&[0; 8]))
            .await
            .unwrap();
        assert_eq!(stats.payload_bytes_read, 0);
        assert_eq!(stats.other_bytes_read, 8);
        store.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn zero_header_rejects_zero_and_hello_keys() {
    bounded(async {
        let store = MemStore::new();
        for hash in [Hash::from_bytes([0; 32]), root(HELLO_HEX)] {
            let error = get(&store, hash, Bytes::from_static(&[0; 8]))
                .await
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    GetError::Decode {
                        source: DecodeError::LeafHashMismatch {
                            num: ChunkNum(0),
                            ..
                        },
                        ..
                    }
                ),
                "{error:?}"
            );
        }
        store.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn short_header_has_remote_not_found_wrapper() {
    bounded(async {
        let store = MemStore::new();
        let error = get(&store, root(EMPTY_HEX), Bytes::from_static(&[0; 7]))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                GetError::AtBlobHeaderNext {
                    source: AtBlobHeaderNextError::NotFound { .. },
                    ..
                }
            ),
            "{error:?}"
        );
        store.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn hello_runs_actual_decoder_and_import() {
    bounded(async {
        let store = MemStore::new();
        let hash = root(HELLO_HEX);
        let stats = get(&store, hash, hello_wire()).await.unwrap();
        assert_eq!(stats.payload_bytes_read, 5);
        assert_eq!(stats.other_bytes_read, 8);
        assert_eq!(store.get_bytes(hash).await.unwrap().as_ref(), b"hello");
        store.shutdown().await.unwrap();
    })
    .await;
}
