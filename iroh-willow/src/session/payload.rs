use std::io;

use bytes::Bytes;
use iroh_blobs::Hash;
use tokio::sync::mpsc;

use super::Error;
use crate::{
    proto::{data_model::PayloadDigest, wgps::Message},
    session::channels::ChannelSenders,
};

const CHUNK_SIZE: usize = 1024 * 32;

/// Send a payload in chunks.
///
/// Returns `true` if the payload was sent.
/// Returns `false` if blob is not found in `payload_store`.
/// Returns an error if the store or sending on the `senders` return an error.
// TODO: Include outboards.
pub async fn send_payload_chunked(
    digest: PayloadDigest,
    payload_store: &iroh_blobs::api::Store,
    senders: &ChannelSenders,
    offset: u64,
    map: impl Fn(Bytes) -> Message,
) -> Result<bool, Error> {
    let hash: Hash = digest.into();
    let blobs = payload_store.blobs();
    let status = blobs.status(hash).await.map_err(|e| Error::PayloadStore(io::Error::other(e.to_string())))?;
    let size = match status {
        iroh_blobs::api::blobs::BlobStatus::Complete { size } => size,
        _ => return Ok(false),
    };

    // Export the blob data as a single byte range and send as chunks
    let data = blobs.export_ranges(hash, offset..size)
        .concatenate()
        .await
        .map_err(|e| Error::PayloadStore(io::Error::other(e.to_string())))?;

    let data = Bytes::from(data);
    let mut pos = 0;
    while pos < data.len() {
        let end = (pos + CHUNK_SIZE).min(data.len());
        let chunk = data.slice(pos..end);
        let msg = map(chunk);
        senders.send(msg).await?;
        pos = end;
    }
    Ok(true)
}

#[derive(Debug, Default)]
pub struct CurrentPayload(Option<CurrentPayloadInner>);

#[derive(Debug)]
struct CurrentPayloadInner {
    payload_digest: PayloadDigest,
    expected_length: u64,
    received_length: u64,
    total_length: u64,
    offset: u64,
    writer: Option<PayloadWriter>,
}

#[derive(derive_more::Debug)]
struct PayloadWriter {
    task: tokio::task::JoinHandle<io::Result<()>>,
    sender: mpsc::Sender<io::Result<Bytes>>,
}

impl CurrentPayload {
    /// Set the payload to be received.
    pub fn set(
        &mut self,
        payload_digest: PayloadDigest,
        total_length: u64,
        available_length: Option<u64>,
        offset: Option<u64>,
    ) -> Result<(), Error> {
        if self.0.is_some() {
            return Err(Error::InvalidMessageInCurrentState);
        }
        let offset = offset.unwrap_or(0);
        let available_length = available_length.unwrap_or(total_length);
        let expected_length = available_length - offset;
        self.0 = Some(CurrentPayloadInner {
            payload_digest,
            writer: None,
            expected_length,
            total_length,
            offset,
            received_length: 0,
        });
        Ok(())
    }

    pub async fn recv_chunk(
        &mut self,
        store: &iroh_blobs::api::Store,
        chunk: Bytes,
    ) -> anyhow::Result<()> {
        let state = self.0.as_mut().ok_or(Error::InvalidMessageInCurrentState)?;
        let len = chunk.len();
        let writer = state.writer.get_or_insert_with(|| {
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            let store = store.clone();
            let hash: Hash = state.payload_digest.into();
            let _total_length = state.total_length;
            let _offset = state.offset;
            let fut = async move {
                // Use the blobs API to import the data by collecting chunks
                let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
                let _temp_tag = store.blobs().add_stream(stream).await.temp_tag().await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                // Verify hash matches
                if _temp_tag.hash() != hash {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "payload hash mismatch",
                    ));
                }
                Ok(())
            };
            let task = tokio::task::spawn_local(fut);
            PayloadWriter {
                task,
                sender: tx,
            }
        });
        writer.sender.send(Ok(chunk)).await?;
        state.received_length += len as u64;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        let Some(state) = self.0.as_ref() else {
            return false;
        };
        state.received_length >= state.expected_length
    }

    pub async fn finalize(&mut self) -> Result<(), Error> {
        let state = self.0.take().ok_or(Error::InvalidMessageInCurrentState)?;
        // The writer is only set if we received at least one payload chunk.
        if let Some(writer) = state.writer {
            drop(writer.sender);
            writer
                .task
                .await
                .expect("payload writer panicked")
                .map_err(Error::PayloadStore)?;
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.0.as_ref().map(|s| s.writer.is_some()).unwrap_or(false)
    }

    pub fn ensure_none(&self) -> Result<(), Error> {
        if self.is_active() {
            Err(Error::InvalidMessageInCurrentState)
        } else {
            Ok(())
        }
    }
}
