use super::{
    Provider, Source, invalid, transport,
    wire::{HEADER_BYTES, OK, Request, UNAVAILABLE},
};
use crate::{
    endpoint::{Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler},
};
use std::{fmt, io, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

/// File protocol with an injected provider and explicit admission/I/O budgets.
pub struct FileProtocol<P> {
    provider: P,
    connections: Arc<Semaphore>,
    timeout: Duration,
}
impl<P> fmt::Debug for FileProtocol<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Provider internals can contain private namespaces and local paths.
        f.debug_struct("FileProtocol").finish_non_exhaustive()
    }
}
impl<P: Provider> FileProtocol<P> {
    /// Set per-host connection admission and per-request/idle deadlines.
    pub fn new(provider: P, max_connections: usize, timeout: Duration) -> io::Result<Self> {
        if max_connections == 0 || max_connections > Semaphore::MAX_PERMITS || timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid file service budget",
            ));
        }
        Ok(Self {
            provider,
            connections: Arc::new(Semaphore::new(max_connections)),
            timeout,
        })
    }

    async fn serve(
        &self,
        connection: &Connection,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> io::Result<()> {
        let mut header = [0; HEADER_BYTES];
        recv.read_exact(&mut header).await.map_err(transport)?;
        let request = Request::decode(header)?;
        if recv.read(&mut [0]).await.map_err(transport)?.is_some() {
            return Err(invalid());
        }
        let result = async {
            let source = self
                .provider
                .open(connection.remote_id(), request.descriptor.file)
                .await?;
            if source.descriptor() != request.descriptor {
                return Err(invalid());
            }
            let bytes = source.read(request.offset, request.length).await?;
            if bytes.len() != request.length {
                return Err(invalid());
            }
            Ok(bytes)
        }
        .await;
        match result {
            Ok(bytes) => {
                send.write_all(&[OK]).await.map_err(transport)?;
                send.write_all(&bytes).await.map_err(transport)?;
            }
            Err(_error) => {
                // Never disclose presence, authorization reasons or storage paths.
                send.write_all(&[UNAVAILABLE]).await.map_err(transport)?;
            }
        }
        send.finish().map_err(transport)?;
        send.stopped().await.map_err(transport)?;
        Ok(())
    }
}
impl<P: Provider> ProtocolHandler for FileProtocol<P> {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let Ok(_permit) = self.connections.clone().try_acquire_owned() else {
            connection.close(1u32.into(), b"file service busy");
            return Ok(());
        };
        loop {
            let streams = match tokio::time::timeout(self.timeout, connection.accept_bi()).await {
                Ok(Ok(streams)) => streams,
                Ok(Err(_)) => return Ok(()),
                Err(_) => {
                    connection.close(1u32.into(), b"file service idle");
                    return Ok(());
                }
            };
            match tokio::time::timeout(self.timeout, self.serve(&connection, streams.0, streams.1))
                .await
            {
                Ok(Ok(())) => {}
                _ => {
                    connection.close(1u32.into(), b"file request failed");
                    return Err(AcceptError::from_err(invalid()));
                }
            }
        }
    }
}
