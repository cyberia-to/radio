use super::{
    ALPN, Descriptor, Sink, invalid, transport,
    wire::{OK, Request, UNAVAILABLE},
};
use crate::{Endpoint, EndpointAddr, endpoint::Connection};
use std::{fmt, io, time::Duration};

/// Sequential bounded requests on one authenticated Radio connection.
pub struct Client {
    connection: Connection,
    timeout: Duration,
}
impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileClient").finish_non_exhaustive()
    }
}
impl Client {
    /// Connect to the expected endpoint identity with an explicit I/O deadline.
    pub async fn connect(
        endpoint: &Endpoint,
        address: EndpointAddr,
        timeout: Duration,
    ) -> io::Result<Self> {
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero file deadline",
            ));
        }
        let connection = tokio::time::timeout(timeout, endpoint.connect(address, ALPN))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(transport)?;
        Ok(Self {
            connection,
            timeout,
        })
    }

    /// Fetch a complete frame and wait for the bound sink to accept it.
    /// This does not establish full-file verification or application retention.
    pub async fn deliver(
        &mut self,
        sink: &impl Sink,
        offset: u64,
        length: usize,
    ) -> io::Result<()> {
        let bytes = self.read_range(sink.descriptor(), offset, length).await?;
        sink.write(offset, bytes).await
    }

    /// Receive exactly one bounded range. The caller must verify its identity
    /// under the descriptor profile before exposing it as authenticated content.
    pub async fn read_range(
        &mut self,
        descriptor: Descriptor,
        offset: u64,
        length: usize,
    ) -> io::Result<Vec<u8>> {
        let header = Request {
            descriptor,
            offset,
            length,
        }
        .encode()?;
        tokio::time::timeout(self.timeout, async {
            let (mut send, mut recv) = self.connection.open_bi().await.map_err(transport)?;
            send.write_all(&header).await.map_err(transport)?;
            send.finish().map_err(transport)?;
            let mut status = [0];
            recv.read_exact(&mut status).await.map_err(transport)?;
            match status[0] {
                OK => {}
                UNAVAILABLE => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "file range unavailable",
                    ));
                }
                _ => return Err(invalid()),
            }
            let mut bytes = vec![0; length];
            recv.read_exact(&mut bytes).await.map_err(transport)?;
            if recv.read(&mut [0]).await.map_err(transport)?.is_some() {
                return Err(invalid());
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }

    /// Close this transfer connection; retained data remains at the host.
    pub fn close(&self) {
        self.connection.close(0u32.into(), b"file client closed");
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}
