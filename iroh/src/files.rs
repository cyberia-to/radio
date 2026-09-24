//! Bounded file transfer through host-provided storage capabilities.
//!
//! This module owns transport framing. The host owns authorization, identity
//! verification, durable content, recovery and retention.
mod client;
mod server;
mod wire;

pub use client::Client;
pub use server::FileProtocol;

use std::{future::Future, io};

use crate::EndpointId;

/// Opt-in transport dialect; structural identity qualification remains separate.
pub const ALPN: &[u8] = b"/cyber/file-stream";
/// Memory and wire budget for one range; independent of total file length.
pub const MAX_RANGE_BYTES: usize = 1024 * 1024;

/// File identity and its required verifier profile, supplied by the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    /// The file's canonical particle.
    pub particle: [u8; 32],
    /// Exact identity-verification profile.
    pub profile: [u8; 32],
}

/// Expected immutable file descriptor; local storage names remain at the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// File identity and profile.
    pub file: FileId,
    /// Complete byte length, independent of physical part boundaries.
    pub length: u64,
}

/// A narrowly authorized immutable reader. Implementations may access storage.
pub trait Source: Send + Sync + 'static {
    /// The sealed file selected by the provider.
    fn descriptor(&self) -> Descriptor;
    /// Read exactly the requested bounded range, or report its failure.
    fn read(&self, offset: u64, length: usize) -> impl Future<Output = io::Result<Vec<u8>>> + Send;
}

/// The host authorizes each range request before returning a reader.
pub trait Provider: Send + Sync + 'static {
    /// Storage capability granted by a successful authorization decision.
    type Source: Source;
    /// Authorize the authenticated transport peer for this precise file.
    fn open(
        &self,
        peer: EndpointId,
        file: FileId,
    ) -> impl Future<Output = io::Result<Self::Source>> + Send;
}

impl<F, Fut, S> Provider for F
where
    F: Fn(EndpointId, FileId) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<S>> + Send,
    S: Source,
{
    type Source = S;
    fn open(&self, peer: EndpointId, file: FileId) -> impl Future<Output = io::Result<S>> + Send {
        self(peer, file)
    }
}

/// The host accepts complete range frames under one bound descriptor.
pub trait Sink: Send + Sync {
    /// Descriptor persisted/admitted by the receiving host.
    fn descriptor(&self) -> Descriptor;
    /// Accept a complete frame. Durable adapters return after storage commit.
    fn write(&self, offset: u64, bytes: Vec<u8>) -> impl Future<Output = io::Result<()>> + Send;
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid file range frame")
}
fn transport(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}
