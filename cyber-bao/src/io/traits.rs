//! I/O traits for reading and writing outboard data.
//!
//! These traits abstract over sync/async and memory/disk storage,
//! allowing the same BAO logic to work with different backends.

use std::io;

use bytes::Bytes;

use crate::tree::{BaoTree, TreeNode};

/// Read bytes at a given offset (sync, random-access).
pub trait ReadAt {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Read exactly `buf.len()` bytes at offset, or return an error.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let n = self.read_at(offset, buf)?;
        if n < buf.len() {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short read in read_exact_at",
            ))
        } else {
            Ok(())
        }
    }
}

/// Write bytes at a given offset (sync, random-access).
pub trait WriteAt {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<usize>;
    fn flush(&mut self) -> io::Result<()>;

    /// Write all bytes at offset, or return an error.
    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        let n = self.write_at(offset, buf)?;
        if n < buf.len() {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write in write_all_at",
            ))
        } else {
            Ok(())
        }
    }
}

/// Query the known size of a data source.
pub trait Size {
    fn size(&self) -> io::Result<Option<u64>>;
}

/// Read bytes at an offset, returning an owned `Bytes`.
pub trait ReadBytesAt {
    fn read_bytes_at(&self, offset: u64, size: usize) -> io::Result<Bytes>;
}

/// Sync outboard trait — read-only access to the hash tree.
pub trait Outboard {
    /// The hash type used (e.g., `cyber_poseidon2::Hash`).
    type Hash: AsRef<[u8]> + Clone + Eq + std::fmt::Debug;

    /// The root hash.
    fn root(&self) -> Self::Hash;

    /// The tree geometry.
    fn tree(&self) -> BaoTree;

    /// Load the hash pair for an internal node.
    ///
    /// Returns `None` if the node doesn't exist in this tree.
    fn load(&self, node: TreeNode) -> io::Result<Option<(Self::Hash, Self::Hash)>>;
}

/// Blanket impl: &O is also Outboard if O is.
impl<O: Outboard> Outboard for &O {
    type Hash = O::Hash;
    fn root(&self) -> Self::Hash {
        (**self).root()
    }
    fn tree(&self) -> BaoTree {
        (**self).tree()
    }
    fn load(&self, node: TreeNode) -> io::Result<Option<(Self::Hash, Self::Hash)>> {
        (**self).load(node)
    }
}

/// Sync outboard mutation trait — write hash pairs.
pub trait OutboardMut: Sized {
    /// The hash type.
    type Hash: AsRef<[u8]> + Clone + Eq;

    /// Save a hash pair for an internal node.
    fn save(&mut self, node: TreeNode, hash_pair: &(Self::Hash, Self::Hash)) -> io::Result<()>;

    /// Flush pending writes.
    fn sync(&mut self) -> io::Result<()>;
}

// --- Vec<u8> impls for ReadAt/WriteAt ---

impl ReadAt for Vec<u8> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let offset = offset as usize;
        if offset >= self.len() {
            return Ok(0);
        }
        let available = &self[offset..];
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }
}

impl WriteAt for Vec<u8> {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<usize> {
        let offset = offset as usize;
        let end = offset + buf.len();
        if end > self.len() {
            self.resize(end, 0);
        }
        self[offset..end].copy_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Size for Vec<u8> {
    fn size(&self) -> io::Result<Option<u64>> {
        Ok(Some(self.len() as u64))
    }
}

impl ReadBytesAt for Vec<u8> {
    fn read_bytes_at(&self, offset: u64, size: usize) -> io::Result<Bytes> {
        let offset = offset as usize;
        if offset + size > self.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read_bytes_at out of bounds",
            ));
        }
        Ok(Bytes::copy_from_slice(&self[offset..offset + size]))
    }
}

// --- &[u8] impls ---

impl ReadAt for &[u8] {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let offset = offset as usize;
        if offset >= self.len() {
            return Ok(0);
        }
        let available = &self[offset..];
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }
}

impl ReadBytesAt for &[u8] {
    fn read_bytes_at(&self, offset: u64, size: usize) -> io::Result<Bytes> {
        let offset = offset as usize;
        if offset + size > self.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read_bytes_at out of bounds",
            ));
        }
        Ok(Bytes::copy_from_slice(&self[offset..offset + size]))
    }
}

// --- Bytes impls ---

impl ReadAt for Bytes {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let offset = offset as usize;
        if offset >= self.len() {
            return Ok(0);
        }
        let available = &self[offset..];
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }
}

impl ReadBytesAt for Bytes {
    fn read_bytes_at(&self, offset: u64, size: usize) -> io::Result<Bytes> {
        let offset = offset as usize;
        if offset + size > self.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read_bytes_at out of bounds",
            ));
        }
        Ok(self.slice(offset..offset + size))
    }
}

impl Size for Bytes {
    fn size(&self) -> io::Result<Option<u64>> {
        Ok(Some(self.len() as u64))
    }
}

// --- &mut T delegating impls ---

impl<T: WriteAt> WriteAt for &mut T {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<usize> {
        (**self).write_at(offset, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (**self).flush()
    }
}

// --- File impls ---

#[cfg(not(target_family = "wasm"))]
impl ReadAt for std::fs::File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_at(self, buf, offset)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::FileExt::seek_read(self, buf, offset)
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl WriteAt for std::fs::File {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::write_at(self, buf, offset)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::FileExt::seek_write(self, buf, offset)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(self)
    }
}

#[cfg(not(target_family = "wasm"))]
impl Size for std::fs::File {
    fn size(&self) -> io::Result<Option<u64>> {
        Ok(Some(self.metadata()?.len()))
    }
}

#[cfg(not(target_family = "wasm"))]
impl ReadAt for &std::fs::File {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            std::os::unix::fs::FileExt::read_at(*self, buf, offset)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::FileExt::seek_read(*self, buf, offset)
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl ReadBytesAt for std::fs::File {
    fn read_bytes_at(&self, offset: u64, size: usize) -> io::Result<Bytes> {
        let mut buf = vec![0u8; size];
        self.read_exact_at(offset, &mut buf)?;
        Ok(Bytes::from(buf))
    }
}

#[cfg(not(target_family = "wasm"))]
impl ReadBytesAt for &std::fs::File {
    fn read_bytes_at(&self, offset: u64, size: usize) -> io::Result<Bytes> {
        let mut buf = vec![0u8; size];
        self.read_exact_at(offset, &mut buf)?;
        Ok(Bytes::from(buf))
    }
}
