use super::{Descriptor, FileId, MAX_RANGE_BYTES, invalid};
use std::io;

pub(super) const HEADER_BYTES: usize = 84;
pub(super) const OK: u8 = 0;
pub(super) const UNAVAILABLE: u8 = 1;

pub(super) struct Request {
    pub descriptor: Descriptor,
    pub offset: u64,
    pub length: usize,
}
impl Request {
    pub fn validate(&self) -> io::Result<()> {
        if self.length == 0
            || self.length > MAX_RANGE_BYTES
            || self
                .offset
                .checked_add(self.length as u64)
                .is_none_or(|end| end > self.descriptor.length)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn encode(&self) -> io::Result<[u8; HEADER_BYTES]> {
        self.validate()?;
        let mut bytes = [0; HEADER_BYTES];
        bytes[..32].copy_from_slice(&self.descriptor.file.particle);
        bytes[32..64].copy_from_slice(&self.descriptor.file.profile);
        bytes[64..72].copy_from_slice(&self.descriptor.length.to_be_bytes());
        bytes[72..80].copy_from_slice(&self.offset.to_be_bytes());
        bytes[80..].copy_from_slice(&(self.length as u32).to_be_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: [u8; HEADER_BYTES]) -> io::Result<Self> {
        let request = Self {
            descriptor: Descriptor {
                file: FileId {
                    particle: bytes[..32].try_into().map_err(|_| invalid())?,
                    profile: bytes[32..64].try_into().map_err(|_| invalid())?,
                },
                length: u64::from_be_bytes(bytes[64..72].try_into().map_err(|_| invalid())?),
            },
            offset: u64::from_be_bytes(bytes[72..80].try_into().map_err(|_| invalid())?),
            length: u32::from_be_bytes(bytes[80..].try_into().map_err(|_| invalid())?) as usize,
        };
        request.validate()?;
        Ok(request)
    }
}
