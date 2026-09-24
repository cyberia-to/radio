use super::{Descriptor, FileId, MAX_RANGE_BYTES, invalid};
use std::io;

pub(super) const HEADER_BYTES: usize = 85;
pub(super) const OK: u8 = 0;
pub(super) const UNAVAILABLE: u8 = 1;

pub(super) struct Request {
    pub describe: bool,
    pub descriptor: Descriptor,
    pub offset: u64,
    pub length: usize,
}
impl Request {
    pub fn validate(&self) -> io::Result<()> {
        if self.describe {
            return if self.descriptor.length == 0 && self.offset == 0 && self.length == 0 {
                Ok(())
            } else {
                Err(invalid())
            };
        }
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
        bytes[0] = u8::from(self.describe);
        bytes[1..33].copy_from_slice(&self.descriptor.file.particle);
        bytes[33..65].copy_from_slice(&self.descriptor.file.profile);
        bytes[65..73].copy_from_slice(&self.descriptor.length.to_be_bytes());
        bytes[73..81].copy_from_slice(&self.offset.to_be_bytes());
        bytes[81..].copy_from_slice(&(self.length as u32).to_be_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: [u8; HEADER_BYTES]) -> io::Result<Self> {
        let describe = match bytes[0] {
            0 => false,
            1 => true,
            _ => return Err(invalid()),
        };
        let request = Self {
            describe,
            descriptor: Descriptor {
                file: FileId {
                    particle: bytes[1..33].try_into().map_err(|_| invalid())?,
                    profile: bytes[33..65].try_into().map_err(|_| invalid())?,
                },
                length: u64::from_be_bytes(bytes[65..73].try_into().map_err(|_| invalid())?),
            },
            offset: u64::from_be_bytes(bytes[73..81].try_into().map_err(|_| invalid())?),
            length: u32::from_be_bytes(bytes[81..].try_into().map_err(|_| invalid())?) as usize,
        };
        request.validate()?;
        Ok(request)
    }
}
