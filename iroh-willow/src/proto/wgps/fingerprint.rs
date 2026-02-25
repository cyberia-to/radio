use std::fmt;

use serde::{Deserialize, Serialize};
use willow_store::{FixedSize, LiftingCommutativeMonoid, PointRef};

use crate::{
    proto::data_model::Entry,
    store::willow_store_glue::{
        path_to_blobseq, IrohWillowParams, StoredAuthorisedEntry, StoredTimestamp,
    },
};

#[derive(
    Eq,
    PartialEq,
    Clone,
    Copy,
    zerocopy_derive::FromBytes,
    zerocopy_derive::AsBytes,
    zerocopy_derive::FromZeroes,
)]
#[repr(transparent)]
pub struct Fingerprint(pub [u8; 64]);

impl Default for Fingerprint {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut seq = serializer.serialize_tuple(64)?;
        for byte in &self.0 {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Fingerprint;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "64 bytes")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Fingerprint, A::Error> {
                let mut bytes = [0u8; 64];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq.next_element()?.ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(Fingerprint(bytes))
            }
        }
        deserializer.deserialize_tuple(64, Visitor)
    }
}

impl Fingerprint {
    pub(crate) fn lift_stored_entry(
        key: &PointRef<IrohWillowParams>,
        payload_digest: &[u8; 64],
        payload_size: u64,
    ) -> Self {
        let mut hasher = cyber_poseidon2::Hasher::new();
        hasher.update(key.as_slice());
        hasher.update(payload_digest);
        hasher.update(&payload_size.to_le_bytes());
        Self(*hasher.finalize().as_bytes())
    }

    pub fn lift_entry(entry: &Entry) -> Self {
        let point = willow_store::Point::<IrohWillowParams>::new(
            entry.subspace_id(),
            &StoredTimestamp::new(entry.timestamp()),
            &path_to_blobseq(entry.path()),
        );
        Self::lift_stored_entry(
            &point,
            entry.payload_digest().0.as_bytes(),
            entry.payload_length(),
        )
    }
}

impl FixedSize for Fingerprint {
    const SIZE: usize = std::mem::size_of::<Self>();
}

impl LiftingCommutativeMonoid<PointRef<IrohWillowParams>, StoredAuthorisedEntry> for Fingerprint {
    fn neutral() -> Self {
        Self([0u8; 64])
    }

    fn lift(key: &PointRef<IrohWillowParams>, value: &StoredAuthorisedEntry) -> Self {
        Self::lift_stored_entry(key, &value.payload_digest, value.payload_size)
    }

    fn combine(&self, other: &Self) -> Self {
        let mut slf = *self;
        slf ^= *other;
        slf
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Fingerprint({})",
            data_encoding::HEXLOWER.encode(&self.0[..10])
        )
    }
}

impl Fingerprint {
    pub fn add_entry(&mut self, entry: &Entry) {
        // TODO: Don't allocate
        let next = Self::lift_entry(entry);
        *self ^= next;
    }

    pub fn add_entries<'a>(&mut self, iter: impl Iterator<Item = &'a Entry>) {
        for entry in iter {
            self.add_entry(entry);
        }
    }

    pub fn from_entries<'a>(iter: impl Iterator<Item = &'a Entry>) -> Self {
        let mut this = Self::default();
        this.add_entries(iter);
        this
    }

    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl std::ops::BitXorAssign for Fingerprint {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= b;
        }
    }
}
