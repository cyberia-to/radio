use iroh_blobs::Hash;
use rand::Rng;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::proto::data_model::DIGEST_LENGTH;

pub const CHALLENGE_LENGTH: usize = 32;
pub const CHALLENGE_HASH_LENGTH: usize = DIGEST_LENGTH;

#[derive(derive_more::Debug, Copy, Clone, Eq, PartialEq)]
pub struct ChallengeHash(
    #[debug("{}..", data_encoding::HEXLOWER.encode(&self.0))] [u8; CHALLENGE_HASH_LENGTH],
);

impl Serialize for ChallengeHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut seq = serializer.serialize_tuple(64)?;
        for byte in &self.0 {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for ChallengeHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ChallengeHash;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "64 bytes")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<ChallengeHash, A::Error> {
                let mut bytes = [0u8; 64];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq.next_element()?.ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(ChallengeHash(bytes))
            }
        }
        deserializer.deserialize_tuple(64, Visitor)
    }
}

impl ChallengeHash {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; CHALLENGE_HASH_LENGTH]) -> Self {
        Self(bytes)
    }
}

#[derive(derive_more::Debug, Copy, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct AccessChallenge(
    #[debug("{}..", data_encoding::HEXLOWER.encode(&self.0))] AccessChallengeBytes,
);

pub type AccessChallengeBytes = [u8; CHALLENGE_LENGTH];

impl Default for AccessChallenge {
    fn default() -> Self {
        Self::generate()
    }
}

impl AccessChallenge {
    pub fn generate() -> Self {
        Self(rand::random())
    }

    pub fn generate_with_rng(rng: &mut impl CryptoRngCore) -> Self {
        Self(rng.gen())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn hash(&self) -> ChallengeHash {
        ChallengeHash(*Hash::new(self.0).as_bytes())
    }
}
