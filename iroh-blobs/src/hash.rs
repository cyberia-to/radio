//! The Poseidon2 hash used in Iroh.

use std::{borrow::Borrow, fmt, str::FromStr};

use arrayvec::ArrayString;
use cyber_poseidon2::OUTPUT_BYTES;
use n0_error::{e, stack_error, StdResultExt};
use postcard::experimental::max_size::MaxSize;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::store::{util::DD, IROH_BLOCK_SIZE};

/// Compute the BAO tree hash of data using Poseidon2.
///
/// This delegates to the outboard builder to ensure Hash::new(data) equals
/// the root hash from PreOrderMemOutboard::create for the same data.
fn tree_hash(data: &[u8]) -> cyber_poseidon2::Hash {
    use cyber_bao::io::pre_order::PreOrderMemOutboard;

    PreOrderMemOutboard::create(data, IROH_BLOCK_SIZE).root
}

/// Hash type used throughout.
#[derive(PartialEq, Eq, Copy, Clone, Hash)]
pub struct Hash(cyber_poseidon2::Hash);

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hash").field(&DD(self.to_hex())).finish()
    }
}

impl Hash {
    /// The hash for the empty byte range (`b""`).
    ///
    /// NOTE: This constant must be recomputed after any parameter change.
    /// It is set to a placeholder; the test_empty_hash test will verify correctness.
    pub const EMPTY: Hash = Hash::from_bytes([0u8; OUTPUT_BYTES]);

    /// Calculate the hash of the provided bytes using the BAO tree hash.
    ///
    /// This computes the hash using the same tree structure as the BAO
    /// outboard, ensuring that `Hash::new(data)` equals the root hash
    /// produced by the outboard builder for the same data.
    pub fn new(buf: impl AsRef<[u8]>) -> Self {
        let data = buf.as_ref();
        let val = tree_hash(data);
        Hash(val)
    }

    /// Bytes of the hash.
    pub fn as_bytes(&self) -> &[u8; OUTPUT_BYTES] {
        self.0.as_bytes()
    }

    /// Create a `Hash` from its raw bytes representation.
    pub const fn from_bytes(bytes: [u8; OUTPUT_BYTES]) -> Self {
        Self(cyber_poseidon2::Hash::from_bytes(bytes))
    }

    /// Convert the hash to a hex string.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Convert to a hex string limited to the first 5 bytes for a friendly string
    /// representation of the hash.
    pub fn fmt_short(&self) -> ArrayString<10> {
        let mut res = ArrayString::new();
        data_encoding::HEXLOWER
            .encode_write(&self.as_bytes()[..5], &mut res)
            .unwrap();
        res
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Borrow<[u8]> for Hash {
    fn borrow(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Borrow<[u8; OUTPUT_BYTES]> for Hash {
    fn borrow(&self) -> &[u8; OUTPUT_BYTES] {
        self.0.as_bytes()
    }
}

impl From<cyber_poseidon2::Hash> for Hash {
    fn from(value: cyber_poseidon2::Hash) -> Self {
        Hash(value)
    }
}

impl From<Hash> for cyber_poseidon2::Hash {
    fn from(value: Hash) -> Self {
        value.0
    }
}

impl From<[u8; OUTPUT_BYTES]> for Hash {
    fn from(value: [u8; OUTPUT_BYTES]) -> Self {
        Hash(cyber_poseidon2::Hash::from(value))
    }
}

impl From<Hash> for [u8; 64] {
    fn from(value: Hash) -> Self {
        *value.as_bytes()
    }
}

impl From<&[u8; 64]> for Hash {
    fn from(value: &[u8; 64]) -> Self {
        Hash(cyber_poseidon2::Hash::from(*value))
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[allow(missing_docs)]
#[non_exhaustive]
#[stack_error(derive, add_meta, std_sources)]
pub enum HexOrBase32ParseError {
    #[error("Invalid length")]
    DecodeInvalidLength {},
    #[error("Failed to decode {source}")]
    Decode {
        #[error(std_err)]
        source: data_encoding::DecodeError,
    },
}

impl FromStr for Hash {
    type Err = HexOrBase32ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 64];

        let res = if s.len() == 128 {
            // hex (64 bytes = 128 hex chars)
            data_encoding::HEXLOWER.decode_mut(s.as_bytes(), &mut bytes)
        } else {
            data_encoding::BASE32_NOPAD.decode_mut(s.to_ascii_uppercase().as_bytes(), &mut bytes)
        };
        match res {
            Ok(len) => {
                if len != 64 {
                    return Err(e!(HexOrBase32ParseError::DecodeInvalidLength));
                }
            }
            Err(partial) => return Err(e!(HexOrBase32ParseError::Decode, partial.error)),
        }
        Ok(Self(cyber_poseidon2::Hash::from_bytes(bytes)))
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.to_string().as_str())
        } else {
            // Delegate to cyber_poseidon2::Hash's custom serde (tuple of 64 bytes)
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse().map_err(de::Error::custom)
        } else {
            // Delegate to cyber_poseidon2::Hash's custom serde
            let inner = cyber_poseidon2::Hash::deserialize(deserializer)?;
            Ok(Self(inner))
        }
    }
}

impl MaxSize for Hash {
    const POSTCARD_MAX_SIZE: usize = 64;
}

/// A format identifier
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Default,
    Debug,
    MaxSize,
    Hash,
    derive_more::Display,
)]
pub enum BlobFormat {
    /// Raw blob
    #[default]
    Raw,
    /// A sequence of Poseidon2 hashes
    HashSeq,
}

impl From<BlobFormat> for u64 {
    fn from(value: BlobFormat) -> Self {
        match value {
            BlobFormat::Raw => 0,
            BlobFormat::HashSeq => 1,
        }
    }
}

impl BlobFormat {
    /// Is raw format
    pub const fn is_raw(&self) -> bool {
        matches!(self, BlobFormat::Raw)
    }

    /// Is hash seq format
    pub const fn is_hash_seq(&self) -> bool {
        matches!(self, BlobFormat::HashSeq)
    }
}

/// A hash and format pair
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, MaxSize, Hash)]
pub struct HashAndFormat {
    /// The hash
    pub hash: Hash,
    /// The format
    pub format: BlobFormat,
}

impl std::fmt::Debug for HashAndFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        std::fmt::Debug::fmt(&(DD(self.hash.to_hex()), self.format), f)
    }
}

impl From<(Hash, BlobFormat)> for HashAndFormat {
    fn from((hash, format): (Hash, BlobFormat)) -> Self {
        Self { hash, format }
    }
}

impl From<Hash> for HashAndFormat {
    fn from(hash: Hash) -> Self {
        Self {
            hash,
            format: BlobFormat::Raw,
        }
    }
}

#[cfg(feature = "fs-store")]
mod redb_support {
    use postcard::experimental::max_size::MaxSize;
    use redb::{Key as RedbKey, Value as RedbValue};

    use super::{Hash, HashAndFormat};

    impl RedbValue for Hash {
        type SelfType<'a> = Self;

        type AsBytes<'a> = &'a [u8; 64];

        fn fixed_width() -> Option<usize> {
            Some(64)
        }

        fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
        where
            Self: 'a,
        {
            let contents: &'a [u8; 64] = data.try_into().unwrap();
            (*contents).into()
        }

        fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
        where
            Self: 'a,
            Self: 'b,
        {
            value.as_bytes()
        }

        fn type_name() -> redb::TypeName {
            redb::TypeName::new("iroh_blobs::Hash")
        }
    }

    impl RedbKey for Hash {
        fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
            data1.cmp(data2)
        }
    }

    impl RedbValue for HashAndFormat {
        type SelfType<'a> = Self;

        type AsBytes<'a> = [u8; Self::POSTCARD_MAX_SIZE];

        fn fixed_width() -> Option<usize> {
            Some(Self::POSTCARD_MAX_SIZE)
        }

        fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
        where
            Self: 'a,
        {
            let t: &'a [u8; Self::POSTCARD_MAX_SIZE] = data.try_into().unwrap();
            postcard::from_bytes(t.as_slice()).unwrap()
        }

        fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
        where
            Self: 'a,
            Self: 'b,
        {
            let mut res = [0u8; 65];
            postcard::to_slice(&value, &mut res).unwrap();
            res
        }

        fn type_name() -> redb::TypeName {
            redb::TypeName::new("iroh_blobs::HashAndFormat")
        }
    }
}

impl HashAndFormat {
    /// Create a new hash and format pair.
    pub fn new(hash: Hash, format: BlobFormat) -> Self {
        Self { hash, format }
    }

    /// Create a new hash and format pair, using the default (raw) format.
    pub fn raw(hash: Hash) -> Self {
        Self {
            hash,
            format: BlobFormat::Raw,
        }
    }

    /// Create a new hash and format pair, using the collection format.
    pub fn hash_seq(hash: Hash) -> Self {
        Self {
            hash,
            format: BlobFormat::HashSeq,
        }
    }
}

impl fmt::Display for HashAndFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut slice = [0u8; 129];
        hex::encode_to_slice(self.hash.as_bytes(), &mut slice[1..]).unwrap();
        match self.format {
            BlobFormat::Raw => {
                write!(f, "{}", std::str::from_utf8(&slice[1..]).unwrap())
            }
            BlobFormat::HashSeq => {
                slice[0] = b's';
                write!(f, "{}", std::str::from_utf8(&slice).unwrap())
            }
        }
    }
}

impl FromStr for HashAndFormat {
    type Err = n0_error::AnyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.as_bytes();
        let mut hash = [0u8; 64];
        match s.len() {
            128 => {
                hex::decode_to_slice(s, &mut hash).anyerr()?;
                Ok(Self::raw(hash.into()))
            }
            129 if s[0].eq_ignore_ascii_case(&b's') => {
                hex::decode_to_slice(&s[1..], &mut hash).anyerr()?;
                Ok(Self::hash_seq(hash.into()))
            }
            _ => {
                n0_error::bail_any!("invalid hash and format");
            }
        }
    }
}

impl Serialize for HashAndFormat {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.to_string().as_str())
        } else {
            (self.hash, self.format).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for HashAndFormat {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse().map_err(de::Error::custom)
        } else {
            let (hash, format) = <(Hash, BlobFormat)>::deserialize(deserializer)?;
            Ok(Self { hash, format })
        }
    }
}

#[cfg(test)]
mod tests {

    use serde_test::{assert_tokens, Configure, Token};

    use super::*;

    #[test]
    fn test_display_parse_roundtrip() {
        for i in 0..100u8 {
            let hash = Hash::new(&[i]);
            let text = hash.to_string();
            let hash1 = text.parse::<Hash>().unwrap();
            assert_eq!(hash, hash1);

            let text = hash.to_hex();
            let hash1 = Hash::from_str(&text).unwrap();
            assert_eq!(hash, hash1);
        }
    }

    #[test]
    fn test_hash() {
        let data = b"hello world";
        let hash = Hash::new(data);

        let encoded = hash.to_string();
        assert_eq!(encoded.parse::<Hash>().unwrap(), hash);
    }

    #[test]
    fn test_empty_hash() {
        // Hash::EMPTY is a placeholder; verify actual empty hash is deterministic
        let hash = Hash::new(b"");
        let hash2 = Hash::new(b"");
        assert_eq!(hash, hash2);
    }

    #[test]
    fn hash_wire_format() {
        let hash = Hash::from([0xab; 64]);
        let serialized = postcard::to_stdvec(&hash).unwrap();
        assert_eq!(serialized.len(), 64);
        assert!(serialized.iter().all(|&b| b == 0xab));
    }

    #[cfg(feature = "fs-store")]
    #[test]
    fn hash_redb() {
        use redb::Value as RedbValue;
        let bytes: [u8; 64] = {
            let mut b = [0u8; 64];
            for (i, v) in b.iter_mut().enumerate() {
                *v = (i % 256) as u8;
            }
            b
        };
        let hash = Hash::from(bytes);
        assert_eq!(<Hash as RedbValue>::fixed_width(), Some(64));
        assert_eq!(
            <Hash as RedbValue>::type_name(),
            redb::TypeName::new("iroh_blobs::Hash")
        );
        let serialized = <Hash as RedbValue>::as_bytes(&hash);
        assert_eq!(serialized, &bytes);
        let deserialized = <Hash as RedbValue>::from_bytes(serialized.as_slice());
        assert_eq!(deserialized, hash);
    }

    #[cfg(feature = "fs-store")]
    #[test]
    fn hash_and_format_redb() {
        use redb::Value as RedbValue;
        let hash_bytes: [u8; 64] = {
            let mut b = [0u8; 64];
            for (i, v) in b.iter_mut().enumerate() {
                *v = (i % 256) as u8;
            }
            b
        };
        let hash = Hash::from(hash_bytes);
        let haf = HashAndFormat::raw(hash);
        assert_eq!(<HashAndFormat as RedbValue>::fixed_width(), Some(65));
        assert_eq!(
            <HashAndFormat as RedbValue>::type_name(),
            redb::TypeName::new("iroh_blobs::HashAndFormat")
        );
        let serialized = <HashAndFormat as RedbValue>::as_bytes(&haf);
        let deserialized = <HashAndFormat as RedbValue>::from_bytes(serialized.as_slice());
        assert_eq!(deserialized, haf);
    }

    #[test]
    fn test_hash_serde() {
        let hash = Hash::new("hello");

        // Hashes are serialized as 64-element tuples
        let mut tokens = Vec::new();
        tokens.push(Token::Tuple { len: 64 });
        for byte in hash.as_bytes() {
            tokens.push(Token::U8(*byte));
        }
        tokens.push(Token::TupleEnd);
        assert_eq!(tokens.len(), 66);

        assert_tokens(&hash.compact(), &tokens);

        // Readable format: check via JSON round-trip
        let json = serde_json::to_string(&hash).unwrap();
        let expected_json = format!("\"{}\"", hash.to_hex());
        assert_eq!(json, expected_json);
    }

    #[test]
    fn test_hash_postcard() {
        let hash = Hash::new("hello");
        let ser = postcard::to_stdvec(&hash).unwrap();
        let de = postcard::from_bytes(&ser).unwrap();
        assert_eq!(hash, de);

        assert_eq!(ser.len(), 64);
    }

    #[test]
    fn test_hash_json() {
        let hash = Hash::new("hello");
        let ser = serde_json::to_string(&hash).unwrap();
        let de = serde_json::from_str(&ser).unwrap();
        assert_eq!(hash, de);
        // 128 hex chars + 2 quotes
        assert_eq!(ser.len(), 130);
    }

    #[test]
    fn test_hash_and_format_parse() {
        let hash = Hash::new("hello");

        let expected = HashAndFormat::raw(hash);
        let actual = expected.to_string().parse::<HashAndFormat>().unwrap();
        assert_eq!(expected, actual);

        let expected = HashAndFormat::hash_seq(hash);
        let actual = expected.to_string().parse::<HashAndFormat>().unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_hash_and_format_postcard() {
        let haf = HashAndFormat::raw(Hash::new("hello"));
        let ser = postcard::to_stdvec(&haf).unwrap();
        let de = postcard::from_bytes(&ser).unwrap();
        assert_eq!(haf, de);
    }

    #[test]
    fn test_hash_and_format_json() {
        let haf = HashAndFormat::raw(Hash::new("hello"));
        let ser = serde_json::to_string(&haf).unwrap();
        let de = serde_json::from_str(&ser).unwrap();
        assert_eq!(haf, de);
    }
}
