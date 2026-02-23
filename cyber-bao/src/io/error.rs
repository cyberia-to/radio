//! Error types for BAO encoding and decoding.

use std::{fmt, io};

use crate::tree::{ChunkNum, TreeNode};

/// Error during BAO encoding (validation of outboard data).
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EncodeError {
    /// Parent hash mismatch at the given tree node.
    ParentHashMismatch(TreeNode),
    /// Leaf hash mismatch at the given chunk.
    LeafHashMismatch(ChunkNum),
    /// I/O error.
    #[cfg_attr(feature = "serde", serde(with = "io_error_serde"))]
    Io(io::Error),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::ParentHashMismatch(node) => {
                write!(f, "parent hash mismatch at node {node}")
            }
            EncodeError::LeafHashMismatch(chunk) => {
                write!(f, "leaf hash mismatch at chunk {chunk}")
            }
            EncodeError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for EncodeError {}

impl From<io::Error> for EncodeError {
    fn from(e: io::Error) -> Self {
        EncodeError::Io(e)
    }
}

impl From<EncodeError> for io::Error {
    fn from(e: EncodeError) -> Self {
        match e {
            EncodeError::Io(e) => e,
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}

/// Error during BAO decoding (verification failure).
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DecodeError {
    /// A parent node was not found in the outboard.
    ParentNotFound(TreeNode),
    /// A leaf chunk was not found in the data.
    LeafNotFound(ChunkNum),
    /// A parent hash pair didn't match the expected parent CV.
    ParentHashMismatch(TreeNode),
    /// A leaf chunk's hash didn't match the expected CV.
    LeafHashMismatch(ChunkNum),
    /// I/O error.
    #[cfg_attr(feature = "serde", serde(with = "io_error_serde"))]
    Io(io::Error),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::ParentNotFound(node) => {
                write!(f, "parent not found at node {node}")
            }
            DecodeError::LeafNotFound(chunk) => {
                write!(f, "leaf not found at chunk {chunk}")
            }
            DecodeError::ParentHashMismatch(node) => {
                write!(f, "parent hash mismatch at node {node}")
            }
            DecodeError::LeafHashMismatch(chunk) => {
                write!(f, "leaf hash mismatch at chunk {chunk}")
            }
            DecodeError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<io::Error> for DecodeError {
    fn from(e: io::Error) -> Self {
        DecodeError::Io(e)
    }
}

impl From<DecodeError> for io::Error {
    fn from(e: DecodeError) -> Self {
        match e {
            DecodeError::Io(e) => e,
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}

#[cfg(feature = "serde")]
mod io_error_serde {
    use std::{fmt, io};

    use serde::{
        de::{self, Visitor},
        Deserializer, Serializer,
    };

    pub fn serialize<S>(error: &io::Error, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{:?}:{}", error.kind(), error))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<io::Error, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IoErrorVisitor;

        impl Visitor<'_> for IoErrorVisitor {
            type Value = io::Error;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an io::Error string representation")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(io::Error::other(value))
            }
        }

        deserializer.deserialize_str(IoErrorVisitor)
    }
}
