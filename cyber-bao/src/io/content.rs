//! Content item types for the BAO streaming protocol.

use bytes::Bytes;

use crate::tree::TreeNode;

/// A parent hash pair in the BAO tree.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Parent<H = cyber_poseidon2::Hash> {
    /// The tree node this pair belongs to.
    pub node: TreeNode,
    /// The (left, right) child hash pair.
    pub pair: (H, H),
}

/// A leaf data chunk.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Leaf {
    /// Byte offset of this leaf in the original data.
    pub offset: u64,
    /// The leaf data.
    pub data: Bytes,
}

/// A content item yielded during BAO streaming decode.
///
/// Either a parent hash pair or a verified leaf data chunk.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BaoContentItem<H = cyber_poseidon2::Hash> {
    /// A parent hash pair.
    Parent(Parent<H>),
    /// A verified leaf data chunk.
    Leaf(Leaf),
}

impl<H> BaoContentItem<H> {
    /// Returns true if this is a leaf item.
    pub fn is_leaf(&self) -> bool {
        matches!(self, Self::Leaf(_))
    }

    /// Returns true if this is a parent item.
    pub fn is_parent(&self) -> bool {
        matches!(self, Self::Parent(_))
    }
}
