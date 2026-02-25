//! Pre-order and post-order outboard storage types.
//!
//! `PreOrderOutboard<H, D>` stores parent hash pairs in pre-order traversal
//! order, allowing random access to any node's hashes via `pre_order_offset`.
//!
//! `PostOrderOutboard<H, D>` stores them in post-order, enabling append-only
//! construction (children written before parents).

use std::io;

use cyber_poseidon2::OUTPUT_BYTES;

use crate::io::outboard as outboard_fn;
use crate::io::traits::{Outboard, OutboardMut, ReadAt, WriteAt};
use crate::tree::{BaoTree, BlockSize, TreeNode};

/// Size of a hash pair (two hashes concatenated).
const PAIR_SIZE: usize = OUTPUT_BYTES * 2;

/// Pre-order outboard with generic hash and data storage.
///
/// The `data` field stores parent hash pairs (left || right)
/// in pre-order traversal order.
#[derive(Debug, Clone)]
pub struct PreOrderOutboard<H = cyber_poseidon2::Hash, D = Vec<u8>> {
    /// Root hash of the tree.
    pub root: H,
    /// Tree geometry.
    pub tree: BaoTree,
    /// Serialized parent hash pairs in pre-order.
    pub data: D,
}

impl<H, D> Outboard for PreOrderOutboard<H, D>
where
    H: AsRef<[u8]> + Clone + Eq + std::fmt::Debug + From<[u8; OUTPUT_BYTES]>,
    D: ReadAt,
{
    type Hash = H;

    fn root(&self) -> H {
        self.root.clone()
    }

    fn tree(&self) -> BaoTree {
        self.tree
    }

    fn load(&self, node: TreeNode) -> io::Result<Option<(H, H)>> {
        let Some(offset) = self.tree.pre_order_offset(node) else {
            return Ok(None);
        };
        let byte_offset = offset * PAIR_SIZE as u64;
        let mut buf = [0u8; PAIR_SIZE];
        self.data.read_exact_at(byte_offset, &mut buf)?;
        let left = H::from(<[u8; OUTPUT_BYTES]>::try_from(&buf[..OUTPUT_BYTES]).unwrap());
        let right = H::from(<[u8; OUTPUT_BYTES]>::try_from(&buf[OUTPUT_BYTES..]).unwrap());
        Ok(Some((left, right)))
    }
}

impl<H, D> OutboardMut for PreOrderOutboard<H, D>
where
    H: AsRef<[u8]> + Clone + Eq,
    D: WriteAt,
{
    type Hash = H;

    fn save(&mut self, node: TreeNode, hash_pair: &(H, H)) -> io::Result<()> {
        let Some(offset) = self.tree.pre_order_offset(node) else {
            return Ok(());
        };
        let byte_offset = offset * PAIR_SIZE as u64;
        let mut buf = [0u8; PAIR_SIZE];
        buf[..OUTPUT_BYTES].copy_from_slice(hash_pair.0.as_ref());
        buf[OUTPUT_BYTES..].copy_from_slice(hash_pair.1.as_ref());
        self.data.write_all_at(byte_offset, &buf)?;
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        self.data.flush()
    }
}

/// In-memory pre-order outboard (convenience type).
#[derive(Debug, Clone)]
pub struct PreOrderMemOutboard<H = cyber_poseidon2::Hash> {
    /// Root hash.
    pub root: H,
    /// Tree geometry.
    pub tree: BaoTree,
    /// Parent hash pairs serialized in pre-order.
    pub data: Vec<u8>,
}

impl PreOrderMemOutboard<cyber_poseidon2::Hash> {
    /// Create an outboard by hashing the given data using Poseidon2.
    pub fn create(data: &[u8], block_size: BlockSize) -> Self {
        let backend = crate::hash::Poseidon2Backend;
        let ob = outboard_fn::outboard(&backend, data, block_size);
        Self {
            root: ob.root,
            tree: ob.tree,
            data: ob.data,
        }
    }
}

impl<H> Outboard for PreOrderMemOutboard<H>
where
    H: AsRef<[u8]> + Clone + Eq + std::fmt::Debug + From<[u8; OUTPUT_BYTES]>,
{
    type Hash = H;

    fn root(&self) -> H {
        self.root.clone()
    }

    fn tree(&self) -> BaoTree {
        self.tree
    }

    fn load(&self, node: TreeNode) -> io::Result<Option<(H, H)>> {
        let Some(offset) = self.tree.pre_order_offset(node) else {
            return Ok(None);
        };
        let byte_offset = (offset as usize) * PAIR_SIZE;
        if byte_offset + PAIR_SIZE > self.data.len() {
            return Ok(None);
        }
        let left = H::from(<[u8; OUTPUT_BYTES]>::try_from(&self.data[byte_offset..byte_offset + OUTPUT_BYTES]).unwrap());
        let right =
            H::from(<[u8; OUTPUT_BYTES]>::try_from(&self.data[byte_offset + OUTPUT_BYTES..byte_offset + PAIR_SIZE]).unwrap());
        Ok(Some((left, right)))
    }
}

impl<H> OutboardMut for PreOrderMemOutboard<H>
where
    H: AsRef<[u8]> + Clone + Eq,
{
    type Hash = H;

    fn save(&mut self, node: TreeNode, hash_pair: &(H, H)) -> io::Result<()> {
        let Some(offset) = self.tree.pre_order_offset(node) else {
            return Ok(());
        };
        let byte_offset = (offset as usize) * PAIR_SIZE;
        let end = byte_offset + PAIR_SIZE;
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[byte_offset..byte_offset + OUTPUT_BYTES].copy_from_slice(hash_pair.0.as_ref());
        self.data[byte_offset + OUTPUT_BYTES..end].copy_from_slice(hash_pair.1.as_ref());
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// --- Post-order outboard storage ---

/// Post-order outboard with generic hash and data storage.
///
/// The `data` field stores parent hash pairs (left || right)
/// in post-order traversal order. This format allows append-only construction:
/// children are written before their parents.
#[derive(Debug, Clone)]
pub struct PostOrderOutboard<H = cyber_poseidon2::Hash, D = Vec<u8>> {
    /// Root hash of the tree.
    pub root: H,
    /// Tree geometry.
    pub tree: BaoTree,
    /// Serialized parent hash pairs in post-order.
    pub data: D,
}

impl<H, D> Outboard for PostOrderOutboard<H, D>
where
    H: AsRef<[u8]> + Clone + Eq + std::fmt::Debug + From<[u8; OUTPUT_BYTES]>,
    D: ReadAt,
{
    type Hash = H;

    fn root(&self) -> H {
        self.root.clone()
    }

    fn tree(&self) -> BaoTree {
        self.tree
    }

    fn load(&self, node: TreeNode) -> io::Result<Option<(H, H)>> {
        let Some(offset) = self.tree.post_order_offset(node) else {
            return Ok(None);
        };
        let byte_offset = offset * PAIR_SIZE as u64;
        let mut buf = [0u8; PAIR_SIZE];
        self.data.read_exact_at(byte_offset, &mut buf)?;
        let left = H::from(<[u8; OUTPUT_BYTES]>::try_from(&buf[..OUTPUT_BYTES]).unwrap());
        let right = H::from(<[u8; OUTPUT_BYTES]>::try_from(&buf[OUTPUT_BYTES..]).unwrap());
        Ok(Some((left, right)))
    }
}

impl<H, D> OutboardMut for PostOrderOutboard<H, D>
where
    H: AsRef<[u8]> + Clone + Eq,
    D: WriteAt,
{
    type Hash = H;

    fn save(&mut self, node: TreeNode, hash_pair: &(H, H)) -> io::Result<()> {
        let Some(offset) = self.tree.post_order_offset(node) else {
            return Ok(());
        };
        let byte_offset = offset * PAIR_SIZE as u64;
        let mut buf = [0u8; PAIR_SIZE];
        buf[..OUTPUT_BYTES].copy_from_slice(hash_pair.0.as_ref());
        buf[OUTPUT_BYTES..].copy_from_slice(hash_pair.1.as_ref());
        self.data.write_all_at(byte_offset, &buf)?;
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        self.data.flush()
    }
}

/// In-memory post-order outboard (convenience type).
#[derive(Debug, Clone)]
pub struct PostOrderMemOutboard<H = cyber_poseidon2::Hash> {
    /// Root hash.
    pub root: H,
    /// Tree geometry.
    pub tree: BaoTree,
    /// Parent hash pairs serialized in post-order.
    pub data: Vec<u8>,
}

impl PostOrderMemOutboard<cyber_poseidon2::Hash> {
    /// Create a post-order outboard by hashing the given data using Poseidon2.
    pub fn create(data: &[u8], block_size: BlockSize) -> Self {
        let backend = crate::hash::Poseidon2Backend;
        let ob = outboard_fn::outboard(&backend, data, block_size);
        let tree = ob.tree;

        // Convert from pre-order to post-order layout
        let post_data = if tree.blocks() <= 1 {
            Vec::new()
        } else {
            let pre_order = tree.pre_order_chunks();
            let parent_count = pre_order
                .iter()
                .filter(|c| matches!(c, crate::tree::BaoChunk::Parent { .. }))
                .count();

            let mut post_data = vec![0u8; parent_count * PAIR_SIZE];
            let mut pre_offset = 0usize;
            for chunk in &pre_order {
                if let crate::tree::BaoChunk::Parent { node, .. } = chunk {
                    let pair_bytes = &ob.data[pre_offset..pre_offset + PAIR_SIZE];
                    if let Some(post_idx) = tree.post_order_offset(*node) {
                        let post_byte = (post_idx as usize) * PAIR_SIZE;
                        post_data[post_byte..post_byte + PAIR_SIZE].copy_from_slice(pair_bytes);
                    }
                    pre_offset += PAIR_SIZE;
                }
            }
            post_data
        };

        Self {
            root: ob.root,
            tree,
            data: post_data,
        }
    }
}

impl<H> Outboard for PostOrderMemOutboard<H>
where
    H: AsRef<[u8]> + Clone + Eq + std::fmt::Debug + From<[u8; OUTPUT_BYTES]>,
{
    type Hash = H;

    fn root(&self) -> H {
        self.root.clone()
    }

    fn tree(&self) -> BaoTree {
        self.tree
    }

    fn load(&self, node: TreeNode) -> io::Result<Option<(H, H)>> {
        let Some(offset) = self.tree.post_order_offset(node) else {
            return Ok(None);
        };
        let byte_offset = (offset as usize) * PAIR_SIZE;
        if byte_offset + PAIR_SIZE > self.data.len() {
            return Ok(None);
        }
        let left =
            H::from(<[u8; OUTPUT_BYTES]>::try_from(&self.data[byte_offset..byte_offset + OUTPUT_BYTES]).unwrap());
        let right =
            H::from(<[u8; OUTPUT_BYTES]>::try_from(&self.data[byte_offset + OUTPUT_BYTES..byte_offset + PAIR_SIZE]).unwrap());
        Ok(Some((left, right)))
    }
}

impl<H> OutboardMut for PostOrderMemOutboard<H>
where
    H: AsRef<[u8]> + Clone + Eq,
{
    type Hash = H;

    fn save(&mut self, node: TreeNode, hash_pair: &(H, H)) -> io::Result<()> {
        let Some(offset) = self.tree.post_order_offset(node) else {
            return Ok(());
        };
        let byte_offset = (offset as usize) * PAIR_SIZE;
        let end = byte_offset + PAIR_SIZE;
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[byte_offset..byte_offset + OUTPUT_BYTES].copy_from_slice(hash_pair.0.as_ref());
        self.data[byte_offset + OUTPUT_BYTES..end].copy_from_slice(hash_pair.1.as_ref());
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Poseidon2Backend;
    use crate::io::outboard::outboard;

    #[test]
    fn pre_order_outboard_roundtrip() {
        let backend = Poseidon2Backend;
        let data = vec![0x42u8; 4096];
        let ob = outboard(&backend, &data, BlockSize::ZERO);

        let pre = PreOrderOutboard {
            root: ob.root.clone(),
            tree: ob.tree,
            data: ob.data.clone(),
        };

        assert_eq!(Outboard::root(&pre), ob.root);
        assert_eq!(pre.tree(), ob.tree);

        let root_node = ob.tree.root();
        let pair = pre.load(root_node).unwrap();
        assert!(pair.is_some());
    }

    #[test]
    fn pre_order_mem_outboard_create() {
        let data = vec![0x42u8; 2048];
        let ob = PreOrderMemOutboard::create(&data, BlockSize::ZERO);
        assert_eq!(ob.data.len(), PAIR_SIZE);
    }

    #[test]
    fn post_order_mem_outboard_create() {
        let data = vec![0x42u8; 2048];
        let ob = PostOrderMemOutboard::create(&data, BlockSize::ZERO);
        assert_eq!(ob.data.len(), PAIR_SIZE);
    }

    #[test]
    fn post_order_outboard_all_nodes_match_pre_order() {
        let data = vec![0xABu8; 8192]; // 8 blocks -> 7 parent nodes
        let pre_ob = PreOrderMemOutboard::create(&data, BlockSize::ZERO);
        let post_ob = PostOrderMemOutboard::create(&data, BlockSize::ZERO);

        assert_eq!(Outboard::root(&pre_ob), Outboard::root(&post_ob));

        let tree = pre_ob.tree;
        let pre_order = tree.pre_order_chunks();
        for chunk in &pre_order {
            if let crate::tree::BaoChunk::Parent { node, .. } = chunk {
                let pre_pair = pre_ob.load(*node).unwrap();
                let post_pair = post_ob.load(*node).unwrap();
                assert_eq!(pre_pair, post_pair, "mismatch at node {:?}", node);
            }
        }
    }

    #[test]
    fn post_order_can_validate_via_encode_ranges() {
        use crate::io::sync::encode_ranges_validated;
        use crate::ChunkRanges;

        let data = vec![0x42u8; 4096];
        let post_ob = PostOrderMemOutboard::create(&data, BlockSize::ZERO);

        let mut encoded = Vec::new();
        encode_ranges_validated(&data[..], &post_ob, &ChunkRanges::all(), &mut encoded)
            .expect("post-order outboard should be usable for encoding");
        assert_eq!(encoded.len(), 3 * PAIR_SIZE + 4096);
    }

    #[test]
    fn pre_order_outboard_block_size_nonzero() {
        // BlockSize(1) = 2KB blocks (2 chunks per block)
        let bs = BlockSize::from_chunk_log(1);
        // 8KB data → 4 blocks of 2KB → 3 parents
        let data = vec![0x42u8; 8192];
        let ob = PreOrderMemOutboard::create(&data, bs);
        assert_eq!(ob.data.len(), 3 * PAIR_SIZE);

        // Verify all parent nodes can be loaded
        let tree = ob.tree;
        let pre_order = tree.pre_order_chunks();
        for chunk in &pre_order {
            if let crate::tree::BaoChunk::Parent { node, .. } = chunk {
                let pair = ob.load(*node).unwrap();
                assert!(pair.is_some(), "missing pair at {:?}", node);
            }
        }
    }

    #[test]
    fn post_order_matches_pre_order_block_size_nonzero() {
        let bs = BlockSize::from_chunk_log(1);
        let data = vec![0xABu8; 8192];
        let pre_ob = PreOrderMemOutboard::create(&data, bs);
        let post_ob = PostOrderMemOutboard::create(&data, bs);

        assert_eq!(Outboard::root(&pre_ob), Outboard::root(&post_ob));

        let tree = pre_ob.tree;
        let pre_order = tree.pre_order_chunks();
        for chunk in &pre_order {
            if let crate::tree::BaoChunk::Parent { node, .. } = chunk {
                let pre_pair = pre_ob.load(*node).unwrap();
                let post_pair = post_ob.load(*node).unwrap();
                assert_eq!(pre_pair, post_pair, "mismatch at node {:?}", node);
            }
        }
    }
}
