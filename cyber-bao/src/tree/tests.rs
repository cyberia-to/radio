use super::*;

#[test]
fn tree_node_level() {
    assert_eq!(TreeNode(0).level(), 0); // leaf
    assert_eq!(TreeNode(1).level(), 1); // level 1 parent
    assert_eq!(TreeNode(2).level(), 0); // leaf
    assert_eq!(TreeNode(3).level(), 2); // level 2 parent
    assert_eq!(TreeNode(7).level(), 3); // level 3 parent
}

#[test]
fn tree_node_is_leaf() {
    assert!(TreeNode(0).is_leaf());
    assert!(!TreeNode(1).is_leaf());
    assert!(TreeNode(2).is_leaf());
    assert!(!TreeNode(3).is_leaf());
}

#[test]
fn tree_node_children() {
    let parent = TreeNode(1);
    assert_eq!(parent.left_child(), Some(TreeNode(0)));
    assert_eq!(parent.right_child(), Some(TreeNode(2)));

    let leaf = TreeNode(0);
    assert_eq!(leaf.left_child(), None);
    assert_eq!(leaf.right_child(), None);

    let l2_parent = TreeNode(3);
    assert_eq!(l2_parent.left_child(), Some(TreeNode(1)));
    assert_eq!(l2_parent.right_child(), Some(TreeNode(5)));
}

#[test]
fn tree_node_chunk_range() {
    assert_eq!(TreeNode(0).chunk_range(), ChunkNum(0)..ChunkNum(2));
    assert_eq!(TreeNode(1).chunk_range(), ChunkNum(0)..ChunkNum(4));
    assert_eq!(TreeNode(3).chunk_range(), ChunkNum(0)..ChunkNum(8));
}

#[test]
fn block_size_bytes() {
    assert_eq!(BlockSize::ZERO.bytes(), CHUNK_SIZE);
    assert_eq!(BlockSize::DEFAULT.bytes(), CHUNK_SIZE * 4);
    assert_eq!(BlockSize::from_chunk_log(1).bytes(), CHUNK_SIZE * 2);
}

#[test]
fn block_size_from_bytes() {
    assert_eq!(
        BlockSize::from_bytes(CHUNK_SIZE as u64),
        Some(BlockSize::ZERO)
    );
    assert_eq!(
        BlockSize::from_bytes(CHUNK_SIZE as u64 * 4),
        Some(BlockSize::DEFAULT)
    );
    assert_eq!(BlockSize::from_bytes(512), None);
    assert_eq!(BlockSize::from_bytes(3000), None);
}

#[test]
fn bao_tree_basic() {
    let tree = BaoTree::new(CHUNK_SIZE as u64, BlockSize::ZERO);
    assert_eq!(tree.chunks(), ChunkNum(1));
    assert_eq!(tree.blocks(), 1);
    assert_eq!(tree.outboard_size(), 0);
}

#[test]
fn bao_tree_two_blocks() {
    let tree = BaoTree::new(CHUNK_SIZE as u64 * 2, BlockSize::ZERO);
    assert_eq!(tree.chunks(), ChunkNum(2));
    assert_eq!(tree.blocks(), 2);
    assert_eq!(tree.outboard_size(), PAIR_SIZE as u64); // one parent pair
}

#[test]
fn bao_tree_empty() {
    let tree = BaoTree::new(0, BlockSize::ZERO);
    assert_eq!(tree.blocks(), 1); // min 1
    assert_eq!(tree.outboard_size(), 0);
}

#[test]
fn bao_tree_large() {
    let tree = BaoTree::new(1_000_000, BlockSize::DEFAULT);
    assert!(tree.blocks() > 0);
    assert!(tree.outboard_size() > 0);
}

#[cfg(feature = "std")]
#[test]
fn pre_order_single_block() {
    let tree = BaoTree::new(CHUNK_SIZE as u64, BlockSize::ZERO);
    let chunks = tree.pre_order_chunks();
    assert_eq!(chunks.len(), 1);
    assert!(matches!(
        chunks[0],
        BaoChunk::Leaf {
            start_chunk: 0,
            size,
            is_root: true,
        } if size == CHUNK_SIZE
    ));
}

#[cfg(feature = "std")]
#[test]
fn pre_order_two_blocks() {
    let tree = BaoTree::new(CHUNK_SIZE as u64 * 2, BlockSize::ZERO);
    let chunks = tree.pre_order_chunks();
    // Should be: Parent(root), Leaf(0), Leaf(1)
    assert_eq!(chunks.len(), 3);
    assert!(matches!(chunks[0], BaoChunk::Parent { is_root: true, .. }));
    assert!(matches!(
        chunks[1],
        BaoChunk::Leaf {
            start_chunk: 0,
            is_root: false,
            ..
        }
    ));
    assert!(matches!(
        chunks[2],
        BaoChunk::Leaf {
            start_chunk: 1,
            is_root: false,
            ..
        }
    ));
}

#[cfg(feature = "std")]
#[test]
fn post_order_two_blocks() {
    let tree = BaoTree::new(CHUNK_SIZE as u64 * 2, BlockSize::ZERO);
    let chunks = tree.post_order_chunks();
    // Should be: Leaf(0), Leaf(1), Parent(root)
    assert_eq!(chunks.len(), 3);
    assert!(matches!(
        chunks[0],
        BaoChunk::Leaf {
            start_chunk: 0,
            is_root: false,
            ..
        }
    ));
    assert!(matches!(
        chunks[1],
        BaoChunk::Leaf {
            start_chunk: 1,
            is_root: false,
            ..
        }
    ));
    assert!(matches!(chunks[2], BaoChunk::Parent { is_root: true, .. }));
}

#[cfg(feature = "std")]
#[test]
fn pre_order_four_blocks() {
    let tree = BaoTree::new(CHUNK_SIZE as u64 * 4, BlockSize::ZERO);
    let chunks = tree.pre_order_chunks();
    // Root parent, left parent, leaf 0, leaf 1, right parent, leaf 2, leaf 3
    assert_eq!(chunks.len(), 7);
    // First item is root parent
    assert!(matches!(chunks[0], BaoChunk::Parent { is_root: true, .. }));
    // All leaves are non-root
    let leaf_count = chunks
        .iter()
        .filter(|c| matches!(c, BaoChunk::Leaf { .. }))
        .count();
    assert_eq!(leaf_count, 4);
}
