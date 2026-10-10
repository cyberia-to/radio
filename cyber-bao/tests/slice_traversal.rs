//! Literal tree/proof decompositions, independent of radio's traversal/extractor.
use cyber_bao::{
    BlockSize, CHUNK_SIZE, ChunkNum, ChunkRanges, Poseidon2Backend,
    io::{
        pre_order::PreOrderMemOutboard,
        slice::{SliceDecodeError, decode_slice, extract_slice_ranges},
    },
};
use hemera::{
    Hash,
    tree::{chunk_cv, fixed_chunk_root, parent_cv},
};

fn body(bytes: usize) -> Vec<u8> {
    (0..bytes)
        .map(|index| ((index * 31 + index / CHUNK_SIZE) % 256) as u8)
        .collect()
}

fn leaves<const N: usize>(data: &[u8]) -> [Hash; N] {
    core::array::from_fn(|index| {
        let start = index * CHUNK_SIZE;
        chunk_cv(
            &data[start..(start + CHUNK_SIZE).min(data.len())],
            index as u64,
            false,
        )
    })
}

fn pair(proof: &mut Vec<u8>, left: &Hash, right: &Hash) {
    proof.extend_from_slice(left.as_bytes());
    proof.extend_from_slice(right.as_bytes());
}

fn ranges(start: u64, end: u64) -> ChunkRanges {
    ChunkRanges::from(ChunkNum(start)..ChunkNum(end))
}

fn check(
    data: &[u8],
    proof: &[u8],
    root: &Hash,
    request: &ChunkRanges,
    log: u8,
    expected: &[(usize, usize)],
) {
    let block_size = BlockSize::from_chunk_log(log);
    // This comparison is secondary: neither root nor wire is derived by radio.
    let (extracted_root, extracted_proof) =
        extract_slice_ranges(&Poseidon2Backend, data, request, block_size);
    assert_eq!(&extracted_root, root);
    assert_eq!(extracted_proof, proof);
    let actual = decode_slice(&Poseidon2Backend, proof, root, request, block_size)
        .expect("independently constructed valid proof must decode");
    assert_eq!(actual.len(), expected.len());
    for ((offset, bytes), &(start, size)) in actual.iter().zip(expected) {
        assert_eq!(*offset, start as u64);
        assert_eq!(bytes, &data[start..start + size]);
    }
}

#[derive(Debug)]
struct Four {
    data: Vec<u8>,
    h: [Hash; 4],
    left: Hash,
    right: Hash,
    root: Hash,
}

impl Four {
    fn new() -> Self {
        let data = body(4 * CHUNK_SIZE);
        let h = leaves(&data);
        let left = parent_cv(&h[0], &h[1], false);
        let right = parent_cv(&h[2], &h[3], false);
        let root = parent_cv(&left, &right, true);
        Self {
            data,
            h,
            left,
            right,
            root,
        }
    }

    fn header(&self) -> Vec<u8> {
        let mut proof = (self.data.len() as u64).to_le_bytes().to_vec();
        pair(&mut proof, &self.left, &self.right);
        proof
    }

    fn right_proof(&self) -> Vec<u8> {
        let mut proof = self.header();
        pair(&mut proof, &self.h[2], &self.h[3]);
        proof.extend_from_slice(&self.data[2 * CHUNK_SIZE..]);
        proof
    }
}

#[test]
fn literal_right_subtree_is_authenticated() {
    let f = Four::new();
    assert_eq!(
        f.root.to_string(),
        "ed9bec157f55deb7db92a3ae251e2b1e74a729b4bac2baa639b3c3b5dae8579c"
    );
    assert_eq!(f.root, fixed_chunk_root(&f.data));
    let proof = f.right_proof();
    assert_eq!(proof.len(), 8328);
    check(
        &f.data,
        &proof,
        &f.root,
        &ranges(2, 4),
        0,
        &[(8192, 4096), (12288, 4096)],
    );
}

#[test]
fn literal_left_and_full_controls() {
    let f = Four::new();
    let mut proof = f.header();
    pair(&mut proof, &f.h[0], &f.h[1]);
    proof.extend_from_slice(&f.data[..2 * CHUNK_SIZE]);
    check(
        &f.data,
        &proof,
        &f.root,
        &ranges(0, 2),
        0,
        &[(0, 4096), (4096, 4096)],
    );
    pair(&mut proof, &f.h[2], &f.h[3]);
    proof.extend_from_slice(&f.data[2 * CHUNK_SIZE..]);
    check(
        &f.data,
        &proof,
        &f.root,
        &ranges(0, 4),
        0,
        &[(0, 4096), (4096, 4096), (8192, 4096), (12288, 4096)],
    );
}

#[test]
fn literal_nested_right_subtree() {
    let data = body(8 * CHUNK_SIZE);
    let h: [Hash; 8] = leaves(&data);
    let p: [Hash; 4] = core::array::from_fn(|i| parent_cv(&h[2 * i], &h[2 * i + 1], false));
    let left = parent_cv(&p[0], &p[1], false);
    let right = parent_cv(&p[2], &p[3], false);
    let root = parent_cv(&left, &right, true);
    let mut proof = (data.len() as u64).to_le_bytes().to_vec();
    pair(&mut proof, &left, &right);
    pair(&mut proof, &p[2], &p[3]);
    pair(&mut proof, &h[6], &h[7]);
    proof.extend_from_slice(&data[6 * CHUNK_SIZE..]);
    check(
        &data,
        &proof,
        &root,
        &ranges(6, 8),
        0,
        &[(24576, 4096), (28672, 4096)],
    );
}

#[test]
fn literal_sparse_leaves() {
    let f = Four::new();
    let mut proof = f.header();
    pair(&mut proof, &f.h[0], &f.h[1]);
    proof.extend_from_slice(&f.data[..CHUNK_SIZE]);
    pair(&mut proof, &f.h[2], &f.h[3]);
    proof.extend_from_slice(&f.data[3 * CHUNK_SIZE..]);
    let request = ranges(0, 1) | ranges(3, 4);
    check(
        &f.data,
        &proof,
        &f.root,
        &request,
        0,
        &[(0, 4096), (12288, 4096)],
    );
}

#[test]
fn literal_partial_fifth_leaf_and_mixed_outside_query() {
    let data = body(4 * CHUNK_SIZE + 500);
    let h: [Hash; 5] = leaves(&data);
    let p01 = parent_cv(&h[0], &h[1], false);
    let p23 = parent_cv(&h[2], &h[3], false);
    let left = parent_cv(&p01, &p23, false);
    let root = parent_cv(&left, &h[4], true);
    let mut proof = (data.len() as u64).to_le_bytes().to_vec();
    pair(&mut proof, &left, &h[4]);
    let mut right_proof = proof.clone();
    right_proof.extend_from_slice(&data[4 * CHUNK_SIZE..]);
    check(
        &data,
        &right_proof,
        &root,
        &ranges(4, 5),
        0,
        &[(16384, 500)],
    );

    // The padded right span can be visited without emitting a leaf. No final
    // stack-empty assertion belongs to the in-file traversal invariant.
    pair(&mut proof, &p01, &p23);
    pair(&mut proof, &h[0], &h[1]);
    proof.extend_from_slice(&data[..CHUNK_SIZE]);
    let request = ranges(0, 1) | ranges(6, 7);
    check(&data, &proof, &root, &request, 0, &[(0, 4096)]);
}

#[test]
fn literal_grouped_right_blocks() {
    let data = body(8 * CHUNK_SIZE);
    let h: [Hash; 8] = leaves(&data);
    let blocks: [Hash; 4] = core::array::from_fn(|i| parent_cv(&h[2 * i], &h[2 * i + 1], false));
    let left = parent_cv(&blocks[0], &blocks[1], false);
    let right = parent_cv(&blocks[2], &blocks[3], false);
    let root = parent_cv(&left, &right, true);
    let mut proof = (data.len() as u64).to_le_bytes().to_vec();
    pair(&mut proof, &left, &right);
    pair(&mut proof, &blocks[2], &blocks[3]);
    proof.extend_from_slice(&data[4 * CHUNK_SIZE..]);
    check(
        &data,
        &proof,
        &root,
        &ranges(4, 8),
        1,
        &[(16384, 8192), (24576, 8192)],
    );
}

#[test]
fn right_proof_rejects_corruption_and_truncation() {
    let f = Four::new();
    let proof = f.right_proof();
    let decode = |bytes: &[u8], root: &Hash| {
        decode_slice(
            &Poseidon2Backend,
            bytes,
            root,
            &ranges(2, 4),
            BlockSize::ZERO,
        )
    };
    for (index, expected) in [
        (8, SliceDecodeError::ParentMismatch { node: 3 }),
        (72, SliceDecodeError::ParentMismatch { node: 5 }),
        (136, SliceDecodeError::LeafMismatch { start_chunk: 2 }),
    ] {
        let mut corrupt = proof.clone();
        corrupt[index] ^= 1;
        assert_eq!(decode(&corrupt, &f.root), Err(expected));
    }
    for end in [7, 71, 135, proof.len() - 1] {
        assert_eq!(
            decode(&proof[..end], &f.root),
            Err(SliceDecodeError::Truncated)
        );
    }
    assert_eq!(
        decode(&proof, &Hash::from_bytes([0; 32])),
        Err(SliceDecodeError::ParentMismatch { node: 3 })
    );
}

#[test]
fn multiblock_empty_and_outside_queries_preserve_existing_behavior() {
    let f = Four::new();
    let header = (f.data.len() as u64).to_le_bytes();
    for request in [ChunkRanges::empty(), ranges(10, 12)] {
        // Empty output is only existing query behavior, not root authentication.
        check(&f.data, &header, &f.root, &request, 0, &[]);
    }
}

#[test]
fn grouped_single_block_has_canonical_root_finalization() {
    let data = body(2 * CHUNK_SIZE);
    let h: [Hash; 2] = leaves(&data);
    let internal = parent_cv(&h[0], &h[1], false);
    let canonical = parent_cv(&h[0], &h[1], true);
    let grouped = PreOrderMemOutboard::create(&data, BlockSize::from_chunk_log(4));
    let ungrouped = PreOrderMemOutboard::create(&data, BlockSize::ZERO);
    assert_eq!(grouped.root, canonical);
    assert_eq!(ungrouped.root, canonical);
    assert_eq!(fixed_chunk_root(&data), canonical);
    assert_ne!(internal, canonical);
    assert_eq!(
        internal.to_string(),
        "11890a7e7cf1e4de463a04bf53bfdf269d627983a221daaf9029a3ff43297389"
    );
    assert_eq!(
        canonical.to_string(),
        "2abf65dd26465a7352707d79d18ff3aab9ee5d97614a774619c79ed527e20190"
    );
}
