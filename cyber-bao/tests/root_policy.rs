//! Independent fixed-tree roots, literal proofs, and public verification paths.
use std::convert::Infallible;

use bytes::Bytes;
use cyber_bao::{
    BaoTree, BlockSize, CHUNK_SIZE, ChunkNum, ChunkRanges, Poseidon2Backend,
    io::{
        EncodeError,
        decode::{DecodeError as CombinedError, decode},
        encode::encode,
        hash_block,
        mixed::{EncodedItem, Sender, traverse_ranges_validated},
        outboard::outboard,
        pre_order::{PostOrderMemOutboard, PreOrderMemOutboard},
        slice::{SliceDecodeError, decode_slice, extract_slice_ranges},
        sync::{encode_ranges_validated, valid_ranges},
    },
};
use hemera::{
    Hash,
    tree::{chunk_cv, fixed_chunk_root, parent_cv},
};

const CANONICAL: &str = "2abf65dd26465a7352707d79d18ff3aab9ee5d97614a774619c79ed527e20190";
const OLD: &str = "11890a7e7cf1e4de463a04bf53bfdf269d627983a221daaf9029a3ff43297389";

fn body(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i * 31 + i / CHUNK_SIZE) % 256) as u8)
        .collect()
}

fn fixture() -> (Vec<u8>, Hash, Hash, Vec<u8>) {
    let data = body(8192);
    let left = chunk_cv(&data[..CHUNK_SIZE], 0, false);
    let right = chunk_cv(&data[CHUNK_SIZE..], 1, false);
    let root = parent_cv(&left, &right, true);
    let old = parent_cv(&left, &right, false);
    assert_eq!(root.to_string(), CANONICAL);
    assert_eq!(old.to_string(), OLD);
    assert_eq!(root, fixed_chunk_root(&data));
    let mut wire = 8192u64.to_le_bytes().to_vec();
    wire.extend_from_slice(&data);
    (data, root, old, wire)
}

fn grouped(root: Hash) -> PreOrderMemOutboard {
    PreOrderMemOutboard {
        root,
        tree: BaoTree::new(8192, BlockSize::from_chunk_log(4)),
        data: Vec::new(),
    }
}

#[test]
fn literal_root_reaches_every_producer() {
    let (data, root, _, wire) = fixture();
    let bs = BlockSize::from_chunk_log(4);
    assert_eq!(
        hash_block(&Poseidon2Backend, &data, 0, true, bs.bytes()),
        root
    );
    let ob = outboard(&Poseidon2Backend, &data, bs);
    assert_eq!(ob.root, root);
    assert!(ob.data.is_empty());
    assert_eq!(PreOrderMemOutboard::create(&data, bs).root, root);
    assert_eq!(PostOrderMemOutboard::create(&data, bs).root, root);
    assert_eq!(encode(&Poseidon2Backend, &data, bs), (root, wire.clone()));
    assert_eq!(
        extract_slice_ranges(&Poseidon2Backend, &data, &ChunkRanges::all(), bs),
        (root, wire)
    );
}

#[test]
fn literal_proof_accepts_canonical_root() {
    let (data, root, _, wire) = fixture();
    let bs = BlockSize::from_chunk_log(4);
    assert_eq!(decode(&Poseidon2Backend, &wire, &root, bs).unwrap(), data);
    assert_eq!(
        decode_slice(&Poseidon2Backend, &wire, &root, &ChunkRanges::all(), bs).unwrap(),
        [(0, data.clone())]
    );
    let mut encoded = Vec::new();
    encode_ranges_validated(&data[..], &grouped(root), &ChunkRanges::all(), &mut encoded).unwrap();
    // Sync range encoding carries no size prefix.
    assert_eq!(encoded, wire[8..]);
    let ranges = ChunkRanges::all();
    let valid: Vec<_> = valid_ranges(grouped(root), &data[..], &ranges)
        .into_iter()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(valid.len(), 1);
    assert_eq!(valid[0], ChunkNum(0)..ChunkNum(2));
}

#[test]
fn literal_proof_rejects_the_old_internal_cv() {
    let (data, _, old, wire) = fixture();
    let bs = BlockSize::from_chunk_log(4);
    assert_eq!(
        decode(&Poseidon2Backend, &wire, &old, bs),
        Err(CombinedError::LeafMismatch { start_chunk: 0 })
    );
    assert_eq!(
        decode_slice(&Poseidon2Backend, &wire, &old, &ChunkRanges::all(), bs),
        Err(SliceDecodeError::LeafMismatch { start_chunk: 0 })
    );
    let mut encoded = Vec::new();
    assert!(matches!(
        encode_ranges_validated(&data[..], &grouped(old), &ChunkRanges::all(), &mut encoded),
        Err(EncodeError::LeafHashMismatch(ChunkNum(0)))
    ));
    assert!(encoded.is_empty());
    assert!(
        valid_ranges(grouped(old), &data[..], &ChunkRanges::all())
            .into_iter()
            .next()
            .is_none()
    );
}

#[test]
fn grouping_preserves_fixed_tree_at_boundaries() {
    // Five-leaf partial root:16385/log4; non-root groups4+2 and4+3:24576/28672 log2.
    for len in [
        0, 1, 4095, 4096, 4097, 8192, 12288, 16384, 16385, 24576, 28672, 65536, 65537, 131072,
    ] {
        let data = body(len);
        let expected = fixed_chunk_root(&data);
        for log in [0, 1, 2, 4] {
            let bs = BlockSize::from_chunk_log(log);
            assert_eq!(
                outboard(&Poseidon2Backend, &data, bs).root,
                expected,
                "len={len} log={log}"
            );
        }
    }
}

#[test]
fn published_empty_and_hello_tree_vectors_are_unchanged() {
    // Hemera23f3bbcf vectors/hemera.json: these inputs are also one fixed chunk.
    for (data, expected) in [
        (
            &b""[..],
            "ea57b2e6b1ec7d2de11b15cb6d7060dd61d247fe0fbf5f7d3fb97a7be9328552",
        ),
        (
            &b"hello"[..],
            "626fa46e4e7bd5c87d630eef8333931a0b9198587400a0191eae7821692880d7",
        ),
    ] {
        assert_eq!(fixed_chunk_root(data).to_string(), expected);
        assert_eq!(
            PreOrderMemOutboard::create(data, BlockSize::from_chunk_log(4))
                .root
                .to_string(),
            expected
        );
    }
}

#[test]
fn non_root_partial_and_odd_groups_verify_with_absolute_counters() {
    for (len, log) in [(24576, 2), (28672, 2), (65537, 4)] {
        let data = body(len);
        let bs = BlockSize::from_chunk_log(log);
        let start = 1u64 << log;
        let ranges = ChunkRanges::from(ChunkNum(start)..ChunkNum::chunks(len as u64));
        let (root, wire) = extract_slice_ranges(&Poseidon2Backend, &data, &ranges, bs);
        assert_eq!(root, fixed_chunk_root(&data));
        let offset = start * CHUNK_SIZE as u64;
        assert_eq!(
            decode_slice(&Poseidon2Backend, &wire, &root, &ranges, bs).unwrap(),
            [(offset, data[offset as usize..].to_vec())]
        );
        let mut encoded = Vec::new();
        let ob = PreOrderMemOutboard::create(&data, bs);
        encode_ranges_validated(&data[..], &ob, &ranges, &mut encoded).unwrap();
        assert_eq!(encoded, wire[8..]);
    }
}

#[derive(Default)]
struct Events(Vec<EncodedItem>);

impl Sender for Events {
    type Error = Infallible;

    async fn send(&mut self, item: EncodedItem) -> Result<(), Self::Error> {
        self.0.push(item);
        Ok(())
    }
}

#[tokio::test]
async fn mixed_canonical_success_and_old_root_terminal_error() {
    let (data, root, old, _) = fixture();
    let mut events = Events::default();
    traverse_ranges_validated(
        Bytes::copy_from_slice(&data),
        grouped(root),
        &ChunkRanges::all(),
        &mut events,
    )
    .await
    .unwrap();
    let [
        EncodedItem::Size(8192),
        EncodedItem::Leaf(leaf),
        EncodedItem::Done,
    ] = events.0.as_slice()
    else {
        panic!("unexpected success events: {:?}", events.0);
    };
    assert_eq!(leaf.offset, 0);
    assert_eq!(leaf.data.as_ref(), data);
    let mut events = Events::default();
    traverse_ranges_validated(
        Bytes::from(data),
        grouped(old),
        &ChunkRanges::all(),
        &mut events,
    )
    .await
    .unwrap();
    assert!(matches!(
        events.0.as_slice(),
        [
            EncodedItem::Size(8192),
            EncodedItem::Error(EncodeError::LeafHashMismatch(ChunkNum(0)))
        ]
    ));
}

#[cfg(feature = "tokio_fsm")]
#[tokio::test]
async fn fsm_literal_canonical_leaf_and_old_root_error() {
    use cyber_bao::io::{
        BaoContentItem, DecodeError,
        fsm::{ResponseDecoder, ResponseDecoderNext},
    };
    let (data, root, old, _) = fixture();
    let tree = grouped(root).tree;
    let decoder = ResponseDecoder::new(
        root,
        ChunkRanges::all(),
        tree,
        Bytes::copy_from_slice(&data),
    );
    let ResponseDecoderNext::More((next, Ok(BaoContentItem::Leaf(leaf)))) = decoder.next().await
    else {
        panic!("canonical leaf was rejected");
    };
    assert_eq!(leaf.offset, 0);
    assert_eq!(leaf.data.as_ref(), data);
    let ResponseDecoderNext::Done(remaining) = next.next().await else {
        panic!("unexpected extra item");
    };
    assert!(remaining.is_empty());
    let decoder = ResponseDecoder::new(old, ChunkRanges::all(), tree, Bytes::from(data));
    assert!(matches!(
        decoder.next().await,
        ResponseDecoderNext::More((_, Err(DecodeError::LeafHashMismatch(ChunkNum(0)))))
    ));
}
