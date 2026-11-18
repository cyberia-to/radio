//! The verified-streaming format exists once.
//!
//! `hemera::stream` is the canonical pre-order format (8-byte length header,
//! then parent pairs interleaved with leaf chunks in pre-order). `cyber-bao`
//! is radio's ranged adapter over the same tree. This test pins that at the
//! whole-tree block size the two produce the same root, the same outboard
//! pairs and the same combined stream, byte for byte, so neither can drift
//! into a second format.

use cyber_bao::io::pre_order::PreOrderMemOutboard;
use cyber_bao::io::sync::encode_ranges_validated;
use cyber_bao::{BlockSize, ChunkRanges};

const HEADER: usize = 8;

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

fn check(len: usize) {
    let data = sample(len);

    let (h_root, h_outboard) = hemera::stream::outboard(&data);
    let (h_root_2, h_combined) = hemera::stream::encode(&data);
    assert_eq!(h_root, h_root_2, "hemera outboard/encode roots differ at {len}");
    assert_eq!(&h_outboard[..HEADER], &(len as u64).to_le_bytes());

    let ob = PreOrderMemOutboard::create(&data, BlockSize::ZERO);
    assert_eq!(ob.root, h_root, "root differs from hemera at len {len}");
    assert_eq!(&ob.data[..], &h_outboard[HEADER..], "outboard pairs differ at len {len}");

    let mut combined = Vec::new();
    encode_ranges_validated(&data[..], &ob, &ChunkRanges::all(), &mut combined)
        .expect("encode whole tree");
    assert_eq!(&combined[..], &h_combined[HEADER..], "combined stream differs at len {len}");
}

#[test]
fn whole_tree_format_matches_hemera_stream() {
    for len in [0usize, 1, 100, 4095, 4096, 4097, 8192, 12_345, 100_000, 1_000_000] {
        check(len);
    }
}
