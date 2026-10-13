#![allow(dead_code)]
//! Independent small-tree expressions and literal carrier coordinates.
use std::ops::Range;

use cyber_bao::{HashBackend, Poseidon2Backend};
use hemera::Hash;

pub struct Case {
    pub name: &'static str,
    pub root: [u8; 32],
    pub size: u64,
    pub log: u8,
    pub request: Range<u64>,
    pub wire: Vec<u8>,
    pub actions: usize,
    /// None is one opaque parent; Some is (proof offset, file offset, length).
    pub output: Vec<Option<(usize, u64, usize)>>,
}

pub fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((31 * i + i / 4096) % 256) as u8).collect()
}
pub fn digest(hex: &str) -> [u8; 32] {
    std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
}
pub fn leaf(data: &[u8], counter: u64) -> Hash {
    Poseidon2Backend.chunk_hash(data, counter, false)
}
pub fn parent(left: Hash, right: Hash, root: bool) -> Hash {
    Poseidon2Backend.parent_hash(&left, &right, root)
}
pub fn pair(wire: &mut Vec<u8>, left: Hash, right: Hash) {
    wire.extend_from_slice(left.as_bytes());
    wire.extend_from_slice(right.as_bytes());
}
fn case(name: &'static str, root: Hash, size: u64, log: u8, request: Range<u64>) -> Case {
    Case {
        name,
        root: *root.as_bytes(),
        size,
        log,
        request,
        wire: size.to_le_bytes().to_vec(),
        actions: 0,
        output: Vec::new(),
    }
}
pub fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    let empty = Poseidon2Backend.chunk_hash(&[], 0, true);
    assert_eq!(
        *empty.as_bytes(),
        digest("ea57b2e6b1ec7d2de11b15cb6d7060dd61d247fe0fbf5f7d3fb97a7be9328552")
    );
    let mut c = case("empty", empty, 0, 0, 0..0);
    c.actions = 4;
    out.push(c);
    let hello = Poseidon2Backend.chunk_hash(b"hello", 0, true);
    assert_eq!(
        *hello.as_bytes(),
        digest("626fa46e4e7bd5c87d630eef8333931a0b9198587400a0191eae7821692880d7")
    );
    let mut c = case("hello", hello, 5, 0, 1..4);
    c.wire.extend_from_slice(b"hello");
    c.actions = 4;
    c.output = vec![Some((8, 0, 5))];
    out.push(c);

    let d = data(12288);
    let l0 = leaf(&d[..4096], 0);
    let l1 = leaf(&d[4096..8192], 1);
    let l2 = leaf(&d[8192..], 2);
    let p01 = parent(l0, l1, false);
    let root = parent(p01, l2, true);
    assert_eq!(
        *root.as_bytes(),
        digest("373d0ded6b2bd351ba575cdc690ca79bbc04af1a49844f67140ce7a10e672992")
    );
    let mut c = case("three-right", root, 12288, 0, 8192..8193);
    pair(&mut c.wire, p01, l2);
    c.wire.extend_from_slice(&d[8192..]);
    c.actions = 5;
    c.output = vec![None, Some((72, 8192, 4096))];
    out.push(c);
    let mut c = case("three-interior", root, 12288, 0, 4097..4100);
    pair(&mut c.wire, p01, l2);
    pair(&mut c.wire, l0, l1);
    c.wire.extend_from_slice(&d[4096..8192]);
    c.actions = 6;
    c.output = vec![None, None, Some((136, 4096, 4096))];
    out.push(c);
    let mut c = case("three-boundary", root, 12288, 0, 4095..4097);
    pair(&mut c.wire, p01, l2);
    pair(&mut c.wire, l0, l1);
    c.wire.extend_from_slice(&d[..8192]);
    c.actions = 8;
    c.output = vec![None, None, Some((136, 0, 4096)), Some((4232, 4096, 4096))];
    out.push(c);
    let mut c = case("grouped-left", root, 12288, 1, 4095..4097);
    pair(&mut c.wire, p01, l2);
    c.wire.extend_from_slice(&d[..8192]);
    c.actions = 7;
    c.output = vec![None, Some((72, 0, 8192))];
    out.push(c);
    let short = data(8193);
    let final_cv = leaf(&short[8192..], 2);
    let short_root = parent(p01, final_cv, true);
    assert_eq!(
        *short_root.as_bytes(),
        digest("40c6bd68b6e89443753bce2dd95fd159da63a7399340fa6070a762d102d9e3ae")
    );
    let mut c = case("final-short", short_root, 8193, 1, 8192..8193);
    pair(&mut c.wire, p01, final_cv);
    c.wire.extend_from_slice(&short[8192..]);
    c.actions = 5;
    c.output = vec![None, Some((72, 8192, 1))];
    out.push(c);
    let root2 = parent(l0, l1, true);
    assert_eq!(
        *root2.as_bytes(),
        digest("2abf65dd26465a7352707d79d18ff3aab9ee5d97614a774619c79ed527e20190")
    );
    assert_eq!(
        *p01.as_bytes(),
        digest("11890a7e7cf1e4de463a04bf53bfdf269d627983a221daaf9029a3ff43297389")
    );
    assert_ne!(root2, p01);
    let mut c = case("sole-group", root2, 8192, 1, 1..8191);
    c.wire.extend_from_slice(&d[..8192]);
    c.actions = 6;
    c.output = vec![Some((8, 0, 8192))];
    out.push(c);

    for (log, actions) in [(0, 10), (1, 9), (2, 8), (4, 8)] {
        let mut c = case("full-three", root, 12288, log, 0..12288);
        if log == 0 {
            pair(&mut c.wire, p01, l2);
            pair(&mut c.wire, l0, l1);
            c.output = vec![
                None,
                None,
                Some((136, 0, 4096)),
                Some((4232, 4096, 4096)),
                Some((8328, 8192, 4096)),
            ];
        } else if log == 1 {
            pair(&mut c.wire, p01, l2);
            c.output = vec![None, Some((72, 0, 8192)), Some((8264, 8192, 4096))];
        } else {
            c.output = vec![Some((8, 0, 12288))];
        }
        c.wire.extend_from_slice(&d);
        c.actions = actions;
        out.push(c);
    }
    let d = data(7 * 4096);
    let l: Vec<_> = d
        .chunks(4096)
        .enumerate()
        .map(|(i, b)| leaf(b, u64::try_from(i).unwrap()))
        .collect();
    let p01 = parent(l[0], l[1], false);
    let p23 = parent(l[2], l[3], false);
    let p03 = parent(p01, p23, false);
    let p45 = parent(l[4], l[5], false);
    let p46 = parent(p45, l[6], false);
    let root5 = parent(p03, l[4], true);
    let root7 = parent(p03, p46, true);
    let mut c = case("five-right", root5, 5 * 4096, 0, 16384..16385);
    pair(&mut c.wire, p03, l[4]);
    c.wire.extend_from_slice(&d[16384..20480]);
    c.actions = 5;
    c.output = vec![None, Some((72, 16384, 4096))];
    out.push(c);
    let mut c = case("five-interior", root5, 5 * 4096, 0, 12289..12290);
    pair(&mut c.wire, p03, l[4]);
    pair(&mut c.wire, p01, p23);
    pair(&mut c.wire, l[2], l[3]);
    c.wire.extend_from_slice(&d[12288..16384]);
    c.actions = 7;
    c.output = vec![None, None, None, Some((200, 12288, 4096))];
    out.push(c);
    let mut c = case("seven-right", root7, 7 * 4096, 0, 24576..24577);
    pair(&mut c.wire, p03, p46);
    pair(&mut c.wire, p45, l[6]);
    c.wire.extend_from_slice(&d[24576..]);
    c.actions = 6;
    c.output = vec![None, None, Some((136, 24576, 4096))];
    out.push(c);
    let mut c = case("seven-interior", root7, 7 * 4096, 0, 20481..20482);
    pair(&mut c.wire, p03, p46);
    pair(&mut c.wire, p45, l[6]);
    pair(&mut c.wire, l[4], l[5]);
    c.wire.extend_from_slice(&d[20480..24576]);
    c.actions = 7;
    c.output = vec![None, None, None, Some((200, 20480, 4096))];
    out.push(c);
    out
}

pub fn named(name: &str) -> Case {
    cases().into_iter().find(|c| c.name == name).unwrap()
}

/// Synthetic commitment prefix; no actual enormous complete file is witnessed.
pub fn deep_prefix() -> ([u8; 32], Vec<u8>) {
    let d = data(4096);
    let mut left = leaf(&d, 0);
    let zero = Hash::from_bytes([0; 32]);
    let mut pairs = Vec::new();
    for level in 0..52 {
        pairs.push((left, zero));
        left = parent(left, zero, level == 51);
    }
    let mut wire = u64::MAX.to_le_bytes().to_vec();
    for (left, right) in pairs.into_iter().rev() {
        pair(&mut wire, left, right);
    }
    wire.extend_from_slice(&d);
    assert_eq!(wire.len(), 7432);
    (*left.as_bytes(), wire)
}
