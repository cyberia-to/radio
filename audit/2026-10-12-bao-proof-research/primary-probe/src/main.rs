//! Primary expressions and manual carriers, not a proposed verifier prototype.
use cyber_bao::{
    BlockSize, ChunkNum, ChunkRanges, HashBackend, Poseidon2Backend,
    group::GroupHasher,
    io::slice::{decode_slice, extract_slice},
};
use hemera::{Hash, field::P};
use std::{ops::Range, path::Path};

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((31 * i + i / 4096) % 256) as u8).collect()
}
fn leaf(data: &[u8], index: u64) -> Hash {
    Poseidon2Backend.chunk_hash(data, index, false)
}
fn parent(left: Hash, right: Hash, root: bool) -> Hash {
    Poseidon2Backend.parent_hash(&left, &right, root)
}
fn pair(wire: &mut Vec<u8>, left: Hash, right: Hash) {
    wire.extend_from_slice(left.as_bytes());
    wire.extend_from_slice(right.as_bytes());
}
fn save(dir: &Path, name: &str, wire: &[u8]) {
    std::fs::write(dir.join(format!("{name}.bin")), wire).unwrap();
}
fn ranges(range: Range<u64>) -> ChunkRanges {
    ChunkRanges::from(ChunkNum(range.start / 4096)..ChunkNum(range.end.div_ceil(4096)))
}
#[allow(clippy::too_many_arguments)]
fn witness(
    dir: &Path,
    name: &str,
    body: &[u8],
    root: Hash,
    wire: &[u8],
    request: Range<u64>,
    log: u8,
    expected: &[(u64, Vec<u8>)],
    actions: u64,
) {
    assert_eq!(
        u64::from_le_bytes(wire[..8].try_into().unwrap()),
        u64::try_from(body.len()).unwrap()
    );
    assert_eq!(
        decode_slice(
            &Poseidon2Backend,
            wire,
            &root,
            &ranges(request.clone()),
            BlockSize(log)
        )
        .unwrap(),
        expected
    );
    // Producer agreement is supplemental. The wire above was built by literal expressions.
    assert_eq!(
        extract_slice(&Poseidon2Backend, body, request.clone(), BlockSize(log)),
        (root, wire.to_vec())
    );
    save(dir, name, wire);
    println!(
        "fixture={name} size={} log={log} request={}..{} wire={} root={root} expected_actions={actions}",
        body.len(),
        request.start,
        request.end,
        wire.len()
    );
}
fn main() {
    let dir = std::env::args_os().nth(1).expect("fixture directory");
    let dir = Path::new(&dir);
    assert_eq!(P, 0xffff_ffff_0000_0001);
    let empty = Poseidon2Backend.chunk_hash(&[], 0, true);
    let hello = Poseidon2Backend.chunk_hash(b"hello", 0, true);
    assert_eq!(
        empty.to_string(),
        "ea57b2e6b1ec7d2de11b15cb6d7060dd61d247fe0fbf5f7d3fb97a7be9328552"
    );
    assert_eq!(
        hello.to_string(),
        "626fa46e4e7bd5c87d630eef8333931a0b9198587400a0191eae7821692880d7"
    );
    save(dir, "empty", &0u64.to_le_bytes());
    let mut wire = 5u64.to_le_bytes().to_vec();
    wire.extend_from_slice(b"hello");
    witness(
        dir,
        "hello",
        b"hello",
        hello,
        &wire,
        1..4,
        0,
        &[(0, b"hello".to_vec())],
        4,
    );
    println!("fixture=empty size=0 log=0 request=0..0 wire=8 root={empty} expected_actions=4");

    let body = data(12288);
    let l0 = leaf(&body[..4096], 0);
    let l1 = leaf(&body[4096..8192], 1);
    let l2 = leaf(&body[8192..], 2);
    let p01 = parent(l0, l1, false);
    let root = parent(p01, l2, true);
    let mut wire = 12288u64.to_le_bytes().to_vec();
    pair(&mut wire, p01, l2);
    wire.extend_from_slice(&body[8192..]);
    witness(
        dir,
        "three-right",
        &body,
        root,
        &wire,
        8192..8193,
        0,
        &[(8192, body[8192..].to_vec())],
        5,
    );
    let mut wire = 12288u64.to_le_bytes().to_vec();
    pair(&mut wire, p01, l2);
    pair(&mut wire, l0, l1);
    wire.extend_from_slice(&body[4096..8192]);
    witness(
        dir,
        "three-interior",
        &body,
        root,
        &wire,
        4097..4100,
        0,
        &[(4096, body[4096..8192].to_vec())],
        6,
    );
    let mut wire = 12288u64.to_le_bytes().to_vec();
    pair(&mut wire, p01, l2);
    pair(&mut wire, l0, l1);
    wire.extend_from_slice(&body[..8192]);
    witness(
        dir,
        "three-boundary",
        &body,
        root,
        &wire,
        4095..4097,
        0,
        &[
            (0, body[..4096].to_vec()),
            (4096, body[4096..8192].to_vec()),
        ],
        8,
    );
    let mut wire = 12288u64.to_le_bytes().to_vec();
    pair(&mut wire, p01, l2);
    wire.extend_from_slice(&body[..8192]);
    witness(
        dir,
        "grouped-left",
        &body,
        root,
        &wire,
        4095..4097,
        1,
        &[(0, body[..8192].to_vec())],
        7,
    );

    let body = data(8193);
    let l2 = leaf(&body[8192..], 2);
    let root = parent(p01, l2, true);
    let mut wire = 8193u64.to_le_bytes().to_vec();
    pair(&mut wire, p01, l2);
    wire.extend_from_slice(&body[8192..]);
    witness(
        dir,
        "final-short",
        &body,
        root,
        &wire,
        8192..8193,
        1,
        &[(8192, body[8192..].to_vec())],
        5,
    );

    let body = data(8192);
    let root = parent(l0, l1, true);
    assert_eq!(
        root.to_string(),
        "2abf65dd26465a7352707d79d18ff3aab9ee5d97614a774619c79ed527e20190"
    );
    assert_eq!(
        p01.to_string(),
        "11890a7e7cf1e4de463a04bf53bfdf269d627983a221daaf9029a3ff43297389"
    );
    assert_ne!(root, p01);
    let mut wire = 8192u64.to_le_bytes().to_vec();
    wire.extend_from_slice(&body);
    witness(
        dir,
        "sole-group",
        &body,
        root,
        &wire,
        1..8191,
        1,
        &[(0, body.clone())],
        6,
    );
    let mut reducer = GroupHasher::new(&Poseidon2Backend, &body, 0, true).unwrap();
    assert_eq!(reducer.step(), None);
    assert_eq!(reducer.step(), None);
    assert_eq!(reducer.step(), Some(root));
    assert!(reducer.is_complete());
    assert_eq!(reducer.step(), None);

    // Synthetic parent commitment, NOT the root of a witnessed complete file.
    // Its unselected sibling is an arbitrary zero CV. This probes representation.
    let zero = Hash::from_bytes([0; 32]);
    let synthetic_root = parent(l0, zero, true);
    let mut canonical = 8192u64.to_le_bytes().to_vec();
    pair(&mut canonical, l0, zero);
    canonical.extend_from_slice(&body[..4096]);
    let query = ranges(0..1);
    let baseline = decode_slice(
        &Poseidon2Backend,
        &canonical,
        &synthetic_root,
        &query,
        BlockSize(0),
    )
    .unwrap();
    assert_eq!(baseline, [(0, body[..4096].to_vec())]);
    save(dir, "synthetic-canonical", &canonical);
    for word in 0..4 {
        let mut noncanonical = [0; 32];
        noncanonical[word * 8..word * 8 + 8].copy_from_slice(&P.to_le_bytes());
        let raw = Hash::from_bytes(noncanonical);
        assert_ne!(raw, zero);
        assert_eq!(raw.as_bytes(), &noncanonical);
        assert_eq!(parent(l0, raw, true), synthetic_root);
        let mut alias = canonical.clone();
        alias[40 + word * 8..48 + word * 8].copy_from_slice(&P.to_le_bytes());
        assert_eq!(
            decode_slice(
                &Poseidon2Backend,
                &alias,
                &synthetic_root,
                &query,
                BlockSize(0)
            )
            .unwrap(),
            baseline
        );
        save(dir, &format!("synthetic-alias-{word}"), &alias);
        println!(
            "alias_word={word} raw_equal=false parent_equal=true legacy_accept=true root={synthetic_root}"
        );
    }
    for value in [0, P - 1, P, u64::MAX] {
        let mut raw = [0; 32];
        raw[..8].copy_from_slice(&value.to_le_bytes());
        assert_eq!(Hash::from_bytes(raw).as_bytes(), &raw);
        println!("word={value} proposed_canonical={}", value < P);
    }
    println!(
        "No new verifier API, allocation guarantee, or whole-file synthetic-root authority is tested here."
    );
}
