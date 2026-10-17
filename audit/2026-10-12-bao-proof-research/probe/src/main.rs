//! Characterize the committed legacy carrier, without proposing a new decoder.
use cyber_bao::{
    BlockSize, CHUNK_SIZE, ChunkNum, ChunkRanges, HashBackend, Poseidon2Backend,
    io::slice::{decode_slice, extract_slice},
};

fn main() {
    let backend = Poseidon2Backend;
    let hello = b"hello";
    let (root, proof) = extract_slice(&backend, hello, 0..5, BlockSize::ZERO);
    assert_eq!(proof, [5_u64.to_le_bytes().as_slice(), hello].concat());
    let one = ChunkRanges::from(ChunkNum(0)..ChunkNum(1));
    for declared in [0_u64, 4, 5, 6, 4096] {
        let mut changed = proof.clone();
        changed[..8].copy_from_slice(&declared.to_le_bytes());
        let decoded = decode_slice(&backend, &changed, &root, &one, BlockSize::ZERO)
            .expect("legacy single-group decoder accepts changed header");
        assert_eq!(decoded, vec![(0, hello.to_vec())]);
        println!("single declared={declared} payload=5 accepted=true");
    }

    let body = vec![0x42; 2 * CHUNK_SIZE];
    let all = ChunkRanges::from(ChunkNum(0)..ChunkNum(2));
    let (root, mut proof) = extract_slice(&backend, &body, 0..8192, BlockSize::ZERO);
    let original_len = proof.len();
    proof.extend_from_slice(b"suffix");
    let decoded = decode_slice(&backend, &proof, &root, &all, BlockSize::ZERO)
        .expect("legacy multi-group decoder accepts suffix");
    assert_eq!(
        decoded,
        vec![(0, body[..4096].to_vec()), (4096, body[4096..].to_vec())]
    );
    println!("multi original={original_len} suffix=6 accepted=true");

    let (_, single_empty) = extract_slice(&backend, hello, 2..2, BlockSize::ZERO);
    assert_eq!(
        single_empty,
        [5_u64.to_le_bytes().as_slice(), hello].concat()
    );
    let (_, multi_empty) = extract_slice(&backend, &body, 2..2, BlockSize::ZERO);
    assert_eq!(multi_empty, 8192_u64.to_le_bytes());
    let empty = ChunkRanges::from(ChunkNum(0)..ChunkNum(0));
    let wrong = backend.chunk_hash(b"wrong", 0, true);
    let decoded = decode_slice(&backend, &multi_empty, &wrong, &empty, BlockSize::ZERO)
        .expect("legacy empty traversal performs no root check");
    assert!(decoded.is_empty());
    println!(
        "empty single_wire={} multi_wire={} multi_wrong_root_accepted=true",
        single_empty.len(),
        multi_empty.len()
    );
}
