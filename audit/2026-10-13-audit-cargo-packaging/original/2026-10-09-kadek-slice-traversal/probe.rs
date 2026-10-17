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

fn fixture(chunks: usize) -> Vec<u8> {
    (0..chunks * CHUNK_SIZE)
        .map(|index| ((index * 31 + index / CHUNK_SIZE) % 256) as u8)
        .collect()
}

fn append_hash(bytes: &mut Vec<u8>, hash: Hash) {
    bytes.extend_from_slice(hash.as_bytes());
}

fn main() {
    std::fs::create_dir_all("fixtures").unwrap();
    println!("radio_revision=db1d62e2cd1e4b2f309fa19bcc158bd29b44753d");
    println!(
        "hemera_registry_version=0.3.1 source_revision=23f3bbcff910ea6d504ceb505680a539260869da"
    );
    println!("fixture_byte[index]=(index*31+index/4096)%256");

    let data = fixture(2);
    std::fs::write("fixtures/body-8192.bin", &data).unwrap();
    let grouped = PreOrderMemOutboard::create(&data, BlockSize::from_chunk_log(4));
    let ungrouped = PreOrderMemOutboard::create(&data, BlockSize::ZERO);
    let canonical = fixed_chunk_root(&data);
    let left = chunk_cv(&data[..CHUNK_SIZE], 0, false);
    let right = chunk_cv(&data[CHUNK_SIZE..], 1, false);
    let manual_root = parent_cv(&left, &right, true);
    let manual_internal = parent_cv(&left, &right, false);
    println!(
        "root_case body_bytes={} log4={} log0={} fixed_chunk_root={}",
        data.len(),
        grouped.root,
        ungrouped.root,
        canonical
    );
    println!(
        "root_case parent_root={} parent_internal={}",
        manual_root, manual_internal
    );
    assert_eq!(
        ungrouped.root, canonical,
        "log0 must match published Hemera fixed tree"
    );
    assert_eq!(canonical, manual_root, "independent two-leaf decomposition");
    assert_eq!(grouped.root, manual_internal, "observe lost root flag");
    assert_ne!(
        grouped.root, canonical,
        "reproduce block grouping changing root identity"
    );
    println!("root_case observed_defect=log4_root_differs_from_canonical_and_log0");

    let data = fixture(4);
    std::fs::write("fixtures/body-16384.bin", &data).unwrap();
    let backend = Poseidon2Backend;
    let ranges = ChunkRanges::from(ChunkNum(2)..ChunkNum(4));
    let (root, proof) = extract_slice_ranges(&backend, &data, &ranges, BlockSize::ZERO);
    std::fs::write("fixtures/right-2-4-log0.proof", &proof).unwrap();
    let leaves: [Hash; 4] = core::array::from_fn(|index| {
        chunk_cv(
            &data[index * CHUNK_SIZE..(index + 1) * CHUNK_SIZE],
            index as u64,
            false,
        )
    });
    let left_parent = parent_cv(&leaves[0], &leaves[1], false);
    let right_parent = parent_cv(&leaves[2], &leaves[3], false);
    let manual_root = parent_cv(&left_parent, &right_parent, true);
    let mut manual_proof = (data.len() as u64).to_le_bytes().to_vec();
    append_hash(&mut manual_proof, left_parent);
    append_hash(&mut manual_proof, right_parent);
    append_hash(&mut manual_proof, leaves[2]);
    append_hash(&mut manual_proof, leaves[3]);
    manual_proof.extend_from_slice(&data[2 * CHUNK_SIZE..]);
    assert_eq!(root, fixed_chunk_root(&data));
    assert_eq!(root, manual_root);
    assert_eq!(
        proof, manual_proof,
        "public extractor matches independent fixed four-leaf wire construction"
    );
    assert_eq!(proof.len(), 8 + 2 * 64 + 2 * CHUNK_SIZE);
    let result = decode_slice(&backend, &proof, &root, &ranges, BlockSize::ZERO);
    println!(
        "right_case body_bytes={} chunks=2..4 log=0 proof_bytes={} root={} independent_wire_match=true",
        data.len(),
        proof.len(),
        root
    );
    match &result {
        Ok(leaves) => println!("right_case actual=Ok leaves={}", leaves.len()),
        Err(error) => println!(
            "right_case actual=Err({error:?}) expected=Ok(offset8192,4096bytes;offset12288,4096bytes)"
        ),
    }
    assert_eq!(
        result,
        Err(SliceDecodeError::Truncated),
        "reproduce valid right-only proof rejection"
    );

    // Left-only and full requests distinguish the skip-state defect from a
    // generally invalid fixture, changed root convention, or broken extractor.
    for (start, end) in [(0, 2), (0, 4)] {
        let ranges = ChunkRanges::from(ChunkNum(start)..ChunkNum(end));
        let (control_root, control_proof) =
            extract_slice_ranges(&backend, &data, &ranges, BlockSize::ZERO);
        assert_eq!(control_root, root);
        let decoded =
            decode_slice(&backend, &control_proof, &root, &ranges, BlockSize::ZERO).unwrap();
        assert_eq!(decoded.len(), (end - start) as usize);
        for (index, (offset, bytes)) in decoded.iter().enumerate() {
            let expected_offset = (start as usize + index) * CHUNK_SIZE;
            assert_eq!(*offset, expected_offset as u64);
            assert_eq!(bytes, &data[expected_offset..expected_offset + CHUNK_SIZE]);
        }
        println!(
            "control_case chunks={start}..{end} actual=Ok leaves={} bytes_match=true",
            decoded.len()
        );
    }
    println!("isolated_source_repro=both_defects_observed_not_a_radio_gate");
}
