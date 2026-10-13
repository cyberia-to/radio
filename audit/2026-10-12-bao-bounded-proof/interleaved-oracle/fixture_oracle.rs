// Research fixture assembly from explicit small-tree expressions. Uses only
// committed kernels, never a Bao encoder, traversal or proof verifier.
use cyber_bao::{HashBackend, Poseidon2Backend};
use std::{env, fs, path::Path};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let target = env::args().nth(1).expect("new output directory");
    let target = Path::new(&target);
    fs::create_dir(target).unwrap();
    let data: Vec<u8> = (0..16384)
        .map(|i| ((29 * i + 7 * (i / 4096)) % 251) as u8)
        .collect();
    let b = Poseidon2Backend;
    let l0 = b.chunk_hash(&data[..4096], 0, false);
    let l1 = b.chunk_hash(&data[4096..8192], 1, false);
    let l2 = b.chunk_hash(&data[8192..12288], 2, false);
    let l3 = b.chunk_hash(&data[12288..], 3, false);
    let p01 = b.parent_hash(&l0, &l1, false);
    let p23 = b.parent_hash(&l2, &l3, false);
    let root = b.parent_hash(&p01, &p23, true);
    let particle = hemera::hash(&data);

    let mut wire = (data.len() as u64).to_le_bytes().to_vec();
    for h in [p01, p23, l0, l1] {
        wire.extend_from_slice(h.as_bytes());
    }
    assert_eq!(wire.len(), 136);
    wire.extend_from_slice(&data[..8192]);
    assert_eq!(wire.len(), 8328);
    for h in [l2, l3] {
        wire.extend_from_slice(h.as_bytes());
    }
    assert_eq!(wire.len(), 8392);
    wire.extend_from_slice(&data[8192..12288]);
    assert_eq!(wire.len(), 12488);
    assert_eq!(&wire[136..4232], &data[..4096]);
    assert_eq!(&wire[4232..8328], &data[4096..8192]);
    assert_eq!(&wire[8392..12488], &data[8192..12288]);

    let mut selected = Vec::new();
    selected.extend_from_slice(&wire[4231..4232]);
    selected.extend_from_slice(&wire[4232..8328]);
    selected.extend_from_slice(&wire[8392..8393]);
    assert_eq!(selected, data[4095..8193]);
    assert_eq!(selected.len(), 4098);
    // A contiguous slice of the proof carrier includes the intervening pair,
    // and demonstrably is not the requested file range.
    assert_ne!(&wire[4231..4231 + selected.len()], selected.as_slice());

    fs::write(target.join("body.bin"), &data).unwrap();
    fs::write(target.join("interleaved.bao"), &wire).unwrap();
    fs::write(target.join("selected.bin"), &selected).unwrap();
    let manifest = format!(
        "{{\n  \"file_len\": 16384,\n  \"request\": [4095, 8193],\n  \"group_log\": 0,\n  \"particle\": \"{}\",\n  \"root\": \"{}\",\n  \"wire_bytes\": 12488,\n  \"groups\": [[136, 0, 4096], [4232, 4096, 4096], [8392, 8192, 4096]],\n  \"parent_offsets\": [8, 72, 8328],\n  \"derived_verification_actions\": 11,\n  \"derived_output_actions\": 73,\n  \"derived_total_actions\": 84\n}}\n",
        hex(particle.as_bytes()),
        hex(root.as_bytes())
    );
    fs::write(target.join("manifest.json"), &manifest).unwrap();
    print!("{manifest}");
    println!(
        "Explicit small-tree assembly PASS; no Bao traversal/encoder/verifier or Kadek adapter executed"
    );
}
