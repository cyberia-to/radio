use cyber_bao::{ChunkNum, ChunkRanges, CHUNK_SIZE};
use hemera::tree::{chunk_cv, parent_cv};

use crate::{store::IROH_BLOCK_SIZE, Hash};

pub(super) const GROUP: usize = 65536;

pub(super) fn ranges(start: u64, end: u64) -> ChunkRanges {
    (ChunkNum(start)..ChunkNum(end)).into()
}

pub(super) fn body(size: usize) -> Vec<u8> {
    assert_eq!(CHUNK_SIZE, 4096);
    assert_eq!(IROH_BLOCK_SIZE.bytes(), GROUP);
    (0..size)
        .map(|i| ((31 * i + i / 4096) % 256) as u8)
        .collect()
}

// Four explicit nonroot levels; no radio encoder, outboard or traversal oracle.
fn group_root(data: &[u8], start_chunk: u64) -> hemera::Hash {
    assert_eq!(data.len(), GROUP);
    let leaves: [_; 16] = core::array::from_fn(|i| {
        chunk_cv(
            &data[i * 4096..(i + 1) * 4096],
            start_chunk + i as u64,
            false,
        )
    });
    let p: [_; 8] = core::array::from_fn(|i| parent_cv(&leaves[2 * i], &leaves[2 * i + 1], false));
    let q: [_; 4] = core::array::from_fn(|i| parent_cv(&p[2 * i], &p[2 * i + 1], false));
    let r: [_; 2] = core::array::from_fn(|i| parent_cv(&q[2 * i], &q[2 * i + 1], false));
    parent_cv(&r[0], &r[1], false)
}

pub(super) struct Fixture {
    pub data: Vec<u8>,
    pub root: Hash,
    pub prefix: Vec<u8>,
}

impl Fixture {
    pub fn wire(&self, payload: &[u8]) -> Vec<u8> {
        let mut wire = self.prefix.clone();
        wire.extend_from_slice(payload);
        wire
    }

    pub fn full(&self) -> Vec<u8> {
        self.wire(&self.data)
    }

    pub fn middle(&self) -> Vec<u8> {
        self.wire(&self.data[GROUP..2 * GROUP])
    }
}

pub(super) fn two_groups() -> Fixture {
    let data = body(2 * GROUP);
    let left = group_root(&data[..GROUP], 0);
    let right = group_root(&data[GROUP..], 16);
    let root = parent_cv(&left, &right, true);
    assert_eq!(
        root.to_string(),
        "9ccd2809b2bcca875ee39f2c034c80969c176a5510a66d638b2c88c3cd7c7f0f"
    );
    let mut prefix = 131072u64.to_le_bytes().to_vec();
    prefix.extend_from_slice(left.as_bytes());
    prefix.extend_from_slice(right.as_bytes());
    let result = Fixture {
        data,
        root: root.into(),
        prefix,
    };
    assert_eq!(
        result.middle(),
        include_bytes!("right-proof.bin").as_slice()
    );
    result
}

pub(super) fn three_groups() -> Fixture {
    let data = body(3 * GROUP);
    let a = group_root(&data[..GROUP], 0);
    let b = group_root(&data[GROUP..2 * GROUP], 16);
    let c = group_root(&data[2 * GROUP..], 32);
    let ab = parent_cv(&a, &b, false);
    let root = parent_cv(&ab, &c, true);
    assert_eq!(root, hemera::tree::fixed_chunk_root(&data));
    let mut prefix = 196608u64.to_le_bytes().to_vec();
    for hash in [ab, c, a, b] {
        prefix.extend_from_slice(hash.as_bytes());
    }
    let result = Fixture {
        data,
        root: root.into(),
        prefix,
    };
    assert_eq!(result.full().len(), 196744);
    if let Some(dir) = std::env::var_os("RADIO_PARENT_PAIRS_FIXTURE_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::write(dir.join("three-full.bin"), result.full()).unwrap();
        std::fs::write(dir.join("three-middle.bin"), result.middle()).unwrap();
        std::fs::write(dir.join("three-root.txt"), root.to_string()).unwrap();
    }
    result
}
