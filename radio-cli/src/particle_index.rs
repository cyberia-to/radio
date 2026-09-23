//! Maps a cyber particle hash (Poseidon2/hemera, the identity `cyb` and the
//! rest of the graph address a file by) to the iroh-blobs content hash
//! (BLAKE3) of the same bytes, so a blob can be requested from a peer by
//! particle instead of by the transport's own hash. The two hashes are
//! computed independently over identical bytes and never coincide, so
//! resolving "fetch this particle" into "fetch this blob hash" needs this
//! translation step before the standard `iroh_blobs` get protocol can run.
//!
//! Stored as one `<particle-hex> <blob-hash-hex>` pair per line — no new
//! dependency for a mapping this small.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ParticleIndex(HashMap<String, String>);

impl ParticleIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, particle: hemera::Hash, blob_hash: iroh_blobs::Hash) {
        self.0.insert(particle.to_string(), blob_hash.to_string());
    }

    pub fn lookup(&self, particle: &hemera::Hash) -> Option<iroh_blobs::Hash> {
        self.0.get(&particle.to_string())?.parse().ok()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// An index file that does not exist yet is an empty index — `Add`
    /// creates it on first use instead of requiring it be pre-created.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let mut map = HashMap::new();
        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let particle = parts.next().with_context(|| {
                format!("{}:{}: missing particle hash", path.display(), lineno + 1)
            })?;
            let blob = parts.next().with_context(|| {
                format!("{}:{}: missing blob hash", path.display(), lineno + 1)
            })?;
            map.insert(particle.to_string(), blob.to_string());
        }
        Ok(Self(map))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut text = String::with_capacity(self.0.len() * 130);
        for (particle, blob) in &self.0 {
            text.push_str(particle);
            text.push(' ');
            text.push_str(blob);
            text.push('\n');
        }
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "radio-cli-particle-index-test-{}-{}-{}",
            std::process::id(),
            name,
            rand::random::<u32>()
        ))
    }

    #[test]
    fn load_missing_file_is_empty() {
        let path = temp_path("missing");
        let idx = ParticleIndex::load(&path).unwrap();
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn insert_then_lookup_round_trips() {
        let particle = hemera::hash(b"a bostrom file");
        let blob_hash = iroh_blobs::Hash::new(b"a bostrom file");

        let mut idx = ParticleIndex::new();
        idx.insert(particle, blob_hash);

        assert_eq!(idx.lookup(&particle), Some(blob_hash));
    }

    #[test]
    fn lookup_unknown_particle_is_none() {
        let idx = ParticleIndex::new();
        let particle = hemera::hash(b"never indexed");
        assert_eq!(idx.lookup(&particle), None);
    }

    #[test]
    fn save_then_load_round_trips_across_files() {
        let path = temp_path("roundtrip");
        let particle = hemera::hash(b"round trip bytes");
        let blob_hash = iroh_blobs::Hash::new(b"round trip bytes");

        let mut idx = ParticleIndex::new();
        idx.insert(particle, blob_hash);
        idx.save(&path).unwrap();

        let reloaded = ParticleIndex::load(&path).unwrap();
        assert_eq!(reloaded.lookup(&particle), Some(blob_hash));
        assert_eq!(reloaded.len(), 1);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn save_then_load_keeps_multiple_entries() {
        let path = temp_path("multi");
        let mut idx = ParticleIndex::new();
        let entries: Vec<_> = (0..5)
            .map(|i| {
                let bytes = format!("entry {i}").into_bytes();
                let particle = hemera::hash(&bytes);
                let blob_hash = iroh_blobs::Hash::new(&bytes);
                idx.insert(particle, blob_hash);
                (particle, blob_hash)
            })
            .collect();
        idx.save(&path).unwrap();

        let reloaded = ParticleIndex::load(&path).unwrap();
        assert_eq!(reloaded.len(), 5);
        for (particle, blob_hash) in entries {
            assert_eq!(reloaded.lookup(&particle), Some(blob_hash));
        }

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn blank_lines_are_skipped() {
        let path = temp_path("blank-lines");
        let particle = hemera::hash(b"surrounded by blank lines");
        let blob_hash = iroh_blobs::Hash::new(b"surrounded by blank lines");
        std::fs::write(&path, format!("\n\n{particle} {blob_hash}\n\n")).unwrap();

        let idx = ParticleIndex::load(&path).unwrap();
        assert_eq!(idx.lookup(&particle), Some(blob_hash));

        std::fs::remove_file(&path).ok();
    }
}
