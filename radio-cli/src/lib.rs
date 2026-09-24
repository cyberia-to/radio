//! `radio-cli`'s own logic, importable outside the `radio` binary.
//!
//! Everything here is free of `clap`, `tokio` and the iroh endpoint: pure
//! parsing and encoding, the CLI's own domain rules independent of the
//! terminal it happens to run in. This is the seam a future integration
//! test (row 22, particle-addressed blob fetch) builds on — an
//! integration test lives in a separate crate under `tests/`, and a
//! separate crate can only see a `[lib]` target, not `main.rs`.

use anyhow::{Context, Result, bail};

/// Decode a hex string into bytes. `odd-length` and non-hex digits are
/// rejected with a message naming the problem, not a panic.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        bail!("odd-length hex string");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).context("invalid hex digit"))
        .collect()
}

/// Parse a 64-character hex string into a Poseidon2 hash.
pub fn parse_poseidon_hash(hex: &str) -> Result<hemera::Hash> {
    let bytes = hex_to_bytes(hex).context("invalid hex hash")?;
    if bytes.len() != 32 {
        bail!("hash must be 32 bytes (64 hex chars), got {} bytes", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(hemera::Hash::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_bytes_round_trips_lowercase() {
        assert_eq!(hex_to_bytes("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
    }

    #[test]
    fn hex_to_bytes_rejects_odd_length() {
        assert!(hex_to_bytes("abc").is_err());
    }

    #[test]
    fn hex_to_bytes_rejects_non_hex_digits() {
        assert!(hex_to_bytes("zz").is_err());
    }

    #[test]
    fn hex_to_bytes_empty_is_empty() {
        assert_eq!(hex_to_bytes("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn parse_poseidon_hash_round_trips_through_display() {
        let h = hemera::hash(b"radio-cli lib target");
        let parsed = parse_poseidon_hash(&h.to_string()).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn parse_poseidon_hash_rejects_wrong_length() {
        assert!(parse_poseidon_hash("ab").is_err());
    }

    #[test]
    fn parse_poseidon_hash_rejects_bad_hex() {
        assert!(parse_poseidon_hash(&"z".repeat(64)).is_err());
    }
}
