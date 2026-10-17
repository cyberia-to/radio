use std::fs;
use std::io::{self, Read};
use std::process;

use cyber_bao::hash::Poseidon2Backend;
use cyber_bao::io::{decode, encode, outboard};
use cyber_bao::tree::BlockSize;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "hash" => cmd_hash(&args[2..]),
        "encode" => cmd_encode(&args[2..]),
        "decode" => cmd_decode(&args[2..]),
        "outboard" => cmd_outboard(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "help" | "--help" | "-h" => print_usage(),
        other => {
            eprintln!("unknown command: {other}");
            print_usage();
            process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("particle — Poseidon2 hashing and BAO verified streaming");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  particle hash [FILE...]       Hash files (or stdin if no files)");
    eprintln!("  particle encode <FILE>        Encode file to combined BAO format (stdout)");
    eprintln!("  particle decode <FILE> <HASH> Decode and verify combined BAO file");
    eprintln!("  particle outboard <FILE>      Print outboard hash tree info");
    eprintln!("  particle verify <FILE> <HASH> Verify file against a root hash");
}

fn cmd_hash(args: &[String]) {
    if args.is_empty() {
        // Hash stdin
        let mut data = Vec::new();
        io::stdin()
            .read_to_end(&mut data)
            .unwrap_or_else(|e| fatal(&format!("reading stdin: {e}")));
        let h = hemera::hash(&data);
        println!("{h}");
    } else {
        for path in args {
            let data =
                fs::read(path).unwrap_or_else(|e| fatal(&format!("reading {path}: {e}")));
            let h = hemera::hash(&data);
            if args.len() > 1 {
                println!("{h}  {path}");
            } else {
                println!("{h}");
            }
        }
    }
}

fn cmd_encode(args: &[String]) {
    if args.is_empty() {
        eprintln!("usage: particle encode <FILE>");
        process::exit(1);
    }
    let path = &args[0];
    let data = fs::read(path).unwrap_or_else(|e| fatal(&format!("reading {path}: {e}")));

    let backend = Poseidon2Backend;
    let (root, encoded) = encode::encode(&backend, &data, BlockSize::ZERO);

    // Write encoded to stdout
    io::Write::write_all(&mut io::stdout(), &encoded)
        .unwrap_or_else(|e| fatal(&format!("writing output: {e}")));

    eprintln!("root hash: {root}");
    eprintln!("encoded size: {} bytes", encoded.len());
}

fn cmd_decode(args: &[String]) {
    if args.len() < 2 {
        eprintln!("usage: particle decode <ENCODED_FILE> <ROOT_HASH>");
        process::exit(1);
    }
    let path = &args[0];
    let hash_hex = &args[1];

    let encoded =
        fs::read(path).unwrap_or_else(|e| fatal(&format!("reading {path}: {e}")));
    let root = parse_hash(hash_hex);
    let backend = Poseidon2Backend;

    match decode::decode(&backend, &encoded, &root, BlockSize::ZERO) {
        Ok(data) => {
            io::Write::write_all(&mut io::stdout(), &data)
                .unwrap_or_else(|e| fatal(&format!("writing output: {e}")));
            eprintln!("verified OK — {} bytes", data.len());
        }
        Err(e) => {
            eprintln!("verification FAILED: {e}");
            process::exit(1);
        }
    }
}

fn cmd_outboard(args: &[String]) {
    if args.is_empty() {
        eprintln!("usage: particle outboard <FILE>");
        process::exit(1);
    }
    let path = &args[0];
    let data = fs::read(path).unwrap_or_else(|e| fatal(&format!("reading {path}: {e}")));

    let backend = Poseidon2Backend;
    let ob = outboard::outboard(&backend, &data, BlockSize::ZERO);

    println!("root hash:      {}", ob.root);
    println!("data size:      {} bytes", data.len());
    println!("blocks:         {}", ob.tree.blocks());
    println!("outboard size:  {} bytes", ob.data.len());
}

fn cmd_verify(args: &[String]) {
    if args.len() < 2 {
        eprintln!("usage: particle verify <FILE> <EXPECTED_HASH>");
        process::exit(1);
    }
    let path = &args[0];
    let expected_hex = &args[1];

    let data = fs::read(path).unwrap_or_else(|e| fatal(&format!("reading {path}: {e}")));
    let expected = parse_hash(expected_hex);

    let backend = Poseidon2Backend;
    let ob = outboard::outboard(&backend, &data, BlockSize::ZERO);

    if ob.root == expected {
        println!("OK — root hash matches");
    } else {
        eprintln!("FAILED — hash mismatch");
        eprintln!("  expected: {expected}");
        eprintln!("  actual:   {}", ob.root);
        process::exit(1);
    }
}

fn parse_hash(hex: &str) -> hemera::Hash {
    let bytes = hex_to_bytes(hex).unwrap_or_else(|| {
        fatal(&format!("invalid hex hash: {hex}"));
    });
    if bytes.len() != 32 {
        fatal(&format!(
            "hash must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    hemera::Hash::from_bytes(arr)
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn fatal(msg: &str) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let h = hemera::hash(b"cyberlink");
        let hex = h.to_string();
        let parsed = parse_hash(&hex);
        assert_eq!(parsed, h);
    }

    #[test]
    fn hex_to_bytes_rejects_odd_length() {
        assert_eq!(hex_to_bytes("abc"), None);
    }

    #[test]
    fn hex_to_bytes_rejects_non_hex() {
        assert_eq!(hex_to_bytes("zz"), None);
    }

    // encode -> decode round trip through the exact API the CLI wraps: a
    // file fetched by particle hash must reconstruct byte-identical data.
    #[test]
    fn encode_decode_roundtrip_recovers_original_bytes() {
        let data = b"the graph comes home as files and cyberlinks".to_vec();
        let backend = Poseidon2Backend;
        let (root, encoded) = encode::encode(&backend, &data, BlockSize::ZERO);

        let decoded = decode::decode(&backend, &encoded, &root, BlockSize::ZERO)
            .expect("decode of untampered encoding must succeed");
        assert_eq!(decoded, data);
    }

    // this is the "verified" half of verified streaming: a peer that
    // returns bytes for the wrong particle, or corrupts even one byte in
    // transit, must be caught before the caller sees bad data.
    #[test]
    fn decode_rejects_corrupted_bytes() {
        let data = vec![7u8; 4096 * 3 + 17]; // spans multiple BAO chunks
        let backend = Poseidon2Backend;
        let (root, mut encoded) = encode::encode(&backend, &data, BlockSize::ZERO);

        let mid = encoded.len() / 2;
        encoded[mid] ^= 0xff;

        let result = decode::decode(&backend, &encoded, &root, BlockSize::ZERO);
        assert!(result.is_err(), "corrupted encoding must not verify");
    }

    #[test]
    fn verify_detects_hash_mismatch() {
        let data = b"bostrom".to_vec();
        let backend = Poseidon2Backend;
        let ob = outboard::outboard(&backend, &data, BlockSize::ZERO);

        let wrong = hemera::hash(b"pussy");
        assert_ne!(ob.root, wrong);
    }

    // the other half of "verified": a peer that answers a request for
    // particle p with a perfectly well-formed encoding of some other content
    // q must be rejected, because the root the caller asked for is the key
    // the stream is checked against, not anything the peer sends.
    #[test]
    fn decode_rejects_well_formed_bytes_of_another_particle() {
        let backend = Poseidon2Backend;
        let (root_p, _encoded_p) = encode::encode(&backend, b"bostrom", BlockSize::ZERO);
        let (root_q, encoded_q) = encode::encode(&backend, b"pussy", BlockSize::ZERO);
        assert_ne!(root_p, root_q);

        let result = decode::decode(&backend, &encoded_q, &root_p, BlockSize::ZERO);
        assert!(result.is_err(), "bytes of q must not verify as p");
    }
}
