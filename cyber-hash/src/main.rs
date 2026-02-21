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
    eprintln!("cyber-hash — Poseidon2 hashing and BAO verified streaming");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  cyber-hash hash [FILE...]       Hash files (or stdin if no files)");
    eprintln!("  cyber-hash encode <FILE>        Encode file to combined BAO format (stdout)");
    eprintln!("  cyber-hash decode <FILE> <HASH> Decode and verify combined BAO file");
    eprintln!("  cyber-hash outboard <FILE>      Print outboard hash tree info");
    eprintln!("  cyber-hash verify <FILE> <HASH> Verify file against a root hash");
}

fn cmd_hash(args: &[String]) {
    if args.is_empty() {
        // Hash stdin
        let mut data = Vec::new();
        io::stdin()
            .read_to_end(&mut data)
            .unwrap_or_else(|e| fatal(&format!("reading stdin: {e}")));
        let h = cyber_poseidon2::hash(&data);
        println!("{h}");
    } else {
        for path in args {
            let data =
                fs::read(path).unwrap_or_else(|e| fatal(&format!("reading {path}: {e}")));
            let h = cyber_poseidon2::hash(&data);
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
        eprintln!("usage: cyber-hash encode <FILE>");
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
        eprintln!("usage: cyber-hash decode <ENCODED_FILE> <ROOT_HASH>");
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
        eprintln!("usage: cyber-hash outboard <FILE>");
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
        eprintln!("usage: cyber-hash verify <FILE> <EXPECTED_HASH>");
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

fn parse_hash(hex: &str) -> cyber_poseidon2::Hash {
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
    cyber_poseidon2::Hash::from_bytes(arr)
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
