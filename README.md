# radio

Verified content streaming over Poseidon2.

Radio is a fork of [iroh](https://github.com/n0-computer/iroh) where every hash — content identifiers, verified streaming trees, relay handshakes — runs through Poseidon2 over the Goldilocks field instead of BLAKE3.

## Why replace a fast hash with a slow one?

BLAKE3 hashes at 2 GB/s. Poseidon2 over Goldilocks hashes at ~50-100 MB/s on CPU. By every throughput benchmark, BLAKE3 wins.

But throughput is the wrong metric when the goal is a self-verifying knowledge graph at planetary scale.

BLAKE3 uses bit-oriented operations — XOR, rotation, shift — that are cheap on CPUs and catastrophic in arithmetic circuits. Proving a single BLAKE3 hash inside a STARK costs 50,000-100,000 constraints. Poseidon2 costs ~300. That is not a percentage improvement. It is the difference between a system that can prove its own state transitions and one that cannot.

A content-addressed network where every hash is cheaply provable in zero knowledge enables:

- Storage proofs that verify content availability without downloading it
- Verified streaming where every chunk is authenticated against a Poseidon2 Merkle tree
- Private collective computation over encrypted knowledge graphs (MPC, FHE)
- Post-quantum security — STARKs rely on hash collision resistance only, no pairings

One hash everywhere. No "fast hash for data, ZK hash for proofs" split. The content identifier IS the proof-friendly identifier. Deduplication, verified streaming, and zero-knowledge proofs all operate on the same identity.

The performance gap narrows with GPU acceleration (Poseidon2 is massively parallelizable) and larger chunk groups (16 KB blocks amortize per-chunk overhead). For the proving system, there is no gap at all — Poseidon2 is 100x cheaper where it matters.

See [hash function selection](https://cyb.ai/oracle/ask/hash-function-selection) for the full analysis across seven domains: content addressing, deduplication, ZK proofs, MPC, FHE, quantum resistance, and planetary scale.

## Architecture

Radio preserves iroh's networking layer — QUIC connections, hole-punching, relay servers — and replaces the cryptographic substrate:

```
┌──────────────────────────────────────────────────────────────┐
│                        Protocols                             │
│   iroh-blobs    iroh-docs    iroh-gossip    iroh-willow      │
│   (content)     (key-value)  (pub-sub)      (sync)           │
├──────────────────────────────────────────────────────────────┤
│                    Verified Streaming                         │
│                       cyber-bao                               │
│            (Poseidon2 Merkle tree encode/decode)              │
├──────────────────────────────────────────────────────────────┤
│                     Content Identity                          │
│                    cyber-poseidon2                             │
│       (sponge, compression, KDF — Goldilocks field)           │
├──────────────────────────────────────────────────────────────┤
│                       Networking                              │
│               iroh (QUIC, hole-punching)                      │
│              iroh-relay (relay servers)                        │
└──────────────────────────────────────────────────────────────┘
```

## Crates

| Crate | Description |
|-------|-------------|
| `cyber-poseidon2` | Poseidon2 hash over Goldilocks (Hemera: t=16, rate=8, capacity=8, x^7). CPU backend via p3-poseidon2, GPU scaffolding via wgpu. |
| `cyber-bao` | Verified streaming with Poseidon2. Encoding, decoding, outboard, slice extraction — the BAO protocol rebuilt on algebraic hashing. |
| `cyber-hash` | CLI tool for Poseidon2 hashing from the command line. |
| `iroh` | Hole-punching and QUIC connections between endpoints. Dial by public key. |
| `iroh-relay` | Relay server with Poseidon2-based handshake. |
| `iroh-base` | Common types — `Hash` (Poseidon2 digest), keys, `RelayUrl`. |
| `iroh-blobs` | Content-addressed blob transfer with Poseidon2 verified streaming. Scales from kilobytes to terabytes. |
| `iroh-docs` | Eventually-consistent key-value store over iroh-blobs. |
| `iroh-gossip` | Publish-subscribe overlay networks. |
| `iroh-car` | CAR (Content Addressable aRchive) format support. |
| `iroh-willow` | Willow protocol implementation. |
| `iroh-dns-server` | DNS-based endpoint discovery. |

## Hemera Parameters

Frozen at deployment. These never change — changing them changes every content identifier in the network.

| Parameter | Value |
|-----------|-------|
| Field | Goldilocks (p = 2^64 - 2^32 + 1) |
| State width | 16 elements (128 bytes) |
| Rate | 8 elements (64 bytes absorbed per permutation) |
| Capacity | 8 elements (64 bytes) |
| Full rounds | 8 (4 initial + 4 final) |
| Partial rounds | 64 |
| S-box | x^7 |
| Padding | 0x01 &#124;&#124; 0x00* |
| Encoding | Little-endian canonical |
| Output | 8 elements = 64 bytes |
| Security | 256-bit collision resistance |

## Migration Status

Complete. Zero BLAKE3 dependencies remain in any Cargo.toml or Cargo.lock. 395 tests pass across all crates.

| Phase | Status |
|-------|--------|
| cyber-poseidon2 (CPU + GPU scaffolding) | Done |
| cyber-bao (verified streaming) | Done |
| iroh-blobs (content addressing) | Done |
| iroh-relay (handshake) | Done |
| iroh-docs, iroh-gossip, iroh-car | Done |
| Blake3 removal | Done |
| Validation (395 tests, 0 failures) | Done |

## Getting Started

```sh
# Build the workspace
cargo build

# Run tests
cargo test

# Hash something
cargo run --bin cyber-hash -- "hello"
```

## License

Copyright 2025 N0, INC.

Dual-licensed under MIT or Apache-2.0, at your option.

[iroh]: https://github.com/n0-computer/iroh
[Poseidon2]: https://eprint.iacr.org/2023/323
[Goldilocks]: https://en.wikipedia.org/wiki/Goldilocks_field
