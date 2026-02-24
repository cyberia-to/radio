# Blake3 to Poseidon2: Complete Migration Plan

## 1. Motivation

The migration from Blake3 to Poseidon2 is driven by the need for a hash function
that operates natively over finite fields. Blake3's bit-oriented operations (XOR,
rotation, shift) are 50-100x more expensive when proved inside STARK circuits.
Poseidon2, operating natively over finite fields, enables:

- **Zero-knowledge proofs**: ~2M+ hashes/sec in Plonky3/STARK proving systems
- **Multi-party computation (MPC)**: Practical threshold operations over arithmetic circuits
- **Fully homomorphic encryption (FHE)**: Word-level homomorphic encryption compatibility
- **Content addressing**: Collision-resistant fixed-length output suitable for CIDs
- **Planetary-scale verifiability**: Every hash in the system becomes cheaply provable

See: https://cyber.page/hash-function-selection/

This is not a narrow library swap. Blake3 is deeply woven into iroh's architecture
across multiple repositories. This document covers the **complete** migration surface.

---

## 2. Full Blake3 Dependency Map Across the Iroh Ecosystem

The iroh project spans multiple repositories. Blake3 is used at every layer.

### 2.1 Repository Inventory

From `.github/workflows/project_sync.yaml`, the iroh ecosystem includes:

| Repository | Blake3 Role | Migration Complexity |
|-----------|------------|---------------------|
| **iroh** (this repo) | Relay handshake KDF | Low |
| **iroh-blobs** | Content addressing (Hash type), blob transfer protocol | Critical |
| **bao-tree** | BLAKE3 Merkle tree for verified streaming | Critical - requires novel replacement |
| **abao** | Async BAO (async verified streaming) | Critical - depends on bao-tree |
| **iroh-blake3** | Custom BLAKE3 fork with hazmat API | Must be replaced entirely |
| **iroh-docs** | Key-value store using iroh-blobs hashes | Depends on iroh-blobs migration |
| **iroh-gossip** | Pub-sub overlays (may reference blob hashes) | Depends on iroh-blobs migration |
| **iroh-car** | CAR (Content Addressable aRchives) format | Depends on hash type migration |
| **iroh-willow** | Willow protocol implementation | Depends on hash type migration |

### 2.2 Blake3 Feature Usage by Layer

#### Layer 1: Cryptographic Primitive (iroh-blake3)

iroh maintains a **custom fork** of the BLAKE3 crate (`iroh-blake3`) because the
upstream BLAKE3 crate historically did not expose the internal APIs needed for BAO
streaming. The new BLAKE3 "hazmat" API was contributed by the iroh team and provides:

- `HasherExt` - setting input chunk offsets for non-sequential hashing
- `merge_subtree_root()` / `merge_subtree_non_root()` - combining chaining values
  at internal tree nodes
- Non-root finalization - computing intermediate (non-root) chaining values
- Access to raw chaining values (32-byte intermediate digests)

**Migration requirement**: All of these internal APIs must have Poseidon2 equivalents.

#### Layer 2: Verified Streaming (bao-tree, abao)

BAO (BLAKE3 Authenticated and Oblivious) is the core innovation that enables iroh's
blob transfer protocol. It exploits BLAKE3's internal Merkle tree structure:

**How BLAKE3's Merkle Tree Works:**
1. Input is split into 1024-byte chunks
2. Each chunk is hashed independently via the BLAKE3 compression function, producing
   a 32-byte chaining value (CV)
3. Pairs of CVs are combined as parent nodes (64-byte input -> 32-byte output;
   with Goldilocks: 2x4 elements = 8 elements absorbed, 4 elements squeezed)
4. Tree is built upward until a single root hash remains
5. Domain separation flags distinguish chunk nodes, parent nodes, and the root node
6. Each chunk carries a counter (its position) for ordering

**What BAO Provides:**

| Feature | Description |
|---------|-------------|
| **Combined encoding** | Serializes the hash tree interleaved with data in pre-order traversal. A decoder can verify every byte as it arrives without buffering the whole file. |
| **Outboard encoding** | Stores only the hash tree (no data). Like a `.torrent` file - verification metadata stored separately from content. |
| **Slice extraction** | Extracts the minimal subset of the tree needed to verify a specific byte range. For a 1 GB file, verifying a single 1 KB range requires only ~30 parent hashes (~1.9 KB overhead). |
| **Range requests** | Fetch and verify arbitrary byte ranges against the root hash with O(log N) overhead. |
| **Streaming decode** | Data is verified and returned chunk-by-chunk during download. No need to wait for the full file. |
| **Pre-order format** | Nodes appear in the exact order needed for sequential depth-first verification - no seeking required. |
| **Post-order format** | Nodes appear after their children. Enables efficient append-only file sync (new data appends without rewriting existing tree nodes). |

**bao-tree extensions beyond standard BAO:**

| Extension | Purpose |
|-----------|---------|
| Configurable `BlockSize` | Chunk groups larger than 1024 bytes (e.g., 16 KiB) to reduce outboard size |
| Multi-range queries | Request multiple non-overlapping byte ranges in a single query: `[0..1000, 5000..6000]` |
| Async support | Both sync (`io::sync`) and async (`io::fsm`) implementations sharing core logic |
| Post-order outboard | Append-only storage format for incremental file synchronization |

#### Layer 3: Content Addressing (iroh-blobs)

iroh-blobs provides content-addressed blob storage and transfer:

| Component | Blake3 Usage |
|-----------|-------------|
| **`Hash` type** | Wraps `blake3::Hash` (32 bytes). The universal content identifier for all blobs. |
| **`BlobFormat::Raw`** | Single blob identified by its BLAKE3 hash |
| **`BlobFormat::HashSeq`** | Ordered sequence of BLAKE3 hashes (used for collections/directories) |
| **Blob transfer protocol** | Uses BAO encoding to stream blobs with per-chunk verification |
| **Content discovery** | Blobs are requested and routed by their BLAKE3 hash |
| **Storage backend** | Blobs stored and indexed by BLAKE3 hash |
| **Deduplication** | Identical content produces identical BLAKE3 hash = automatic dedup |

**The Hash type is the atom of iroh's content addressing.** Every blob, every
collection, every piece of content in the iroh ecosystem is identified by its
BLAKE3 hash. Changing this hash function changes every identifier in the system.

#### Layer 4: Relay Handshake (iroh-relay, this repo)

The only Blake3 usage in this repository:

**Production** (`iroh-relay/src/protos/handshake.rs:215`):
```rust
fn message_to_sign(&self) -> [u8; 32] {
    blake3::derive_key(DOMAIN_SEP_CHALLENGE, &self.challenge)
}
```

**Test** (`iroh-relay/src/protos/handshake.rs:594-598`):
```rust
let label_key = blake3::hash(label);
let context_key = blake3::keyed_hash(label_key.as_bytes(), context.unwrap_or(&[]));
let mut hasher = blake3::Hasher::new_keyed(context_key.as_bytes());
hasher.update(&self.shared_secret?.to_le_bytes());
hasher.finalize_xof().fill(output.as_mut());
```

#### Layer 5: Higher-Level Protocols

| Protocol | Blake3 Dependency |
|----------|------------------|
| **iroh-docs** | Documents contain blob hashes (BLAKE3). Key-value entries reference content by Hash. |
| **iroh-gossip** | Message payloads may include blob hashes for content routing |
| **iroh-willow** | Willow entries reference content by Hash |
| **iroh-car** | CAR archives contain CIDs built from BLAKE3 hashes |

### 2.3 Complete Blake3 API Surface Used Across Ecosystem

| Blake3 API | Where Used | Poseidon2 Must Provide |
|-----------|-----------|----------------------|
| `blake3::hash(input) -> Hash` | Content addressing (iroh-blobs) | Sponge hash, 32-byte output |
| `blake3::derive_key(context, input) -> [u8; 32]` | Relay handshake KDF (iroh-relay) | Domain-separated sponge KDF |
| `blake3::keyed_hash(key, input) -> Hash` | Test utilities (iroh-relay) | Keyed sponge mode |
| `blake3::Hasher::new()` + `update()` + `finalize()` | Incremental content hashing (iroh-blobs) | Incremental sponge |
| `blake3::Hasher::new_keyed()` + XOF | Test utilities (iroh-relay) | Keyed sponge + squeeze XOF |
| **Hazmat: non-root chaining values** | BAO tree construction (bao-tree) | Intermediate Poseidon2 compression |
| **Hazmat: merge_subtree_root/non_root** | BAO parent node hashing (bao-tree) | 2-to-1 compression function |
| **Hazmat: chunk counter** | BAO chunk ordering (bao-tree) | Counter as absorbed field element |
| **Hazmat: is_root flag** | BAO root finalization (bao-tree) | Distinct root finalization constant |
| **Hazmat: HasherExt (offset)** | Non-sequential chunk hashing (bao-tree) | Sponge with explicit position |

---

## 3. Poseidon2 Technical Assessment

### 3.1 Properties Comparison

| Property | Blake3 | Poseidon2 |
|----------|--------|-----------|
| Design | Bit-oriented (Merkle tree of compress functions) | Algebraic (operations over prime fields) |
| Collision resistance | 128-bit | 128-bit (with proper parameters) |
| Preimage resistance | 256-bit | Depends on parameter/field choice |
| Output size | 256-bit default, XOF-capable | Field-element width (e.g., ~254-bit over BN254) |
| ZK circuit cost | 50,000-100,000 constraints per hash | 500-1,500 constraints per hash |
| Native CPU throughput | 1-7 GiB/s (SIMD-accelerated) | ~3-4M hashes/sec (Goldilocks faster than BN254 due to 64-bit arithmetic) |
| Sponge mode | Not native (tree-based) | Native sponge construction |
| Compression mode | Native (internal compress function) | Native: `C(x) = Trunc_d(P(x) + M*x)` |
| XOF capability | Native | Via repeated sponge squeeze |
| KDF mode | Native `derive_key()` | Via domain-separated sponge |
| Merkle tree | Native (BLAKE3 IS a Merkle tree hash) | Must be built on top of compression mode |
| Maturity | NIST-level analysis, deployed widely | Peer-reviewed (AFRICACRYPT 2023), growing ZK adoption |

### 3.2 The Critical Performance Tradeoff

| Operation | Blake3 | Poseidon2 (Goldilocks, t=12, d=7) | Impact |
|-----------|--------|-------------------------------------|--------|
| Hash 1 KB chunk | ~1 us | ~50-100 us (est.) | ~50-100x slower |
| Hash 1 GB file | ~0.15-1 sec | ~50-100 sec (est.) | Significant but workable |
| Parent node (2-to-1) | <1 us | ~1-3 us | Acceptable |
| Prove hash in STARK | ~50,000 constraints | ~500 constraints | 100x cheaper (the point) |

**Goldilocks advantage over BN254**: 64-bit field arithmetic is ~5-10x faster than
254-bit BN254 arithmetic on modern CPUs. This narrows the performance gap significantly
compared to BN254-based Poseidon2. The regression is real but far less severe than
with larger fields.

**For content addressing and verified streaming, the CPU performance regression must
be addressed architecturally** (see Section 5: chunk group sizing and GPU acceleration).

### 3.3 Available Rust Implementations

| Crate | Version | Downloads | Description | Goldilocks Support |
|-------|---------|-----------|-------------|-------------------|
| **`p3-poseidon2`** | **0.4.2** | **1M+** | **Plonky3's Poseidon2 permutation** | **Yes - native Goldilocks support** |
| `zkhash` | 0.2.0 | 888K | Poseidon2 + related primitives | Via ark-ff (possible but not native) |
| `light-poseidon` | 0.4.0 | 7.1M | Poseidon v1 (not v2) | No |
| `taceo-poseidon2` | - | - | Poseidon2 for BN254 | No |

**Recommended crate: `p3-poseidon2`** from Plonky3. It is the only production-ready
implementation with native Goldilocks field support, matching our parameter selection.
Plonky3 is MIT/Apache-2.0 licensed, production-ready, and powers SP1's prover.

### 3.4 Poseidon2 Mode Mapping for All Blake3 Features

| Blake3 Feature | Poseidon2 Equivalent | Implementation |
|---------------|---------------------|----------------|
| `hash(bytes)` | Sponge: absorb field-encoded bytes, squeeze | Standard Poseidon2 sponge |
| `derive_key(ctx, bytes)` | Absorb domain separator into capacity, absorb input, squeeze | Duplex construction |
| `keyed_hash(key, bytes)` | Initialize capacity with key elements, absorb, squeeze | Keyed sponge |
| `Hasher` (incremental) | Sponge state with incremental absorption | Stateful sponge |
| XOF (finalize_xof + fill) | Repeated squeeze operations | Sponge squeeze |
| Chunk hashing (1024B -> 32B CV) | Absorb ~147 Goldilocks elements (rate=8), squeeze 4 elements | ~19 permutations per chunk |
| Parent hashing (64B -> 32B CV) | Absorb 2x4 child elements into rate (8 elements), squeeze 4 | 1 permutation per parent |
| Chunk counter | Absorb counter as field element before chunk data | Additional absorbed element |
| Domain separation (chunk/parent/root) | Capacity initialization constants per mode | Distinct capacity values |
| Non-root finalization | Squeeze without root flag | Different finalization constant |
| Root finalization | Squeeze with root flag | Root-specific constant |

### 3.5 Byte-to-Field-Element Encoding

Poseidon2 operates on field elements, not bytes. All input data must be encoded:

| Field | Element Size | Usable Bytes/Element | Elements per 1 KB Chunk | Notes |
|-------|-------------|---------------------|------------------------|-------|
| **Goldilocks (64-bit)** | **8 bytes** | **~7 bytes** | **~147** | **Selected field. Plonky3-native, fast on CPU and GPU** |
| BN254 (~254-bit) | 32 bytes | ~31 bytes | ~34 | Ethereum-compatible, but slower field arithmetic |
| BabyBear (31-bit) | 4 bytes | ~3.8 bytes | ~270 | Smallest field, highest absorption count |

**Selected field: Goldilocks (p = 2^64 - 2^32 + 1)**

Goldilocks is chosen because:
- Native 64-bit arithmetic on modern CPUs (single machine word)
- Plonky3-native (SP1 uses BabyBear, but Goldilocks has broader STARK support)
- Fast on both CPU and GPU
- 8-byte elements mean a 32-byte hash output = 4 field elements

**Our Poseidon2 parameters: t=12, R_F=8, R_P=22, d=7**
- `t=12`: state width of 12 Goldilocks field elements (96 bytes total state)
- `R_F=8`: 8 full rounds (4 at start, 4 at end) - all elements get S-box
- `R_P=22`: 22 partial rounds - only first element gets S-box
- `d=7`: S-box exponent x^7 (chosen for Goldilocks field characteristics)
- Rate = 8 elements (64 bytes absorbed per permutation), Capacity = 4 elements (32 bytes)
- **Output**: squeeze 4 elements = 32 bytes (matches Blake3 output size)

**Encoding rules** (must be canonical and deterministic):
1. Pad input to element-boundary with unambiguous padding (e.g., 10*1 padding)
2. Encode each group of 7 bytes as a Goldilocks field element (little-endian, must be < p)
3. Include input length as a final absorbed element to prevent length-extension
4. Absorb 8 elements (64 bytes of encoded input) per permutation call

---

## 4. What Does Not Exist Today (Must Be Built)

### 4.1 "Poseidon2-BAO": Verified Streaming with Poseidon2

**No existing implementation provides BAO-like streaming verification with Poseidon2.**

This is the largest piece of novel engineering in the migration. Existing Poseidon2
Merkle tree implementations (merkle-poseidon, poseidon-merkle, Plonky3 internal)
are all designed for ZK proof membership, not streaming data transfer. None provide:

- Pre-order or post-order tree encoding for streaming
- Slice extraction for range-based verification
- Outboard storage format
- Streaming decode with per-chunk verification
- Configurable chunk groups
- Multi-range queries

**What must be built:**

| Component | Source | Effort |
|-----------|--------|--------|
| Tree geometry & traversal | Extract from bao-tree, make hash-agnostic | Medium |
| Range management (ChunkRanges, ByteRanges) | Reuse from bao-tree (hash-independent) | Low |
| Poseidon2 chunk hashing | New: sponge (t=12, rate=8) over Goldilocks-encoded chunks; ~19 permutations per 1 KB | Medium |
| Poseidon2 parent hashing (2-to-1) | New: two 4-element digests = 8 elements = exactly 1 rate-width absorption -> 1 permutation | Low |
| Domain separation scheme | New: capacity constants for chunk/parent/root | Medium |
| Pre-order combined encoding | Adapt from bao-tree, swap hash | Low |
| Outboard encoding | Adapt from bao-tree, swap hash | Low |
| Post-order outboard | Adapt from bao-tree, swap hash | Low |
| Slice extraction | Adapt from bao-tree (mostly hash-agnostic) | Low |
| Streaming decoder | Adapt from bao-tree, swap verification | Medium |
| Async streaming decoder | Adapt from abao, swap verification | Medium |
| Test vectors | Generate from reference implementation | Medium |

### 4.2 Poseidon2 Sponge Wrapper Crate

A new crate providing the Blake3-equivalent API surface:

```
poseidon2_hash(input: &[u8]) -> [u8; 32]
poseidon2_derive_key(context: &str, input: &[u8]) -> [u8; 32]
poseidon2_keyed_hash(key: &[u8; 32], input: &[u8]) -> [u8; 32]
Poseidon2Hasher::new() / new_keyed() / update() / finalize() / finalize_xof()
```

Plus hazmat-level APIs for BAO tree construction:
```
chunk_cv(chunk_data: &[u8], counter: u64, is_root: bool) -> [u8; 32]
parent_cv(left: &[u8; 32], right: &[u8; 32], is_root: bool) -> [u8; 32]
```

### 4.3 Hash Type Migration

The `Hash` type in iroh-blobs wraps `blake3::Hash`. This is the fundamental content
identifier. Migration requires:

1. A new `Hash` type wrapping 4 Goldilocks field elements (serialized as 32 bytes)
2. Same API: `Hash::new(bytes)`, `as_bytes()`, `from_bytes()`, `to_hex()`, Display, serde
3. The 32-byte output (4 x 8-byte Goldilocks elements) matches Blake3's output size,
   so all existing APIs expecting `[u8; 32]` remain compatible at the type level
4. CID format: Algorithm-agile Content Identifier encoding that tags the hash algorithm
5. Transition: dual-CID period where both Blake3 and Poseidon2 hashes coexist

---

## 5. Migration Strategy

### 5.1 Approach: Pure Poseidon2 with GPU Acceleration via wgpu

**Decision**: Complete Blake3 replacement with Poseidon2 everywhere. No hybrid, no
dual-hash complexity. Single hash function across the entire stack.

**Two execution backends:**

| Backend | Use Case | Implementation |
|---------|----------|---------------|
| **CPU** | `p3-poseidon2` (Plonky3) | Goldilocks-native, production-ready, for relay handshake and small data |
| **GPU** | Custom wgpu compute shaders | For content hashing, BAO tree construction, bulk blob processing |

**Why this works:**

- **CPU path** (`p3-poseidon2`): Goldilocks 64-bit arithmetic is fast on modern CPUs.
  For relay handshake KDF (single hash of 16 bytes) this is more than adequate.
  For small blobs (<1 MB) CPU hashing is practical (~3-7s/GB with 16 KB chunk groups).

- **GPU path** (wgpu): Poseidon2 over Goldilocks is massively parallelizable - each
  chunk hashes independently, parent nodes at each tree level are independent.
  wgpu provides cross-platform GPU compute (Vulkan, Metal, DX12, WebGPU) without
  vendor lock-in. The Poseidon2 permutation (t=12, 30 rounds of field multiplications)
  maps naturally to GPU SIMD lanes.

  Expected GPU acceleration:
  - Each permutation: 12 * 30 = 360 field multiplications (Goldilocks mul is 64-bit)
  - Modern GPU: thousands of parallel permutations
  - Target: approach or exceed Blake3 CPU throughput for bulk hashing

- **wgpu advantages over CUDA/Icicle**:
  - Cross-platform: works on all GPUs (not NVIDIA-only)
  - WebGPU compatible: same shaders work in browser (WASM target)
  - Rust-native: `wgpu` crate integrates cleanly into the iroh ecosystem
  - No proprietary runtime dependency

**Architecture:**

```rust
// cyber-poseidon2 crate provides unified API with backend selection

pub enum Backend {
    Cpu,           // p3-poseidon2, always available
    Gpu(wgpu::Device), // wgpu compute shaders, when GPU available
}

// High-level API automatically selects backend based on input size
pub fn hash(input: &[u8]) -> [u8; 32];           // auto-selects
pub fn hash_with(backend: &Backend, input: &[u8]) -> [u8; 32]; // explicit

// BAO tree construction benefits most from GPU (all chunks parallel)
pub fn compute_outboard(backend: &Backend, data: &[u8]) -> Outboard;
```

**Fallback**: CPU path is always available. GPU is an acceleration layer, not a
requirement. Nodes without GPU capability operate correctly, just slower for
large blob hashing.

---

### 5.2 Migration Phases

---

### Phase Status Summary (updated 2026-02-24)

| Phase | Description | Status | Commit |
|-------|-------------|--------|--------|
| 0a | cyber-poseidon2 CPU backend | DONE | `1517ebff54` |
| 0b | cyber-poseidon2 GPU scaffolding | DONE | `5aefbfedb3` |
| 1 | cyber-bao verified streaming | **DONE** | `2c91d5b9e2`, `b1f6de6ba2`, (pending commit) |
| 2 | iroh-blobs integration | NOT STARTED | -- |
| 3 | Relay handshake migration | DONE | `07e31dd236` |
| 4 | Higher-level protocols | NOT STARTED | -- |
| 5 | Blake3 removal | NOT STARTED | -- |
| 6 | Validation | NOT STARTED | -- |

### Phase 1 Gap Analysis (updated 2026-02-24)

Phase 1 is COMPLETE. All 7 gaps have been closed. 66 tests pass, 0 warnings.

| # | Gap | Status | Resolution |
|---|-----|--------|------------|
| 1 | **Post-order outboard I/O** | CLOSED | `PostOrderOutboard<H,D>` and `PostOrderMemOutboard<H>` with full Outboard/OutboardMut trait impls. Conversion from pre-order in `PostOrderMemOutboard::create()`. |
| 2 | **Multi-range slice extraction** | CLOSED | `extract_slice_ranges()` accepts `&ChunkRangesRef` for multi-range queries. `extract_slice()` is now a convenience wrapper. |
| 3 | **Slice verification** | CLOSED | `decode_slice()` with stack-based verification against trusted root hash. Returns `Vec<(u64, Vec<u8>)>` of verified leaf data. |
| 4 | **Async range filtering** | CLOSED | `ResponseDecoder::new()` calls `tree.pre_order_chunks_filtered(&ranges)`. `traverse_ranges_validated()` in mixed.rs uses `pre_order_chunks_filtered(ranges)`. Sync `valid_ranges` uses `pre_order_chunks_filtered(ranges)`. |
| 5 | **Async final-length validation** | CLOSED | `ResponseDecoder::next0()` checks `decoded_bytes > tree.size()` after exhausting all items. |
| 6 | **HashBackend genericity in protocol layer** | ACCEPTED | Protocol-layer code (`sync.rs`, `fsm.rs`, `mixed.rs`, `io/mod.rs::hash_block`) hardcodes `Poseidon2Backend`. This is intentional — the protocol is Poseidon2-specific; low-level encode/decode/outboard/slice remain generic. |
| 7 | **BlockSize non-zero test coverage** | CLOSED | encode, decode, slice, sync, and pre_order modules all have `BlockSize::from_chunk_log(1)` and/or `BlockSize::DEFAULT` tests. Fixed a bug where `outboard()` used `chunk_hash()` instead of `hash_block()` in the single-block path, causing hash mismatches with non-zero block sizes. |

---

#### Phase 0: Foundation - Poseidon2 Primitive Crate

**Status: DONE** (0a: `1517ebff54`, 0b: `5aefbfedb3`)

**Goal**: Build a standalone crate providing all Poseidon2 operations needed by the ecosystem.

**Deliverable**: `cyber-poseidon2` crate

Dual-backend: CPU via `p3-poseidon2`, GPU via custom wgpu compute shaders.
Both backends produce identical output for the same input (same Poseidon2 permutation).

```
cyber-poseidon2/
  src/
    lib.rs          -- Public API, backend selection
    sponge.rs       -- Sponge construction over Goldilocks (rate=8, capacity=4)
    compression.rs  -- 2-to-1 compression: 8 elements in, 4 elements out
    kdf.rs          -- derive_key() with domain separation
    hasher.rs       -- Stateful incremental hasher + XOF (squeeze mode)
    encoding.rs     -- Byte-to-Goldilocks-element encoding (7 bytes -> 1 element)
    hazmat.rs       -- Low-level APIs for BAO tree construction (chunk_cv, parent_cv)
    params.rs       -- Frozen Poseidon2 parameters and round constants
    constants.rs    -- Domain separation constants
    cpu/
      mod.rs        -- CPU backend via p3-poseidon2
    gpu/
      mod.rs        -- GPU backend orchestration
      permutation.wgsl -- Poseidon2 permutation compute shader
      sponge.wgsl   -- Sponge absorb/squeeze compute shader
      tree.wgsl     -- Parallel Merkle tree construction shader
```

**Parameters (frozen):**

1. **Field**: Goldilocks (p = 2^64 - 2^32 + 1, 64-bit prime field)
2. **State width**: t = 12 (12 Goldilocks elements = 96 bytes)
3. **Full rounds**: R_F = 8 (4 initial + 4 final)
4. **Partial rounds**: R_P = 22
5. **S-box exponent**: d = 7 (x^7)
6. **Rate**: 8 elements (64 bytes per absorption)
7. **Capacity**: 4 elements (32 bytes, determines security level)
8. **Output**: 4 squeezed elements = 32 bytes

**Security level**: capacity = 4 * 64 = 256 bits -> 128-bit collision resistance

**CPU backend**: `p3-poseidon2` from Plonky3 (native Goldilocks support).
Always available. Used for relay handshake, small data, and as fallback.

**GPU backend**: wgpu compute shaders implementing the same Poseidon2 permutation.
Used for bulk content hashing and BAO tree construction. Cross-platform:
Vulkan (Linux/Windows/Android), Metal (macOS/iOS), DX12 (Windows), WebGPU (browser).

**wgpu shader design** for Poseidon2 permutation:
- Each workgroup processes one permutation (12 Goldilocks elements)
- Dispatch N workgroups to hash N chunks in parallel
- Goldilocks multiplication: 64-bit multiply + Barrett reduction (fits in u32x2 on GPU)
- S-box x^7: computed as `x^2 * x^2 * x^2 * x` (3 multiplications)
- MDS matrix: 12x12 matrix-vector multiply per full round
- Round constants loaded from uniform buffer (frozen, same for all invocations)

**API specification:**

```rust
// === Backend selection ===

pub enum Backend {
    Cpu,                    // p3-poseidon2, always available
    Gpu(GpuContext),        // wgpu compute shaders
}

pub struct GpuContext {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipelines: Pipelines,   // pre-compiled compute pipelines
}

impl GpuContext {
    /// Initialize GPU backend. Returns None if no GPU available.
    pub async fn new() -> Option<Self>;
}

// === High-level API (Blake3 equivalent) ===

/// Hash arbitrary bytes to a 32-byte digest.
/// Auto-selects backend: GPU for large inputs, CPU for small.
pub fn hash(input: &[u8]) -> [u8; 32];

/// Derive a key with domain separation (equivalent to blake3::derive_key).
/// Always CPU - single hash, not worth GPU dispatch overhead.
pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32];

/// Keyed hash (MAC-like).
pub fn keyed_hash(key: &[u8; 32], input: &[u8]) -> [u8; 32];

/// Incremental hasher with XOF support.
pub struct Hasher { /* sponge state */ }
impl Hasher {
    pub fn new() -> Self;
    pub fn new_keyed(key: &[u8; 32]) -> Self;
    pub fn update(&mut self, data: &[u8]);
    pub fn finalize(&self) -> [u8; 32];
    pub fn finalize_xof(&self) -> OutputReader;
}

pub struct OutputReader { /* squeeze state */ }
impl OutputReader {
    pub fn fill(&mut self, buf: &mut [u8]);
}

// === Hazmat API (for BAO tree construction) ===

/// Hash a single chunk of data, returning a chaining value.
pub fn chunk_cv(data: &[u8], counter: u64, is_root: bool) -> [u8; 32];

/// Combine two child chaining values into a parent chaining value.
pub fn parent_cv(left: &[u8; 32], right: &[u8; 32], is_root: bool) -> [u8; 32];

// === GPU bulk operations (the performance win) ===

/// Hash all chunks of a blob in parallel on GPU, returning all chaining values.
/// This is the key operation that makes Poseidon2 competitive with Blake3.
pub async fn batch_chunk_cvs(
    gpu: &GpuContext,
    data: &[u8],
    chunk_size: usize,
) -> Vec<[u8; 32]>;

/// Build the full Merkle tree from chunk CVs on GPU (parallel tree levels).
pub async fn build_tree(
    gpu: &GpuContext,
    chunk_cvs: &[[u8; 32]],
) -> (Vec<[u8; 32]>, [u8; 32]); // (parent nodes, root hash)
```

**Testing:**
- Determinism: same input always produces same output
- **CPU/GPU equivalence**: CPU and GPU backends produce identical output for all inputs
- Domain separation: `hash(x) != derive_key(ctx, x) != keyed_hash(k, x)`
- Avalanche: single-bit input change flips ~50% of output bits
- Reference vectors: cross-validate against Poseidon2 reference implementation
- Collision resistance: property tests ensuring distinct inputs produce distinct outputs
- GPU stress tests: large blobs (1 GB+), verify against CPU reference

---

#### Phase 1: Poseidon2-BAO - Verified Streaming Library

**Status: ~80% DONE** (`2c91d5b9e2`, `b1f6de6ba2`) — see Gap Analysis above.

**Goal**: Replace bao-tree and abao with Poseidon2-based equivalents.

**Approach**: Fork bao-tree and make it hash-agnostic, then plug in Poseidon2.

**Architecture:**

```
cyber-bao/  (or poseidon2-bao)
  src/
    tree.rs         -- BaoTree geometry (hash-agnostic, from bao-tree)
    node.rs         -- TreeNode traversal (hash-agnostic)
    ranges.rs       -- ChunkRanges, ByteRanges (hash-agnostic, reuse from bao-tree)
    hash_backend.rs -- Trait for pluggable hash (Poseidon2 implementation)
    encode.rs       -- Pre-order combined encoding
    outboard.rs     -- Outboard encoding (pre-order and post-order)
    decode.rs       -- Streaming verified decoder
    slice.rs        -- Slice extraction and verification
    io/
      sync.rs       -- Synchronous I/O operations
      fsm.rs        -- Async finite state machine I/O
```

**The `HashBackend` trait (making bao-tree hash-agnostic):**

```rust
pub trait HashBackend {
    type Hash: AsRef<[u8]> + Clone + Eq;

    /// Hash a data chunk at the given position.
    fn chunk_hash(&self, data: &[u8], counter: u64, is_root: bool) -> Self::Hash;

    /// Combine two child hashes into a parent hash.
    fn parent_hash(&self, left: &Self::Hash, right: &Self::Hash, is_root: bool) -> Self::Hash;

    /// Size of the hash output in bytes.
    fn hash_size(&self) -> usize;
}
```

**Features that must be preserved (no functionality loss):**

| bao-tree Feature | Status | Notes |
|-----------------|--------|-------|
| Combined encoding (pre-order) | Must implement | Hash function swapped |
| Outboard encoding (pre-order) | Must implement | Hash function swapped |
| Post-order outboard | Must implement | Hash function swapped |
| Slice extraction (single range) | Must implement | Tree logic unchanged |
| Multi-range slice extraction | Must implement | Tree logic unchanged |
| Configurable BlockSize (chunk groups) | Must implement | May help with performance |
| Streaming decode (sync) | Must implement | Verification uses Poseidon2 |
| Streaming decode (async) | Must implement | Verification uses Poseidon2 |
| 8-byte length header | Must implement | Format unchanged |
| Validation of final chunk for length | Must implement | Security-critical |

**Performance mitigation via chunk group size:**

Increasing the chunk group size reduces the number of Poseidon2 hash operations.
With Goldilocks (t=12, rate=8, 64 bytes per absorption), a chunk requires
ceil(chunk_size / 64) permutation calls plus parent hashing:

| Chunk Group Size | Absorptions per Chunk | Chunk Hashes for 1 GB | Est. Time (Goldilocks) |
|-----------------|----------------------|----------------------|----------------------|
| 1 KB (Blake3 default) | 16 | ~1M | ~50-100 sec |
| 16 KB (bao-tree default) | 256 | ~65K | ~3-7 sec |
| 64 KB | 1024 | ~16K | ~1-2 sec |
| 256 KB | 4096 | ~4K | ~0.3-0.5 sec |

**Goldilocks advantage**: 64-bit field arithmetic makes each permutation ~5-10x
faster than BN254, bringing Poseidon2 hashing into a practical range especially
with chunk groups >= 16 KB.

**Tradeoff**: Larger chunks mean coarser-grained verification. A 256 KB chunk group
means the decoder must buffer up to 256 KB before verification. For streaming,
16-64 KB is likely the sweet spot balancing verification granularity and throughput.

---

#### Phase 2: Hash Type and Content Addressing (iroh-blobs)

**Status: NOT STARTED** — iroh-blobs vendored into workspace, 0 files modified yet.

**Goal**: Migrate the `Hash` type and all content addressing to Poseidon2.

**Integration surface**: 67 references to `bao_tree`/`cyber_bao` across 30 source files.

**Sub-phase decomposition:**

| Sub-phase | Scope | Files | Depends on |
|-----------|-------|-------|------------|
| **2a** Foundation types | `Hash` type, `BaoTree` imports | `hash.rs`, `store/util/size_info.rs` | Phase 1 gaps 1-3 |
| **2b** Trait bridge | cyber-bao traits ↔ iroh-blobs I/O | `store/util/mem_or_file.rs`, `store/util/sparse_mem_file.rs`, `store/util/partial_mem_storage.rs` | 2a |
| **2c** Outboard & storage | Core data path | `store/fs/bao_file.rs`, `store/fs/import.rs`, `store/fs/meta.rs`, `store/fs/entry_state.rs`, `store/fs.rs` (7 refs), `store/mem.rs`, `store/readonly_mem.rs`, `store/gc.rs`, `store/mod.rs` | 2b |
| **2d** Protocol & streaming | Wire format | `protocol.rs` (5 refs), `protocol/range_spec.rs`, `get.rs` (11 refs), `get/request.rs`, `provider.rs` | 2c |
| **2e** API layer | Public surface | `api.rs`, `api/blobs.rs`, `api/blobs/reader.rs`, `api/downloader.rs`, `api/remote.rs`, `api/proto.rs`, `api/proto/bitfield.rs` | 2d |
| **2f** Tests | Integration tests | `tests.rs`, `util.rs` | 2e |

**Order**: 2a → 2b → 2c → 2d → 2e → 2f (bottom-up, each committable).

**Changes in iroh-blobs:**

1. **`Hash` type**: Change from wrapping `blake3::Hash` to wrapping `[u8; 32]` from Poseidon2
2. **Blob hashing**: Replace `blake3::Hasher` with `cyber_poseidon2::Hasher` for computing blob hashes
3. **BAO integration**: Replace bao-tree with cyber-bao (Poseidon2 backend)
4. **Transfer protocol**: Wire format carries Poseidon2 tree nodes instead of Blake3 CVs
5. **Storage**: Re-index stored blobs under new Poseidon2 hashes
6. **`BlobFormat::HashSeq`**: Sequences now contain Poseidon2 hashes

**CID (Content Identifier) format:**

To enable algorithm agility and future migration capability, use an algorithm-tagged
CID format:

```
CID = <version><hash-algorithm-code><digest-length><digest-bytes>
```

Where `hash-algorithm-code` distinguishes:
- `0x1e` (or custom code) = Blake3 (legacy)
- `0x?? ` (new code) = Poseidon2-BN254 (current)

This allows the network to handle both Blake3 and Poseidon2 content identifiers
during a transition period.

**Data migration for existing content:**

Per the hash function selection rationale, migration at planetary scale requires:

1. A functional storage proof system guaranteeing content availability
2. Rehashing original content under Poseidon2
3. A dual-CID transition period
4. At scale (10^15 particles): ~17 hours across 10^6 nodes

---

#### Phase 3: Relay Handshake Migration (this repo)

**Status: DONE** (`07e31dd236`)

**Goal**: Replace Blake3 in the relay handshake protocol.

**Files to modify in iroh-relay:**

1. `Cargo.toml`: Replace `blake3 = "1.8.2"` with `cyber-poseidon2` dependency
2. `src/protos/handshake.rs:215`: `blake3::derive_key(...)` -> `cyber_poseidon2::derive_key(...)`
3. `src/protos/handshake.rs:312`: Update comment referencing blake3
4. `src/protos/handshake.rs:594-598`: Replace test keying material simulation

**Protocol version bump:**
```rust
// Bump version to signal Poseidon2:
const DOMAIN_SEP_CHALLENGE: &str = "iroh-relay handshake v2 challenge signature";
const DOMAIN_SEP_TLS_EXPORT_LABEL: &[u8] = b"iroh-relay handshake v2";
```

**Wire compatibility**: This is a breaking change. Old and new clients/servers are
incompatible. Coordinated deployment required.

---

#### Phase 4: Higher-Level Protocol Migration

**Status: NOT STARTED** — blocked on Phase 2.

**Goal**: Update all protocols that reference Blake3 hashes.

| Component | Change Required |
|-----------|----------------|
| iroh-docs | Update Hash references to new Poseidon2 Hash type |
| iroh-gossip | Update any blob hash references |
| iroh-willow | Update content hash references |
| iroh-car | Update CID encoding to use Poseidon2 hash code |
| iroh-ffi | Update FFI bindings for new Hash type |

---

#### Phase 5: Remove Blake3 Dependencies

**Status: NOT STARTED** — blocked on Phases 2 + 4.

**Goal**: Complete removal of all Blake3 dependencies across the ecosystem.

1. Remove `blake3` from all `Cargo.toml` files
2. Remove `iroh-blake3` custom fork (entire repository archived)
3. Remove `bao-tree` (replaced by `cyber-bao`)
4. Remove `abao` (async functionality integrated into `cyber-bao`)
5. Verify: `grep -r blake3` across all repositories returns zero results
6. Update all documentation, READMEs, CHANGELOGs

---

#### Phase 6: Validation

**Status: NOT STARTED** — blocked on Phase 5.

**Goal**: Verify zero functionality loss.

**Test matrix:**

| Test Category | What to Verify |
|--------------|----------------|
| Content hashing | Same content produces deterministic Poseidon2 hash |
| Verified streaming (combined) | Full blob download with per-chunk verification |
| Verified streaming (outboard) | Outboard metadata + original file verification |
| Slice extraction | Single-range and multi-range slice correctness |
| Range requests | Arbitrary byte range verified against root hash |
| Streaming decode (sync) | Sequential verified decode produces original data |
| Streaming decode (async) | Async verified decode produces original data |
| Post-order outboard | Append-only file sync with incremental verification |
| Relay handshake (challenge) | Client-server auth via signed challenge |
| Relay handshake (keying material) | Client-server auth via TLS keying material |
| Relay handshake (fallback) | Mismatched keying material falls back to challenge |
| Relay handshake (denial) | Authentication denial works correctly |
| Hash type serialization | Hash serializes/deserializes correctly (serde, Display, hex) |
| BlobFormat::Raw | Single blob addressed by Poseidon2 hash |
| BlobFormat::HashSeq | Collection of Poseidon2 hashes |
| CID encoding | Algorithm-agile CID correctly tags Poseidon2 |
| Storage re-indexing | Blobs re-indexed under new hashes |
| Deduplication | Identical content deduplicates via Poseidon2 hash |
| Large blob transfer | Multi-GB blob transfer with streaming verification |
| Partial blob transfer | Resume interrupted transfer with range requests |

**Benchmarks:**

| Benchmark | Measure |
|-----------|---------|
| Blob hashing throughput (1 KB - 1 GB) | Bytes/sec for Poseidon2 vs Blake3 |
| Verified streaming throughput | Download speed with per-chunk verification |
| Slice extraction latency | Time to extract a range from a large blob |
| Relay handshake latency | End-to-end handshake time |
| Tree construction time | Time to build outboard for various blob sizes |

---

## 6. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Poseidon2-BAO has no precedent | Certain | High | Thorough design review; reuse bao-tree tree logic |
| CPU-only path too slow for large blobs | Certain | Medium | GPU backend via wgpu; CPU is fallback, not primary path for bulk hashing |
| wgpu GPU shader produces different results than CPU | Medium | Critical | Exhaustive cross-validation tests; same frozen constants in both backends |
| wgpu not available on some platforms/hardware | Low | Medium | CPU fallback always available; wgpu covers Vulkan/Metal/DX12/WebGPU |
| Goldilocks 64-bit multiply precision on GPU (u32x2) | Medium | High | Careful Barrett reduction implementation; test against CPU reference |
| Poseidon2 sponge wrapper has cryptographic bug | Medium | Critical | Security audit; reference vector validation; property testing |
| Field element encoding produces non-canonical or non-uniform bytes | Medium | High | Strict canonical encoding spec; exhaustive edge case testing |
| All existing content identifiers become invalid | Certain | Critical | Dual-CID transition period; storage proof-backed migration |
| Poseidon2 parameters (t=12, R_F=8, R_P=22, d=7) later found weak | Low | Catastrophic | Parameters from peer-reviewed analysis; frozen at genesis |
| Ecosystem-wide migration takes too long | High | Medium | Phase incrementally; relay handshake (Phase 3) can ship independently |
| Downstream consumers break (iroh-docs, iroh-gossip, etc.) | Certain | Medium | Coordinate releases; version-bump all crates simultaneously |
| bao-tree internals too tightly coupled to Blake3 | Medium | High | Investigate bao-tree source early; may need significant refactoring |

---

## 7. Dependency Graph and Ordering

```
Phase 0a: cyber-poseidon2 CPU backend (p3-poseidon2 wrapper)
    |
    +---> Phase 0b: cyber-poseidon2 GPU backend (wgpu shaders) [parallel with 0a]
    |
    +---> Phase 1: cyber-bao (verified streaming) [needs 0a, benefits from 0b]
    |         |
    |         +---> Phase 2: iroh-blobs (content addressing)
    |                   |
    |                   +---> Phase 4: iroh-docs, iroh-gossip, iroh-willow, iroh-car
    |
    +---> Phase 3: iroh-relay (handshake) [needs only 0a, parallel with everything]
    |
    +---> Phase 5: Remove all Blake3 deps [after all above complete]
    |
    +---> Phase 6: Validation [after Phase 5]
```

- Phase 0a and 0b can proceed in parallel (CPU and GPU backends are independent)
- Phase 3 (relay handshake) needs only CPU backend, can ship first
- Phase 1 (cyber-bao) needs CPU backend and benefits from GPU for bulk tree construction
- GPU backend can be refined throughout later phases

---

## 8. Decided Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **Field** | Goldilocks (p = 2^64 - 2^32 + 1) | 64-bit native arithmetic, Plonky3-native, fast CPU/GPU |
| **State width (t)** | 12 | 12 Goldilocks elements = 96 bytes state |
| **Full rounds (R_F)** | 8 | 4 initial + 4 final, standard security margin |
| **Partial rounds (R_P)** | 22 | Balances security and performance |
| **S-box exponent (d)** | 7 | x^7, suitable for Goldilocks field characteristics |
| **Rate** | 8 elements (64 bytes) | Absorb 64 bytes per permutation |
| **Capacity** | 4 elements (32 bytes) | 256-bit capacity -> 128-bit collision resistance |
| **Output** | 4 elements (32 bytes) | Matches Blake3 output size |
| **Implementation** | `p3-poseidon2` (Plonky3) | Native Goldilocks, production-ready, MIT/Apache-2.0 |

## 9. Open Questions

1. **Chunk group size**: What is the optimal chunk group size to balance GPU dispatch
   efficiency vs verification granularity? 16 KB? 64 KB? (see Phase 1 performance table)

2. **bao-tree refactoring strategy**: Fork and modify, or rewrite from scratch with
   hash-agnostic design? Need to assess how tightly bao-tree is coupled to Blake3 internals.

3. **CID multicodec**: What multicodec code to register for Poseidon2-Goldilocks
   (t=12, R_F=8, R_P=22, d=7)?

4. **Transition period duration**: How long must the network support both Blake3 and
   Poseidon2 content identifiers?

5. **Storage proofs**: The migration plan from cyber.page requires storage proofs as a
   prerequisite for content migration. What is the timeline for storage proof implementation?

6. **wgpu shader precision**: Goldilocks field multiplication requires 64-bit precision.
   GPUs natively support u32. Must implement u64 arithmetic as u32x2 in WGSL.
   Need to validate correctness across all GPU vendors (AMD, NVIDIA, Apple, Intel).

7. **wgpu WebGPU target**: wgpu compute shaders on WASM/WebGPU - verify Poseidon2
   permutation works in browser context. This would make iroh-relay WASM client
   capable of Poseidon2 hashing.

8. **Round constant generation**: Must generate and freeze round constants for
   (t=12, R_F=8, R_P=22, d=7) over Goldilocks. Use Plonky3's default constant
   generation or derive independently?

9. **Backward compatibility for existing stored content**: Must existing nodes rehash
   all stored blobs, or can they serve legacy Blake3-addressed content alongside new
   Poseidon2-addressed content?

10. **GPU memory limits**: For very large blobs (10+ GB), GPU buffer size limits may
    require chunked dispatch. Design the batch API to handle streaming GPU dispatch.

---

## 10. Estimated Effort

| Phase | Scope | Estimated Effort |
|-------|-------|-----------------|
| Phase 0a: cyber-poseidon2 CPU backend | p3-poseidon2 wrapper, sponge, KDF, hazmat API | 2-3 weeks |
| Phase 0b: cyber-poseidon2 GPU backend | wgpu compute shaders (WGSL), Goldilocks u64 arithmetic on GPU, cross-validation | 3-5 weeks |
| Phase 1: cyber-bao (verified streaming) | Fork + refactor bao-tree, hash-agnostic design, Poseidon2 backend | 4-8 weeks |
| Phase 2: iroh-blobs migration | Modify existing crate, Hash type change | 2-4 weeks |
| Phase 3: iroh-relay handshake | 2-3 file changes | 1-2 days |
| Phase 4: Higher-level protocols | Cascading Hash type updates | 1-2 weeks |
| Phase 5: Blake3 removal | Dependency cleanup | 1-2 days |
| Phase 6: Validation | Testing, benchmarking, GPU vendor testing, security review | 3-5 weeks |
| **Total** | | **~16-28 weeks** |

---

## 11. References

- [Hash Function Selection Rationale](https://cyber.page/hash-function-selection/)
- [Poseidon2 Paper (IACR ePrint 2023/323)](https://eprint.iacr.org/2023/323)
- [Poseidon2: AFRICACRYPT 2023](https://dl.acm.org/doi/abs/10.1007/978-3-031-37679-5_8)
- [Original Poseidon Paper (USENIX Security 2021)](https://eprint.iacr.org/2019/458.pdf)
- [Poseidon Cryptanalysis Initiative](https://www.poseidon-initiative.info/)
- [Plonky3 Repository (p3-poseidon2)](https://github.com/Plonky3/Plonky3)
- [p3-poseidon2 crate](https://crates.io/crates/p3-poseidon2)
- [zkhash crate](https://crates.io/crates/zkhash)
- [BAO Specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
- [bao-tree (n0-computer)](https://github.com/n0-computer/bao-tree)
- [iroh-blobs](https://github.com/n0-computer/iroh-blobs)
- [BLAKE3 Hazmat API (iroh blog)](https://www.iroh.computer/blog/blake3-hazmat-api)
- [Poseidon2 in Plonky3 Analysis](https://hackmd.io/@sin7y/r1VOOG8bR)
- [Faster Hashing in ZK Settings](https://hackmd.io/@hackmdhl/B1DdpVmK2)
- [Poseidon Merkle Trees in Hardware (Irreducible)](https://www.irreducible.com/posts/poseidon-merkle-trees-in-hardware)
- [Icicle GPU Poseidon2](https://dev.ingonyama.com/2.8.0/icicle/primitives/poseidon2)
- [Concealed HTTP Auth RFC 9729](https://datatracker.ietf.org/doc/rfc9729/)
- [TLS Keying Material Export RFC 5705](https://datatracker.ietf.org/doc/html/rfc5705)

---

## Appendix A: Iroh License Analysis

Iroh is licensed under **MIT OR Apache-2.0** (dual license, user chooses).
Copyright 2025 N0, INC.

Additionally, some files derived from Tailscale are under **BSD 3-Clause**
(specifically `iroh/src/socket**` and `iroh-relay` socket code).

### What This Means for the Migration

| Aspect | Implication |
|--------|------------|
| **Forking iroh** | Fully permitted under both MIT and Apache-2.0 |
| **Modifying and redistributing** | Permitted; Apache-2.0 requires marking modified files |
| **Using in proprietary products** | Permitted under both licenses |
| **Patent protection** | Apache-2.0 provides explicit patent grant from contributors |
| **Sublicensing** | MIT allows sublicensing; Apache-2.0 allows redistribution under different terms |
| **Tailscale-derived code (BSD-3)** | Cannot use N0/Tailscale names to endorse derivatives without permission |
| **p3-poseidon2 compatibility** | MIT/Apache-2.0 - fully compatible with iroh's license |
| **Obligation** | Must include copyright notice and license text in distributions |

**No license conflicts** with the migration: `p3-poseidon2` (Plonky3) is MIT/Apache-2.0,
identical to iroh's own license. The `zkhash` crate is also MIT/Apache-2.0.

The dual MIT/Apache-2.0 license is the standard Rust ecosystem license and is
maximally permissive for both open-source and commercial use.
