# Canonical BAO ROOT finalization

Status: draft v3, awaiting correction PLAN review; no implementation.
Serves: Kadek phase-1 foundation row 4 and runtime proof-before-admission clause;
radio's Hemera BAO dependency, pinned tree ROOT finalization contract.
Base: radio `258724bd8ab797ad8d2ef43c6a4a2e07f1fc9e24`; Hemera
`23f3bbcff910ea6d504ceb505680a539260869da`. See [research](research.md) for
source commands, immutable closure, exact primary vectors and consumer inventory.

## Result and compatibility boundary

The five group reductions and traced consumers named in research will implement the same fixed-4096-byte,
left-balanced Hemera tree: empty/single leaf uses CHUNK|ROOT at file root;
multiple leaves use PARENT|ROOT only on the final file-root merge, with absolute
leaf counters and non-ROOT internal CVs. Primary authority is pinned Hemera
`specs/tree.md:74–97` and `rs/src/tree.rs::{fixed_chunk_root,chunk_cv,parent_cv}`.
CDC `root_hash` and plain `hash` are distinct and remain unchanged.

This changes native log4 content keys for files of 4097..65536 bytes, because
current code advertises an internal CV. Default log2 changes 4097..16384; log0,
empty/single-chunk and multi-group files retain their roots under this correction.
Proof serialization remains unchanged. For affected lengths new imports use new
keys; existing stored keys, tickets, GetRequest hashes and embedded references
still name old roots. Corrected verifiers reject old roots; old verifiers reject
canonical ones. Explicit complete-body rehash/reindex/reimport and new references
are needed; partial records alone cannot establish the replacement identity.
No deployment inventory or automatic migration is claimed. Rollback of code does
not migrate newly indexed canonical records. No alias/dual policy, protocol-id
choice, version bump, tag, release or canonical particle change is in scope.
The old 8192-byte root is also an internal CV of a larger file sharing that
prefix at the same counters. Restoring ROOT separation is the specified security
benefit; this unit makes no broader cryptographic-audit claim.

## Steps and verification

1. Add independent regression oracles first → verify failure on exact parent:
   D[i]=(i*31+i/4096)%256 for 8192 bytes; L/R are chunk_cv with counters0/1,
   is_root=false. Canonical parent_cv(L,R,true) is
   `2abf65dd26465a7352707d79d18ff3aab9ee5d97614a774619c79ed527e20190`;
   current parent_cv(L,R,false) is
   `11890a7e7cf1e4de463a04bf53bfdf269d627983a221daaf9029a3ff43297389`.
   Literal proof LE64(8192)||D is 8200 bytes, empty outboard. Test canonical
   acceptance and old-root rejection independently of encode/decode roundtrips.
   Pin unchanged Hash::new and fixed_chunk_root to published empty/hello tree
   literals from research. Never use the CDC tree.4k_zeros vector as a fixed-tree
   oracle: uniform 4096-byte CDC input splits at 2048.
2. Replace the five duplicated reductions with one private generic
   `hash_group<B: HashBackend>(backend,data,start_chunk,is_root)->B::Hash`
   in existing io/mod.rs → verify recording-backend flags/counters and independent
   2/3/5-leaf trees. Final parent uses `is_root && level.len()==2`; every prior
   parent is non-ROOT. Keep absolute leaf counters, odd-node promotion, empty and
   one-chunk rules. This is one shared implementation of existing control logic.
   Public concrete io::hash_block signature remains byte-for-byte compatible,
   including block_bytes and existing let _ = block_bytes; it delegates.
   Private outboard/decode/slice/sync helpers
   disappear and their callers use hash_group. Preserve current Vec allocation
   strategy and generic B::Hash/Clone behavior; no Poseidon-only hardwiring.
   Allocation-free redesign is a different unit.
3. Route and test the inspected producer/verifier paths → outboard, combined
   encode/decode, slice decode, sync encode_ranges_validated, sync valid_ranges,
   mixed encode and #[cfg(feature="tokio_fsm")] FSM decoding accept the oracle.
   The old grouped root is rejected on verification. Generic recording-backend
   tests cover nonzero start_chunk and non-root groups so a local fix cannot
   incorrectly ROOT-finalize a subtree of a larger file.
   For the old 8192-byte root, preserve exact failures: combined
   io::decode::DecodeError::LeafMismatch{start_chunk:0}; slice
   SliceDecodeError::LeafMismatch{start_chunk:0}; sync
   EncodeError::LeafHashMismatch(ChunkNum(0)); FSM
   io::error::DecodeError::LeafHashMismatch(ChunkNum(0)); valid_ranges yields no
   ranges and no Err; the canonical root yields one Ok(ChunkNum(0)..ChunkNum(2)),
   whose aggregate is ChunkRanges::from(ChunkNum(0)..ChunkNum(2)). Do not change other branches'
   existing block-granularity behavior. Mixed emits exactly Size(8192),
   Error(EncodeError::LeafHashMismatch(ChunkNum(0))), then returns Ok(()) with a
   successful sender; no Parent, Leaf or Done. Canonical success is exactly
   Size(8192), Leaf{offset:0,data:D}, Done, and Ok(()); no Parent.
4. Exercise native consumers with the canonical one-group fixture → Hash::new,
   actual store/import root and the existing ExportBaoProgress harness retain
   exact byte/offset/progress oracles. A BlobTicket carries the new Hash; parsing
   an old ticket preserves its old bytes, never normalizes them. No ticket wire
   rewrite. Keep the public hash function's docs explicit about canonical tree
   identity; do not claim it equals plain Hemera particle.
   In export_pairs.rs, test both ReadonlyMemStore::new([D]) and MemStore::new()
   with add_bytes(D).await. Require each list().hashes().await to contain only
   the canonical key; the mutable import's returned key must match it. Require
   both keys equal Hash::new(D), fixed_chunk_root(D) and the independent literal.
   Each export_bao(key, ranges(0,2)).bao_to_vec().await must be exactly LE64(8192)||D;
   get_bytes returns D and both stores shut down. This covers CompleteStorage::create
   and mutable import_bytes/finish_import at an affected length, without relying
   on the unchanged 4096/131072-byte existing store cases.
   In export_pairs.rs, #[cfg(feature="fs-store")], create two separate FsStores
   with Options::new and max_data_inlined=32768/4096 respectively; both use
   max_outboard_inlined=16384. Assert is_inlined_all(8192) true/false (meta.rs
   raw_outboard_size delegates to BaoTree(log4).outboard_size()==0), then add_bytes
   of the same D. Require both returned keys equal each other, Hash::new(D),
   fixed_chunk_root(D) and the literal above; get_bytes returns D from each;
   shutdown both before dropping their temporary directories. This exercises
   tiny versus non-tiny data import (outboard is empty in both), without dedup
   masking a path. util.rs::outboard_with_progress already delegates to public
   io::hash_block; both memory creation paths delegate to PreOrderMemOutboard::create.
   These inspected store/importer production sources remain unchanged.
5. Replace only the named grouped-defect-preservation test with canonical policy
   tests; preserve historical audit → PR31 right-only traversal remains covered.
   PR32 131072-byte right-only log4 proof remains exactly the pinned fixture:
   root `9ccd2809b2bcca875ee39f2c034c80969c176a5510a66d638b2c88c3cd7c7f0f`,
   SHA256 `108022aa95ee61a1058d6d4bb53979a95bc46de114b036fcc6620fbd65648a51`.
   Required grouping/boundary matrix: log0/1/2/4 with lengths0,1,4095,4096,
   4097,8192,12288,16384,16385,24576,28672,65536,65537,131072. Pin 16385/log4:
   five leaves with a one-byte final leaf in one group. Pin 24576/log2: groups
   of 4+2 chunks, both non-root; 28672/log2: 4+3 chunks, odd non-root last group.
   Use decisive cases per API, not every Cartesian combination.
6. Freeze exact source/receipts; fresh different-vendor CODE review and gates →
   report actual exits, warnings, baseline parity and behavioral break explicitly.
   No production source until PLAN approval; no release or row-4 closure claim.

## Exact source scope

- cyber-bao/src/io/{mod,outboard,decode,slice,sync}.rs: the single helper,
  callers, relevant documentation and recording-backend unit tests.
- cyber-bao/tests/slice_traversal.rs: replace the named defect-preservation test.
- New cyber-bao/tests/root_policy.rs and, only if needed for length separation,
  root_policy_async.rs: public sync/mixed/FSM canonical fixtures; new files <=500 lines.
- iroh-blobs/src/hash.rs: narrow canonical-tree docs plus #[cfg(test)] mod root_policy;
  new hash/root_policy.rs: Hash literals/canonical keys and ticket tests, <=500 lines.
- iroh-blobs/src/api/blobs/export_pairs.rs and support.rs: existing actual-store/
  exporter test reuse only; no provider production change.
- Read-only review inputs: complete iroh-blobs/src/{util,api}.rs,
  store/{mem,readonly_mem,util}.rs, store/fs/{import,options}.rs and
  format/collection.rs trace native key producers/delegates. A labelled
  store/fs/meta.rs imports/raw_outboard_size excerpt pins the inline predicate.
- Task research/plan/review and new audit receipt/reproducer; no old audit rewrite.

Pinned existing hash.rs is615 lines and gets narrow docs/module declaration only; sync.rs is439,
mod.rs140, outboard.rs237, decode.rs302, slice.rs399, export_pairs.rs344 and
support.rs184 (wc -l at base). Do not split unrelated existing files to satisfy
the new-file limit; all new source/test files remain <=500 lines.

No tree geometry, trailing-data policy, Hash::EMPTY placeholder, unchecked generic
profile hardening, particle CLI behavior, manifest/lock/version or Kadek change.
Hash::EMPTY stays the zero placeholder; zero-size special cases are a separate
existing identity defect. Particle encode/decode/outboard/verify use log0 and
cmd_hash uses plain Hemera, so particle-produced identities are unchanged.
If a decisive fixture exposes another defect, record it with exact evidence and
return to planning rather than expanding this patch silently.

## Isolated gates and review envelope

Gate roots contain only exact radio/Hemera archives, with committed Cargo.lock;
no live sibling paths, registry substitute, shared target, shim or network server.
Use matching pinned compiler/Cargo, log versions and cargo metadata local packages.
Run strict warnings and retain ordinary and release results separately:

- RUSTFLAGS=-Dwarnings cargo test -p cyber-bao --locked --offline;
  also --all-features and release all-features.
- RUSTFLAGS=-Dwarnings cargo test --manifest-path iroh-blobs/Cargo.toml
  --lib root_policy --locked --offline and --lib export_pairs;
  default/all-features/release variants. Name newly added consumer tests root_policy_*.
- RUSTFLAGS=-Dwarnings cargo clippy --manifest-path <crate>/Cargo.toml
  --all-targets --all-features --locked --offline -- -D warnings, separately for
  cyber-bao and iroh-blobs (local and registry iroh-blobs share name/version).
- cargo fmt --all -- --check; RUSTFLAGS=-Dwarnings cargo test --workspace --locked --offline.
- RUSTFLAGS=-Dwarnings RUSTDOCFLAGS=-Dwarnings cargo doc
  --manifest-path <crate>/Cargo.toml --all-features --no-deps --locked --offline,
  separately for cyber-bao and iroh-blobs.
- Actual declared MSRV1.89: record rustup run 1.89.0 rustc -Vv and cargo -V;
  set RUSTC to rustup which --toolchain 1.89.0 rustc, RUSTDOC equivalently and
  RUSTFLAGS=-Dwarnings. With rustup run 1.89.0 cargo, check cyber-bao all-targets/
  all-features and cargo test -p cyber-bao --test root_policy --all-features
  (also root_policy_async if added); run iroh-blobs --lib root_policy and
  --lib export_pairs via its manifest. Use --locked --offline throughout. A
  missing compiler or dependency MSRV failure is recorded, never run on stable
  under an MSRV label; no lock regeneration. These are scoped MSRV checks.
- RUSTFLAGS=-Dwarnings cargo test -p particle -p radio-cli
  -p radio-integration-tests --all-features --locked --offline.
- cargo semver-checks check-release for touched crates against last tag and exact
  parent diagnostic; retain scratch manifests/locks if tool resolution diverges.
- git diff --check; frozen source SHA256 manifest and primary fixture checksums.

Existing broad gate failures are retained, repeated on exact parent for parity,
never hidden with warnings suppression. Prior receipts have Clippy and mixed
local/registry endpoint-type failures. Source-level semver may remain green while
content identities change: review must explicitly decide this behavioral
compatibility consequence. Compute applicable component reverse closure before
claiming a rung gate; actual radio import/export callers make this more than a
local Kadek facade. No rung/release readiness follows from scoped tests.
Research records the pinned component map and source-only reverse-closure inventory;
verify actual package IDs with isolated cargo metadata before dependent checks.
Applicable named native workflow tasks follow repository gates; absent external
product/rung receipts remain an explicit unexecuted stage, never a source-review pass.

Fresh review bundle: this research/plan, exact five reductions/callers, HashBackend,
BaoTree, pinned Hemera fixed-tree/flag sources, independent vectors, native Hash,
import, ticket, request sources, and prior PR31/32 tests/receipts. The earlier
reviews approved narrower scopes and do not approve root-policy changes.

## Five failure questions

1. Do any duplicate paths keep the old policy, or ROOT-finalize an internal group?
   The pinned token inventory and named source reads bound this claim; one helper,
   flag/counter traces, sync/mixed/FSM, both memory stores and tiny/non-tiny FsStore
   tests guard the identified paths. A newly found reduction returns to planning.
2. Does grouping or odd-leaf structure alter identity? Cross-log independent
   3/5-leaf and partial-chunk vectors compare with fixed_chunk_root, not CDC root.
3. Could producer and verifier agree on another wrong root? Literal canonical
   acceptance and old-root rejection use independently assembled proof bytes;
   published empty/hello vectors supply external unchanged anchors.
4. Does unchanged proof layout hide key/ticket/import incompatibility? Native
   Hash/store checks and preserved old ticket bytes demonstrate the identity break;
   full-body rebuild/migration remains explicit, with no legacy alias.
5. Is this mistaken for bounded or particle-authenticated verification? Plain/tree
   primary vectors and unchanged allocator/traversal behavior delimit this unit.

## Next dependencies, not implementation scope

After canonical ROOT lands: one bounded no_std-capable cyber-bao proof engine,
then a sealed Kadek VerifiedBody-derived particle/root/length association and
pooled proof admission into existing VerifiedRange/PacketData. Cold association
requires a separately authenticated mapping contract; transport bounds fetching
and framing, not cryptographic authority. No generic trusted trait, parallel
packet type or new wire protocol is chosen here.
