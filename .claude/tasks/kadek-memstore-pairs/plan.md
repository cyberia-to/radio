# Canonical in-memory BAO parent pairs

Status: proposed PLAN v2; fresh different-vendor approval required before source edits.
Serves: Kadek phase-1 row4, existing radio verified-range import/storage dependency.
Base radio `0d11468503c052aa5dcefb0dabc4602bd8efdc60`, exact Hemera
`23f3bbcff910ea6d504ceb505680a539260869da`; source facts in [research](research.md).

## Result and boundary

Both current memory-backed parent writers store exactly left32||right32 at
pre-order parent ordinal*64, matching existing readers and canonical proofs.
The native log4 geometry remains4096-byte chunks/65536-byte groups. No public
signature, root/key, protocol, version, manifest, lock or spec change. MemStore
imports that currently panic will succeed; existing complete entries stay readable.
FsStore's PartialMem writer gets the same correction, verified through a complete
public import. FsStore incomplete checkpoints/resume remain separately defective.
This repairs width and ordering; no bounded-memory/work or particle/root authority
claim. The draft store-retirement roadmap is not implemented in this patch.

## Steps → verification

1. Freeze new independent tests before production → run test-only overlay against
   exact parent archives (debug and release). Success expectations must fail on
   the32→64 copy; preserve raw worker panic/request error/timeout as observed.
   Never mark a panic as test success. Every new asynchronous workflow has a
   finite30s n0_future::time::timeout; timeouts fail. No wait_idle or sleep-based
   completion. Shutdown finished stores, including successful corruption tests.
2. Add `pub(super) const HASH_PAIR_BYTES:usize=2*hemera::OUTPUT_BYTES` and
   `pub(super) fn encode_parent_pair(&(hemera::Hash,hemera::Hash))->[u8;HASH_PAIR_BYTES]`
   in existing store/util.rs, visible only within store → a literal pair with
   bytes0..31 and32..63 must serialize exactly0..63. No generic serializer,
   allocation, new public type, decode helper or speculative profile abstraction.
   Both writers pass `&parent.pair`; moved and borrowed Parent bindings work.
   Hemera is already a direct renamed dependency. Deliberately retain the same-named
   private api/blobs.rs helper: store must not depend on private API implementation;
   moving that correct exporter helper would widen this repair. Two module-local
   helpers exist, with this new one shared by the two faulty store writers only.
3. MemStore import and PartialMemStorage::write_batch use the helper and same
   pair stride → three-group proof exercises ordinal1. Preserve each existing
   writer's error policy: MemStore multiplication and write expect;
   PartialMemStorage checked_mul+expect and write io Result;
   change only the multiplicand to the derived width. Pre-order geometry bounds
   this width multiplication for every native u64 file length. Do not change
   state ordering, channels, batching, size bookkeeping or allocation strategy.
   Already-correct MemStore OutboardReader consolidates constants to the derived
   width/OUTPUT_BYTES halves and arrays; retain UnexpectedEof/"short read".
   print_outboard changes the assert modulus and chunk width128→64, halves64→32:
   accept64/128 bytes; reject96. Its old slice conversion compiled but panicked
   at runtime. Retain #[allow(dead_code)] for non-test builds. Leave the correct
   PartialFileStorage writer/reader untouched.
4. Public MemStore two-group lifecycle oracle → include exact committed PR32
   right-proof bytes, assert literal root and body construction. Import requested
   ChunkNum16..32; status exactly Partial{size:Some(131072)}; right export equals
   golden bytes. Complementary left proof is the same LE64+root pair+left body;
   after import require Complete{size:131072}, get_bytes==D, full export exactly
   LE64+pair+D. Re-import into completed entry must succeed without changing
   data/status/root/export. Requests finish before reading status, no polling.
5. Public MemStore nonzero-ordinal oracle → D length196608, explicit primary
   chunk_cv at absolute counters0..47; four fixed nonroot merge levels give
   group A/B/C, AB nonroot, final parent ROOT. Assemble literal full proof
   LE64(196608)||AB||C||A||B||D, length196744. Require complete import, exact
   body/full export, and exact middle-group proof LE64||AB||C||A||B||D[65536..131072].
   This requires reading parent ordinal1 at byte64 and detects fixing only the
   copy lengths. Pin CHUNK_SIZE4096 and IROH_BLOCK_SIZE65536 independently.
   Derive expected bytes without radio encoder/outboard/traversal; cross-check
   root with Hemera fixed_chunk_root only as a second oracle. Record primary-only
   generator, literal root and wire SHA in audit after approved execution.
6. Public rejection and unchanged control → separate fresh MemStores receive
   golden with first parent byte flipped, or a right-leaf byte flipped. Match
   RequestError::Inner{source:Error::Io(e),..}, InvalidData, exact respective
   "parent hash mismatch at node 1" / "leaf hash mismatch at chunk 16".
   Status is Partial{size:None}; valid right-only retry then reaches expected
   Partial{Some(size)} and exact export. Verified parent storage may remain after
   rejected leaf; no transactional rollback guarantee. A4096-byte parent-free
   proof uses primary chunk_cv(D,0,true), succeeds with exact header+body wire.
   Pin reader short-pair error plus print64/128 success and96 rejection in narrow
   private tests; only the deliberate malformed print test catches its assertion.
   No public authority bypass added for tests.
7. Real FsStore route, #[cfg(feature="fs-store")] → independent full three-group
   proof from step5, fresh temporary store with max_data_inlined=196608 and
   max_outboard_inlined=128. Assert is_inlined_data(196608) and
   is_inlined_outboard(128): both are exact <= equality boundaries. The decoder's
   Parent(node3), Parent(node1), Leaf(A), Leaf(B), Leaf(C) form one complete batch
   (no Parent after Leaf), selecting the repaired PartialMem writer and completion.
   Require Complete{196608}, exact
   get_bytes/full export/middle-group export; shutdown, reopen same database with
   same options and repeat. Existing FsStore options/API only, no injected
   internal state. FsStore's slice to_vec keeps gap-zero bytes, unlike MemStore's
   TryFrom gap rejection. With64-byte pairs but a stale128-byte stride, it would
   inline192 bytes, including a64-byte gap, against the computed128-byte outboard:
   exact middle/full proof bytes after reopen are the required stride oracle.
   This route never intentionally persists an incomplete batch.
   If another defect blocks it, capture evidence and return to planning rather
   than widening into checksum/recovery/actor changes or weakening assertions.
8. Freeze source and receipts → coordinator review plus fresh different-vendor
   CODE review after gates. Report each red/blocked/masked check and compatibility
   scope honestly. Parent and candidate gates use exact immutable source closures.

## Files and source compatibility

- iroh-blobs/src/store/mem.rs: writer/reader/print and cfg(test) module declaration.
- iroh-blobs/src/store/util.rs: private constant/concrete helper only; checksum
  functions remain byte-identical despite sharing this file.
- iroh-blobs/src/store/util/partial_mem_storage.rs: same serializer/stride repair.
- New store/mem/parent_pairs.rs, optional sibling parent_pairs/fixtures.rs if
  needed to keep every new source/test file≤500 lines; FsStore public test can
  live in the same cfg-gated module. Create mem/ alongside mem.rs (edition2021);
  no new dependency or production module.
- Task research/plan/review, audit source/receipt/reproducer after execution.

Base line counts: mem.rs1128 (narrow legacy exception), util.rs433,
partial_mem_storage.rs54. No unrelated formatting/splitting of large legacy files.
Private helper leaves public source API unchanged; semver gate must verify it.
No migration of persisted formats: corrected ephemeral pair writes match the
already-existing64-byte file layout. Previously partial records may be incomplete;
this patch does not reconstruct or certify them. Rollback restores the defect.

## Isolated gates, named tools and acceptance limits

Create fresh full git archives of radio/Hemera side by side, preserve committed
Cargo.lock; exclude only tracked nettools/target with a recorded list. No dirty
sibling sources, path shim or registry substitute. Record source/lock hashes and
locked cargo metadata package IDs. Separate parent/witness/candidate targets;
jobs4, ≤20GiB before heavy gates/≤30GiB live total, clean only completed own targets
after retaining logs. Ordinary matching Rustup1.95.0 Cargo/RUSTC/RUSTDOC;
RUSTFLAGS=-Dwarnings, strict docs RUSTDOCFLAGS=-Dwarnings, --locked --offline.
Installed tool binaries/provenance from ROOT receipt are reused after hash check,
with their historical acquisition dates; no “missing tool” placeholder.

- `cargo test --manifest-path iroh-blobs/Cargo.toml --lib parent_pairs`:
  default, --no-default-features, --all-features, and --release --all-features.
  Exact-parent test-only debug/release run the same eventual test-source freeze.
- Existing `--lib store::mem::tests::smoke`, `--lib export_pairs`, `--lib root_policy`;
  default/all-feature checks as applicable. `cargo test -p cyber-bao --all-features`
  verifies unchanged traversal/root dependency. Retain separate counts/overlaps.
- Native all-target all-feature strict Clippy; strict owning docs with
  `cargo doc --manifest-path iroh-blobs/Cargo.toml --all-features --no-deps`.
  Dependency lint failure may mask new-test lint; never certify masked targets.
- `cargo fmt --all -- --check`; named make0.37.24 `format-check` with updates disabled.
  Format only changed lines/new files according to repository style.
- Actual MSRV1.89.0 Cargo/RUSTC/RUSTDOC: `cargo check --manifest-path
  iroh-blobs/Cargo.toml --all-targets --all-features`; scoped `--lib parent_pairs`
  and `--lib export_pairs` tests. Record compiler versions; no accidental stable override.
- Workspace test compiler outcome; local consumer tests radio-cli and
  radio-integration-tests --all-features. If compile succeeds, execute finite tests.
- nextest0.9.80 owning `--manifest-path iroh-blobs/Cargo.toml --lib --all-features`
  with repository default30s slow-test termination, `--no-fail-fast`, gives a
  bounded unfiltered diagnostic; compare exact parent to candidate names/errors.
  Also named workspace nextest default/none/all compilation and execution only
  when compile succeeds. No manual suppression of known failures/hangs.
- Workspace strict Clippy default/none/all; CI nightly2025-10-09 docs command
  `cargo doc --workspace --all-features --no-deps --document-private-items`, actual
  matching nightly binaries, RUSTDOCFLAGS='--cfg docsrs' exactly as CI.
- deny0.18.9 workspace/all-features check with same archived advisory DB
  7eebec69c352c7191b1f13eb95dd510eeca5d1de, --disable-fetch and -Dwarnings;
  retain unchanged/red dependency and policy findings, not a legal conclusion.
- semver0.51.0 owning iroh-blobs against exact parent and last tag v0.1.0;
  expect no public API change, retain scratch manifests/locks and resolution
  differences. Tag's unversioned Hemera path uses the explicit current pin,
  so this is not a historical release-closure pass.
- `git diff --check`, exact source whitelist/fixture SHA verification and fresh
  CODE review. Paired baseline diagnostics name actual commands, not assumed parity.

Use --manifest-path to distinguish local iroh-blobs from registry same-name/version.
Existing broad failures are anticipated from prior receipts, not predeclared current
results. Applicable external product/rung and platform gates remain unexecuted
until their own exact closures run; no ring1/release/row4 completion follows.
No commit/push/PR before root handoff; any red source commit requires wip: and
the first actual error. No versions, tags or publishing.

## Five failure questions

1. Can fixing copies leave the wrong stride? Three-group ordinal1 exact full and
   middle proof plus shared pair width catch it; two-group fixture alone cannot.
2. Can importer/exporter agree on wrong bytes? Published PR32 golden, explicit
   primary-only three-group construction and exact wire comparisons are independent.
3. Can malformed input become complete? Public verification errors, exact Partial
   state and valid retry cover rejection; already-verified low-level items retain
   their documented trust contract.
4. Does the FsStore test actually hit the second writer? Threshold/one-batch
   proof shape pins NonExisting→PartialMem→Complete; reopen verifies produced
   data/outboard. Incomplete persistence/checksum remains an explicit separate gap.
5. Can async panic/hang or broad red gates disappear behind filtered success?
   Failure-first public success assertions, finite timeouts, bounded nextest,
   raw baseline/candidate receipts and no masked-Clippy pass prevent that claim.
