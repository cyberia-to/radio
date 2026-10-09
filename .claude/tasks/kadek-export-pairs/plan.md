# Correct actual BAO exporter pair width

Status: source-only plan awaiting fresh different-vendor approval; no code/tests
edited or builds run. Base origin/main `764d732ac38fb9116c4cf525a6d1bb463d409a06`.
Owned branch/worktree: `fix/kadek-export-pairs` /
`/Users/master/cyber/radio-kadek-export-pairs`.
Serves: kadek foundation row 4 · radio proof provider · current 32-byte Hash wire.
[Research](research.md) pins sources, feasible fixtures, rules and baseline reds.
Root owns vendor calls, commits/PR/merge; this task does not close row 4.

## Result and exact scope

All three actual ExportBaoProgress serializers emit `left32 || right32` for a
Parent; completed parent writes credit exactly 64 overhead bytes. Size remains
LE64, leaves preserve data/order, existing error/progress sequencing remains.
No public API, hash domain, root, storage format, version or dependency change.

- `iroh-blobs/src/api/blobs.rs`: add private
  `fn encode_parent_pair(pair: &(hemera::Hash, hemera::Hash)) -> [u8; 2 * hemera::OUTPUT_BYTES]`.
  Fill halves split at OUTPUT_BYTES. Reuse in write, write_with_progress and
  into_byte_stream; use Bytes::copy_from_slice for the latter. Credit data.len()
  after successful send. Add only the private cfg(test) child-module declaration.
- New `iroh-blobs/src/api/blobs/export_pairs.rs`: private regression tests.
  If helpers exceed the file budget, place only independent fixture generation,
  scripted stream, sink and progress recorder in its private child
  `iroh-blobs/src/api/blobs/export_pairs/support.rs`. Both files ≤500 lines;
  retain every case, no artificial monolith or additional Rust dependency.
- Task research/plan and later compact audit receipt/reproduction script (Nu),
  exact source/lock/patch/fixture digests and gate outcomes; root owns final audit.

No provider/store/BAO/Hemera production edits, neighboring refactors, broad
formatting, manifests/locks, warning suppression, transport policy or CI repairs.
Keep prior traversal receipt unchanged. Any newly blocking compiler issue is
reported before expanding source scope.

## Steps → verification

1. After approval, archive the exact full dependency closure described below.
   → verify origin blobs, archive/lock hashes and isolated metadata paths; retain
   setup errors, no original dirty siblings or tracked build-cache inputs.
2. Add tests first; overlay just the new test module(s) and cfg(test) declaration
   onto untouched production in a separate baseline archive.
   → verify actual Parent copy panics in each of the three exporter methods,
   debug/release, with ordinary test failures (no should_panic masking). Execute
   parent-free controls too. Compilation failure is not a reproduced panic.
3. Implement one fixed-array serializer and three integrations.
   → verify literal/scripted wire, independent real Store proof and exact
   progress/error behavior below; no hash/traversal implementation changes.
4. Run the focused and owning gate sets against frozen candidate bytes.
   → verify commands/exits/source and dependency hashes retained; classify
   pre-existing failures against baseline, report unavailable tools/platforms.
   Broad reds do not stop independent meaningful scoped checks.
5. Freeze source diff plus per-file hashes for fresh different-vendor code
   review and root's ring/merge adjudication. → verify scope, new-file size,
   unchanged old receipt and explicit remaining compatibility/storage gaps.

## Independent regression cases

Use `export_pairs` as the focused module filter. Tests call actual methods;
helper-only or exporter-to-exporter equality is insufficient.

| Test / case | Required evidence |
|---|---|
| `geometry_pins` | Separate named assertions: CHUNK_SIZE=4096, IROH_BLOCK_SIZE.bytes()=65536. Fixture construction checks the same pins before deriving geometry; do not take the stale store/mod.rs 1024-byte comment as authority. |
| `literal_parent_write`, `literal_parent_progress`, `literal_parent_byte_stream` | Fresh scripted Size, Parent(left 0..31/right 32..63), nonempty Leaf, Done. Assert exact LE64 + literal 64 bytes + leaf, independent of the helper; byte-stream chunk lengths 8/64/leaf. Progress records original index/root/size and leaf offset/length, overhead 72. These are primary red-first cases. |
| `readonly_store_right_block` | Derive B=IROH_BLOCK_SIZE.bytes(), C=B/CHUNK_SIZE; body length2*B, query C..2*C. Independent root/proof below; all three methods equal manual wire of length8+2*OUTPUT_BYTES+B (65608), overhead72, payload offset/lengthB (65536). Decode returns that exact right block. |
| `readonly_store_parent_free` | Exactly one chunk (CHUNK_SIZE bytes), root `chunk_cv(data,0,true)`, query0..1. All three outputs exactly LE64(CHUNK_SIZE)+data; overhead8, payload CHUNK_SIZE, no Parent. |
| `encoded_error_propagates` | Script valid header/pair then EncodedItem::Error(Io with sentinel kind/detail), close sender. Writers return ExportBaoInner; byte stream yields prefix then Error::Io. No later payload/write credit. |
| `readonly_store_missing` | Unknown root via real store: write/write_with_progress return ExportBaoError::ExportBaoInner containing EncodeError::Io(UnexpectedEof); into_byte_stream yields api::Error::Io(UnexpectedEof). All preserve "export task ended unexpectedly"; no bytes/progress. |
| `writer_failure_accounting` | Inject sentinel BrokenPipe before accepting header, parent, or leaf. Actual write and progress writer return ExportBaoIo. Progress header failure has start notification but overhead0; parent failure overhead8; leaf failure overhead72 and no payload callback. No later item written. |
| `partial_parent_failure` | Sink accepts an explicit prefix of Parent then errors. Prefix remains in target, error propagates, completed-write overhead remains8; no rollback/retry claim. |
| `payload_progress_failure` | Actual writer sends leaf successfully, then callback returns `ProgressError::from(AbortReason::Permission)` per provider/events.rs. Assert ExportBaoError::ClientError containing ProgressError::Permission; wire contains leaf, overhead72, one callback attempt and no subsequent scripted leaf. |

Scripted fixtures use bounded irpc channel capacity sufficient for their finite
sequence, close the sender, and preserve method-specific existing termination.
The sink implements actual AsyncStreamWriter and SendStream; every unused method
is inert or explicitly fails the test if unexpectedly called. No network fixture.
Use Tokio runtime for real Store actor, retain Store, await shutdown afterward.
Free helpers without awaits stay synchronous; trait-impl async methods implement
the actual traits. Preserve partial-write behavior without rollback/retry claims.

Geometry comes from `cyber-bao/src/tree.rs:13,240–255` and the IROH constant;
first assert CHUNK_SIZE=4096 and B=65536 with distinct failure messages. Then
derive C=B/CHUNK_SIZE=16, body length2*B=131072, query C..2*C=16..32. The oracle
uses body[i] = `(i*31+i/CHUNK_SIZE)%256`; calculate 2*C leaf CVs using absolute
counters and root=false, reduce each C-leaf half through four explicit pairwise
levels (C is pinned16), all root=false. Set root=parent_cv(L,R,true).
Assemble `LE64(2*B)||L.as_bytes()||R.as_bytes()||body[B..]` directly.
Neither root nor expected bytes come from radio's outboard, extractor or helper.
During red-first preparation record root hex and independently generated proof
SHA256 in the receipt (external shasum, no Rust hashing dependency); do not label
them measured before execution. Hemera itself is the pinned cryptographic oracle.
This case avoids grouped-single-root nonconformance and makes no plain-Particle
binding claim. That separate root/profile decision remains open.

## Isolation and exact commands

Create fresh `/tmp/<run>/{baseline,candidate,tag}/` roots. Each has radio and
hemera siblings exported with git archive: radio base above, source Hemera
`23f3bbcff910ea6d504ceb505680a539260869da`; tag radio is v0.1.0 commit
`f2b1298daa9f635c821d53996c4d1dc4f1042b3d`. Exclude only tracked nettools/target
using the existing traversal receipt's archive selection. Export all other
internal/vendored packages, preserve manifests/lints/locks. Candidate differs
from base only by the reviewed task source patch; hash that patch and files.
No registry-Hemera substitution, pruned toy crate or serializer-copy harness.

Before any compile: `cargo metadata --format-version 1 --all-features --offline
--locked`, verify every source=null manifest path resides inside its isolated
root. Record rustc/cargo versions, source archive hashes, package identities and
Cargo.lock hashes before/after. If caches are incomplete, `cargo fetch --locked`
may fetch committed identities; never regenerate the lock or escape isolation.
Use a private target under each isolated root, not archived target directories.

From isolated radio, with RUSTFLAGS=-Dwarnings (docs also RUSTDOCFLAGS=-Dwarnings):

```text
cargo test --manifest-path iroh-blobs/Cargo.toml --lib export_pairs --offline --locked
cargo test --manifest-path iroh-blobs/Cargo.toml --lib export_pairs --release --offline --locked
cargo test --manifest-path iroh-blobs/Cargo.toml --lib export_pairs --no-default-features --offline --locked
cargo test --manifest-path iroh-blobs/Cargo.toml --lib export_pairs --all-features --offline --locked
cargo test --manifest-path iroh-blobs/Cargo.toml --all-features --offline --locked
cargo test --manifest-path iroh-blobs/Cargo.toml --no-default-features --offline --locked
cargo test --manifest-path iroh-blobs/Cargo.toml --offline --locked
cargo clippy --manifest-path iroh-blobs/Cargo.toml --all-features --all-targets --offline --locked -- -D warnings
cargo doc --manifest-path iroh-blobs/Cargo.toml --all-features --no-deps --offline --locked
rustup run 1.89.0 cargo check --manifest-path iroh-blobs/Cargo.toml --all-features --all-targets --offline --locked
cargo semver-checks check-release --manifest-path iroh-blobs/Cargo.toml --baseline-root <tag>/radio/iroh-blobs --verbose
cargo test -p radio-cli -p radio-integration-tests --all-features --offline --locked
```

Use manifest-path because local and registry iroh-blobs share name/version.
The baseline's three literal tests must report the actual copy panic; preserve
full failure output. If an unchanged compile warning prevents reaching tests,
record it and return the blocker rather than waive warnings or repair neighbors.
Semver tool 0.51.0 was identified by version/help only; baseline-root points to the
tag's package directory. Before claiming the gate, retain verbose output and
metadata confirming both compared local iroh-blobs 0.98.0 paths and tag tree,
never the registry package. Tool/setup failure is not an API-compatibility pass.

Also attempt owning native repository gates exactly from `.github/workflows/
ci.yml`, `tests.yaml`, Makefile.toml: `cargo make format-check`; nextest workspace
lib/bin/tests for default/no-default/all features; all-feature workspace doctests;
workspace Clippy with all targets for each feature mode; docs/private items on
nightly-2025-10-09; MSRV1.89 workspace/all-target check; cargo deny. Preserve first
errors and continue scoped checks; record tool/platform-unavailable jobs rather
than infer results. Cross/Android/wasm/netsim and remote CI remain named separate
results. Prior receipt's red Clippy, workspace APIs, formatting, missing tools and
remote missing-Hemera failure remain visible; no broad CI repair in this unit.

## Ring, risks and rollback

Ring0 plus soft3 layer7 ring1: registry pin and local reverse dependencies are in
research. Root owns actual rung/spec/drift assessment; no all-green rung claim.
Soft3's old radio release pin already drifts; only the owner's bump flow can
change it. No release/tag/publish action is part of this source repair.

Five likely failures and checks:

1. Half width/order still wrong → independent literal 0..63 pair in all methods.
2. A parent-free fixture hides the bug → real two-block log4 proof requires Parent.
3. Progress credits failed/partial writes → injected header/pair/leaf failures.
4. Test shares the producer's mistake → manual Hemera decomposition plus exact wire.
5. Build silently selects registry/dirty inputs → manifest-path, immutable archives,
   locked identities and source=null path audit before compile.

Rollback is an ordinary revert of the narrow source/test commit; this unit writes
no stored data and performs no migration. Any independently discovered root,
mutable-store width or receive-channel policy defect becomes a separate task.
