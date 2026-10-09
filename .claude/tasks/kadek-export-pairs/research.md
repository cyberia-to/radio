# BAO exporter pair width

2026-10-09. Source-only preparation; no build, new panic reproduction or gate.
Serves: kadek foundation row 4 · radio proof provider · current Hemera pair wire.
Discovered from kadek's committed `16b53f7b85640be5a68a07787815a44ec6559377`,
`audit/2026-10-09-bao-source-repro/`, and the separate traversal task A.

## Inputs and rules

`git fetch origin main; git rev-parse origin/main` established radio
`764d732ac38fb9116c4cf525a6d1bb463d409a06`, merged PR #31. Owned worktree:
`/Users/master/cyber/radio-kadek-export-pairs`, branch `fix/kadek-export-pairs`.
No original dirty tree is a source/build input. Traversal's source fix and
[red gate receipt](../../../audit/2026-10-09-kadek-slice-traversal/README.md)
remain unchanged. That receipt records implementation `590e69ea` and actual
gates; it does not establish newly executed results for the present base.

`git ls-remote --symref origin HEAD` for Hemera returned main at
`23f3bbcff910ea6d504ceb505680a539260869da`. Its `rs/Cargo.toml` names
`cyber-hemera` 0.3.1 and supplies the required `serde` feature. Use this exact
source at the sibling path, not a registry substitution or dirty local checkout.
Radio's committed lock resolves path Hemera 0.3.1, `iroh-io` 0.6.2 and `irpc`
0.12.0. Their cached registry source APIs were read at those locked versions.

Read `~/cyber/cyberia/dev.md`, parent AGENTS and prior task rules. Radio's pinned
tree contains no AGENTS.md/CLAUDE.md. Research → fresh different-vendor plan
approval → implementation/red-first tests → fresh code review remains required.
Keep minimal scope, explicit-path staging, no history rewrite, new files ≤500
lines. Root owns reviews/commits/PR/merge; a red committed state requires `wip:`
and its first error. No version bump, release or upstream CI repair is included.

## Actual path and defect

Sources were read from the clean pinned worktree with `sed`/`rg`:

| Source at base | Finding |
|---|---|
| `iroh-blobs/src/provider.rs:596–607` | `send_blob` calls Store.export_bao then `write_with_progress`; its writer is generic SendStream. |
| `iroh-blobs/src/api/blobs.rs:1110–1187` | `write`, `write_with_progress` and `into_byte_stream` each allocate 128 bytes and copy each 32-byte Hash into a 64-byte half. Any Parent reaches a length-mismatched copy. Progress also credits 128 bytes. |
| `cyber-bao/src/io/mixed.rs:21–32` | EncodedItem carries Size, Parent<hemera::Hash>, Leaf, Error, Done. The actual current hash width is `hemera::OUTPUT_BYTES = 32`. |
| `iroh-blobs/src/store/readonly_mem.rs:269–305,366–382` | ReadonlyMemStore creates complete entries and serves them through the actual actor/Store API and validated mixed traversal. |
| `iroh-blobs/src/store/mem.rs:1007–1014` | CompleteStorage::create uses PreOrderMemOutboard::create, bypassing mutable import's stale pair-stride writes. |
| `cyber-bao/src/tree.rs:12–13,239–255` | `CHUNK_SIZE: usize = 4096`; from_chunk_log stores its log and `BlockSize::bytes()` returns `CHUNK_SIZE << self.0`. |
| `iroh-blobs/src/store/mod.rs:16–17` | Constant selects from_chunk_log(4). The preceding `2^4*1024 = 16KiB` comment is stale; executable geometry is 16 chunks / 65536 bytes, derived from tree.rs above. No comment repair is included. |
| `iroh-blobs/src/provider/events.rs:87–97,133–139,161` | Actual `ProgressError::Permission {}` variant; `From<AbortReason>` constructs it; `ClientResult = Result<(), ProgressError>`. This was read directly, not inferred from the exporter. |

The copy panic is a direct source inference until the planned tests execute the
real methods. Provider networking is unnecessary to reach the exact method it
uses; an in-memory SendStream suffices, with no UDP/QUIC endpoint or server.

## Feasible real-store and controlled fixtures

Create `ReadonlyMemStore::new([body.as_slice()])` inside a Tokio runtime; retain
the store while requesting each fresh `store.export_bao(root, ranges)` and await
`store.shutdown()` after the tests. `Hash::from(hemera::Hash)` is implemented.
Derive B=`IROH_BLOCK_SIZE.bytes()`, C=`B/CHUNK_SIZE`, body length `2*B`, query
`ChunkNum(C)..ChunkNum(2*C)`. Separate assertions pin CHUNK_SIZE=4096 and B=65536;
thus C=16, size=131072, one Parent, right Leaf offset/length B, Done.
Use a root constructed independently with Hemera leaf/parent operations, so the
Store lookup also checks agreement with its actual complete-outboard root.

Independent decomposition: body[i] = `(i*31+i/CHUNK_SIZE)%256`; each of 2*C leaf CVs
uses its absolute chunk counter and root=false. Reduce each group of 16 with
four explicit pairwise levels, all root=false. Let those CVs be L and R;
root = parent_cv(L,R,true). Proof is `LE64(2*B) || L32 || R32 || body[B..]`,
length `8+2*OUTPUT_BYTES+B` (65608), overhead72. Build it without radio encoder/outboard/extractor.
Decode the actual bytes against that root with merged decode_slice at log4:
exactly one returned block `(65536, body[65536..])`. This shape avoids the known
grouped-single-root discrepancy. Plain file Particle equivalence is not asserted.

Private child tests can call ExportBaoProgress::new and supply a bounded local
`irpc::channel::mpsc::channel` of scripted items. A literal pair with left bytes
0..31 and right bytes 32..63 independently exposes width/order/zero-padding
mistakes without a cryptographic oracle. The stream is explicitly closed after
terminal Done or Error; tests do not redefine stream's existing Done/error policy.

`iroh-io` 0.6.2's AsyncStreamWriter has write/write_bytes/sync, with a Vec<u8>
implementation. A private deterministic sink can additionally implement
`util::SendStream` (send_bytes/send/sync/reset/stopped/id), capturing writes and
injected errors. WriteProgress has transfer-start, overhead and fallible payload
callbacks. `ExportBaoError::{ExportBaoIo,ExportBaoInner,ClientError}` distinguishes
sink, encoded and progress failures. byte-stream errors use `api::Error::Io`.
Both writer traits allow partial writes before error; no rollback is promised.
The missing-entry path (`readonly_mem.rs:277–287`) sends EncodeError::Io with
UnexpectedEof / "export task ended unexpectedly" before Size. Writers wrap it
as ExportBaoError::ExportBaoInner; into_byte_stream maps it to api::Error::Io
(`api.rs:198–204`), preserving kind/detail. The parent-free control is exactly
CHUNK_SIZE bytes, so its independent root is chunk_cv(data,0,true).

## Scope exclusions and known reds

Mutable import `store/mem.rs:648–654`, partial storage/util checksum widths and
print_outboard retain separate stale-width issues. Grouped ROOT policy changes
would alter affected stored identities and need an explicit compatibility unit.
No global 64/128 replacement, storage migration, root reinterpretation, bounded
verification, receive-channel policy change or kadek dependency bump belongs here.

The existing receipt records cyber-bao Clippy red (first mixed.rs:115
clone_on_copy, 16 remaining diagnostics), full-workspace bench `radio` import
errors, gossip test Result API mismatch and local/registry Endpoint/PublicKey
mismatches. Make/nextest/deny were unavailable; formatting drift is recorded.
Archive vergen warnings were retained. Remote PR31 CI could not load missing
sibling Hemera; codespell had unrelated baseline findings. These are historical
executed results with pinned diagnostics, not fresh measurements of task B.
No baseline is assumed green and no unrelated repair is authorized.

## Dependency closure and ring

Complete isolated builds must archive radio at this pin (all internal crates,
vendored quinn/nettools, excluding tracked nettools/target) and exact Hemera into
sibling directories. Keep radio manifests/lock/lints unchanged. Metadata must
show every source=null manifest beneath the fresh root; fetch missing registry/
git dependencies only at the committed lock's identities. Prior receipt proves
this isolation approach was feasible, not that task B's test target passes.

The lock has both local and registry `iroh-blobs` 0.98.0: bare `-p iroh-blobs`
can select ambiguously. Use `--manifest-path iroh-blobs/Cargo.toml` for this crate.
Local reverse dependents are `radio-cli` and `radio-integration-tests` (their
manifests use paths); iroh-docs/willow depend on the separate registry package.
`v0.1.0` = `f2b1298daa9f635c821d53996c4d1dc4f1042b3d` contains the exact same
iroh-blobs tree as this base: `dabd7c13cdf5b6184a6ae60a20825c96ddafab50`.
That tag is the semver source baseline, with its own exact-source dependency closure.
Tool identity checked without running a gate: `/Users/master/.cargo/bin/cargo-semver-checks`,
`cargo semver-checks --version` → 0.51.0. `check-release --help` defines baseline-root
as the directory containing baseline crate source: use `<tag>/radio/iroh-blobs`,
then retain verbose output proving local package name/version/path and tag source.
Executable SHA256: `a4fcf9eae2dd1ee88f91dc71f1236b49faa7d90165d9c326dbf2f1fb7dd41c18`.

Soft3 origin `94af9de717658b3e912bcfccc85409fd29b23a10` assigns radio to layer 7,
part_of soft3, in release/components.toml. Its crate/conformance manifests have
no direct local radio/iroh-blobs dependency; this limits the named Cargo search,
not the ring obligation. Its phase1 radio pin remains `db1d62e2...`, already
behind this merged origin: drift is retained red and never fixed by this patch.
Ring 1 needs parent-owned rung/spec/drift assessment; local exporter checks alone
cannot claim it green. All task B build/gate status is presently unexecuted.
