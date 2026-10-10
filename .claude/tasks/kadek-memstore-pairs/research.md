# In-memory BAO parent-pair storage

Status: research / proposed PLAN, 2026-10-10; no implementation or new gate run.
Serves: Kadek phase-1 foundation row 4, authenticated-range transport prerequisite;
radio's existing Hemera BAO import/storage contract. Discovered from PR32/PR33.

## Pinned inputs and authority

`git ls-remote origin refs/heads/main` returned radio
`0d11468503c052aa5dcefb0dabc4602bd8efdc60`; fetched main and created owned
`/Users/master/cyber/radio-kadek-memstore-pairs`, branch `fix/kadek-memstore-pairs`,
at that exact pushed merge. Original working trees remain untouched.
Hemera stays `23f3bbcff910ea6d504ceb505680a539260869da`, path package 0.3.1.
Committed Cargo.lock SHA256: `295b21c8804e3885a195511ffca6fcf368e7c762c5b411374aecf20ba4d14052`.
Read `~/cyber/cyberia/dev.md`, `~/cyber/AGENTS.md`, and new `roadmap/soft3-radio.md`.
Radio has no tracked AGENTS.md/CLAUDE.md (Git tree search); named gates are in
Makefile.toml, .github/workflows/{ci.yml,tests.yaml,docs.yaml}, .config/nextest.toml.
The draft roadmap proposes retiring stores later and deriving digest width from
Hemera. This task repairs current canonical bytes; it creates no new storage
architecture and does not implement the draft trimming roadmap.

Primary width: Hemera `rs/src/params.rs:90` OUTPUT_BYTES=32;
`sponge.rs::Hash` holds `[u8;OUTPUT_BYTES]`. BAO `tree.rs:16,320–326` derives a
parent pair as two such hashes; `pre_order_offset:355` returns a parent ordinal.
Hemera `specs/tree.md:74–97` and `rs/src/tree.rs` define fixed-chunk left-balanced
ROOT finalization; merged PR33 implements it. Plain particle and BAO root remain
different domains; width correctness creates no authenticated association.

## Observed sources and reachable defect

At the pin, mem.rs:620–678 `import_bao` copies each 32-byte hash into a 64-byte
half of a 128-byte buffer, then writes parent ordinal*128. Its first Parent
therefore panics by Rust's copy length contract. This is source evidence; the
new exact-parent failure-first execution is still planned. OutboardReader:884–897
already consumes ordinal*64, halves32; replacing its literals is consolidation,
not defect repair. `print_outboard:1026` repeats128/64: slice conversion compiles
but panics when called. Repair changes its accepted lengths to multiples of64
(64/128 valid,96 invalid); retain #[allow(dead_code)] for non-test builds.
Simply fixing the halves leaves the wrong second-parent stride.

Public path: `api/blobs.rs:436–488` consumes LE64 size, uses ResponseDecoder
(io/fsm.rs) to verify each Parent/Leaf, sends verified items, closes tx and joins
the worker response. Lower-level `import_bao` explicitly trusts verified ordered
items. MemStore's worker updates Partial bitfields on verified leaves and becomes
Complete only on full coverage; `Bitfield::validated_size` requires the final
chunk. Actor:492–535 catches worker panic, logs and continues, but skips draining
idle waiters in that branch. New witnesses use bounded request futures, no wait_idle.

A second copy of the same serializer is active: `store/util/partial_mem_storage.rs`
write_batch:30–53 uses checked ordinal*128 and the same128/64 copy. It is called
by FsStore `fs/bao_file.rs:426`, not by MemStore's import loop. Both write the same
SparseMemFile canonical parent stream. SparseMemFile records gaps and rejects
conversion to Vec when gaps remain; a stale128 stride can therefore also prevent
MemStore completion. These two writers justify one concrete private pair helper.
This new store-private pub(super) helper deliberately duplicates the correct
private api/blobs.rs:1013 helper across the module boundary; the exporter remains
untouched. `&parent.pair` works at both writers; Hemera is a direct dependency.

FsStore trace: fs.rs:1122–1153 batches verified items, flushing before a Parent
after a Leaf and at EOF. `HashContext::write_batch:316` delegates to
`BaoFileStorage::write_batch` in bao_file.rs:413. Under the explicit inline data
threshold, NonExisting→PartialMem uses the second faulty writer; complete batches
then become Complete through into_complete:345. Incomplete batches immediately
persist to Partial files:434, even under that threshold. A batch over the threshold
switches to files before writing:440. Existing file writer:242 writes64/32 correctly;
reader:559 exposes raw bytes to PreOrderOutboard's64-byte reader. Leave both intact.

One full three-group proof yields Parent(node3), Parent(node1), Leaf(A), Leaf(B),
Leaf(C): one final complete batch. `max_data_inlined=196608` and
`max_outboard_inlined=128` force the repaired PartialMem writer and inlined completion.
Both is_inlined predicates use <= and pass at equality, with no spare bytes.
FsStore into_complete uses slice to_vec through SparseMemFile::Deref and keeps
gap zeros; MemStore TryFrom rejects gaps. A hypothetical64-byte pair write with
stale128-byte stride produces192 bytes, not128; byte-exact full/middle proofs
after reopen detect this. The untouched broken writer panics before such output.
Complete shutdown/reopen uses metadata Inline entries, avoiding the separate
partial bitfield checksum writer. This supports a decisive public FsStore test.
It does not establish FsStore partial/resume safety: fs.rs:989 persist calls
PartialFileStorage::sync_all:144, reaching store/util.rs:216's separate64-byte
plain-checksum prefix defect. No checkpoint/recovery format is changed here.

## Oracles and public error surfaces

PR32 immutable fixture: audit/2026-10-09-kadek-export-pairs/right-proof.bin,
65608 bytes, SHA256 `108022aa95ee61a1058d6d4bb53979a95bc46de114b036fcc6620fbd65648a51`;
root `9ccd2809b2bcca875ee39f2c034c80969c176a5510a66d638b2c88c3cd7c7f0f`.
Its source generator is complete in api/blobs/export_pairs/support.rs:
D[i]=(31*i+i/4096)%256;32 leaves with absolute counters, explicit four-level
16-leaf nonroot groups, then ROOT parent. Wire LE64(131072)||L32||R32||D[65536..].
Two groups exercise ordinal0 only. Three groups196608 are mandatory: derive
A/B/C identically from48 leaves; AB=parent_cv(A,B,false), root=parent_cv(AB,C,true).
Full wire is LE64(size)||AB||C||A||B||D; two parent ordinals0/1 occupy offsets0/64.
This algorithm is planned; new root/proof SHA values have not been measured.

Two-group corrupted pair at wire offset8 fails at TreeNode(1), corrupted right
leaf after offset72 at ChunkNum(16). io/error.rs converts both to
io::ErrorKind::InvalidData with respectively `parent hash mismatch at node 1`
and `leaf hash mismatch at chunk 16`. api.rs wraps that as
RequestError::Inner{source:Error::Io(..)}. Fresh entry remains Partial{size:None};
verified parents may survive leaf rejection. No whole-import rollback is promised.
On the broken parent, worker panic may mask the leaf error with a channel error;
record the observed failure without guessing its platform-dependent text.

## Scope, verification history and reproducible reads

Production candidate: mem.rs writer/reader/print; util.rs one private width/helper;
partial_mem_storage.rs writer. Public API, roots, wire, correct disk writer,
manifests/locks and persisted checksum format stay unchanged. `wc -l` at the pin:
mem.rs1128, util.rs433, partial_mem_storage.rs54; narrow legacy mem.rs edits only,
all new source/test files≤500. Root explicitly accepted this research scope expansion.

Commands: `git show <pin>:<path>`; `rg -n 'import_bao|write_batch|PartialMemStorage|128|64'`
over named files; reads of complete mem.rs, api request/error paths, fs import,
write/read/persist transitions, tree/FSM/error and Bitfield sources;
`shasum -a 256` on the golden and lock. New source-only pack indexes complete
review inputs and exact Git/byte identities; no build uses these dirty task docs.

Prior executed evidence belongs to audit/2026-10-09-kadek-export-pairs/README.md
and audit/2026-10-10-bao-root-policy/{README,gates,remote-ci}.md. ROOT's actual
installed tools supersede PR32's older unavailable-tool entries: nextest0.9.80,
make0.37.24, deny0.18.9, semver0.51.0; ordinary Rust1.95.0, actual MSRV1.89.0,
CI nightly2025-10-09. Receipts/provenance are archived with ROOT; no current-unit
gate is inferred from them. Broad lint/compile/format/deny failures remain open;
prior unfiltered native lib had27 failures and3 pending before manual termination.
Existing nextest config already terminates slow tests after3×10s; use it for a
new bounded broad library diagnostic instead of repeating an unbounded hang.

Source-only closure: local-path iroh-blobs consumers radio-cli and integration;
registry iroh-blobs under docs/willow is a different package. Actual isolated
metadata must confirm package IDs before gates. Component map remains explicitly
pinned soft3 `94af9de717658b3e912bcfccc85409fd29b23a10`, radio part_of=soft3;
this is prior inspected committed evidence, not a fresh soft3-head claim.
Separate obligations: Hash::EMPTY, checkpoint checksum/recovery, actor lifecycle,
bounded proof work/allocation and particle/root/length authority. For that later
proof plan, hash.rs::hash_from_bytes accepts arbitrary32 bytes while pinned
Hemera encoding.rs::bytes_to_cv reduces limbs through Goldilocks::new; canonical
encoding policy needs evidence. No malleability/forgery result is claimed here.

PLAN v1 and its complete review/inputs are preserved in
/tmp/kadek-memstore-pairs-plan-v1. V2 responds without treating the reviewer's
self-corrected headings as new defects. Pack byte/Git checks are coordinator
execution evidence, not no-tools reviewer verification; the separate response
records commands and corrects the reviewer's48-section count.
