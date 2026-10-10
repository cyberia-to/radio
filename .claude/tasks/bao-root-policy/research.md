# BAO canonical ROOT policy before bounded proof admission

Draft v3 research and plan candidate, 2026-10-10. Serves: Kadek phase 1,
foundation-closure row 4, runtime provenance and unchanged decoder state on
failed authentication. Source-only findings; no candidate implementation or gates.
Exact-parent gate preparation/receipts are separate and do not validate a candidate.

## Inputs and reproducibility

- Kadek `8d309df132ece1516c3b36b52f594ad7bd0d8889`.
- Radio `258724bd8ab797ad8d2ef43c6a4a2e07f1fc9e24` (PR31 + PR32 merged).
- Hemera `23f3bbcff910ea6d504ceb505680a539260869da`; published
  `cyber-hemera =0.3.1` is the same source revision. Historical published checksum:
  `ebcf7ffcd69170adde7e792826d7cececda962ea220b9834c6535bbc71e5a6df`.
  This is earlier registry provenance, absent from radio's path-source 0.3.1 lock
  record; isolated gates use the exact Git archive, never that registry substitute.
- Direct bytes of radio's committed Cargo.lock SHA-256:
  `295b21c8804e3885a195511ffca6fcf368e7c762c5b411374aecf20ba4d14052`.
  Obtained with `git show 258724bd:Cargo.lock | shasum -a 256`.
- All reads use `git show <pin>:<path>`, `git grep -n <pattern> <pin> -- <paths>`
  and `git ls-tree -r --name-only <pin>`. Original working trees are not inputs.
  Runtime/provenance sources, the two radio receipts and Hemera primary sources
  below were inspected. No fresh origin-head or release-readiness claim.

For future gates archive complete radio source and exact sibling Hemera into a
private root, preserving `radio/../hemera/rs`, using radio's unchanged lock and
separate baseline/candidate target directories. Exclude tracked `nettools/target`
from export, recording the exclusion; never restore/build the dirty original.
The lock pins bytes1.11.1, smallvec1.15.1, range-collections0.4.6,
iroh-io0.6.2, genawaiter0.99.1; willow-rs Git packages at
`12d29767cf3dedfaba7f03e14eaaf4c4cca5b438`, willow-store at
`b1c1bb90aa6c1b732be10c7071d10f0e3c6a195d`. A separate registry Hemera0.1.2
also exists in this lock: do not substitute it for the path Hemera0.3.1.
`audit/2026-10-09-kadek-export-pairs/source-inputs.json` records the existing
20-local-package closure and archive method; regenerate metadata for this pin.
No manifest adaptation or live sibling path is necessary for authoritative gates.

## What remains after the two repairs

PR31 fixed right-only filtered traversal; PR32 fixed exported parent pairs from
incorrect 64-byte component slices to actual 32+32 bytes. Neither changed ROOT
policy. `cyber-bao/tests/slice_traversal.rs:287` explicitly asserts the remaining
single-group discrepancy as a historical defect, not an acceptance requirement.

Hemera primary authority at the pin: `specs/tree.md:74–97` requires a left-balanced
binary tree, CHUNK|ROOT for a single leaf, PARENT|ROOT for the final merge of
multiple leaves, and non-ROOT internal nodes. `rs/src/tree.rs::fixed_chunk_root`
and public `chunk_cv`/`parent_cv` implement that fixed-4096-byte tree. CDC
`root_hash` uses a different chunking rule and is not a general BAO oracle.

Five reductions in the following inspected files discard ROOT on every internal merge:
`cyber-bao/src/io/mod.rs::hash_block`, `outboard.rs::hash_block`,
`decode.rs::hash_block_for_verify`, `slice.rs::hash_block_for_verify`, and
`sync.rs::hash_subtree`. An entire file with multiple chunks in one group thus
gets an internal CV as its advertised root. The same incorrect verifier policy
makes local encode/decode roundtrips pass. FSM and mixed paths call the public
`io::hash_block`; synchronous validated export also calls it; range validation
calls `sync::hash_subtree`.
For mixed traversal, the terminal item is either Done or Error. Source
`io/mixed.rs:67–72` returns sender success after Error without a trailing Done.
Under corrected ROOT policy, the planned canonical D8192 sequence is Size,
Leaf(offset0,D), Done; the old root gives Size, Error(LeafHashMismatch(ChunkNum(0)))
with no Parent/Leaf/Done. The current source's opposite root acceptance changes;
its terminal-event contract stays the same.

### Exact independent oracle and compatibility

Let D[i]=(i*31+i/4096)%256 and D have 8192 bytes. With
L=chunk_cv(D[0..4096],0,false), R=chunk_cv(D[4096..8192],1,false):

- Current log4 root = parent_cv(L,R,false) =
  `11890a7e7cf1e4de463a04bf53bfdf269d627983a221daaf9029a3ff43297389`.
- Canonical root = parent_cv(L,R,true) = log0 = fixed_chunk_root(D) =
  `2abf65dd26465a7352707d79d18ff3aab9ee5d97614a774619c79ed527e20190`.
- One-group proof bytes remain LE64(8192)||D, 8200 bytes; outboard remains empty.
  Root is supplied externally, so unchanged wire bytes do not imply compatibility.

These literal values were measured by the earlier pinned source probe and are
retained in current radio's regression. See Kadek
`audit/2026-10-09-bao-source-repro/{README.md,probe.rs,stdout.txt}`.
No new measurement is claimed. For representable group log g>0 the changed
file-size interval is 4096<N<=4096*2^g. Actual radio log4 means 4097..65536 bytes;
cyber-bao default log2 means 4097..16384. Empty/single-chunk, log0 and files with
multiple groups do not change under this final-merge-only correction.
The old root is literally an internal CV in a larger tree sharing the prefix
and absolute counters. The fix restores tree.md's documented ROOT-domain
separation; this source observation is narrower than a cryptographic audit.

`iroh-blobs/src/hash.rs:15–20,43–49` makes Hash::new equal the log4 outboard root.
`store/fs/import.rs:163–176,190–218` selects tiny Hash::new/PreOrderMemOutboard
versus stream import by Options::is_inlined_all. Non-tiny bytes, streams and files
reach compute_outboard at372ff, which overwrites the placeholder root by
init_outboard at399/410 and uses that root as ImportEntry.hash.
The actual module is inline in `iroh-blobs/src/util.rs:224–352`; there is no
`src/util/outboard_with_progress.rs`. Its hash_subtree at238–241 delegates to
public cyber_bao::io::hash_block; init_impl hashes leaves at303, merges parents
with the supplied is_root at287–291, and assigns outboard.root at309. These full
util.rs/import.rs reads establish delegation for those paths, not a repository-wide
completeness proof. `store/fs/options.rs:138–142` and the complete
`store/fs/meta.rs:947–949::raw_outboard_size` body (BaoTree(log4).outboard_size;
tree.rs:321ff returns0 for <=1 block) establish that the planned
8192-byte add_bytes fixture takes distinct paths at max_data_inlined32768/4096
(max_outboard_inlined16384); get_import_source writes data to a temp file in the
latter. Separate FsStore instances avoid dedup; planned key equality also checks
the independent literal and fixed_chunk_root. This is a source-derived test
design, not a completed import test.

Both memory-store implementations also derive native keys. Full `store/mem.rs`
was read: import_bytes at704–732 calls PreOrderMemOutboard::create at714;
Actor::finish_import at450ff indexes by outboard.root at455. import_byte_stream
and native import_path delegate to import_bytes. Independently,
`store/readonly_mem.rs:367–378` calls CompleteStorage::create at371;
`mem.rs:1008–1014` implements it with PreOrderMemOutboard::create and returns
that root. PreOrderMemOutboard::create in cyber-bao io/pre_order.rs:98–109
delegates to io/outboard.rs; no additional reduction occurs in either inspected
memory path. CompleteStorage::new retains already supplied bytes/outboard; the
partial/import-BAO paths retain caller-supplied identities and use verification,
not a new whole-body key derivation. The plan tests both actual memory stores
with D8192, including list().hashes(), independently expected key and exact
LE64(8192)||D export, because old 4096/131072-byte tests miss the affected interval.

`protocol.rs::GetRequest.hash`,
`ticket.rs::BlobTicket.hash`, provider lookups and hash-sequence references carry
that key. For affected lengths corrected imports use a different key; old tickets
request the old key, old stored records remain indexed by it, and a corrected
verifier rejects the old root for the same payload. Old peers reject the new root.
Existing full bytes permit explicit rehash/reindex/reimport and new tickets;
partial records alone cannot establish the new file identity. References to
changed keys must also be rebuilt. No count of deployed affected records is known.
No automatic alias, dual-acceptance mode, in-place data migration, protocol-version
choice, version bump or release is included. Reverting source restores the old
policy but does not migrate records newly written with canonical keys.

### Bounded producer and hash-call inventory

At the radio pin, `git ls-tree -r --name-only` identifies503 tracked Rust files
after excluding nettools/target, audit and .claude. Reproducible source-only scans:
`/tmp/kadek-bao-root-policy-v3-scan.rb` and `-scan.json` retain exact argv, every
scanned path, the89 matching-file SHA256s and raw grep outputs. The index SHA256
is `f33b503ad7199845b0dfe5d5e17f39248ee7324524c5419202d7ced01e449133`.
The broad root-call query matches34 files; backend/alias query76; the additional
root-assignment query is restricted to cyber-bao/src and iroh-blobs/src (45 files).
These token searches locate calls/aliases; they do not prove absence of an
arbitrarily named algorithm. Exact patterns and exclusions remain in the script.

The inspected production derivation chains are the five io reductions and their
encode/pre_order/FSM/mixed callers, Hash::new, FsStore tiny/non-tiny import,
MemStore import/finish_import and ReadonlyMemStore/CompleteStorage::create above.
Full `format/collection.rs:124–130` delegates serialized metadata to Hash::new;
its store method delegates to add_bytes. Full `store/util.rs` has only debug
Hash::new at326/336 and test-only PreOrderMemOutboard::create at425; its plain
Hemera metadata checksums/symbols are different uses. Both files enter the pack.
Other matched root assignments in api/proto/remote, provider, get, store/fs.rs
and fs/bao_file.rs retain request/entry keys rather than derive a new body key;
the latter's load at159–189 constructs a supplied-root outboard and valid_ranges.
Their matching lines were inspected; full-file review is claimed only for files
explicitly included/read above, not every search match.

Particle's four BAO commands and radio-cli/src/main.rs:184–236 use log0;
their hash commands use plain Hemera. Collections and blob commands use the
traced local store APIs. Other direct Hash::new matches are local tests, or
iroh-docs/willow/FFI callers of registry iroh-blobs (their committed manifests
pin versions0.98/0.35, not the local path). Gossip/relay matches are plain/keyed
Hemera uses. No additional production reduction was found within these named
reads and matched-call inventory; this is the boundary of the scope claim.

## Separate dependency, not this task

Canonical BAO root remains different from Kadek's plain Hemera particle.
Primary `rs/tests/vectors.rs` at the Hemera pin gives plain hello
`e1b19b8235443e9fac8f1d6a1203de66e9a58c53e36cbbc1f71a031c3d13ce77`
and tree hello `626fa46e4e7bd5c87d630eef8333931a0b9198587400a0191eae7821692880d7`.
Plain empty is `a67a71b221e6bdd6442a20432bf5d74c885d89e5dfbeec3ec4e334cb806d563c`,
tree empty `ea57b2e6b1ec7d2de11b15cb6d7060dd61d247fe0fbf5f7d3fb97a7be9328552`.
Published vectors/hemera.json tree.empty/tree.hello apply to fixed_chunk_root:
below the CDC minimum they are one leaf. Its tree.4k_zeros is a CDC value and
must not be used for the fixed tree (uniform 4096 bytes splits at2048).
`particle/src/main.rs::cmd_hash` uses plain hash; encode/decode/outboard/verify
use BlockSize::ZERO, so no particle-produced identity moves in this repair.
Hemera also documents CDC `root_hash` as semantic identity: these existing naming
conventions do not authorize replacing Kadek's implemented particle contract.
ROOT correction never proves equivalence of these separate hash domains.

The smallest truthful future mapping is sealed `(particle,root,length)` derived
from the same immutable Kadek VerifiedBody, retained after its body is released.
Cold partial-only input lacks that association: receiving a pair does not
authenticate it. External association needs a separately chosen authority/format;
changing the particle convention instead affects existing references and canon.
No such protocol, identity change or unchecked authority constructor is proposed.

Current sync and FSM verifiers eagerly allocate traversal Vecs, use spillable
SmallVec stacks and hash complete groups in one call. Default features=[] still
uses std. A later canonical cyber-bao bounded engine requires lazy checked
geometry, fixed frontiers, resumable bounded hashing and core-only dependency
separation. Transport bounds framing/fetch/retained input; Kadek bounds pooled
verification/output and work before codec admission. Neither must trust a
transport-supplied particle/root assertion. These are separate units; root repair
is a prerequisite and does not close Kadek foundation row 4.

Existing Hash::EMPTY is zero32, unlike the published empty tree root; its
hash.rs test only checks determinism. api/blobs.rs::observe_with_opts and
import_bao_reader retain this sentinel, including zero-size rejection of the real
root. That identity defect is separate. Existing trailing-data/declared-size
policy, dual DecodeError types, valid_ranges granularity, unchecked geometry and
sync malformed-geometry unwraps also stay out of scope.

## Review inputs and limits

Fresh review must include the five current reduction bodies, HashBackend,
BaoTree/group geometry, Hemera fixed tree/flags, prior literal probes, native
Hash/import/ticket/request consumers, and existing slice/export tests.
Prior PLAN/CODE reviews in radio's two 2026-10-09 audit directories approved
traversal and parent-width scopes only; they deliberately excluded root changes.
They are historical evidence, not approval of this plan. Source inspection and
archived measured vectors establish the defect; future candidate results belong
in a new audit receipt, not this research artifact. No candidate production edit,
build, gate, deployment inventory or release was performed here. The v1 source-only
PLAN review requested corrected mixed events and complete import-path evidence;
v2 supplied them. V2 additionally requested memory-store derivation evidence;
v3 supplies full mem.rs, the call trace, affected-length tests and bounded inventory.
V1/v2 documents, packs, indexes, briefs and verdicts are preserved separately
under /tmp/kadek-bao-root-policy-v1 and -v2; no prior verdict enters the v3 pack.

## Existing local inputs for the fresh source-only PLAN review

Every radio path below exists and matches its Git blob at 258724bd; every Hemera
path exists and matches its Git blob at 23f3b (full revisions above). Checks were
`test -f <absolute-path>`, `git hash-object <absolute-path>`, compared with
`git -C <owning-repo> rev-parse <revision>:<relative-path>`; every selected file
matched. This verifies source identity, not compilation.
Hemera paths locate the preserved exact-source PR32 archive; Git revision/blob,
not the temporary path, establishes identity. Include complete Rust files except
the labelled meta.rs imports/function excerpt (lines1–48 and947–949, full source
SHA and exact ranges in index). The omitted binary fixture is pinned by generator,
length/root/SHA; prior review transcripts and old plans are omitted. Read only
the selected prior receipts, not raw audit directories. Fresh task research/plan
are the two reviewed candidate documents. Cargo.lock stays complete at its source
pin; the text bundle labels an excerpt selecting full package records with no
registry/Git source (local packages), plus named hash/backend/I/O dependencies.
Features come from full manifests, not lock records. The machine-readable index
records exact selection names, source SHA, excerpt SHA and omission reasons.
Read-only store/fs.rs is kept outside the pack (83038 bytes, setup/actor/GC,
unmodified); SHA256 at the radio pin is
`572f234c8adf8367b3493c77a5e95e4346972cdfbaf307234fd89b761ae37996`.
The inspected methods are Actor::handle_command (ImportBytes/ImportByteStream/
ImportPath dispatch,532–543), handle_fs_command (FinishImport,579–599),
Actor::new (633–675; directories/options/actor setup), FsStore::load/load_with_opts
(1388–1429) and FsStore Deref/new (1452–1475). These establish the planned public
test setup; complete import.rs/util.rs/options.rs/api.rs provide the hashing path.

```text
/Users/master/cyber/radio-kadek-root-policy/Cargo.toml
/Users/master/cyber/radio-kadek-root-policy/Cargo.lock
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/Cargo.toml
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/lib.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/hash.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/tree.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/io/mod.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/io/outboard.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/io/decode.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/io/slice.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/io/sync.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/io/encode.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/io/fsm.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/io/mixed.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/io/pre_order.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/io/content.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/io/error.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/src/io/traits.rs
/Users/master/cyber/radio-kadek-root-policy/cyber-bao/tests/slice_traversal.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/Cargo.toml
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/hash.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/ticket.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/protocol.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/get.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/store/mod.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/store/fs/import.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/store/fs/options.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/store/readonly_mem.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/store/mem.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/store/util.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/store/fs/meta.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/format/collection.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/util.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/api.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/api/blobs.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/api/blobs/export_pairs.rs
/Users/master/cyber/radio-kadek-root-policy/iroh-blobs/src/api/blobs/export_pairs/support.rs
/Users/master/cyber/radio-kadek-root-policy/particle/Cargo.toml
/Users/master/cyber/radio-kadek-root-policy/particle/src/main.rs
/Users/master/cyber/radio-kadek-root-policy/audit/2026-10-09-kadek-slice-traversal/README.md
/Users/master/cyber/radio-kadek-root-policy/audit/2026-10-09-kadek-slice-traversal/probe.rs
/Users/master/cyber/radio-kadek-root-policy/audit/2026-10-09-kadek-slice-traversal/expected-probe.stdout
/Users/master/cyber/radio-kadek-root-policy/audit/2026-10-09-kadek-slice-traversal/FIXTURE-SHA256SUMS
/Users/master/cyber/radio-kadek-root-policy/audit/2026-10-09-kadek-export-pairs/README.md
/Users/master/cyber/radio-kadek-root-policy/audit/2026-10-09-kadek-export-pairs/right-root.txt
/Users/master/cyber/radio-kadek-root-policy/radio-cli/Cargo.toml
/Users/master/cyber/radio-kadek-root-policy/tests/integration/Cargo.toml
/Users/master/cyber/radio-kadek-root-policy/iroh-docs/Cargo.toml
/Users/master/cyber/radio-kadek-root-policy/iroh-willow/Cargo.toml
/Users/master/cyber/radio-kadek-root-policy/Makefile.toml
/Users/master/cyber/radio-kadek-root-policy/.github/workflows/ci.yml
/Users/master/cyber/radio-kadek-root-policy/.github/workflows/tests.yaml
/tmp/radio-export-pairs.FbuGlp/candidate/hemera/rs/Cargo.toml
/tmp/radio-export-pairs.FbuGlp/candidate/hemera/rs/src/lib.rs
/tmp/radio-export-pairs.FbuGlp/candidate/hemera/rs/src/tree.rs
/tmp/radio-export-pairs.FbuGlp/candidate/hemera/rs/src/params.rs
/tmp/radio-export-pairs.FbuGlp/candidate/hemera/rs/src/sponge.rs
/tmp/radio-export-pairs.FbuGlp/candidate/hemera/rs/src/encoding.rs
/tmp/radio-export-pairs.FbuGlp/candidate/hemera/specs/tree.md
/tmp/radio-export-pairs.FbuGlp/candidate/hemera/specs/capacity.md
/tmp/radio-export-pairs.FbuGlp/candidate/hemera/rs/tests/vectors.rs
/tmp/radio-export-pairs.FbuGlp/candidate/hemera/vectors/hemera.json
```

### Gate staging and component closure (planned, not completed)

Committed soft3 origin/main object `94af9de717658b3e912bcfccc85409fd29b23a10`
has release/components.toml radio part_of=soft3 and kadek part_of=cyb. Source was
read with `git -C /Users/master/cyber/soft3 show 94af9de:release/components.toml`;
this is a pinned local remote-tracking object, not a fresh remote-head claim.
Radio's committed manifest search finds local cyber-bao consumers iroh-blobs,
particle, radio-cli and radio-integration-tests; local iroh-blobs consumers are
radio-cli/integration. iroh-docs/willow request registry iroh-blobs and must not be
mistaken for local-path reverse dependencies. Cargo metadata must confirm exact
package IDs/features in the isolated closure before running dependent gates.

Stage 1 runs focused root oracles plus repository checks in exact archived
baseline/candidate closures. Stage 2 records source-only reverse dependency
inventory from those manifests and pinned component map, then runs local consumer
checks and applicable named native workflow tasks; unexecuted rung/platform
checks remain explicitly unexecuted. A source-only review is not an executed
ring-1 gate. Full product/rung acceptance requires its actual owner-repository
closure and gate receipts; no release/temperature/readiness follows here.
The plan's per-crate iroh-blobs commands use --manifest-path because the lock also
contains the registry package with the same name/version. No alias/shim avoids
existing closure errors. Public hash_block keeps its block_bytes argument; only
the private helper is generic and preserves B::Hash behavior and Clone contract.
