# Radio storage extraction inventory

Baseline: Radio `8b9e22ac3234bca289a71bdafb34c61edcd3201f`, inspected on
2026-09-24 before the CLI cutover. This records the starting surface; subsequent
commits must update the parity evidence before claiming extraction complete.

## Actual consumers

| Surface | Dependency and ownership | Cutover obligation |
|---|---|---|
| `radio-cli` | Local `iroh-blobs`; `src/main.rs` creates a fresh `MemStore` in node start and every blob command | Preserve import, serve, retrieve/export, enumeration and gossip; connect each invocation to the same host-owned BBG store |
| `iroh-blobs` | Workspace library; `store/fs.rs` creates `blobs.db`, data/outboard files and its own runtime/GC; `store/mem.rs` owns transient content | Replace storage, progress, tags and retention with BBG capabilities; preserve transfer behavior through the new protocol |
| `iroh-docs` | Workspace library; registry `iroh-blobs 0.98` and registry `iroh-gossip 0.96`, alongside local Radio | Move metadata publication/history to Cybergraph/FS, reconciliation to Foculus, bytes to BBG; retain scoped sharing and sync behavior |
| `iroh-willow` | Workspace library; registry `iroh-blobs 0.98`; its own redb metadata store and external `willow-store` | Preserve capability-scoped areas, subscriptions and reconciliation through owner interfaces before removing its persistent implementation |
| `tests/integration` | Local blobs, docs and gossip | Port blob transfer, document sync and full-pipeline scenarios; baseline currently fails to compile |
| `iroh-ffi`, `iroh-ffi/iroh-js` | Separate nested workspace, absent from the main workspace; registry blobs/docs/iroh `0.35` | Inventory as dormant bindings, not a consumer of the local replacement; their constructors still create `docs.redb` and a `blobs/` store |

The main Radio transport library (`iroh/src`), base types and gossip do not
depend on the blob/docs stores. Transport session/address caches and simulation
output are separate from durable file ownership.

Sibling source inspection found no direct blob/docs store consumer:

| Product surface | Observed wiring |
|---|---|
| Cyber | `cyber/Cargo.toml` depends on Soft3; the default Soft3 node has no Radio file-transfer assembly |
| Cyb default workspace | `cyb/Cargo.toml` selects `core`, `shell`, `cli`; excludes `crates/cyb` |
| Cyb optional runtime | `cyb/crates/cyb/src/wire.rs` uses Radio Endpoint/QUIC with its own signal frames; no blob/docs API. Soft3 includes this only through feature `stack` |
| Foculus | Feature `net` uses registry `iroh 0.96`, not local `cyber-radio`; `src/node.rs` and `src/radio_settle.rs` transport graph/settlement messages |

Sibling HEADs at inspection: Cyber `80c7bf3332a0ea4816113962974088893be48cb3`,
Cyb `46a05d2f5dac6cf31ef14e937e8bae7b57f77b87`, Soft3
`9784d92eb507207f96faa886fcc44886707e0db2`, Foculus
`9e32aa688e0f03ffa8fd9a3c099bc7e50cc8c744`. Cyber and Cyb owner trees had
unrelated edits; inspected manifests/runtime files above matched their HEADs.
No owner tree was changed. This is source wiring evidence, not a release
dependency qualification.

## Behavior that must survive

| Area | Existing surface | Required acceptance |
|---|---|---|
| CLI | `radio-cli/src/main.rs`: hash sum/verify, BAO encode/decode/outboard, node id/start, blob add/get/list, gossip open/join | Cross-invocation durable add/list/serve; interrupted get resumes after restart; retrieved output verifies before publication; gossip still works |
| Content | `iroh-blobs/src/api/blobs.rs`: import bytes/path/stream, read, range export, status, observation, enumeration, import/export progress | Bounded BBG I/O and explicit staging/sealed state; existing large-file use cases remain possible |
| Names and retention | `iroh-blobs/src/api/tags.rs`: named and temporary tags, rename, prefix/range listing and deletion; `store/gc.rs` | Atomic binding updates, independent aliases, retained historical content, safe release/read leases/GC |
| Transfer | `iroh-blobs/src/api/remote.rs`, `api/downloader.rs`: missing coverage, pull/push, multiple providers, collections, progress | BBG owns resume state; Foculus owns scheduling; Radio transports bounded requests; verified integrity guarantees survive |
| Replicas | `iroh-docs/src/api.rs`: create/open/drop/import/share, set bytes/reference, exact/prefix query, delete prefix, sync/leave/events, download policy | Authorized namespace metadata and content closure synchronize together, including reconnect and competing writes |
| Custody | Docs stores author/namespace secrets; Willow stores secrets and capabilities | Persistent secrets use Vault custody; transport receives authorized operations rather than unscoped secret tables |

The old CLI's `blob add` loses its MemStore when it exits, `blob list` opens an
empty MemStore, and `node start` opens another empty MemStore. These are baseline
defects, not behavior to preserve. Old `blob get` takes only particle and peer;
the replacement needs descriptor discovery or an explicit descriptor ticket.

`hash sum` uses the flat Hemera sponge, while `hash verify` constructs a BAO
outboard root. A cutover must identify this mismatch explicitly rather than
reinterpret old roots as canonical particles.

## Document history and rename

Docs currently stores one record per `(namespace, author, key)` in
`iroh-docs/src/store/fs/tables.rs`. `ranger.rs::Store::put` rejects dominated
records and removes older entries covered by a newer prefix. `api.rs::del`
inserts a prefix deletion marker. There is no retained revision history and no
atomic document rename operation in this API. Blob tag rename exists separately.

The successor should publish immutable attributed revisions and conditional
name bindings through Cybergraph/FS. Rename changes a binding while preserving
the referenced particle; edit creates a new content revision. History retention
and conflict representation must survive synchronization. An importer can
preserve the old store's surviving records, signatures and deletion markers;
it cannot recover revisions already pruned by the old store.

## Physical removal boundary

Deleting only `iroh-docs/src/store/fs.rs` is not a coherent change:
`store.rs` publicly re-exports that concrete `Store`, and `actor.rs`, `sync.rs`,
`engine.rs` and `protocol.rs` depend on it. `protocol.rs::Builder::spawn`
also creates `docs.redb` and `default-author`; `engine.rs` owns content-download
coordination and a GC protection task. Relocating these constructors to another
directory would retain the duplicated ownership.

After the CLI cutover, the smallest coherent local blob removal unit is
`iroh-blobs` plus its integration harness and examples: the remaining direct
local dependent is `tests/integration`. First move the useful transfer and
replica scenarios to the owner integration tests and provide an explicit legacy
import path. Then remove the package, its workspace entry and orphaned
references together. Registry blobs still arrive through docs/Willow, so this
unit alone does not finish extraction.

The next metadata removal unit is the docs engine/API/store package after its
scoped sharing, query, sync and content-publication replacement qualifies.
Willow's persistent implementation is a separate unit: its `Storage` trait
already separates entries, secrets and capabilities, but `payloads()` is still
hardwired to registry `iroh_blobs::api::Store`. Replace that boundary too.
Upstream FFI bindings require an explicit adaptation or retirement decision;
removing their main-workspace references would have no effect because there
are none.

`iroh-car` and `particle` have no blob/docs dependencies or main-workspace
consumers beyond their own tests/entry points. CAR is an archive codec;
`particle` is a BAO/Hemera utility. Removing them is a format/tooling decision,
not removal of a persistent store. They compile at the baseline below.

## Migration and completion checklist

- [ ] Import old data read-only in bounded pages; verify old identity and new
  canonical identity separately and retain their explicit mapping/provenance.
- [ ] Preserve named references, retained content, document records and
  deletion markers. Stage incomplete files until verification completes.
- [ ] Make import restartable and idempotent; compare recovered content and
  metadata before any legacy source deletion.
- [ ] Qualify rename/edit conflicts, historical reads, restore and independent
  aliases over the shared owner, including crash boundaries.
- [ ] Replace provider selection, download policy and durable transfer jobs
  through Foculus; remove Radio-owned protection callbacks and GC.
- [ ] Assemble the actual Cyber/Cyb product path and check its dependency
  closure. New library tests alone do not establish product cutover.
- [ ] Remove local and transitive storage constructors, obsolete bindings and
  competing identity paths only after their supported behavior has a successor.

## Reproduction

Source inventory used `rg -n 'iroh[-_]blobs|iroh[-_]docs' --glob Cargo.toml`
inside Radio and the same search across sibling manifests/source; constructor
inspection used `rg -n 'FsStore|MemStore|redb|BlobsProtocol'` over production
source directories. Paths in this report are relative to Radio unless qualified.

Both commands below ran from Radio at the baseline above, using an independent
target directory to avoid mixing the Radio and adapter build artifacts:

```sh
CARGO_TARGET_DIR=/tmp/cyber-content-storage-20260924/target-inventory cargo check -p particle -p iroh-car -p radio-integration-tests --tests --locked --offline
CARGO_TARGET_DIR=/tmp/cyber-content-storage-20260924/target-inventory cargo check -p particle -p iroh-car --tests --locked --offline
```

The combined check exited 101 in local `iroh-docs`: first error `E0053` at
`src/engine/live.rs:906`, where `find_providers` returns local Radio endpoint
identities but registry blobs expects registry Iroh identities. The compiler
reported nine errors, including `protocol.rs:106` passing a local Endpoint to
a registry downloader. The independent particle/CAR test-target check exited
0; its Cyber-BAO dependency emitted three existing unused `PAIR_SIZE` warnings
in `io/encode.rs:19`, `io/outboard.rs:15` and `io/slice.rs:18`.
These are compilation checks; test cases were not executed. No claim that the
legacy integration suite currently works follows from the source examples.
