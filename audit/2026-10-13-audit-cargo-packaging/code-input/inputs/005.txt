# Archived Cargo manifest discovery

Status: measured; packaging repair remains proposed. Serves Kadek foundation row 4
through Radio; discovered from the committed strict-proof consumer. Exact Radio
parent is `ce0fb312faa8770e80efe9afa864106ae6b51552` (PR40). This worktree is clean
at that parent before adding these task and research artifacts.

## Observed defect

A separate consumer pins `cyber-bao` to that Git revision, disables default
features, and uses a private Cargo home with Rust 1.95.0. Lock generation,
metadata, debug and release all emit:

```text
warning: skipping duplicate package `cyber-bao v0.1.0 (...#ce0fb312)`:
  /tmp/radio-bao-proof-parent-b933/cyber-bao/Cargo.toml
in favor of .../git/checkouts/radio-1a8d5f25084d9866/ce0fb31/cyber-bao/Cargo.toml
```

The exact full text/argv/times are retained in
`audit/2026-10-13-audit-cargo-packaging/records/consumer-ce0-*`.
The committed `audit/2026-10-12-bao-bounded-proof/nostd-parent/Cargo.toml`
contains that absolute path at line 7. This is a dependency-discovery packaging
defect: Cargo inspects a historical harness manifest when consuming the Git
repository. The observed warning depends on this machine's existing external
probe directory; no universal failure or forged-hash result is claimed.

The effective metadata still selects the pinned `cyber-bao` and Git Hemera
`d5f0a09539360934fb32db9b2e15a91995607db6`, with no features or registry
dependencies. Both profiles pass all eight independent reader controls. Their
source/manifest, literal, tool and resolution snapshots match before/after.
This verifies the selected source for these runs; it does not make acquisition
warning-free. Production Rust and normal manifests need no change.

## Exact inventory and replay implications

`git ls-files -z audit` filtered by the exact basename `Cargo.toml`, cross-checked
with `rg --files audit -g Cargo.toml`, identifies seven manifests (2,141 bytes):

| Capsule | Logical Cargo paths |
|---|---|
| `2026-10-09-kadek-slice-traversal` | `Cargo.toml` |
| `2026-10-12-bao-proof-research` | `probe/Cargo.toml`, `primary-probe/Cargo.toml` |
| `2026-10-12-bao-bounded-proof` | `fixture-probe/Cargo.toml`, `nostd/Cargo.toml`, `nostd-parent/Cargo.toml`, `seals/Cargo.toml` |

The seven exact bytes and Git identities are frozen in `inputs/renames.json`.
All other `Cargo.toml` files are source manifests, outside the rename scope.
Already compressed evidence archives and context text are not discoverable
manifests and need no repackaging.

Both 2026-10-12 capsules' `files.json` include their own verifier's original
hash. Rewriting those verifiers and recalculating the historical indices would
erase an original evidence identity. Keep the indices, receipts, reviews and
context packages byte-for-byte. Preserve each original verifier/reproducer under
an archive filename; a thin entry wrapper can reconstruct its historical logical
layout in a disposable directory and execute those exact original bytes.

The 2026-10-09 reproducer copies its own Cargo manifest into exported workspaces.
It therefore needs the same logical-layout staging. Its broad codec matrix need
not run again: the packaging check can invoke its unchanged `prepare-crate`
function and compare the exported manifest/lock/probe bytes. The separate bounded
proof `code-input/verify.nu` refers to unchanged evidence and requires no edit.
Historical capture helpers in `records/` are receipts, not new replay entrypoints.

Fresh baseline replays on ce0 pass: research has 89 files / 98 Git inputs / 9 raw
records; bounded-proof execution has 619 files / 2,777 original Git input records /
115 raw records. Exact commands and full output are in `research-before` and
`proof-before` records. These are evidence replays, not Cargo or codec reruns.

## Scope and limits

The cached registry at soft3 `18fd6b22ec45725aa776e37d377c5a75aeeaf553` places
Radio in soft3. Kadek is an actual direct Git consumer; its eventual adapter
reaches Cyb separately. This task cannot claim an isolated ring-0 product radius.
Its verification target is archive preservation plus clean Git dependency
discovery and the unchanged reader consumer. No Rust/API/specification/version
or release change is proposed. Previous broad red gates remain historical and
are neither rerun nor relabeled green by this packaging repair.

## PLAN v1 follow-up evidence

The fresh review exposed missing verification precision, not a different repair.
Outer snapshots now explicitly say `historical-ce0-reader-before-runs.json` and
`historical-ce0-reader-after-runs.json`; original bytes/timestamps and v1's frozen
copies are preserved. A future differential must reproduce the warning on ce0
through the same fresh local-Git mechanism as its candidate and keep the external
nostd-parent manifest unchanged throughout. That paired measurement is pending.

`records/original-prepare-v2.json` invokes a child `nu -c` with a literal quoted
source path and calls the private `prepare-crate` on `db1d62e2…` and `590e69ea…`.
It exits 0 without Cargo. The six exported manifest/lock/probe copies and complete
16/17-file cyber-bao exports match their original inputs, with only the function's
existing exact Hemera path-to-registry substitution. Full revision IDs, child
code, input hashes and comparisons are in `inputs/prepare-measurement.json` and
`inputs/v2-additional-source.json`. This demonstrates the invocation mechanism;
it does not yet exercise a packaging wrapper or rerun the surrounding matrix.
