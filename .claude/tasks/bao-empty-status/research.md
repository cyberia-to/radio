# Fs synthetic empty status — current-origin research

Stage: active. Serves Kadek phase 1 foundation row 4, authenticated transport.
Discovered from `bao-empty-root`; current-origin amendment supersedes its unmerged
five-file implementation. Owner: root, executor: radio_resume. No production
change has been applied in this worktree.

## Current inputs and historical boundary

`git ls-remote origin HEAD refs/heads/main` confirms Radio
`bc8b6331d3c76cbc011210e13f81e6ea351ef06f` and Hemera
`d5f0a09539360934fb32db9b2e15a91995607db6` on October 11. The new owned worktree is
`radio-kadek-empty-status`, branch `fix/bao-empty-status`. The old owned tree and
its audit remain unchanged historical evidence against Radio `344ac162` and
Hemera `23f3bbcf`; their old gates and CODE approval are not current evidence.

PR35 already installed the canonical EMPTY literal, its documentation and equality
test; repaired persisted checksum widths, protocol child geometry and examples;
rewired iroh-docs to local blobs/gossip; and enabled optimized dev Hemera. This
task must preserve all those bytes. Only the missing Fs logical-status guard
remains. Old failure counts, registry-only docs ownership and empty-key migration
claims cannot be restated as changes made by this amendment.

Current committed exports are under
`/tmp/radio-empty-status.20261011-60036-oi3wr7/{parent,candidate,witness}` with pinned
sibling Hemera. Only tracked `nettools/target` is excluded, with its inventory
retained. Archives preserve Git export semantics. Original worktrees are not build
inputs. Current Radio lock SHA256:
`ea2b13e89894e604c725ee884d562ded43af292bff8e99b0a3435626dfbd8f14`.
`sources.json`, toolchains and raw preparation/origin receipts identify every input.

## Remaining defect and current consumers

`iroh-blobs/src/store/fs/meta.rs::handle_get_blob_status` still reads only the
blobs table and returns NotFound for no row. It receives Blobs::status/has through
BlobStatusRequest → Fs actor → meta::ReadOnlyCommand::GetBlobStatus. It bypasses
HashContext's existing synthetic empty branches. Canonical empty FinishImport
already returns TempTag::leaking_empty and writes no row. Reads, observations and
BAO exports already support the empty file. The four-line early status reply
Complete{size:0} would align that final handler with the existing logical storage.

Actual current default and all-feature `cargo metadata --format-version 1
--locked --offline` confirm three direct local consumers: iroh-docs, radio-cli,
radio-integration-tests. The reverse closure contains these and iroh-blobs.
iroh-willow still resolves registry iroh-blobs@0.98.0. Full records and extracted
package IDs are in `logs/parent-metadata{,-all}.*`, `resolved-closure.json` and
`resolved-all-features.json`. iroh-docs is now inside the affected closure.

The docs engine's content-status callback calls local blobs.status and maps
Complete/Partial/NotFound to Complete/Incomplete/Missing. live::start_download
returns early on Complete and removes the missing marker. Therefore Fs-backed
canonical-empty queries become Complete for that consumer too. Current docs
tombstones already use this canonical Hash::EMPTY; the amendment changes no
identity, signature, record validation, tombstone filter or dependency. sync.rs
rejects ordinary zero-length inserts, validates empty/hash pairs and constructs
tombstones from EMPTY; store/fs/query.rs compares the same constant.

## Primary evidence and current witness

Current Hemera `vectors/hemera.json`, `specs/tree.md` and `rs/tests/vectors.rs` are
byte-identical to the old pins; `primary-identity.json` records both revisions and
digests. Tree/sponge/permutation implementations changed substantially, so source
identity or measured equivalence is not claimed for them. Fresh current-revision
tests check literal/domain behavior again.

Root authorized a tests-only current-baseline hypothesis experiment before the
new PLAN review. Three historical test files are copied byte-for-byte into a
private witness archive; hash.rs gains only a cfg(test) module declaration.
Current EMPTY/docs/equality and every production handler remain intact. The
overlay manifest pins the files and unchanged meta.rs.

Command `cargo test --manifest-path iroh-blobs/Cargo.toml --lib empty_root
--all-features --locked --offline`, matching actual Rustup1.95.0 tools and
RUSTFLAGS=-Dwarnings, exits101: 17 tests run, 15 pass and 2 fail. Both Fs cases
assert Complete{0} but receive NotFound at stores.rs:19. Literal/domain, raw
serialization/tickets, local/remote empty admission, wrong-key rejection, actual
remote verification and nonempty controls pass. This is a current functional
witness, not an inherited failure or an expected-panic test. Full raw outputs and
source identities are `logs/witness-empty-root-debug.*` and `witness-overlay.json`.

A separate public enumeration probe, removed after its receipt, executes
`cargo test ... --lib fs_enumeration_probe --all-features --locked --offline --
--nocapture`: exit0, fresh=[] and after-empty-add=[], computed key=canonical ROOT.
The current guard proposal therefore preserves enumeration. The old
[]→[canonical] result belongs solely to the historical pre-PR35 baseline.

The separate `--release` witness also exits101 with15 pass/2 failures, the same
Fs assertions; `logs/witness-empty-root-release.*` retains its actual run.
No final candidate, current broad workspace, downstream, lint, docs,
MSRV or semver outcome has yet been measured for this amendment.

## Scope and compatibility

Fresh/add/reopened Fs empty status and has will become Complete{0}/true. Existing
list/read/export/observe behavior remains the same. Legacy canonical rows are
untouched; force deletion cannot remove synthetic availability. A legacy empty
row missing its inline data no longer raises that status-path inconsistency.
Zero/nonempty keys still use the unchanged DB path. No physical empty persistence,
upstream-store parity, global zero alias or migration is asserted.

MemStore's pre-add Partial{None} versus observe complete(0) remains separate.
Bounded proof work/allocation and authenticated particle/root/length binding also
remain open. The prior util.rs:237 checksum panic is repaired upstream; it is not
a current known failure. PR35's audit is historical context, not this worktree's
gate receipt. No plan or review approval authorizes release or promotion.
