# Checked range cursor execution

Stage: active, CODE review pending. Parent is Radio
`a96d86e28d384cdf656aadc4282c78c0c170c102`; candidate is local and uncommitted.
The [PLAN disposition](review-status.md) records fresh approval. Frozen PLAN,
literals and research capsules retain their original bytes.

The change adds `cyber-bao/src/traversal.rs` (172 lines), its public module
export and two public test files. Each pending next pops one intersecting frame,
returns one BaoChunk and pushes at most two children into fixed storage for 53
frames. Width admission precedes range admission. Safe ceil division and group
intervals bound arithmetic; subtraction clips the final leaf. This is geometry
only. Legacy unchecked helpers, eager consumers, proof parsing, particle/root
authority, empty-proof authentication and phase/rung closure remain open.

The ordinary tests were installed byte-identically from the approved external
witnesses before source edits. Actual-parent debug and release both failed at
22:41Z on 2026-10-12 with E0432 (`cyber_bao::traversal` absent); no test body ran.
The candidate passed. Strict no-default Clippy then exposed deliberate reversed
range inputs; one local allow with reason `invalid constructor inputs` preserves
all literals/assertions. The repository formatter subsequently required import
grouping in the two new tests. That was applied only after runtime suites ended.
Both transformations, original bodies and original failures are retained.

Final selected-source digest is
`53f29b5b1cf4d609ecb98c7b482198f87160fb56fdb229466bff8f33568a90eb`:
696 selected inputs, four source/test deltas from parent. This inventory selects
Rust, manifests, locks, Makefile and docs; it is not every repository file.
Workflows are separately frozen in the approved PLAN evidence. Runtime and
earlier broad gates ran at digest
`771518d6b2be2cfe13b8b2802c1fff45e3124dd48bef1f8e015319df3a7a1f4a`;
the bridge to final changes only the two test import blocks. Production and
test bodies are identical across that bridge.

All results below come from exact argv/env, start/end times, source snapshots
and raw streams in the retained execution capsule. Commands use matched Rust
1.95 Cargo/rustc/rustdoc, jobs 2, incremental 0, private targets, except named
MSRV/nightly gates. Dates are 2026-10-12. Counts include existing tests.

| Gate / records | Observed result |
| --- | --- |
| Final `cargo test -p cyber-bao --locked`, default / all-features / no-default, each debug and release; 03c–08c, 23:18Z | 101 / 104 / 28 tests pass in each mode; new public tests are 9 with std, 7 without |
| Final owning no-default strict Clippy; 21c | Pass |
| Final owning rustfmt and repository-config format of three new files; 19c/19d | Pass |
| Owning all-feature strict Clippy; 16c and parent 20c | Red: 11 old library diagnostics; candidate also reports 3 old libtest diagnostics. Parent scheduling did not expose those extra 3; source bodies are unchanged |
| New std-test Clippy supplement; 42c | Pass with four existing library lint categories allowed; strict all-feature gate remains red |
| Actual direct dependents check, all targets; 24 | Pass: iroh-blobs, particle, radio-cli, radio-integration-tests, iroh-docs |
| Workspace nextest default / no-default; 25b/26b, completed 23:09Z / 23:16Z | Each passes 563 tests, 9 skipped; source 771518d6 |
| Workspace nextest all-features; 27b/28b | Candidate and parent fail compiling iroh-gossip with E0599 `add` on Result; no tests run |
| Workspace all-feature doctests; 29/30 | Candidate and parent pass |
| Rust 1.89 workspace all-targets check; 31/32 | Candidate and parent pass |
| Nightly 2025-10-09 private all-feature workspace docs; 33/34 | Both fail reading disk column: `invalid type: null, expected type data at line 1 column 4`; old rustdoc warnings remain; cause unresolved |
| Workspace strict Clippy default / none / all; 35–37 pairs | Both red on existing Radio/BAO lints; observed diagnostic order varies |
| Actual workspace cargo-make format; parent 38b, final 38c | Both red. Three new files have no remaining diff; all 295 normalized formatter hunks match parent, including lib re-export hunk |
| Actual cargo-deny; 39b pair | Both exit 13: advisories, licenses and sources red; bans green |
| Workflow named selectors; 41 | Commands pass, but iroh and iroh-relay select registry crates. This does not establish checks of the renamed workspace owners |
| Fresh-target API against actual parent, default / none; 40 | Both pass, no update required |
| Fresh-target API against last tag f2b1298, default / none; 40 | Default passes; no-default exits 100, six major check categories covering many removed items, the existing reducer feature-boundary floor |

API baselines retain 4,489 Git blob/symlink identities and exact materialization
verification. The last tag is paired with current pinned Hemera d5f0a095,
not represented as the historical release closure. No version or release action
is taken. Historical reducer runtime differences remain historical; this task's
two ordinary workspace runtime modes passed.

The isolated no-default package has no dev dependencies. Its actual thumb
normal graph is probe → cyber-bao → pinned cyber-hemera d5f0a095. Library check
passes; a finite no_std binary build fails with `no global memory allocator found`.
Pinned Hemera declares `extern crate alloc`; the same binary with parent pure
ChunkNum geometry reproduces the boundary. No substitute allocator was added.
Host cursor allocation tests and thumb library compilation establish neither
allocator-free final link nor 32-bit runtime behavior. The first external input
snapshot was late despite its original label; that diagnostic is retained and
10b/11b/12b repeat the small checks with pre-command input hashes.

Initial nextest/make/deny attempts missed the existing gate-tools PATH and failed
before their gates; they remain preparation diagnostics. Corrected tool identities
and runs are retained. Completed compiled targets were inventoried and removed
under the storage cap; source/API baselines and receipts remain. The final
execution replay verifies 84 records, 168 raw streams and five source snapshots.
Green identity replay does not turn the recorded red gates green. Fresh CODE
review and root disposition remain required; no whole repository, rung or release
readiness is claimed.
