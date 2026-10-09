# Correct sync slice traversal

Status: implementation source frozen for fresh code review. Scoped tests pass;
unrelated Clippy/full-workspace/tooling failures remain visible in research.
Base: radio `db1d62e2cd1e4b2f309fa19bcc158bd29b44753d`, freshly fetched origin/main.
Owned worktree: `/Users/master/cyber/radio-kadek-slice-traversal`;
branch `fix/kadek-slice-traversal`.
Serves: kadek foundation closure row 4, authenticated slice-proof dependency;
[research](research.md) pins lineage, executed evidence, rules and limitations.

## Result and invariant

A valid right-only proof returns the exact requested leaf offsets/data against
its trusted root Hash. For in-file requests, the expected-hash stack contains
pending visited nodes, ordered next-to-visit at the top. Every included parent is authenticated
before pushing its visited children; every returned leaf is authenticated.
Use existing filtered traversal flags; no new walker or hash algorithm.
API/error types, proof bytes produced by the extractor, hash domains and the
single-block special path remain unchanged. This is not Particle admission,
root/profile migration or bounded-verifier completion.

## Approved implementation scope to review

- `cyber-bao/src/io/slice.rs`: use filtered traversal only in the multiblock
  decode path; Parent.left/right gate child pushes; delete excluded-node pops
  and duplicate inclusion calculations. Keep root-before-leaf authentication,
  right-before-left stack order, existing local errors and output order.
- `cyber-bao/tests/slice_traversal.rs` (new, <=500 lines): independent public-API
  regressions. Existing private tests remain in place.
- `cyber-bao/src/io/{encode,outboard,slice}.rs`: move each test-only OUTPUT_BYTES
  import/PAIR_SIZE constant into its existing cfg(test) module. No warning allow,
  global formatting, production hash or neighboring function changes.
- Additional measured prerequisite authorized by root: only rename the unused
  `encoded` binding to `_encoded` in `io/fsm.rs::tests::fsm_decode_with_range_filter`.
  Strict all-feature tests exposed this warning at base line 287; preserve the
  encode call and value lifetime. Fresh code review must adjudicate this addition.
- Task research/plan and final `audit/kadek-slice-traversal/` receipt/repro inputs.
  No manifests/lock, tree.rs, backend, async decoder, provider, storage, docs/bao,
  specifications, version or kadek dependency changes.

## Steps and verification

1. After plan approval, export exact sources into isolated fresh directories and
   reproduce the durable base probe unchanged. Export audit inputs from kadek
   commit 16b53f7, not a dirty working tree. Verify fixture hashes and source blob
   identities. -> verify: original right-only Truncated, successful left/full
   controls and known grouped ROOT discrepancy exactly match the old receipt.
2. Add regressions first; place only that new test in the unchanged source
   export. -> verify: `literal_right_subtree_is_authenticated` fails at the
   valid-proof acceptance assertion in debug and release. Record its actual
   error, rather than treating the old probe's intentional exit 0 as a green test.
3. Implement the filtered-stack change and the three test-only warning moves.
   -> verify: focused tests and existing library/tests pass; mismatch/truncation
   behavior remains; no source outside the explicit list changes.
4. Run focused checks below and the owning upstream gate set where reproducible.
   -> verify: exact commands, outputs, toolchains, input/patch digests, failures
   and limitations retained in audit. No broadened unrelated repair for a red
   baseline; return concrete blocker to root before expanding scope.
5. Freeze source for fresh different-vendor code review and root-owned downstream
   review/ring decision. -> verify: baseline/final diff and source manifest,
   reviewed independent oracle, required gates honestly classified. No automatic
   row 4 closure, dependency bump or claim that radio roots equal Particles.

## Independent cases and error expectations

The body formula is `(i*31 + i/4096)%256`. Primary fixture has four 4096-byte
leaves, log 0, query 2..4. Construct h0..h3 with public Hemera chunk_cv, counters
0..3 and root=false; L=parent(h0,h1,false), R=parent(h2,h3,false),
root=parent(L,R,true). Wire is LE64(16384) || L || R || h2 || h3 || body[8192..].
The fixture is assembled independently of radio extractor/traversal.
Assert root hex from research, exact wire length 8328, and compare the generated
proof SHA256 with the durable receipt using the external fixture integrity step
(no new Rust dependency). Extractor equality is a secondary interoperability
check. Expected outputs are `(8192,4096 bytes)` then `(12288,4096 bytes)`, each
matching the corresponding literal body segment. Hash oracle is pinned Hemera,
not an independent cryptographic certification of Hemera.
The final audit may retain a separate adaptation of the durable probe that
changes only its expected right-only result to success, preserving byte
generation and root observations. Hash that new driver; leave the old receipt
unchanged. It emits fixtures for the SHA256 check without a Rust test dependency.

Additional tests use explicit small tree decompositions, not a second generic
copy of the production traversal:

| Case | Required result |
|---|---|
| Left-only 0..2 and full 0..4 | Exact ordered offsets/data; original controls preserved |
| Nested right subtree, eight leaves, 6..8 | Skipped ancestor levels never consume requested hashes |
| Sparse 0..1 plus 3..4 | Both branches selected; no skipped-leaf stack interference |
| Five leaves, final leaf partial, query 4..5 | Promoted/unbalanced right branch, exact final extent |
| Five leaves, query 0..1 plus outside 6..7 | Exact first leaf; preserve padded-span behavior without a final stack/cursor assertion |
| Eight leaves, log 1, query 4..8 | Two requested grouped blocks, output offsets 16384/24576 and sizes 8192 |
| Empty/outside request on multiblock tree | Existing extractor/decoder result behavior retained; no invented root-binding claim |
| Pair mutation at root / included inner node | ParentMismatch at the corresponding node, no Ok output |
| Selected leaf mutation | LeafMismatch at the corresponding start_chunk |
| Header<8 / needed pair cut / selected leaf cut | Truncated |
| Wrong trusted root / substituted sibling commitment | ParentMismatch; excluded sibling still authenticated by its parent pair |

Keep root flags explicit for all decompositions. For the existing 8192-byte log 4
root discrepancy, retain an observational compatibility test or receipt probe
showing both old values unchanged. Do not convert it into canonical success.
The single-block/empty special path, trailing bytes and malformed huge geometry
receive no new acceptance policy in this unit. They remain recorded follow-ups.

## Isolated validation and gate plan

Builds must never resolve the worktree's `../../hemera/rs` against the dirty
sibling. Use two explicit validation scopes after approval:

A. Focused crate export: follow the durable checked Nu recipe, git-archive radio's
cyber-bao at base into fresh /tmp, replacing only the exported Hemera path with
registry `=0.3.1`; preserve feature defaults and workspace lints. Seed its lock
from the committed radio/receipt lock. If extra dev-dependencies require a
resolved lock, record the generation command/diff/checksum, then replay from a
fresh export with --locked. Record every exported Rust blob ID. Apply only the
reviewed patch/test overlay, record digest; a missing cache is a dependency-fetch
prerequisite, not permission to use local sibling contents. Do not edit the
historical receipt assertions or suppress baseline warnings.

B. Owning workspace export: git-archive full radio base and exact Hemera source
23f3bbcff910ea6d504ceb505680a539260869da into /tmp/run/{radio,hemera}; omit archived
nettools/target build products on extraction. Internal quinn/nettools remain
committed radio inputs. Preserve manifests and committed lock, inspect metadata
paths to prove all local packages resolve within that isolated root. Use a new
build directory there; preserve locked git/registry identities and rust versions.
Any required missing material/lock/compile failure is reported explicitly.

Focused commands (execution status in research; final audit records actual filters):

```text
cargo test -p cyber-bao --test slice_traversal --offline --locked
cargo test -p cyber-bao --test slice_traversal --release --offline --locked
cargo test -p cyber-bao --offline --locked
cargo test -p cyber-bao --all-features --offline --locked
cargo test -p cyber-bao --all-features --release --offline --locked
cargo check -p cyber-bao --all-targets --no-default-features --offline --locked
cargo clippy -p cyber-bao --all-features --all-targets --offline --locked -- -D warnings
cargo doc -p cyber-bao --all-features --no-deps --offline --locked
cargo semver-checks check-release -p cyber-bao --baseline-root ../baseline
```

For strict checks set RUSTFLAGS=-Dwarnings; scoped docs RUSTDOCFLAGS=-Dwarnings.
For semver, export tag v0.1.0 to a sibling `baseline` workspace using the same
isolated dependency substitution as the candidate; run from the candidate
workspace. Record actual tool support/results; do not compare to a dirty
baseline checkout. Format owning files with repository format options.
`cargo make format-check` remains the full upstream formatting gate; pre-existing
format drift is reported before any unrelated reformatting.

Full upstream gates, not replaced by scope commands: ci.yml/tests.yaml define
nextest workspace --lib --bins --tests, default/no-default/all features, ignored
case accounting, doctests, cargo doc --workspace --all-features --no-deps
--document-private-items (pinned nightly 2025-10-09); Clippy all three feature
sets/all targets; MSRV 1.89 workspace check; semver action; cargo-deny -Dwarnings;
format-check; configured native/cross/Android/wasm and netsim jobs. Workflow
selectors contain stale package names; their real failures and unexecuted remote
jobs must remain visible. This task neither edits them nor claims them green.

## Risks, boundaries and handoff

1. Pushing an unvisited child / wrong order -> nested-right and sparse proofs.
2. Shared encoder/decoder bug conceals failure -> independent literal proof and
   pinned root/fixture hash, plus exact leaf coordinates.
3. Partial/grouped geometry changes hash domain -> explicit decompositions and
   retained old root discrepancy; tree/hash code untouched.
4. Dirty sibling or stale target supplies input -> archive/blob/lock/metadata
   receipt and fresh isolated directories; never build the original worktree.
5. Narrow green tests conceal baseline/resource failures -> full gate inventory,
   executed/unexecuted separation; no compatibility/admission/row 4 closure claim.

Radio is part_of soft3 (registry 94af9de); direct cyber-bao consumers are
iroh-blobs, particle, radio-cli and tests/integration.
Rung/reverse-dependency coverage must be assessed against exact committed origins;
no ring 1/release acceptance follows from the scoped export. There is no new public
API or manifest/version bump. Fresh vendor plan approval was received in
`/tmp/radio-kadek-slice-traversal-plan-review.txt`; it is source-only, not proof of
soundness or of a passing gate. Root retains commit/PR/merge control for this
handoff; ordinary dev-law review, warning/test and owner-only release rules apply.
