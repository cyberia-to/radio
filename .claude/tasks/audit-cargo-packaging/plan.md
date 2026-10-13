# Lossless archival Cargo manifests

Status: draft; fresh different-vendor PLAN approval required before edits to
existing artifacts. Serves Kadek foundation row 4 through Radio; discovered from
PR40's committed Git consumer. Parent: `ce0fb312faa8770e80efe9afa864106ae6b51552`.

## Result

Rename exactly seven archived harness manifests from `Cargo.toml` to
`Cargo.toml.txt`, preserving every byte. Keep source/workspace manifests and all
dependency pins, locks, Rust sources, tests and specifications unchanged. Cargo
must discover only the actual package when a fresh consumer pins an independent
committed candidate snapshot. The candidate is a local packaging witness, never
an origin release input.

Preserve the three original replay scripts under `verify.original.nu.txt` or
`reproduce.original.nu.txt` beside their existing names. Replace only those entry
scripts with thin Nu wrappers. Add one small shared staging helper in this task's
new audit directory. Preserve each CLI and its defaults explicitly:

| Entry | Default resolution before staging | Forwarded unchanged |
|---|---|---|
| Research `verify.nu` | `--repo`: original capsule's grandparent; `--siblings`: resolved repo's parent | Explicit resolved repo/siblings and optional `--live` |
| Execution `verify.nu` | `--repo`: original capsule's grandparent | Explicit resolved repo and optional `--live` |
| Slice `reproduce.nu` | `--radio-repo ~/cyber/radio`, `--hemera-repo ~/cyber/hemera`; retain these canonical defaults even from another worktree | Implementation revision, expanded selected repo paths, `--fetch`, `--full-workspace` |

Preserve original `--live` checks, including their historical HEAD equality. They
must still fail against a later merged HEAD. Research additionally checks a clean
tracked diff; execution does not. Do not add or infer another cleanliness check.

The helper copies only its selected capsule to a newly created disposable `/tmp`
directory, restores the explicitly listed Cargo logical names, and restores the
original replay script at its historical filename by moving the copied `.txt`
files, so the staged layout does not retain duplicate archived names. Replacing
the copied entry wrapper is the sole intentional collision, after checking its
identity; an existing logical Cargo path or missing archive fails before replay.
It must never create a Cargo.toml inside the real repository.
The original script then executes unchanged. All historical `files.json`, source
indices, contexts, reviews, fixture bytes, raw manifests and command receipts
remain unchanged. The wrapper is new packaging code, not the historically reviewed
verifier. Its own bytes and the original-to-archive mappings are bound by the new
capsule's manifest. `historical-index-bindings.json` records every affected index
entry: index path and JSON pointer, historical logical path/hash/length, satisfying
archived path, and deliberate direct-worktree outcome (missing logical Cargo path
or wrapper replacing original script). An already historical pre-CODE verifier
row is labeled separately and points to its existing preserved original. Physical
indices are deliberately historical; a direct unstaged check is not the replay.
Successful disposable replays are cleaned; failed ones retain
their isolated directory and propagate the original nonzero status.

## Steps and decisive checks

1. Freeze the seven manifest blobs, three original scripts, consuming paths and
   ce0 warning receipts. → Verify: every byte equals the exact committed object;
   discoverable audit manifest inventory is exactly the seven listed below;
   both original 2026-10-12 replay commands pass before mutation. These baseline
   checks are already measured; preserve them unchanged.
2. Rename the seven manifests losslessly and install only the replay wrappers,
   their archived originals and the small staging helper. → Verify: no audit
   `Cargo.toml` remains; the seven `.txt` contents match the original hashes;
   all real source manifests retain their paths and bytes. A complete committed
   tree comparison outside the explicit allowed audit/task paths must be empty,
   including root and cyber-bao manifests and root Cargo.lock.
3. Check the replay boundary. → Verify: research and execution wrappers reproduce
   the original successful JSON results with the same counts; their staging restores
   the complete original indexed file hashes including the original verifier itself.
   Run the unchanged proof CODE input verifier. Exercise 2026-10-09 staging and the
   original `prepare-crate` function for its historical parent/implementation.
   A child `nu -c` receives generated code with a quoted literal `source` path:
   `source "<stage>/reproduce.nu"; prepare-crate "<repo>" "<rev>" "<export>" "<stage>"`.
   This makes the source path constant at the child's parse time and exposes the
   private definition; it does not call `main`. Revisions are `db1d62e2…` and
   `590e69ea…`, fully pinned in evidence. Compare exported Cargo.toml, Cargo.lock,
   src/main.rs and the precise existing Hemera-dependency rewrite against inputs.
   Stage every capsule file, including Cargo.lock, probe.rs, SOURCE-FREEZE.json,
   FIXTURE-SHA256SUMS and expected-probe.stdout; preserve their exact hashes.
   The private-function mechanism already passes on both original revisions.
   Do not rerun the reproducer's codec matrix.
   A deliberate missing archived input/collision in a disposable copy must fail
   before running the historical script, leaving the real repository unchanged.
4. Freeze an independent committed temporary candidate snapshot containing the
   exact candidate tree: committed ce0 blobs plus an explicit allowlist of owned
   candidate changes, never another dirty worktree's inputs. → Verify: it is derived
   from ce0 with only the explicit archive changes, and all production source,
   normal manifest and lock blobs are equal. One private local Git object store
   contains both original ce0 and that candidate commit. Two independent fresh
   consumers use the same `file://` Git URL and differ only in Radio revision and
   explicitly recorded consumer/cache/target paths. Each has a fresh private Cargo
   checkout/cache; neither uses a path dependency. Keep Hemera d5 pinned and acquire
   it through the same bounded cached-object mechanism; no new network claim.
5. Run a same-session differential. → Verify: before, between and after the two
   arms, `/tmp/radio-bao-proof-parent-b933/cyber-bao/Cargo.toml` exists with the same
   length/hash. Do not delete or alter it. The fresh ce0 arm must reproduce the
   duplicate warning; absence invalidates the witness. Lock generation, metadata
   (`--locked --offline`) and eight-case reader debug/release run in both arms with
   matched Rust 1.95, jobs=2, incremental=0 and isolated targets. Candidate commands
   must emit zero Cargo/compiler warnings and resolve cyber-bao from the exact
   candidate Git checkout. This warning-free claim covers only those invocations.
   Require byte-equal reader stdout across both arms/profiles and the frozen
   historical control, and equal `(source path, bytes, SHA256)` tuples for all
   selected cyber-bao/Hemera source files. Within each arm freeze inputs before/after.
   Compare metadata after only the explicit normalization below; do not require
   equality of changed Git pins or physical paths. This is not a broad codec gate.
6. Freeze compact new audit and fresh CODE input. → Verify: lossless historical
   replay, exact raw receipts, input mappings and source equality independently
   replay; different-vendor CODE approval precedes root's final commit/PR/merge.
   Preserve all historical red outcomes without claiming a new full-gate pass.

## Comparison boundary

The historical snapshots are labeled `historical-ce0-reader-before-runs.json` and
`historical-ce0-reader-after-runs.json`; their original timestamps/bytes remain
unchanged, and v1's frozen packet stays intact. They span the old reader runs,
not a repair. New paired measurements have separate ce0/candidate arm labels.

Within the new pair the local Radio Git URL is identical. Normalize only its
validated ce0/candidate revision tokens in package/source IDs, the two consumer
IDs and their exact consumer directories, the admitted checkout-root prefixes
in manifest/target paths, and recorded target/build/workspace directories. Every
replacement has an explicit old/new mapping and path-boundary check; no blanket
regex stripping. Resolve-node IDs/edges use those same exact ID substitutions.
Everything else must match, including features, dependency graph, package versions,
rust-version, target lists and dependency requirements. Historical HTTPS and new
local file URLs are intentionally different and are not a metadata equality claim.
Snapshot/receipt timestamps and Radio commit identities are retained as distinct
measurements, never edited to force equality. Consumer manifests/locks contain
their explicit arm pins; only production source/manifests/locks and reader stdout
have cross-arm byte-equality requirements.

## File scope

Seven manifest renames, each adding only `.txt`:

```text
audit/2026-10-09-kadek-slice-traversal/Cargo.toml
audit/2026-10-12-bao-proof-research/probe/Cargo.toml
audit/2026-10-12-bao-proof-research/primary-probe/Cargo.toml
audit/2026-10-12-bao-bounded-proof/fixture-probe/Cargo.toml
audit/2026-10-12-bao-bounded-proof/nostd/Cargo.toml
audit/2026-10-12-bao-bounded-proof/nostd-parent/Cargo.toml
audit/2026-10-12-bao-bounded-proof/seals/Cargo.toml
```

Three entry wrappers replace their names while preserving exact original bytes:
`audit/2026-10-09-kadek-slice-traversal/reproduce.nu`,
`audit/2026-10-12-bao-proof-research/verify.nu`, and
`audit/2026-10-12-bao-bounded-proof/verify.nu`.
New helper, mappings, documentation, review inputs and raw evidence live only in
`audit/2026-10-13-audit-cargo-packaging/`; task artifacts live only in
`.claude/tasks/audit-cargo-packaging/`. No nested historical audit archive is copied.

## Five likely failures

1. A forgotten archived Cargo manifest still participates in discovery: exhaustive
   tracked basename inventory and a fresh committed-snapshot Git consumer.
2. Renaming silently changes historical bytes or hashes: compare all seven blobs,
   keep every historical index/receipt unchanged, replay the original scripts.
3. A wrapper reads temporary paths as the real source repository: resolve/pass
   explicit repo and sibling paths, including original CLI defaults.
4. Staging overwrites evidence or leaves an executable manifest in the repository:
   unique external destination, explicit mappings/collision checks, failure probe
   in a disposable copy, and before/after repository identity verification.
5. Packaging masks production/dependency drift: exact tree comparison, Git-pinned
   consumer identity, two unchanged literal result streams and honest warning counts.

Radio's cached registry `part_of = soft3` and Kadek's direct dependency remain
explicit. This is a packaging repair with no API/version floor change. There is
no release, tag, registry publication or Kadek dependency update in this unit.
The caller owns subsequent adoption of the actual merged Radio revision.
Previous broad workspace/rung and last-tag gate results remain unrefreshed; no
broader warning-free compiler, source, product or release claim follows.
