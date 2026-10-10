# Canonical BAO ROOT finalization

Radio parent `258724bd8ab797ad8d2ef43c6a4a2e07f1fc9e24`, Hemera
`23f3bbcff910ea6d504ceb505680a539260869da`; candidate changes are pinned by
[source-freeze.json](source-freeze.json). This serves Kadek foundation row 4.
No original working-tree source, manifest, lock, version or pin was changed.

At merge preparation, origin/main is `fd90677c2fd3aa61a9aa9db1a07a5c1c234320cd`.
`git diff --name-status 258724bd fd90677c` contains only the three added pages
`docs/explanation/cybernet.md`, `roadmap/README.md` and `roadmap/soft3-radio.md`.
All executable source, manifests, locks and test inputs remain the tested parent.
The PR carries this documentation-only integration delta without claiming a
second build execution.

## Correction and compatibility

When a complete file spanned multiple fixed chunks but fit one BAO group,
five reductions omitted terminal ROOT finalization and returned an internal
chaining value. One private generic reducer now serves all routes and applies
ROOT only on the final complete-file node. Absolute chunk counters, odd-node
promotion, the public hash_block signature, grouping geometry and allocation
strategy are preserved. Native memory/filesystem key producers and public
verification paths agree with Hemera's fixed-chunk tree. This root is distinct
from the plain Hemera particle domain.

This intentionally changes identity for `4096 < length <= 4096 * 2^g` when
group log `g` is positive; native log 4 affects 4097–65536 bytes. Existing keys,
tickets, indexes and collection references for those files must be reconstructed
from complete bodies. Partial records alone cannot supply that reconstruction.
There is no legacy alias or dual-root acceptance. For a HashSeq body of
`32*(1+children)` bytes, collections with 128–2047 children lie in the affected
native interval; metadata bodies may independently be affected. Rebuild their
referencing records as well. No deployment migration or deployed-data inventory
was performed. Reverting code does not migrate newly canonical records back.

The independent test body `D[i]=(31*i+i/4096)%256`, length 8192, has canonical
root `2abf65dd26465a7352707d79d18ff3aab9ee5d97614a774619c79ed527e20190`;
the former internal value is
`11890a7e7cf1e4de463a04bf53bfdf269d627983a221daaf9029a3ff43297389`.
Public tests derive both from primary chunk/parent primitives and pin the
literals. Canonical proofs succeed; old-root proofs fail without publishing
the claimed leaf. Ticket parsing preserves supplied bytes and does not migrate
the embedded root.

## Executed validation

2026-10-10, Mac16,5 arm64/macOS 26.4.1/25E253. Exact Rustup 1.95.0 binaries
run ordinary locked/offline gates; actual Rust 1.89 runs MSRV gates. Source and
lock integrity are in [source-integrity.json](source-integrity.json).
[Gates](gates.json) record all command arrays, source paths, environments and
receipt hashes; [expanded output summary](gates.md) includes final result lines.
Every count below refers to that frozen overlay and its named gate.

| Gate | Observed result |
|---|---|
| Parent tests-only witness, `--test root_policy` | 1 pass, 5 intended failures; candidate fixes those failures. Exact witness/final differences are recorded below. |
| Parent tests-only native store witnesses | 3 intended canonical-key failures. |
| `cargo test -p cyber-bao --locked --offline` | 69 unit + 7 root-policy + 9 existing traversal tests pass. |
| Same, `--all-features` | 71 + 8 + 9 pass; includes the FSM path. |
| Same, `--release --all-features` | Same 88 tests pass. |
| `cargo test --manifest-path iroh-blobs/Cargo.toml --lib root_policy`, default/all-features/release | 5 selected tests pass in each recorded configuration. |
| Same, `--lib export_pairs`, default/all-features/release | 14 selected tests pass, including 3 store routes added by this unit. These overlap root-policy tests, not an additional unique suite. |
| Rust 1.89 BAO all-target/all-feature check and root tests | Exit 0; all 8 selected root tests pass. |
| Rust 1.89 native root/export filters | 5/14 selected tests pass. |
| Both owning strict rustdoc gates | Exit 0. |
| Exact-parent and last-tag API semver, both crates | Each invocation: 202 checks pass, 58 skip, exit 0. Behavioral identities still change. |

Source v2 contained the final production change. V3 moved a test helper below
imports and replaced a one-range array assertion with explicit cardinality and
element checks; affected debug/release suites were rerun. V4 removed one blank
line only. Named project tools and semver use final v4. These transitions are
preserved in the payload; no production byte changed between those snapshots.

The parent witness has six default tests; the final file has seven. The extra
non-root partial/odd-group control was added after that witness and before v2
candidate gates. It was not a failure-first test and no measured parent pass is
claimed for it. The only other final-test delta is the equivalent range assertion
rewrite. [Witness annotation](witness-delta.md) pins the old source, exact diff
and actual receipt. [Compressed exact diff](witness-delta.diff.gz) preserves its
raw whitespace. The all-features FSM case already existed behind its feature.

The independent right-only proof from PR32 remains exactly 65608 bytes with
SHA `108022aa95ee61a1058d6d4bb53979a95bc46de114b036fcc6620fbd65648a51`,
root `9ccd2809b2bcca875ee39f2c034c80969c176a5510a66d638b2c88c3cd7c7f0f`.
[Its receipt](right-proof.json) names the emitted-file command; no encoder
round-trip substitutes for that byte-exact control.

## Red gates and limits

[Diagnostic comparison](diagnostic-comparison.json) distinguishes unchanged,
removed and masked diagnostics. BAO strict Clippy has 11 existing findings,
down from 13 because duplicate concrete reductions were removed; owning native
Clippy has those plus one existing radio finding. Compilation stops before
all test targets, so the new tests have no complete all-target Clippy certificate.
The first failure remains “error: using `clone` on type `Hash` which implements
the `Copy` trait”.

[Remote CI snapshot](remote-ci.md) records PR33 source commit
`f2b42c0674c586599b7defa72150ca2c5f8c4655` and its actual synthetic merge checkout.
Eight hosted checks stop at the missing sibling Hemera manifest, with the same
failure blocks as PR32; codespell adds one finding from the intervening base
roadmap page. Seventeen self-hosted jobs remain queued without an assigned runner
at the recorded snapshot. These are red/nonterminal checks, not platform passes.
[Raw API responses and completed-job logs](remote-ci.tar.gz) retain all command
receipts; after extracting into an empty directory, verify its SHA256SUMS.
This subsequent receipt-only commit changes no executable source or tested input.

Workspace/consumer/MSRV compilation and installed nextest retain the nine
existing iroh-docs PublicKey type errors. Formatting remains red on the unchanged
baseline findings. Installed cargo-make returns 105 around the failed format
command. Installed cargo-deny returns 13 against the same pinned advisory
database and unchanged dependency graph; that exit is not a finding count.
Its source/license/advisory/yanked findings are retained, not treated as a legal
verdict. CI nightly docs retain the same nine iroh-docs errors and emit four
iroh-bench documentation errors drawn from the parent's 18 compiler errors;
parallel compilation/documentation selected different failure surfaces. This
subset is not proof that unreported paths were repaired.

The unfiltered iroh-blobs library suite is not green or newly executed here:
the prior recorded run had 27 failures and three pending cases before termination.
Selected root/export tests cover the changed paths; an affected-length derived
literal in another unrun test remains a regression risk. Source inspection found
no such literal in the reviewed bounded inventory. Large store/fs and related
files were only partially inspected; there is no whole-repository audit claim.

Semver 0.51.0 uses fresh scratch dependency resolution, distinct from the
committed-lock test graph. Last tag v0.1.0 is paired with pinned current Hemera
for its unversioned path; this is not a historical release closure. Final generated
scratch manifests/locks are retained; they are final tag snapshots where the
tool reused a placeholder, not invented per-stage manifests.

## Review and retained evidence

Fresh different-vendor [PLAN v3](plan-review-approved.txt) and
[CODE review](code-review-approved.txt) returned APPROVE. The coordinator
independently verified every supplied source/artifact section, read the changed
production and tests, and checked raw log hashes. [CODE inventory](code-inputs.json)
and [verification](code-pack-verification.txt) pin the review envelope. Cosmetic
notes are retained without changing the tested source. No four-vendor council
or automatic green-ring decision is claimed.

[Complete receipts](receipts.tar.gz) retain parent/witness/candidate logs,
commands, source inventories, exact tools/advisory identities, right-proof bytes,
semver scratch manifests and helper scripts. [Payload verification](payload-verification.json)
records 115 independently hash-checked raw receipts and fresh archive extraction;
51 entries in the CODE gate index include cleanup/tooling commands as well as
tests. Extract into an empty directory and run `shasum -a 256 -c SHA256SUMS`.
The archive preserves raw whitespace and avoids treating archived Cargo manifests
as new workspace inputs. No binaries, build targets or full third-party standards
are published in this audit.

This behavioral correction has `decision` classification under the owner's
explicit implementation/review/fix/merge request. Required broad gates remain
red, so source commits use `wip:` with the first error. No version, sibling pin,
tag, release promotion or publication changes. MemStore parent import width,
empty-root sentinel, persisted checksum format, bounded verification and the
authenticated particle/root/length association remain separate obligations;
foundation row 4 and phases 1–2 remain open.
