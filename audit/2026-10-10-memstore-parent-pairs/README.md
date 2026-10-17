# Native store parent-pair width

This local candidate repairs the same ephemeral parent-pair serializer in
MemStore and FsStore's PartialMemStorage. Each Hemera hash occupies 32 bytes;
the pair and ordinal stride occupy 64. The old writers copied 32-byte hashes
into 64-byte halves and panicked. The private store helper now derives the
width from `hemera::OUTPUT_BYTES`; the already correct reader shares that
constant, and the unused print diagnostic accepts complete 64-byte records.
The existing exporter, disk writer and persisted checksum format are unchanged.

Radio parent `0d11468503c052aa5dcefb0dabc4602bd8efdc60`, Hemera
`23f3bbcff910ea6d504ceb505680a539260869da`. The six candidate inputs are in
[source-freeze.json](source-freeze.json), SHA
`d7c6cc1560eeeadc1b0c880cca79a3e2b09a2379489bac37706b0603db7069ca`.
The committed gate lock remains
`295b21c8804e3885a195511ffca6fcf368e7c762c5b411374aecf20ba4d14052`.
Private source exports came from those commits through `git archive`, excluding
only tracked `nettools/target`; original dirty working trees were not build inputs.
Archive exports can apply committed attributes, so this does not assert that
every exported file is byte-identical to its Git blob. The final closure check
compares those exports and the explicit overlay, including unchanged locks.
No version, dependency, public API, root convention or specification changed.

## Direct evidence

The measured commands ran on macOS arm64 on 2026-10-10. Ordinary gates use
actual Rustup 1.95.0 Cargo/RUSTC/RUSTDOC; MSRV uses 1.89.0; CI docs use
nightly-2025-10-09. Four build jobs, private targets and locked/offline source
gates are recorded in [gate-index.json](gate-index.json). Each entry names the
exact command, environment, source path, timestamps, exit and stream hashes.
That index has 88 Cargo invocations, including tooling and cleanup; it is not
a count of tests. [Tool identities](tools.json) and [compiler identities](toolchains.json)
pin the binaries. The capsule retains full stdout/stderr and result lines.

| Gate / receipt name | Observed result |
|---|---|
| `witness-pairs-{debug,release}-{v1,final}`: exact parent plus tests only | Each invocation: 2 pass, 9 fail, exit 101. Both faulty writers are reached. |
| `candidate-pairs-{all,default,release}` | Each invocation: 11 pass, exit 0. |
| `candidate-pairs-none` | 10 pass, exit 0; filesystem route is feature-gated. |
| `candidate-pairs-{all,none,release}-final` | Final test bytes: 11 / 10 / 11 pass, exit 0. |
| `candidate-native-smoke`, `candidate-native-export-{default,all}`, `candidate-native-root-policy` | 1 / 14 / 5 selected tests pass. Filters overlap; these are not additive unique counts. |
| `candidate-bao-all` | 71 unit + 8 root-policy + 9 traversal tests pass. |
| `candidate-msrv-pairs`, `{parent,candidate}-msrv-export` | Rust 1.89: 11 / 14 selected tests pass. |
| `{parent,candidate}-native-doc` | Strict owning-package docs exit 0. |
| `candidate-semver-{parent,tag}-iroh-blobs` | Each: 202 checks pass, 58 skip, exit 0. |

The witnesses preserve public outcomes: a right-only independent proof creates
Partial state and re-exports exact bytes, completion creates Complete state,
and corrupt parent/leaf inputs fail before a valid retry. The three-group
fixture exercises nonzero parent ordinal 1. FsStore imports a single five-item
batch, uses equality thresholds of 196608 body bytes and 128 outboard bytes,
then verifies exact body/full/middle proof bytes before and after reopen.
This covers complete in-memory import followed by persistence; incomplete
checkpoint/resume still reaches a separate checksum defect.

The original PR32 right proof is preserved byte-for-byte, 65608 bytes, SHA
`108022aa95ee61a1058d6d4bb53979a95bc46de114b036fcc6620fbd65648a51`.
The new three-group body is `D[i]=(31*i+i/4096)%256`, length 196608, with root
`d0b89aa52d29c4c2c4146ce679dc1db8d6f4aa89fd851046f349f9584987fddf`.
Its oracle uses primary Hemera chunk/parent primitives, independently of the
store encoder. [Fixture identities](fixture-identities.json) pin generated full
and middle proofs; their exact output is retained in the capsule.

The final refreeze moves one test import to satisfy the named formatter.
[Refreeze evidence](format-refreeze.json) proves all three production files and
both fixture files stayed byte-identical. Final-byte tests and both parent
witness profiles were rerun. [Witness overlay](witness-final-overlay.json)
confirms the parent has no production repair. [Closure integrity](source-final-integrity.json)
pins the candidate and surviving semver source copies.

## Red gates and focused diagnosis

Both broad native nextest runs exit 100. Parent: 113 run, 82 pass, 27 fail,
4 timeout, 2 skip. Candidate: 124 run, 83 pass, 25 fail, 16 timeout, 2 skip.
The per-name transitions are 10 PASS→TIMEOUT, 2 FAIL→TIMEOUT and 11 new PASS;
72 common PASS, 25 common FAIL and 4 common TIMEOUT remain.
[Comparison](nextest-comparison.json) and [raw failure bodies](nextest-failure-details.json)
preserve the actual results. No aggregate parity follows from these counts.

[Focused diagnosis](timeout-diagnostic.md) reruns the ten PASS→TIMEOUT names
serially with the same 30-second bound: all ten pass on each source. The other
two names remain distinct: `store::fs::tests::smoke` fails on both;
`tests::two_nodes_observe_mem` fails on parent after the repaired copy panic and
times out at 30.010 seconds on candidate. One separately authorized candidate
diagnostic with a 60-second bound passes in 31.851 seconds. The original named
30-second gate remains red. No near-30-second CPU/stack sample was obtained for
that diagnostic, and initial broad-run machine load was not captured.
There is no demonstrated causal attribution or general performance guarantee.

The CODE review's limitations bullet incorrectly summarizes all twelve focused
names as passing serially on both sources. The raw verdict is preserved without
editing; the preceding per-name results and command receipts correct that claim.
The earlier task prediction that `reader_partial_memory` would turn green is
also withdrawn: its actual first failure is the empty-body `invalid size for
hash` path before it reaches these parent proofs. `Hash::EMPTY` remains separate.

[Diagnostic comparison](comparison.md) describes exact normalization and its
limits. Final ordinary formatting remains 340 parent-matching hunks, exit 1;
named formatting remains 460 matching hunks, cargo-make exit 105. Initial
candidate named formatting had two extra import-order hunks; those are fixed
and both old and final receipts remain. Owning Clippy exits 101 first at the
existing cyber-bao `clone_on_copy` error. Its observed error sets differ because
compilation masks later paths; new tests lack a complete Clippy certificate.
Named Clippy, workspace/consumer checks and nextest compilation remain red.
The nine iroh-docs PublicKey errors, MSRV example type mismatch, and nightly
docs' nine iroh-docs plus 18 iroh-bench errors have paired diagnostic evidence.
Cargo-deny exits 13 on both against the same frozen advisory database, with
the same findings apart from path-dependent diagnostic column/padding. This
exit is not a finding count or legal conclusion. Build-script no-Git/VERGEN
warnings remain in raw logs, including some exit-0 commands.

Semver uses tool 0.51.0 and a fresh 451-package scratch resolution, distinct
from the committed-lock gate graph. The last tag is v0.1.0 at
`f2b1298daa9f635c821d53996c4d1dc4f1042b3d`, paired with the current pinned Hemera.
This is a diagnostic comparison, not a reconstructed historical release.
The tool reused one generated helper directory; only its surviving final tag
manifest/lock is captured, with that limitation stated in the receipt.

## Retained evidence

[receipts.tar.gz](receipts.tar.gz) contains 769 files: 202 original command
receipts and their 404 stdout/stderr streams, usage observations, fixture
outputs, source manifests, comparison scripts, frozen task inputs and review
verdicts (PLAN v1, PLAN v2 and CODE), plus semver manifests/locks. Full third-party
source archives, build targets and installed binaries remain outside this report.
[payload-inputs.json](payload-inputs.json) identifies every member by size and
SHA256; [payload-SHA256SUMS](payload-SHA256SUMS) supplies a standard checksum list.
From this audit directory, `shasum -a 256 -c SHA256SUMS` checks the outer files.
Run `nu audit/2026-10-10-memstore-parent-pairs/verify.nu --source-root "$PWD"`
from the frozen repository to check member safety, fresh extraction, all payload
hashes, raw stream hashes and the six source hashes. Omit `--source-root` after
source evolution. The verifier retains its fresh extraction path for inspection;
it executes no recorded gate command. [Verification](payload-verification.json)
records the actual verification run.

[Root review](root-review.md) records the independent source checks, review
identities, corrected review summary and decision accounting.

This repair serves Kadek foundation row 4. Empty-root identity, incomplete
checksum/recovery, observation performance, bounded proof verification and
authenticated particle/root/length association remain open. Broad gates remain
red; no automatic green-ring, complete media-foundation or release claim follows.
