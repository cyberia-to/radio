# Synthetic empty Fs availability

Implementation and fresh CODE review complete: [APPROVE, no blockers](code-review.txt).
[Root disposition](review-disposition.md) records the review limits. Required
broad gates remain red. This audit does not close the entire Kadek foundation row
or approve a release. The shared original Radio worktree was not modified.

Radio `bc8b6331d3c76cbc011210e13f81e6ea351ef06f`, Hemera
`d5f0a09539360934fb32db9b2e15a91995607db6`, plus the five frozen source paths in
[source-freeze.json](source-freeze.json). Only the Fs status guard changes
production behavior: canonical empty content reports `Complete { size: 0 }`
before database lookup, including after forced deletion. Upstream identity,
constant, documentation, listing, schema, manifests and authoritative lock remain
unchanged. Three independent test files and their module declaration cover the
published literals, local/remote decoding, fresh/add/reopen/delete and nonempty
controls. The current docs consumer skips downloads for this available content;
its tombstone identity and validation remain unchanged.

## Current measurements

All results below belong to those inputs on October 11. Exact commands,
environments, timestamps, exits and unmodified output live in the capsule's
`logs/`; `execution/code-gates.md` lists every executed Cargo command.

| Receipt scope | Observed result |
|---|---|
| `witness-empty-root-debug`, `witness-empty-root-release` | Each17 run:15 pass,2 Fs NotFound failures before guard |
| `candidate-empty-root-all`, `candidate-empty-default`, `candidate-empty-release`; `candidate-empty-none` |17 pass each;15 with no default features |
| `candidate-native-nextest` |141 pass,2 skipped |
| `candidate-consumers-nextest` |108 pass,3 skipped:85 local docs and23 integration; selected CLI compiled with no unit cases |
| `candidate-ci-run-default`; `candidate-ci-run-none` |547 pass/9 skipped;546 pass/1 Willow timeout/9 skipped |
| `candidate-msrv-*` | All seven actual1.89 checks pass: workspace, owner, consumers and four focused filters |
| `candidate-semver-tag-iroh-blobs`; current-parent exact follow-up |202 checks pass/58 skipped each; initial current-parent helper rustc SIGKILL retained as inconclusive |

Current exact-parent comparisons are in `execution/paired-comparison.md` with
complete derived diagnostics and raw streams. Both fail workspace formatting,
strict Clippy, private owning docs (`Self::persist`), all-feature nextest compile
(iroh-gossip address lookup), and dependency policy. Named pinned nightly docs
fail in both at rustdoc search-index invalid-null data. Literal registry
`iroh`/`iroh-relay` feature/doctest failures are not local cyber-radio verification.
Deny has36 matching headings; one synthesized-license block retains the path
length dependent diagnostic column/padding difference.

The full native parent runs124:122 pass and2 connection-pool timeouts,2 skipped;
candidate runs141:all pass. Their timing difference has no established cause.
For CI no-default only the exact failed Willow case was rerun on the parent:
`net failed: failed while active` at6.987s versus candidate TIMEOUT at30.009s.
This is a narrower comparison with different diagnostics, not a full parent CI
run or proof of the same cause. Its generated proptest seed is retained under
`runtime-outputs/`, separately from source changes. Initial owning-parent Clippy
compiler SIGKILL and its one exact follow-up are both retained.

Ordinary Rustup1.95.0, MSRV1.89.0, nightly2025-10-09; at most2 Cargo jobs. Local
locked/offline, serial nextest and incremental-cache limits are explicit in each
receipt. Pinned nextest0.9.80 confirms ci inherits committed default timeout:
termination starts after3×10s, with10s graceful shutdown; no extra timeout profile.
VERGEN archive warnings remain visible. Compiler-masked Clippy does not certify
new-test lint cleanliness. Semver uses separately retained fresh helper locks and
current Hemera even for last-tag source; it is an API diagnostic, not a historical
release closure. No blanket regression-free, platform fleet or conformance claim.

## Retained evidence

[receipts.tar.gz](receipts.tar.gz) contains 979 exact files,
196 current command receipts and 392 raw streams.
[capsule.json](capsule.json) and [payload-inputs.json](payload-inputs.json) identify
all bytes. The current Radio/Hemera/last-tag committed archives, source overlays,
actual semver helper inputs, original PLAN and bounded CODE inputs are preserved.
Tracked `nettools/target` is the sole archive exclusion; its complete inventory
and original tree listing are retained under `archives/`.
The bounded reviewer sees five full candidate sources, full relevant callers and
primary contracts, labeled excerpts and executor-reported gate summaries.
Omitted raw logs/bulk inputs remain in the audit; their hashes do not imply review.

`historical/superseded344/` separately preserves the old five-file candidate,
notes, complete nested audit and raw Grok CODE APPROVE. Origin PR35 superseded
that unmerged candidate. Its nested README predates its CODE verdict and says
pending; the accompanying status and raw verdict resolve that historical status
only. No old344/23f3 gate is a current result. The old worktree was not cleaned.

Fresh current PLAN and CODE APPROVE are retained. Current CODE verdict, invocation,
completion and root response are outer sidecars; the earlier immutable capsule
records review pending. Root independently replayed both bundle/capsule integrity
and the complete source/counterpart identities; see the root verification receipts.
Required reds retain `wip:`/`decision` accounting. Mem pre-add consistency,
proof resource bounds and authenticated particle/root/length binding remain
separate work.

Verify byte integrity and both review bundles without executing recorded commands:

```sh
nu audit/2026-10-11-empty-status/verify.nu --source-root .
```

The verifier uses Nushell and `tar`, checks raw streams, reconstructs current
PLAN/CODE bundles, verifies the nested historical capsule and optionally the five
checkout sources. Successful temporary extraction is removed. Original absolute
paths in historical runners are provenance; the verifier does not invoke them.
The outer `verification.json` records the actual verification outcome.

The optional `verify-closure.nu` additionally uses the retained scaffold and local
Git objects: it reproduces the three archives, checks all seven exported source
pairs, raw streams, exact counterpart mappings and both SIGKILL follow-ups.
`closure-verification.json` and its raw streams record that replay. This auxiliary
check establishes identities; the red gate verdicts remain red.

After the source push, [hosted checks](hosted-checks.md) exposed missing sibling
Hemera checkout and existing spelling findings; platform jobs were queued.
Those observations remain separate from the local gates above.
