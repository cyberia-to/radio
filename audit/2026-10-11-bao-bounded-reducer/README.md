# Bounded BAO group reducer

This unit serves Kadek phase-1 foundation row 4 through Radio/soft3. It adds a
53-slot, one-kernel-per-step group reducer and isolates the existing std APIs.
It calculates hashes; authenticated particle/root association, proof parsing,
legacy eager tree geometry and the later bounded traversal remain open.

The actual parent is `dacd030c9d6301b316a96b5bc6e4ea1e1cec79f1`; the unchanged
Hemera pin is `d5f0a09539360934fb32db9b2e15a91995607db6`. The final selected
693-file source digest is
`398012be57ffe2facb284f541ea54ce7905d56ee5347fb3b82af1ba5d61faf12`.
That selection covers Rust/manifests/locks, not every repository asset; changed
documentation and workflows have separate exact identities in the review pack.
The directory date is the task's start date. Command records retain their actual
October 11–12 UTC timestamps.

[Execution](../../.claude/tasks/bao-bounded-reducer/execution.md) gives the full
disposition, command labels, preparation diagnostics and scope boundaries.
The frozen [PLAN](../../.claude/tasks/bao-bounded-reducer/plan.md) received fresh
Grok APPROVE on October 11. Fresh Opus CODE review approved the exact v3 pack
on October 12 at 21:53:06Z, with no blockers. The [disposition](review.md) records
advice, raw identities and remaining red gates. Candidate code was uncommitted
at review; root owns the ordinary commit/merge. No release or phase closure is
claimed here.

## Recorded results

Every number below comes from a retained `execution/logs/<label>.json` command
record and its original stdout/stderr, bound to the parent or candidate source.
The readable CODE pack includes exact commands, environments, outcomes and
stream identities. The portable archive retains all 101 records / 202 streams.

| Records | Result |
| --- | --- |
| 01/02, 04 | Actual parent fails to compile the frozen public witnesses (missing API) and isolated thumb consumer (std unavailable). These are compile observations, not runtime-red assertions. |
| 23b | All six owning test runs pass: 92 default, 95 all-feature and 21 no-default tests, each in debug/release. |
| 14c/15b, 16–18, 23d–23f, 23h, 42 | Isolated thumb/feature graph, explicit feature checks, strict no-default Clippy, strict owning docs, mechanical split verification and owning formatting pass. |
| 40 | Default API passes 202 checks / 58 skips against actual parent and the applicable tag. |
| 40b | No-default API fails 6 major check categories covering many removed std items on both baselines. This is the reviewed intentional major floor. |
| 23c/20, 35–39 | Broader strict lint, format and deny gates retain paired failures. Owning all-feature Clippy has 9 existing I/O findings and 2 moved legacy traversal findings. |
| 27b/28b, 33b | All-feature workspace nextest compilation fails with existing iroh-gossip E0599 on both sources; exact-environment nightly docs fail on both with the rustdoc null-column error. Its cause remains unresolved. |
| 29–32, 41b | Paired workspace doctests/MSRV and four strict default selectors pass. The inherited iroh/iroh-relay selectors resolve registry v0.96.1, so they do not establish current-owner coverage. |
| 25b/26b, 45, 48 | Candidate runtime suites remain red. The first default comparison has one candidate-fail/parent-pass result; the focused repeat passes on both. Three no-default candidate timeouts pass on parent. Causes remain unresolved. |

The default runtime suite recorded 518 passes, 14 failures and 22 timeouts; the
no-default suite recorded 518 passes, 13 failures and 23 timeouts. Each ran 554
tests with 9 skipped. Every failed tuple and its selected parent result is in
`execution/runtime-comparison.json`. No blanket inherited-failure or flakiness
diagnosis is made. Allocation observations apply to the finite real Poseidon2
witness; the embedded dependency graph still includes Hemera's alloc import.
This is not a full platform, product, rung, specification/Kelvin or release run.

## Portable evidence

Run from the repository root:

```text
nu audit/2026-10-11-bao-bounded-reducer/verify.nu audit/2026-10-11-bao-bounded-reducer
```

The verifier uses Nushell and tar, with no checkout, network or Rust toolchain.
It checks archive paths/types, all object bytes, both submitted review packs,
the PLAN verdict identity, all command streams/runners/source snapshots, frozen
witnesses, finite test counts and isolated embedded outcomes. It replays retained
evidence; it does not rerun gates or validate omitted last-tag archive bodies.
The local CODE verifier separately checked all 4,489 API source archive entries
before packaging. That inventory remains, while its bulky historical source
copies and all compiled targets are omitted.

`evidence-index.json` maps logical paths to content hashes; `evidence.tar.gz`
contains regular `objects/<sha256>` files, deduplicated without changing bytes.
It retains 4 source snapshots / 2,762 logical source files, both review packs,
raw PLAN review, prior source bridge, root replays and the unsubmitted oversize
CODE v1/v2 packaging attempts. No nested prior audit archive is included.
`capsule.json` records exact counts and identities. Full omitted-support bodies
are not claimed reviewer-read; the final readable CODE v3 has 78 sections and
482,123 bytes, SHA256
`e600e1861bf2ee57efd094317f5a7118192be5f083537212828a1de44f9d6a7d`.

The retained portable replay passed at 2026-10-12T21:54:03Z (exit 0);
`portable-replay.json` binds its command, verifier, archive and raw streams.
The CODE review sidecars are outside the immutable capsule and covered by the
outer checksums. The historical capsule's execution text truthfully retains
its pre-verdict pending status.

Target cap crossings and inventory-bound cleanup are preserved in execution.
Only completed owned compiled targets were removed; source snapshots, raw
streams, independent expected values and API baselines remain available.
