# Bounded complete-buffer BAO proof verification

Local implementation on exact Radio parent
`b933829cbe273d2f31fe75ca83125f3ddd8917a2`. Fresh PLAN and CODE reviews approved;
required broad gates remain red and require a decision. Three production paths add
a concrete no_std proof job and sealed borrowed result. No kernel, dependency,
legacy reader or wire producer changes. Additive
minor API, Radio → soft3; prospective Kadek → Cyb integration remains separate.
This evidence does not close foundation row 4 or establish release acceptance.

`source-complete.json` binds the final seven source/test files. `source-ready.json`
is the previous production-identical 17-test freeze; the only final delta adds a
four-leaf parent-after-payload test. `interleaved-test-bridge.json` proves that scope.
Original tests-first, intermediate format/source epochs, failures and raw receipts
remain intact. `acceptance-map.md` describes finite fixture and allocation limits.

Owner matrices pass default118/all121/no-default45 in debug and release at their
recorded source epoch. Final focused corpus passes 18 tests in each debug/release ×
default/no-default mode. Final scoped rustfmt and no-default all-target Clippy pass.
Eight compile negatives match exact sealing/lifetime error classes; control passes.
Workspace MSRV 1.89 and 51 doctests pass. Strict broad default/no-default tests each
run 580 cases: 575 pass, five mDNS cases fail, nine skip. Narrow exact-parent runs
reproduce those same five failures. Other workspace compile/lint/docs/fmt/deny reds
have exact-parent receipts. See `gate-report.md`, `gate-ledger.json`, `comparisons.json`.
A parent failure is evidence of the baseline, never a green gate.

Current-parent semver has no breaking findings in default/no-default modes, under
its explicit `(no change; assume minor)` analysis. This does not prove unchanged
API or eliminate minor acceptance. Tag v0.1.0 comparisons fail on both inputs:
its relative `hemera/rs` dependency is absent in semver's isolated archive. The tag
floor remains unestablished. Named legacy CI package selectors fail on both inputs;
explicit renamed local native packages pass. No hosted CI or full rung closure is
claimed. External inventory is the retained cached observation in research.

Nightly docs effectively use `RUSTDOCFLAGS=--cfg docsrs`, report real warnings and
fail on the same rustdoc search-index error in both isolated outputs. No cause is
asserted. Offline deny uses existing cache and makes no fresh advisory claim.
The isolated thumb library compiles; candidate and parent final binaries need an
allocator through existing Hemera. Host allocation observation covers the stated
paths, not every error branch or final no_std linking. No 32-bit runtime was run.

Replay the compact raw/source capsule with Nushell:

```text
nu audit/2026-10-12-bao-bounded-proof/verify.nu --repo /path/to/radio --live
```

`--repo` must contain exact b933 Git objects. Baseline bytes are read from committed
objects, never a dirty checkout. Omit `--live` when replaying archived evidence;
`--live` also verifies the seven current files and HEAD. `files.json` hashes all
capsule inputs. The verifier reconstructs source epochs, links gate command/raw
hashes and parent comparison names, checks compiler classes and production scope.
It does not rerun Cargo, recompute Hemera or authenticate missing whole-product
inputs. Frozen primary/research replay is separate:

```text
nu audit/2026-10-12-bao-proof-research/verify.nu --repo /path/to/radio --siblings /path/to/cyber
```

That replay requires the exact Radio, Hemera, Kadek and cached soft3 Git objects
named there. Its original `--live` predicate requires pre-implementation source,
so omit it for this candidate. Full prior archives, build targets and unrelated
source bodies are excluded. Readable CODE inputs include selected full sources,
exact primary excerpts and precise gate summaries; omitted raw bodies remain in
this capsule for independent root inspection, not falsely attributed to reviewer
reading. Parent owns final CODE disposition, commit and merge.

The lossless approved PLAN context and fresh CODE context are retained once under
`plan-input/` and `code-input/`. The CODE verifier reconstructs every contiguous
section from its byte coordinates, checks candidate snapshots and exact original
Git/excerpt identities, and accepts `--repo`, `--siblings`, optional `--live`:

```text
nu audit/2026-10-12-bao-bounded-proof/code-input/verify.nu --repo /path/to/radio --siblings /path/to/cyber --live
```

`additional-comparisons.json` explicitly links the differently named thumb controls
and scoped lib formatting receipts. These supplement the CODE packet's summarized
observations without changing its frozen input. Root replay sidecars are retained
under `root-plan-replay/`; those replayed the prior approved research/PLAN, not this
new implementation or the final CODE packet.

Final review and all advice dispositions are in `review/code/disposition.md`.
The exact-parent Clippy library-test comparison is incomplete: 11 shared diagnostics
were emitted by both runs; three additional candidate diagnostics are attributed
to unchanged old source. No all-feature Clippy pass is claimed. Formatting stdout
is proven byte-equal after the exact repository-root and lib.rs line adjustments.
Root replay receipts describe their preserved pre-verdict 601-file capsule, while
the refreshed outer inventory also includes this final disposition.
