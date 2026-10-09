# BAO exporter parent-pair width

The three `ExportBaoProgress` wire methods now emit a parent as `left32 || right32`.
Previously each copied a 32-byte Hemera Hash into a 64-byte half and panicked.
The progress writer credits the actual 64 parent bytes after a successful send.
Only `iroh-blobs/src/api/blobs.rs` and its two private test files changed.
Public APIs, roots, storage, manifests and locks are unchanged.

This is a narrow source repair serving kadek foundation row 4. It does not close
that row or establish an all-green radio/rung/release result.

## Identity and review

Measured on macOS arm64 with [rustc](rustc.txt) / [cargo](cargo.txt) 1.95.0:

- Radio parent: `764d732ac38fb9116c4cf525a6d1bb463d409a06`.
- Implementation: `62e7f53f237ceaf0f5037a396e79ff70f2c735cd`; committed bytes
  match the measured source freeze. The source commit preserves the red-gate
  `wip:` prefix and quotes the first clone_on_copy error.
- Hemera source: `23f3bbcff910ea6d504ceb505680a539260869da` (0.3.1, serde).
- Implementation identity before commit: parent plus [source.patch](source.patch),
  SHA256 `7ccebf6647d6e2e9ade1bb56fb742f8632f4169cb851827eeb3f80ee79bc9f1e`.
- Reviewed source files: [SOURCE-FREEZE.json](SOURCE-FREEZE.json), SHA256
  `293a9b6210a8f26c89e14fea4919011d9a659f13c27e3351986afb293acf549b`.
- Fresh different-vendor PLAN correction review and CODE review: APPROVE.
  [Task review](../../.claude/tasks/kadek-export-pairs/review.md) records transcript
  hashes and limits. Reviews cover frozen source, not this later receipt/reproducer.

[source-inputs.json](source-inputs.json) pins archive/lock hashes, all local package
paths from locked metadata, tool identity and API-smoke scratch hashes. Every
compile used full radio/Hemera archives, preserving the original manifests,
lints and lock; tracked `nettools/target` was excluded. No dirty sibling inputs.
The candidate contains the frozen patch; the baseline contains only test overlay.
[red-source-freeze.json](red-source-freeze.json) pins the actual historical overlay;
its test import order was subsequently formatted, without changing behavior.
The API tool's generated [manifests and locks](api-smoke/) are retained verbatim;
their absolute paths describe the historical run, not a reusable workspace.

## Independent evidence

`red-debug` and `red-release` in [gate-index.json](gate-index.json) both exit 101:
3 controls pass, 8 cases fail with the exact source32/destination64 copy panic.
The failed cases include all three literal exporter methods and the real
`ReadonlyMemStore` right-block proof. Full raw [stdout](logs/red-debug.stdout)
and [stderr](logs/red-debug.stderr) are retained. No `should_panic` masks the bug.

Eleven tests exercise literal pair ordering, each actual exporter, real store
proofs, parent-free output, missing store/error propagation, failed and partial
writes, and rejected progress notifications. The real store fixture bypasses the
separate mutable-import defects using `CompleteStorage::create`.

The oracle pins CHUNK_SIZE=4096 and log4 block size=65536 separately, derives
32 chunks / 2 blocks, and selects chunks16..32. Each leaf CV uses its absolute
counter; each 16-leaf half is reduced through four nonroot parent levels, then
one root parent combines the halves. The expected wire is assembled directly as
`LE64(131072) || left32 || right32 || body[65536..]`, independent of radio's
outboard, extractor and exporter helper. All three actual outputs equal it;
`decode_slice` returns exactly the right block. The single-chunk control has no
parent and tests the distinct header-plus-leaf case.

- [right-proof.bin](right-proof.bin): 65608 bytes, SHA256
  `108022aa95ee61a1058d6d4bb53979a95bc46de114b036fcc6620fbd65648a51`.
- [right-root.txt](right-root.txt): root Hash hex, no trailing newline:
  `9ccd2809b2bcca875ee39f2c034c80969c176a5510a66d638b2c88c3cd7c7f0f`.
- Progress overhead: 72 bytes; payload offset/length: 65536/65536.

These values come from `readonly_store_right_block` in the red-first/focused
commands at the pinned source identities. They do not establish equality between
this BAO root Hash and a plain file Particle or fix grouped-single-root behavior.

## Observed checks

[gate-index.json](gate-index.json) lists all 35 original commands with exact cwd,
timestamps and exit; `logs/<name>.stdout` / `.stderr` retain their full output.
Rust commands used `RUSTFLAGS=-Dwarnings`, docs also `RUSTDOCFLAGS=-Dwarnings`.
Archive-related vergen build-script warnings remain visible and unsuppressed.

| Commands (index names) | Observed result |
|---|---|
| `focused-debug`, `focused-debug-frozen`, `focused-release`, `focused-none`, `focused-all` | 11 pass each; final debug repeats the frozen bytes. |
| `docs` | Strict scoped all-feature docs pass. |
| `msrv-lib-tests` | Rust 1.89 all-feature library + tests check passes. |
| `clippy-all`, `baseline-clippy` | Both red: 13 existing cyber-bao errors; first `io/mixed.rs:115` clone_on_copy. |
| `clippy-primary`, `baseline-clippy-primary` | Both red: 14 existing owning-crate diagnostics; normalized message/location sets identical, none in new code. [Comparison](clippy-primary-comparison.json). |
| `full-default`, `full-none`, `full-all`, `baseline-full-default` | Compile failure before tests: unchanged examples have local/registry Endpoint/PublicKey mismatches and custom-protocol Hash64/32; no-default also imports gated fs-store. |
| `msrv` | All-target Rust 1.89 check red on the same unchanged examples; scoped pass above is not a replacement. |
| `dependents`, `gate-workspace-doc-tests` | Red in unchanged iroh-docs Endpoint/PublicKey types. |
| `gate-clippy-default`, `gate-clippy-none`, `gate-clippy-all` | Red in unchanged cyber-radio / cyber-bao sources. |
| `gate-msrv-workspace` | Red in unchanged iroh/bench unresolved radio imports. |
| `gate-format`, `gate-nextest-default/none/all`, `gate-deny` | Required tools unavailable, exit101. |
| `gate-format-expanded` | Pinned available nightly reports existing formatting drift, exit1. |
| `gate-docs-nightly` | Required nightly-2025-10-09 unavailable, exit1. |
| `tag-metadata` | v0.1.0 committed lock cannot resolve under `--locked`, exit101; lock preserved. No tag compatibility pass. |
| `api-smoke` | Base-vs-candidate only: semver-checks0.51.0 reports 202 pass / 58 skip. It resolves 451 scratch dependencies afresh; not an exact-locked or tag gate. Source locks remain unchanged. |

The baseline-vs-candidate Clippy and default-package failures were reproduced.
Broader workspace classifications refer to diagnostics in unchanged source;
they are not a claim that an entire pristine workspace run completed.
Cross/Android/wasm/netsim and remote CI were not run for this task.

Two broad library runs were manually terminated with SIGTERM, exit101/signal15:
`baseline-lib` (default/debug, observed at10:13) and `lib-all-release` (candidate
all-feature/release, observed at03:53). Both had 27 observed failed names and
three pending tests: `store::fs::tests::test_import_bao_ranges`,
`tests::two_nodes_push_blobs_fs`, `tests::two_nodes_push_blobs_mem`.
[Failed names](broad-unit-comparison.json) and [termination record](unfinished-unit-checks.json)
are retained alongside full raw logs and exact commands. Different profiles and
unfinished runs prevent a completed-suite or full-parity claim.

## Reproduce

From an ordinary checkout containing this receipt:

```sh
nu audit/2026-10-09-kadek-export-pairs/reproduce.nu \
  --radio-repo ~/cyber/radio --hemera-repo ~/cyber/hemera
```

The script reads parent and implementation Git objects into fresh `/tmp` archives
and verifies the frozen source; `--implementation-revision <source-commit>` can
override the pinned implementation only when its files match that freeze.
`--fetch` may download pinned dependencies; locks are never regenerated.
`--prepare-only` checks receipt hashes, archives, source freezes, locks and local
metadata without compiling. It reports the tag's metadata failure explicitly.
The receipt's [preparation check](receipt-validation.json) passed syntax, archive,
source and lock checks; baseline/candidate metadata each contained 20 local
packages, while tag metadata remained exit101. No product tests ran in that check.

Default execution repeats actual debug/release red-first tests, four focused
fixed modes, baseline/candidate Clippy, strict docs and both scoped/all-target
MSRV checks. It compares regenerated proof bytes with this receipt. Each command
keeps stdout/stderr/exit and independent gates continue after ordinary failure;
unexpected red-first/focused outcomes stop with diagnostics. Final exit is 1
when any ordinary gate is red, including the preserved tag lock failure.
The two unfinished broad suites are not launched. `--api-smoke` optionally runs
the explicitly unlocked scratch-resolution comparison against the exact parent.

## Remaining scope

Mutable-import pair strides, partial-storage checksum widths and `print_outboard`
still contain old-width assumptions. The stale block-size comment is unchanged.
Root-domain/profile compatibility and bounded provenance verification remain
separate dependencies for kadek. This repair proves the exporter wire and its
failure/progress behavior for the covered cases, without asserting storage-wide
width correctness, complete conformance, ring1 readiness or a release verdict.
