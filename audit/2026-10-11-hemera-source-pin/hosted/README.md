# Hosted CI supplement for PR 37

Read-only investigation of completed jobs from run `38177461896`, fetched with
`gh api repos/cyberia-to/radio/actions/jobs/<id>/logs`. Each retrieval has exact
argv/time/exit and compressed plus decompressed SHA256 receipts. Full raw stdout
is retained as gzip, including ANSI and timestamps; nothing was corrected in a
log. `summary.json` gives bounded first-error records; `analysis.json.gz` retains
all spelling findings, format locations and Git comparisons. `analyze.rb` records
the derivation. No gate was rerun and no source or CI policy was changed.

All job metadata names head `d90a784fa6a7f410492cc6c6d5242527e221c399`.
Checkout logs show synthetic merge `2d606fbc2638c52c9613ea7d712a6f35ee32a48c`.
Its GitHub commit receipt names parents `a11d342594949d4ea542b26366f71d56ef21662d`
and `d90a784fa6a7f410492cc6c6d5242527e221c399`; its tree
`0f77ec947fb72f1ea9c4df3dd82514aa03294fb6` equals the committed source tree.
This binds the actual hosted checkout rather than assuming it equals the PR head.

| Job | First decisive result | Attribution and limit |
| --- | --- | --- |
| Wasm `114582766431` | `cannot specify features for packages outside of workspace` | The unchanged workflow runs `cargo build --target wasm32-unknown-unknown -p iroh-base --all-features`; the parent manifest already names `cyber-radio-base`. Existing selector mismatch. Later builds/browser tests skipped. |
| Semver `114582766550` | `no matching package named cyber-hemera found` | The error names the exact `git-a11d342.../hemera/rs` baseline export. Current `iroh-bench` parses before this baseline resolution failure. Existing parent delivery prerequisite; no complete API pass. The independent major Hash floor remains. |
| Format `114582766273` | First diff: `iroh-blobs/examples/blobs-transfer.rs:85` | 300 diff sections across 131 distinct files. Every file has the same Git entry at parent and head; workflow/Makefile unchanged. Existing formatting under hosted Rust 1.99.0. |
| Docs `114582766525` | `failed to read column from disk: data consumer error: invalid type: null` | Nightly 2025-10-09 fails writing the rustdoc search index. Similar failure exists in saved local parent diagnostics, but this hosted platform was not rerun on the parent. Cause remains unresolved; no inferred cache cause or documentation pass. |
| Clippy `114582766577` | `trailing semicolon in macro used in expression position` | Hosted Rust 1.99.0 fails the macro in `quinn/quinn-udp/build.rs:5`. That source, its owning manifests, workflow and exact locked macro dependency are unchanged. Existing inputs meet a newer compiler than the local Rust 1.95 matrix; no hosted-parent execution claimed. Other feature checks skipped. |
| Deny `114582766560` | Missing Hemera license expression | Cargo-deny 0.20.2 retains the four Willow source denials and unmatched Quinn entry, with license/advisory reds. No Hemera source denial or unmatched Hemera allowance. Compared with saved local post-policy output, one event-listener advisory heading is absent; all other error-heading counts agree. Hosted advisory DB identity is not available, so no identical-DB claim. |
| Spelling `114582766443` | 157 findings | 139 findings are in byte-identical parent files. The 18 introduced findings occur only in the new evidence index and refer to literal repository/format names in recorded logical paths. Exact findings and source lines are retained in `analysis.json.gz`; original index bytes remain untouched. |

The spelling red is introduced and explicitly retained. Rewriting names would
corrupt provenance. A separately reviewed policy can recognize legitimate names
as vocabulary, or define a precise rule for verified generated metadata; either
changes spelling policy and needs its own justification. A broad audit skip or
unreviewed ignore-list expansion is not proposed here. This supplement preserves
the current red and makes no claim that hosted CI is green.

No observed hosted failure establishes a new implementation blocker in the
eleven-file source migration. This is bounded attribution: unchanged source
identity is not a substitute for an unexecuted parent run, and rustdoc's cause
remains unresolved. The prior decision/wip and major-floor disposition remains
necessary; source merge and release readiness are separate decisions.

Verify saved retrievals and derived counts without network or Cargo:

```sh
nu --no-config-file audit/2026-10-11-hemera-source-pin/hosted/verify.nu audit/2026-10-11-hemera-source-pin/hosted
```

`SHA256SUMS` covers this supplement independently, leaving the already reviewed
capsule and its checksums untouched. Root owns any final commit, push and merge.
