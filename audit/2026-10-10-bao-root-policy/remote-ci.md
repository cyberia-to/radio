# PR33 remote CI snapshot

Read-only GitHub collection on 2026-10-10; no cancellation, rerun, comment, merge, or repository edit. `gh version 2.92.0`, Nushell 0.112.2. API request argv, timestamps, exit, stdout/stderr and SHA256 are preserved per `*.receipt.json`. All downloads completed with exit 0. `SHA256SUMS` covers the resulting payloads.

## Source and observed state

- PR33 head: `f2b42c0674c586599b7defa72150ca2c5f8c4655`; base: `fd90677c2fd3aa61a9aa9db1a07a5c1c234320cd`.
- Hosted checkout, demonstrated by job `git log -1 --format=%H`: synthetic merge `0c13d791e749082ed169a4b1a4c2513b639da5c4`.
- PR32 comparison head: `8d0ff6ccf10af71b3518701d4bccdeef5eb5e910`; hosted checkout: `aff7c792d79df27908a35153ae0b0a4c393739f8`, merging that head into `764d732ac38fb9116c4cf525a6d1bb463d409a06`. PR32's eventual merge commit differs from its tested synthetic checkout.
- Final PR33 active-jobs snapshot requested 02:10:32Z, completed 02:10:33Z. Main CI run `38015735714`: 8 hosted failures and 17 queued self-hosted jobs (9 Linux, 4 Windows, 4 macOS); no assigned runner for those 17. PR32 run `38006719216` has the same 8 failures and 17 queued jobs, queued since 23:55:07Z. This is a finite observation of unassigned jobs, not a runner-inventory claim.
- Other PR33 runs: Docs Preview `38015735646` failed; Commits `38015735593` succeeded; Flaky CI `38015735613` succeeded with its test job skipped. Prior CI `38015735635` was cancelled (25 jobs cancelled); prior Flaky CI `38015735608` was cancelled, with notify success and tests skipped. Cancellations are observed remote state; the collector made none.
- All 56 check/job records captured: 9 failures, 17 queued, 25 cancelled, 3 successes, 2 skipped. Full workflow CI is still nonterminal. There is no green CI or platform-test result.

## Exact failure comparison

`setup-failure-comparison.json` contains eight corresponding PR32/PR33 failure blocks, equal after removing outer GitHub timestamps and ANSI colour only, and extracting from `failed to load manifest for workspace member` through `No such file or directory (os error 2)`:

| Job | PR32 job | PR33 job |
|---|---:|---:|
| Checking fmt | 114077088845 | 114105448417 |
| Checking docs | 114077088939 | 114105448440 |
| clippy_check | 114077089027 | 114105448442 |
| Minimal Supported Rust Version | 114077089007 | 114105448396 |
| Build & test wasm32 for browsers | 114077088835 | 114105448383 |
| check_semver | 114077088936 | 114105448410 |
| cargo deny | 114077088956 | 114105448370 |
| Docs preview | 114077084776 | 114105443884 |

The manifest chain is `iroh-dns-server` → `cyber-radio` → `cyber-radio-relay` → `cyber-hemera`; `/home/runner/work/radio/hemera/rs/Cargo.toml` is missing. Cargo-deny's container path is `/github/hemera/rs/Cargo.toml`. These jobs failed before source compilation or their intended gate. Whole logs differ; only the explicitly extracted failure blocks are identical.

Codespell (`114077088822` → `114105448219`) has 136 → 137 findings, none removed. The sole addition is `./roadmap/soft3-radio.md:220: tru ==> through, true`, from the docs-only base commit. `source-comparison.json` records its exact source and verifies five setup paths byte-identical across PR32 head, PR33 head, and PR33 base: CI/docs/tests workflow files, root Cargo.toml and iroh-relay/Cargo.toml. The added line refers to `tru/specs/locus.md`; this receipt preserves the diagnostic without changing the page or spellchecker.

## Collection and verification

`capture.nu` executes `gh` and retains raw text, hashes and process exit. `collect-logs.nu` downloaded all 24 non-cancelled/non-skipped completed job logs across the captured runs. Cancelled/skipped/queued jobs are retained in API metadata; logs were not requested for them. API counts are checked against returned arrays (all pages fit `per_page=100`). No unchecked truncated result is treated as complete.

Representative commands (every expanded command is in its receipt):

```nu
nu capture.nu pr33 api repos/cyberia-to/radio/pulls/33
nu capture.nu pr33-runs api 'repos/cyberia-to/radio/actions/runs?head_sha=f2b42c0674c586599b7defa72150ca2c5f8c4655&per_page=100'
nu capture.nu pr33-checks api 'repos/cyberia-to/radio/commits/f2b42c0674c586599b7defa72150ca2c5f8c4655/check-runs?per_page=100'
nu capture.nu pr33-final-active-jobs api 'repos/cyberia-to/radio/actions/runs/38015735714/jobs?filter=all&per_page=100'
nu collect-logs.nu
nu analyze.nu
nu check-sources.nu
```

The scripts currently pin `/tmp/radio-bao-root-remote-ci`; `check-sources.nu` additionally reads committed Git objects from the owned root-policy worktree. Scripts consume only read-only GitHub/Git operations and write the receipt directory. `analyze.nu` recomputes all capture hashes and derives exact failure and codespell comparisons. The initial attempts to pass `--version` through the Nu wrapper were rejected by its argument parser before invoking GitHub; `gh version` then succeeded and is captured. No remote outcome was inferred from those local wrapper errors.
