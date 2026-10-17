# Gate results on exact b933 parent

All results are local observations, not hosted CI or release acceptance. The full
argv, source epoch, stream hashes and precise comparison scope are in gate-ledger.json
and comparisons.json. Raw records remain unchanged. Rustup 1.95 is matched to its
Clippy driver; jobs=2, incremental=0, --locked/--offline are local strengthening.
Nextest uses the retained CI configuration plus an explicit local 10-second slow
period/three-period termination, --test-threads=1 and staging relays. The nightly
documentation row effectively uses RUSTDOCFLAGS=--cfg docsrs; its actual warnings
are retained, and it is not described as warnings-denied.

| Gate receipt | Exit | Observed result |
| --- | ---: | --- |
| `ci-selector-iroh-bench` | 0 | completed successfully |
| `ci-selector-iroh-dns-server` | 0 | completed successfully |
| `ci-selector-iroh-relay` | 101 | error: cannot specify features for packages outside of workspace |
| `ci-selector-iroh` | 101 | error: cannot specify features for packages outside of workspace |
| `final-interleaved-clippy-none` | 0 | completed successfully |
| `final-interleaved-format-new` | 0 | completed successfully |
| `final-interleaved-proof-debug-default` | 0 | 18 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `final-interleaved-proof-debug-none` | 0 | 18 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `final-interleaved-proof-release-default` | 0 | 18 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `final-interleaved-proof-release-none` | 0 | 18 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `local-native-cyber-radio-relay` | 0 | completed successfully |
| `local-native-cyber-radio` | 0 | completed successfully |
| `nostd-binary` | 101 | error: no global memory allocator found but one is required; link to std or add `#[global_allocator]` to a static item that implements the GlobalAlloc trait |
| `nostd-library` | 0 | completed successfully |
| `owner-clippy-all-final` | 101 | error: using `clone` on type `Hash` which implements the `Copy` trait; 1 warning lines |
| `owner-debug-all-final` | 0 | 121 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `owner-debug-default-final` | 0 | 118 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `owner-debug-none-final` | 0 | 45 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `owner-doc-default` | 0 | completed successfully |
| `owner-doc-none` | 0 | completed successfully |
| `owner-msrv` | 0 | completed successfully |
| `owner-release-all-final` | 0 | 121 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `owner-release-default-final` | 0 | 118 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `owner-release-none-final` | 0 | 45 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `ready-clippy-none` | 0 | completed successfully |
| `ready-format-lib-candidate` | 1 | see raw output |
| `ready-format-lib-parent` | 1 | see raw output |
| `ready-proof-debug-default` | 0 | 17 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `ready-proof-debug-none` | 0 | 17 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `ready-proof-release-default` | 0 | 17 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `ready-proof-release-none` | 0 | 17 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `semver-parent-default` | 0 | completed successfully |
| `semver-parent-none` | 0 | completed successfully |
| `semver-tag-default` | 101 | error: running 'cargo update' on crate 'cyber-bao' failed with output: |
| `semver-tag-none` | 101 | error: running 'cargo update' on crate 'cyber-bao' failed with output: |
| `workspace-clippy-all` | 101 | error: consider using `sort_by_key`; 1 warning lines |
| `workspace-clippy-default` | 101 | error: using `clone` on type `Hash` which implements the `Copy` trait; 1 warning lines |
| `workspace-clippy-none` | 101 | error: consider using `sort_by_key`; 1 warning lines |
| `workspace-deny` | 13 | error[no-license-field]: license expression was not specified in manifest for crate 'cyber-hemera = 0.3.1' |
| `workspace-doctests` | 0 | 51 passed / 0 failed / 0 ignored (all Cargo test summaries) |
| `workspace-format` | 105 | see raw output |
| `workspace-msrv` | 0 | completed successfully |
| `workspace-nextest-all-isolated` | 101 | error[E0599]: no method named `add` found for enum `Result<T, E>` in the current scope; 1 warning lines |
| `workspace-nextest-default-isolated` | 100 | Summary [ 307.893s] 580 tests run: 575 passed (4 slow), 5 failed, 9 skipped; error: test run failed |
| `workspace-nextest-none-isolated` | 100 | Summary [ 295.185s] 580 tests run: 575 passed (2 slow), 5 failed, 9 skipped; error: test run failed |
| `workspace-nightly-docs` | 101 | warning: output filename collision.; 9 warning lines |

Parent pairs are narrower where named failing-cases; they do not rerun unrelated
passing tests. Five mDNS cases fail on both default and no-default candidate and
parent runs. Compilation/lint/docs/fmt/policy reds remain real gate failures even
when present on the exact parent. Unknown causes are not attributed to memory or
network policy without evidence. Cached offline deny is not a fresh advisory fetch.

The literal CI selectors iroh/iroh-relay fail because those package names do not
select local workspace packages. Explicit cyber-radio/cyber-radio-relay all-feature
native checks verify the actual renamed sources. Broad workspace default/none
runs exercise the local docs/blob/CLI/integration consumers. No external product
closure, Linux/Windows run, 32-bit runtime or final no_std allocator-free link is
claimed. The isolated thumb library succeeds; candidate and parent binaries fail
for the existing Hemera allocator dependency.

Source epochs matter: owner final matrices have 17 new tests (default118, all121,
none45); the later one-line module-order correction has targeted ready checks.
The final interleaved test adds an 18th new test without production edits, and only
its focused checks are new. Original source/test/format/Clippy invocation failures,
the mixed parent/candidate cache incident and harmless cleanup-guard refusal are
retained as historical rows; they are not substituted for current final outcomes.
