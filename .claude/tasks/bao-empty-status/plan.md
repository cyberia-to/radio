# Fs synthetic empty status — PLAN amendment

Stage: active. Fresh Grok4.7 PLAN APPROVE preceded production edits; the exact
reviewed draft and raw verdict remain frozen in the audit. Fresh CODE APPROVE and
root disposition are retained in audit/2026-10-11-empty-status/.
Serves Kadek phase 1 foundation row 4. Discovered from `bao-empty-root`, superseded
unmerged implementation against 344ac162. Current Radio
`bc8b6331d3c76cbc011210e13f81e6ea351ef06f`, Hemera
`d5f0a09539360934fb32db9b2e15a91995607db6`. Ordinary source repair only.

## One remaining production change

Immediately after destructuring BlobStatusMsg in
`iroh-blobs/src/store/fs/meta.rs::handle_get_blob_status`:

```rust
if hash == Hash::EMPTY {
    tx.send(BlobStatus::Complete { size: 0 }).await.ok();
    return Ok(());
}
```

All other paths remain byte-identical. Reuse existing imports, no helper or API.
The canonical EMPTY constant, its upstream documentation and equality test are
already fixed and must remain unchanged. The status query describes the file's
logical availability through existing synthetic reads and exports.

Files: this four-line addition in existing977-line meta.rs; only a cfg(test)
`mod empty_root` declaration in existing621-line hash.rs; the three independent
test files `hash/empty_root.rs` and `hash/empty_root/{stores,remote}.rs`; task
artifacts and measured audit/review receipts. Each new Rust file is below500 lines.
These are narrow existing-file exceptions. No spec, manifest, lock, dependency,
version, docs-engine, storage-schema, list, deletion or Hash identity edit.

## Steps and decisive checks

1. Freeze current origins, committed dependency closure and test-only witness →
   verify raw origin/metadata receipts, unchanged locked inputs, exact parent
   production plus one cfg(test) declaration and three test files. Current debug
   witness has15 pass/2 Fs NotFound failures; preserve it and the release witness.
   The separately measured current listing is [] before/after empty add. Current
   Hemera primary contracts/literals match old byte hashes; optimized code does
   not. Fresh literal/domain controls, not that historical implementation, justify
   reuse of the published expected bytes.

2. After fresh PLAN approval, copy the exact17-test sources/module to the owned
   worktree and candidate export, then add only the guard → verify production
   diff exactly matches this plan. Keep the two existing failing Complete{0}
   assertions. Final all/default/release tests should execute17; no-default15
   because the two Fs tests are feature gated. The named existing EMPTY equality
   test stays upstream-identical and runs as an additional control.

3. Validate synthetic availability through public storage APIs → verify fresh
   status/has, actual add in Raw and HashSeq formats, reads/reader, observe and
   completion, exactly eight zero BAO-header bytes, shutdown/reopen and forced
   deletion. Lists stay empty after current empty adds. Old zero and hello start
   absent; a real hello add is Complete5, exact bytes and LE64(5)||hello export
   before/after reopen, with only hello enumerated. No claim of empty persistence.

4. Preserve admission, identity and verifier controls → verify fixed literal
   empty tree/plain-particle distinction, canonical/zero/hello raw and ticket
   serialization, leaking tag formats; local zero-header guard, short-header and
   wrong-key wrappers; actual remote ResponseDecoder empty success and wrong-root
   leaf mismatch; successful nonempty local/remote control. Tests use existing
   APIs and byte transports, with one finite30s bound, no retry or fake verifier.

5. Exercise the current reverse closure → verify metadata includes iroh-docs,
   radio-cli and radio-integration-tests; test them using actual local package IDs.
   Read full docs engine status/download consumers. The changed Complete result
   avoids requesting already available synthetic empty content. Existing
   tombstone identity/validation remains byte-identical. Registry willow is still
   separate. A downstream failure gets its current-parent counterpart, never an
   explanation copied from old 344ac162 diagnostics.

6. Freeze source and gate receipts → verify exact files, command/environment/time,
   stdout/stderr hashes, locked inputs and current-parent negative comparisons.
   Request fresh CODE review for this narrower current-origin source. Preserve
   both historical and amended plans/verdicts as separately labeled evidence.

## Gates after approval

Use separate committed-source parent, witness and candidate exports with current
pinned Hemera. Only tracked nettools/target is excluded with inventory. Ordinary
actual Rustup1.95.0, MSRV1.89.0, named docs nightly-2025-10-09; matching Cargo,
RUSTC and RUSTDOC, two jobs, RUSTFLAGS=-Dwarnings. Strict owning docs use
RUSTDOCFLAGS=-Dwarnings; named CI docs keep --cfg docsrs. Retain archive VERGEN
warnings without calling a successful exit warning-free. Coordinate targets with
root; clean completed owned targets only,20GB staging and30GB hard budget.

| Scope | Executable check |
|---|---|
| Failure-first | Current production plus test-only overlay: `cargo test --manifest-path iroh-blobs/Cargo.toml --lib empty_root --all-features --locked --offline`, debug/release; current public enumeration probe. |
| Candidate focused | Same owning filters all/default/no-default/release; existing test_empty_hash, root_policy, export_pairs and parent_pairs. `cargo test -p cyber-bao --all-features --locked --offline`. |
| Current broad behavior | Parent and candidate native owning nextest with `--lib --all-features --locked --offline --test-threads 1 --profile default --no-fail-fast`, unchanged committed30s bounds. Per-name outcomes and actual diagnostics. |
| Current reverse consumers | `cargo nextest run -p iroh-docs -p radio-cli -p radio-integration-tests --all-features --lib --bins --tests --locked --offline --profile default --test-threads 1 --no-fail-fast`; parent counterpart for every candidate failure. No older package-ownership shortcut. |
| Owning gates | All-target/all-feature Clippy `-- -D warnings`; strict private owning docs; `git diff --check`, `cargo fmt --all --check`, `cargo make --disable-check-for-updates format-check`. |
| Workspace stack gate | Current `cargo test --workspace --locked --no-run`; bounded workspace runtime is covered by the named CI nextest execution below, without a duplicate matrix. Distinguish it from the unbounded train command. |
| Named CI tasks | Exact workspace nextest no-run and Clippy target/feature loops default/none/all; workflow feature/doctest package loops and workspace all-feature doctests. Runtime commands use the committed profile ci bounds when reached; missing/failed compilation remains a gate failure. |
| MSRV | Actual1.89 owning filters above, plus literal CI `cargo check --workspace --all-targets --locked --offline` (the step title says all features but argv omits that flag). Current consumers also compile. |
| Named nightly docs | Actual pinned nightly `cargo doc --workspace --all-features --no-deps --document-private-items --locked --offline`, CI RUSTDOCFLAGS. |
| Dependency policy | Verified cargo-deny0.18.9 binary; `cargo deny --workspace --all-features --locked check --disable-fetch -Dwarnings` with unchanged frozen advisory DB identified before each run. |
| API | Semver0.51 against exact current parent and last-tagv0.1.0 source, pinned current Hemera; retain actual helper manifests/locks and disclose scratch resolution separately from committed-lock gates. |

Read the current workflow argv before executing named tasks. Metadata may still
resolve literal CI names iroh/iroh-relay to registry packages; report that honestly
and keep actual local consumer gates separate. For each required current red
format/lint/docs/compiler result, run a matching current-parent command and retain
complete diagnostic differences. For test failures/timeouts compare names and
causes, never counts alone. Do not rerun whole matrices merely to seek green.
No cross-target fleet, minimal-version dependency mutation, hosted CI, kelvin,
rung or release pass is implied by local checks. Required reds retain wip/decision
accounting; owner authorization covers this ordinary source fix, not release.

## Failure questions and boundaries

1. Did upstream already fix the guard? Current source and the two unchanged
   ordinary assertions prove it has not; recheck origin immediately before merge.
2. Are old vectors valid after Hemera optimization? Pin current contract/literal
   byte identity and execute current domain/nonempty controls; do not claim full
   implementation equivalence.
3. Does synthetic status mask absent/nonempty data? Match only canonical EMPTY;
   fresh/reopened zero/hello negatives and real hello round trips exercise the
   unchanged lookup. Legacy empty inconsistency masking is explicitly accepted.
4. Did changed dependency wiring widen the effect? Current docs engine is a local
   consumer; run it and preserve tombstone/signature/identity code unchanged.
5. Are stale tests or errors misattributed? Current source/lock manifests and
   failure-first receipts are independent of old344 evidence. Current listing
   already omits synthetic empty; this guard changes status/has only.

MemStore pre-add consistency, bounded proof work/allocation and authenticated
particle/root/length binding remain separate. No API or identity migration and
no release/version/tag action. Root owns review invocation, commit and merge.
