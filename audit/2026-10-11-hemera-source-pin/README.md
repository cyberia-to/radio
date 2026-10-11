# Hemera source delivery audit

[Final review and root disposition](review.md).

This dependency-only change gives Radio's eight workspace Hemera consumers one
exact Git source, preserving their `std`/`serde` features. It includes the narrow
separately reviewed repository allowlist addition. It changes eleven production
files and no Rust algorithms or specifications. The final full diff and both
parent/candidate files are in `code-v2/execution/final/` inside the capsule.

Inputs are Radio `a11d342594949d4ea542b26366f71d56ef21662d` and Hemera
`d5f0a09539360934fb32db9b2e15a91995607db6`. This is a local implementation
audit, not a release candidate. The bounded reducer, slice parsing, Kadek anchor
integration and cold root authority remain separate work.

The compatibility floor is major: the external legacy source-identity probe
passes on the parent (`9-probe-parent-check`) and fails with `E0308` on this
candidate (`11-probe-candidate-check`). Its unchanged Rust exchanges Radio's
concrete `Hash` with a separately path-sourced Hemera. No version, tag, release,
registry dependency, excluded FFI boundary or product release pin is changed.

Repository gates remain red. The paired all-feature build's first Rust error is
`error[E0599]: no method named 'add' found for enum 'Result<T, E>' in the current scope`
(the raw output uses Rust backticks), at `iroh-gossip/src/api.rs:468`. Parent and
candidate records are `16-ci-build-all-parent` and `16-ci-build-all`. Strict
Clippy, formatting and strict documentation also have recorded parent reds.
These results require the root's explicit decision/wip disposition; they are
not a clean repository or release verdict.

Measured scoped results, each bound to exact argv, environment, source epoch and
raw streams in `code-v2/execution/logs/`:

- `05-bao-debug` and `06-bao-release` each pass 88 existing cases. Blobs filter
  runs also pass; overlapping filters are not added into a distinct-case total.
- `21-ci-run-none` and `24-ci-run-default` each pass 547 and skip nine under the
  CI profile. These are separate feature variants. All-feature runtime remains
  blocked by the paired compile error above.
- `31-msrv-workspace` passes the Rust 1.89 workspace/all-targets check; `35-all-doctests` passes 51
  all-feature doctests. Exact labels and commands are indexed by the retained
  `execution/gate-summary.json` and readable `gate-outcomes.txt`.
- The introduced Hemera source-policy failure is repaired: source denials fall
  from five to four in `41-deny-after-policy`; all other diagnostic-heading
  counts remain unchanged. `42-deny-sources-after-policy` retains four Willow
  denials and the existing unmatched Quinn entry. Full deny remains exit 13 and
  sources-only exit 8. The advisory database is clean at identical recorded HEADs
  immediately before/after these two runs. The older pair has only a later
  observed DB snapshot.
- `43-fresh-nightly-docs-candidate` exits zero with warnings. Earlier shared
  stable/nightly target column-cache failures remain harness-sensitive and
  inconclusive. This is not a zero-warning documentation result.
- All parent/last-tag API diagnostics stop on the generated `iroh-car` helper's
  yanked `core2` resolution. Completed package checks do not establish a complete
  workspace compatibility pass, and do not waive the independent major floor.

The original last-tag `40` runs used an export with two incorrect regular license
file bodies, caused by a preparation harness following Git license symlinks.
`api/tag-correction.json` preserves every actual pre-correction entry and the two
bad bodies. The current tag export retains the symlinks as literal Git blob
bodies in the capsule; its full 854-entry Git identity is independently checked.
Only newly labelled `45` runs used that corrected export with fresh targets.
Both still exit 101 on `core2`. The old runs remain input-deviant/inconclusive.
The tag is `v0.1.0` at `f2b1298daa9f635c821d53996c4d1dc4f1042b3d`, under explicitly
current Hemera dependency inputs, not a reconstructed historical release.

Ring 1 remains unverified. Soft3 `44824e6cf64f5b0b1d7443eea412001e74c5f32e`
metadata fails in `38-soft3-metadata` because committed cybergraph
`42fc2512389c7411d8cc3461501d859c1545980e` lacks the requested `local-storage`
feature. There is no current direct Radio Cargo edge in that product; this
prerequisite failure does not exercise candidate Radio integration. Product
build/runtime/conformance, specification/Kelvin checks, wider platforms,
minimal versions, netsim and ring 2 remain unverified.

## Evidence and replay

Run from the repository root:

```sh
nu --no-config-file audit/2026-10-11-hemera-source-pin/verify.nu audit/2026-10-11-hemera-source-pin
```

The verifier requires Nushell, `tar`, `mktemp` and `shasum`. It needs no Cargo,
network, Ruby, Python, sibling checkout or live Git repository. It checks outer
checksums, regular-only archive entries, content-addressed objects, both full
CODE packs and the original/amendment PLANs, exact Git blob bodies, complete
metadata parity, 96 raw command records/192 streams and both historical tag
epochs. This validates saved evidence; it does not rerun gates or authenticate a
Git remote. The original Ruby replayers and root's historical 94-record replay
are retained as provenance. The fresh root CODE replay and vendor verdict are
separate final disposition sidecars.

`evidence-index.json` maps logical paths to `objects/<sha256>` in
`evidence.tar.gz`. Identical files across both CODE packs are stored once;
`capsule.json` records exact sizes and counts from `build-capsule.rb`. CODE v1
was not submitted because its 555820-byte review exceeded the launcher's limit.
CODE v2 is 493061 bytes; the only presentation change replaces repetitive gate
summary JSON with a readable outcome/hash table. The full summary remains in
support. Every complete changed production file remains inline.

Both fresh PLAN approvals, full packs, source manifests, reviews and execution
receipts are retained. Large post-run rustdoc bodies are explicitly omitted
with inventories; they were observed artifacts, not proof of both consumed API
inputs. Redundant original archives and external product source copies are also
explicitly omitted with exact source/hash references in `prepared.json`.
No SDK archive is republished. Full raw implementation streams are retained.

The two incidental EOF blank-line removals were restored before final source
freeze. Complete parsed TOML and default/none/all locked metadata equality are
recorded in `final-bridge/`; earlier command snapshots remain unchanged. Run 01
predates the runner-hash field and retains its original runner without a
contemporaneous binding claim. The initial historical serde resolution probe
omits the later job/incremental controls and proves dependency resolution only.
