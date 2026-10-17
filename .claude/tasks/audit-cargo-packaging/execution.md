# Packaging execution

Stage: approved; final handoff to root. Fresh Opus PLAN v2 approved at 2026-10-13 01:58:51 UTC;
raw SHA256 `27a51f83e0ea67a2fbd7951f8bf83a2572ea4fe859a95d99a33d90f233a7dec4`.
Root read the verdict and independently replayed the frozen input. V1/v2 packets,
both raw reviews and exact launchers are retained without modification.

Adopted advice: normalize only allowed parsed-JSON fields, measure the real audit
tree before/after deliberate staging failures, compare the complete candidate
tree against ce0 using an explicit path allowlist, and enforce the audit manifest
basename guard. The historical external parent directory remains intact.
Global source-manifest escape checks are deferred: legitimate sibling manifests
make that a broader policy change with possible false positives. No such cleanup
or new production guard belongs to this approved packaging unit.

The review's claim that all six other manifests share one relative path is not
used as an oracle; their exact seven bodies and individual mappings are the input.
The slice harness, for example, uses `path = "cyber-bao"`. The demonstrated defect
and approved lossless inventory do not depend on that optional causal shorthand.

The following implementation and paired measurements are complete. The original
ce0 control remains historical; no full-workspace/rung/last-tag gate refresh or
release is implied by these focused consumer results.

## Final measured candidate

The approved seven lossless renames and three preserved-original wrappers are
implemented. The final child invocation uses `complete`, prints each captured
stream with `--no-newline`, then passes the exact exit code to cleanup/retention.
Nu otherwise aborted before the retention notice on a nonzero child. The initial
wrapper's successful replays remain valid, but its failure-path epoch is not the
final implementation. A separate status-77/no-newline witness closes this gap.

Same-session local Git controls at ce0 and temporary candidate
`e22c5b472a0979ad382d241b9706de5b82fed9a9` pass: parent duplicate warnings 4/4,
candidate warnings 0/4, eight identical literal cases in both debug/release
profiles, 63 exact crate source tuples, three dependency nodes, 34 allowlisted
parsed-JSON substitutions per arm. This uses Rust 1.95, jobs 2, incremental 0,
`RUSTFLAGS=-Dwarnings`, independent Cargo homes/targets and only local Git
acquisition (exact Hemera d5 URL rewrite recorded). The external warning-causing
manifest is unchanged across all three observations. No broad-gate conclusion.

The first private snapshot attempt failed at bare-index deletion before Cargo;
`--index-info` corrected it. The second was deliberately interrupted as wrapper
handling changed, preserving its null signal exit in raw evidence; it did not
complete a control arm. The third completes both arms. The temporary committed
snapshot contains the final packaging code and then-current owned task/audit
inputs; later additions are evidence/report files only. Its incremental bundle
and full explicit path list remain replayable against ce0. Final packaging bytes
are frozen separately, so subsequent receipts do not masquerade as the measured
snapshot tree.

Exact historical reconstruction passes 13/90/620 files, two old prepare calls,
two pre-execution failure controls, three default CLI controls and unchanged
research/proof/CODE input replays. `--live` intentionally retains original b933
HEAD failures after ce0, with no new clean-tree policy. The global manifest-escape
guard remains deferred: valid source manifests may intentionally use sibling
paths. The exact audit `Cargo.toml` basename guard is part of final replay.

## CODE disposition

Fresh Opus CODE approved at 2026-10-13 02:30:25.146207 UTC, raw SHA256
`6ae0759ac1d44661e5705914a672007374e17c31cd9b9090b3340b37437176e3`.
Root read the full verdict. No reviewed wrapper or verifier implementation was
changed after approval. `audit/2026-10-13-audit-cargo-packaging/review/code/disposition.md`
records the optional advice, buffering/relative-path constraints and exact
measured-witness versus final-evidence epoch boundary. Root owns commit, PR,
ordinary merge and the fresh HTTPS consumer on that actual merge. No version,
tag or registry publication is authorized in this unit.
