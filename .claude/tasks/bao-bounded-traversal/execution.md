# Bounded traversal — pre-implementation evidence

Current parent is Radio `a96d86e28d384cdf656aadc4282c78c0c170c102`, the actual
PR38 merge. The ordinary fast-forward preserves this task's untracked artifacts.
The 11 Git command records / 22 raw streams in
`/tmp/radio-bao-bounded-traversal-parent-bridge/` bind the before/after refs,
remote main observation, full changed-path list, empty protected-source delta
and equality to reducer source `82a0a293…`. No production edits exist.

`/tmp/radio-bao-bounded-traversal-plan-evidence/` freezes 26 current Radio files,
the two future ordinary test files and the external consumers before their
runs. Witness SHA256 identities are in `witness-freeze.json`; task draft originals
are retained in `initial-draft/`. Tests remain external pending PLAN approval.

Six records under `records/` use matched Rust 1.95 tools, private target,
jobs 2 and incremental 0. Every record carries exact argv, environment,
source/input before-and-after checks, lock epoch and original streams:

- `geometry-resolve` / `probe-resolve`: external offline lock resolution,
  exit 0. These are separate consumer closures, not a workspace gate.
- `geometry-debug` / `geometry-release`: unchanged original probe body, now
  against a96d86e, exit 0 because expected panics are caught. The eager 4096-leaf
  constructor still builds 8191 items in 12 allocation/reallocation requests,
  totaling 393120 requested bytes before the first next. These are requested
  bytes, not peak/live memory. Oversized BlockSize values retain debug panics /
  release wrapping. The u64::MAX last group still panics in debug and reports
  4096 bytes in release instead of the independent literal remainder 4095.
- `probe-debug` / `probe-release`: frozen future tests fail to compile with
  E0432, unresolved `cyber_bao::traversal`, exit 101. No test body executes;
  these establish public-API absence only. Ordinary repository parent negatives
  must still run after PLAN approval and before production changes.

The first geometry resolve wrapper used /tmp for its own input path while Ruby
expanded __dir__ to /private/tmp. Cargo completed and its streams remain, but
the wrapper aborted while constructing post-run metadata. Its incomplete
record and original script are preserved under `preparation/`; no successful
gate is claimed for that attempt. The corrected runner normalizes its own
path, and all six complete records bind unchanged inputs.

The original dacd probe, three records and portable research capsule remain
unchanged. They retain their source epoch. Current observations confirm the
same geometry defects after the predecessor's feature/mechanical split; they
do not authorize legacy API fixes or establish new cursor behavior.

The selected primary source packet pins current Radio callers, Hemera's exact
tree contract and current origin-ref Kadek runtime / soft3 registry. The latter
two bodies match their predecessor snapshots exactly. Tool inventory confirms
the installed Rust 1.95 thumb target; no queried 32-bit runner is available.
Future 32-bit evidence is explicitly compilation, with runtime admission tested
on this 64-bit host. No candidate/repository/rung gate or vendor PLAN verdict is
claimed yet.

Two unsubmitted PLAN packets exceeded the requested 250 KB target (279379 and
251555 bytes). Both remain packaging history. The final version deduplicates
repeated command metadata and hash-indexes prior reducer/test material outside
this cursor's call graph; current decisive source, contracts, complete new
witnesses and every current-parent raw outcome stay readable.
