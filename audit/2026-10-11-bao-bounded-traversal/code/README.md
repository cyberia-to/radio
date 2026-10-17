# Checked traversal implementation evidence

Candidate gate base: Radio `a96d86e28d384cdf656aadc4282c78c0c170c102`.
Fresh Grok PLAN and fresh Opus CODE approved without blockers. The [raw CODE review](review/result.md) and [root disposition](../../../.claude/tasks/bao-bounded-traversal/code-review.md) preserve their exact scope.
[Execution and disposition](../../../.claude/tasks/bao-bounded-traversal/implementation.md)
names exact commands, source epochs, outcomes and limits. The four source/test
paths add an allocation-free geometric cursor over one admitted byte range.
This does not close proof verification, particle/root association or a rung.

CODE v4 is 470,917 readable bytes, 144 sections, SHA256
`a06d3318e3593bfc86a13289b12f6b1d237cbb930c9b93829a58141b4d947616`.
Final selected-source digest is
`53f29b5b1cf4d609ecb98c7b482198f87160fb56fdb229466bff8f33568a90eb`.
The capsule retains 3,967 logical payloads as 934 distinct objects, including
696 final selected inputs, five source snapshots, 84 command records and 168
raw streams. Every gate names actual argv, environment, source and start/end
UTC times. Observed results were recorded on 2026-10-12, not the directory date.

Final owning debug/release suites pass in default/all/no-default modes. Workspace
nextest default and no-default each pass 563 tests with 9 skipped at source
771518d6; the final bridge changes only imports in two test files, followed by
six fresh owning runs. All-feature nextest fails compiling iroh-gossip on both
candidate and parent. Existing strict Clippy, workspace formatting, cargo-deny
and nightly-doc failures remain red, with exact parent pairs. Last-tag no-default
API comparison still requires a major update in six check categories; current
parent API comparisons both pass. None of this is a release verdict.

The isolated thumb library compiles. The finite no_std binary fails because no
global allocator is provided, also observed with a parent pure-geometry control.
Pinned Hemera depends on alloc. No substitute allocator or 32-bit runtime claim
is introduced. Host allocation tests concern the cursor itself.

Run from the repository root:

```text
nu audit/2026-10-11-bao-bounded-traversal/code/verify.nu audit/2026-10-11-bao-bounded-traversal/code
```

Nushell, Git and tar suffice. The verifier checks outer checksums, safe regular
object inventory, complete object hashes, CODE reconstruction, all source and
command/stream identities, final owning/API outcomes, parent E0432 and measured
link/compile boundaries. It first replays the unchanged sibling PLAN and original
research capsules. It does not rerun Cargo or authenticate remote Git history.

The 4,489-entry API baseline Git inventory and its live verification receipt are
retained; their full archive bodies remain external and are explicitly not
portable here. Compiled targets and nested historical capsules are excluded.
Omitted broad review support is hash-indexed, never claimed reviewer-read.
Original preparation failures (tool PATH, late no_std snapshot, oversized or
incomplete packet attempts) remain diagnostic evidence. Final CODE verdict and root merge disposition are separate from this immutable archive.
