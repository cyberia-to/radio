# Bounded BAO traversal research

Owner: mov_pcm_resume, handed off by root; stage active, finite source observations measured. Serves the owner's Kadek phase-1
closure, foundation row 4 and `specs/runtime.md` verified source ranges.
Discovered from the proof-provenance and bounded-reducer tasks. The reducer
is a prerequisite: its production work belongs to a separate branch.

This worktree started at Radio origin/main
`dacd030c9d6301b316a96b5bc6e4ea1e1cec79f1`, confirmed by
`git ls-remote origin refs/heads/main`. No production implementation or PLAN
approval is represented here. It now ordinarily fast-forwards to the actual
reducer merge `a96d86e28d384cdf656aadc4282c78c0c170c102` (PR38), with the
original source snapshot and unsafe-geometry observations retained separately.

## Source findings

At this revision `cyber-bao/src/tree.rs` exposes
`post_order_chunks_iter`, whose constructor calls the complete allocating
`post_order_chunks` traversal. `pre_order_chunks_filtered` returns a growing
Vec built recursively. `io/fsm.rs::ResponseDecoder::new` eagerly builds that
filtered vector and initializes a spillable expected-hash stack. A resumable
group hash alone cannot bound this setup work.

Public `BlockSize(u8)` admits every integer. `blocks` shifts a u64 by that
value; `shifted` adds 12 before shifting; `bytes` shifts usize. Neither the
type nor `BaoTree::new` validates those domains. Traversal leaf arithmetic
computes `(block_idx + 1) * block_bytes` before clipping to file size. These
operations need a checked boundary for untrusted declared lengths/profiles.
This observation does not expand the approved reducer's geometry scope.

Existing slice wire carries an eight-byte little-endian complete length,
selected preorder child-hash pairs, and entire selected group payloads.
`io/slice.rs::extract_slice_ranges` has a one-group shortcut that copies all
body bytes independently of requested ranges; its general path filters.
The filtered geometry and FSM return no items for an empty range set. An
empty request therefore needs an explicit new boundary policy before proof
verification can reuse these paths. No new wire policy is chosen here.

The likely smallest next dependency is a no_std, allocation-free traversal
with admitted geometry and bounded step work, exposing selected parent/leaf
items. A separate proof machine can consume it and the group reducer. Exact
profile/range/empty-input behavior and compatibility remain PLAN questions;
no legacy convenience API change or complete proof implementation is implied.

The [PLAN](plan.md) narrows that direction to one admitted byte interval,
constant-work preorder items and fixed storage. Its empty-query result is purely
geometric. The actual reducer merge bridge is complete; fresh vendor review
is still required before implementation. The plan adds no measured production claim.

## Finite verification

The [receipt](../../../audit/2026-10-11-bao-bounded-traversal/README.md) retains
the public Rust consumer, source/lock/tool identities, exact command records,
raw debug/release output and portable verifier. The eager constructor performs
all traversal before first next. Unchecked oversized BlockSize values produce
panics or wrapped geometry; the maximum-length final group is reported one byte
too long in release. The receipt ties each number to its command/revision and
keeps allocation-request sums separate from peak memory. No body is allocated;
the maximum-length probe selects only the final path.

Inspected source: `cyber-bao/{Cargo.toml,src/{lib,hash,tree}.rs,
src/io/{slice,fsm}.rs,tests/slice_traversal.rs}` at the named revision, plus
Kadek's merged proof-provenance research and runtime source contract. Source
reads used `sed -n`, `cat` and `rg`. No repository/product gates, production
candidate, benchmark or independent vendor review has run for this unit.

## Current-parent bridge and independent expectations

The ordinary merge and before/after records are in
`/tmp/radio-bao-bounded-traversal-parent-bridge/` (11 records / 22 streams).
Actual origin/main was checked before integration. The merge tree equals source
`82a0a2931be86e211ba96e5e2188c8b68cf3252d`. Cargo.lock, root manifest, I/O
consumers, direct-owner manifests and workflow commands have empty deltas.
The predecessor's mechanical split keeps the old traversal bodies intact; this
task reads the current core/tree/traversal modules and does not reinterpret old
observations as a new candidate pass.

The author's initial three draft files are retained under
`/tmp/radio-bao-bounded-traversal-plan-evidence/initial-draft/`. Independent
inspection of literal 1/2/3/5/7/16/17-group tables confirms the complete-left
tree and selected flags. Frozen future ordinary tests supply concrete tokens,
not a second implementation of the proposed split algorithm. The maximum-file
spines use independently evaluated midpoint identities: left `2^k-1`, right
`2^53-2^k-1`, for k=52..1. The full left prefix forces 52 pending siblings plus
the current leaf; the last-only path ends with the literal 4095-byte remainder.

Admission is made precise in the plan: geometry before request, full declared
group width fitting usize even for a short leaf, safe end-minus-one rounding,
and zero items for admitted empty intervals. No algorithmic or wire-policy
change beyond the narrow proposed geometry API is needed. The original draft
had no substantive shape error; these are explicit boundary details.

Tools inspected at this epoch provide Rust 1.95 thumbv7em-none-eabi for isolated
32-bit compilation. No qemu-arm/qemu-system-arm/qemu-i386/wasmtime/wasmer command
was found on PATH. Consequently the planned cross-check is compilation, not
execution of the 32-bit runtime matrix; the host exercises 64-bit admission.
