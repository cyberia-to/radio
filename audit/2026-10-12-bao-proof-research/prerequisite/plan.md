# Bounded BAO range traversal

Stage: draft; independent PLAN review pending, no production changed. Serves the owner's Kadek phase-1
closure, Radio/soft3 and foundation row 4 (bounded authenticated source ranges).
Discovered from the [measured traversal research](research.md). The bounded
group reducer merged in Radio PR38. Current parent is origin/main
`a96d86e28d384cdf656aadc4282c78c0c170c102`, tree-identical to reviewed source
`82a0a2931be86e211ba96e5e2188c8b68cf3252d`. The ordinary fast-forward and exact
owning source bridge are retained; the original unsafe-geometry observations
remain attributed to `dacd030c9d6301b316a96b5bc6e4ea1e1cec79f1`.

## Smallest useful boundary

Add an allocation-free, no_std preorder cursor for one requested byte interval.
It emits the existing `BaoChunk` geometry needed by a future proof verifier.
No hash, authentication authority, proof parser, I/O migration, particle/root
association or legacy traversal behavior changes in this unit. A caller with
multiple source ranges can create one cursor per range; multi-range union and
outboard offsets remain separate requirements.

Public module `cyber_bao::traversal`, with
`RangeTraversal::new(size: u64, block_size: BlockSize,
request: Range<u64>) -> Result<Self, RangeTraversalError>`, implementing
`Iterator<Item = BaoChunk>` and `FusedIterator`, with `is_complete()`.
Public error variants are `InvalidBlockSize` and `InvalidRange`, deriving
Debug/Clone/Copy/PartialEq/Eq and implementing core Display/Error. Display strings
are `invalid traversal block size` and `invalid traversal byte range` respectively.
RangeTraversal Debug reports geometry/progress. No root re-export, Clone,
ExactSizeIterator or new size_hint contract is needed.
No allocator or external range-set dependency is introduced.

Validate block geometry before request: reject `log > 51` before shifting,
form `4096_u64 << log`, then require the group byte count to fit usize (the existing
BaoChunk leaf size type). A 32-bit build consequently admits logs 0..19;
a 64-bit build admits 0..51. These limits concern this new checked cursor only.
The declared group width must fit even when the requested file/leaf is smaller.
Reject start > end and end > size, including an empty range beyond EOF.
An admitted empty request, including 0..0 for an empty file, is immediately
complete and emits no item. This is a geometry result, never a statement that
an empty proof authenticated anything. A nonempty request visits all whole
groups intersecting its half-open byte interval; clip only the final file group.
For nonempty requests, selected groups are
`start / group_bytes .. (end - 1) / group_bytes + 1`; never add a rounding
constant to end. The constructor validates everything before publishing state;
after successful construction next has no fallible operation or error item.

ROOT belongs to the complete file tree: the first parent for a multi-group
file, or the sole leaf for a single-group file. Selecting one leaf from a
larger tree does not grant that leaf ROOT. A parent contains both child hashes;
left/right flags describe which children this query will subsequently visit.

## Constant work and checked geometry

For nonempty files let N=ceil(size/group_bytes), at most 2^52; the empty-query
early result needs no root frame. Each pending frame records the
first group, group count and whether it is the complete root. For count > 1,
split at the largest power of two strictly below count. This directly represents
the complete-left shape; it never walks absent virtual descendants.
The parent's existing in-order index is `2*(first + left_count)-1`.
Intersect the two group intervals with the admitted selected interval, push
right then left when visited, and return the parent with those flags. Compare
group intervals rather than forming a possibly unrepresentable final byte end.
At every parent, `first + left_count < N <= 2^52`, so its index is below 2^53.

One next call pops one pending frame and returns exactly one parent or leaf.
It performs a fixed number of checked/admitted integer operations and pushes
at most two frames. No scan, recursive call, iterator filter, growable storage,
body copy or backend call occurs. A fixed 53-frame stack covers depth 52 plus
pending siblings. Initialization touches that fixed capacity only. After the
last item, is_complete is true; any further next returns None without work.
The caller can check is_complete before charging its own per-call/total budget.
Radio stores no caller quota. Pausing requires simply not calling next. Every
stored frame intersects the request, so a pending next returns Some directly;
there are no skipped frames hidden behind a filter loop. At depth d <= 52,
at most d deferred right siblings and one current frame exist. The maximum
full-file left prefix exercises all 53 slots without traversing the whole file.

For a leaf, compute its admitted start byte and `min(group_bytes, size-start)`;
never multiply the next group index before clipping. Derive start_chunk from
the admitted group start. Because `first < N`, `first*group_bytes <= size-1`;
`first*(group_bytes/4096) <= 2^52-1`. Leaf size fits the admitted usize group
width. These bounds cover every internal operation on 32/64-bit targets without
calling the legacy unchecked TreeNode/BlockSize arithmetic. The maximum u64 file at log 0 has a final 4095-byte
leaf at chunk 4503599627370495. No synthetic oversized Rust slice is required.

## Steps → verification

1. Bridge the reducer merge and freeze production/consumer contracts → prove
   owning geometry source and wire rules against actual Git inputs; keep the
   existing allocation/panic diagnostics at their original dacd revision.
2. Freeze independent tests before implementation → retain external parent
   public-API absence honestly; after PLAN approval install the same ordinary
   repository tests and record actual parent debug/release compilation failures
   before production edits. Literals define preorder nodes, flags, root placement, chunks and
   byte lengths for 1,2,3,5,7,16,17 groups, full and partial last groups.
3. Implement the new checked cursor in `cyber-bao/src/traversal.rs`, export it
   from lib.rs, add `tests/range_traversal.rs` and its allocation witness →
   debug/release/default/no-default tests pass with exact outputs and bounded
   counts. Existing eager source/tests remain unchanged.
4. Freeze final source and run owning/no_std/direct consumer/repository gates
   at the actual parent → compare inherited failures by matching commands and
   source revisions; preserve full raw output. Fresh different-vendor CODE
   review precedes root's ordinary PR/merge. No version/release change.

Production touch set: new `cyber-bao/src/traversal.rs` and the single public
module export in `cyber-bao/src/lib.rs`. New witnesses:
`cyber-bao/tests/range_traversal.rs` and `range_traversal_allocation.rs`.
Task/audit evidence accompanies them. Each source file stays below 500 lines;
no dependency, lock, version, wire format, kernel or existing consumer changes.

## Finite independent cases

The [literal tables](literal-cases.md) fix complete/selected preorder expectations
before implementation. They contain no measured result or generated production
snapshot. Convert these cases directly into the frozen public witness suite.

Literal three-group full preorder: parent node 3 (ROOT, both), parent node 1
(nonroot, both), leaf chunk 0, leaf chunk 1, leaf chunk 2. Right-only query:
parent node 3 (ROOT, right only), leaf chunk 2 (nonroot). For seven groups,
right-only leaf 6 visits parent nodes 7 then 11, then leaf 6; neither phantom
parent 13 nor an unrequested sibling payload appears. Repeat at logs 0 and 2;
node indexes stay group-based while leaf start_chunk scales by 1 or 4.

Query cases: first/last byte, exact group boundary, cross-boundary interval,
full file, empty start/interior/EOF, reversed and beyond-EOF intervals. Size
cases: 0,1,4095,4096,4097 and partial groups at log 2. Geometry-only maximum
u64 length selects the final byte, pinning the exact final remainder. Test
all 256 public BlockSize byte values with independently derived admission
boundaries on 32/64-bit targets; invalid cases fail before shifting or allocating.

An allocator positive control followed by construction, every next and drop
requires zero allocations. Interleave two cursors and pause before each item;
resumption preserves the exact sequence and terminal polls remain empty.
Compare selected finite valid outputs to the existing eager API as supplemental
compatibility evidence, never as the sole oracle. Use literal shape/index/root
tables for decisive expectations; do not duplicate the new split algorithm in
the oracle. Check nonempty traversal item counts and stack bound independently.

## Five principal failure risks

Wrong incomplete-tree shape → literal 3/5/7/17-group paths and flags.
ROOT moves to a selected leaf → right-only multi-group controls.
Query rounding exposes wrong group → byte boundaries and partial final groups.
u64 or target-width overflow → maximum geometry and isolated 32-bit compile/run
where available, without pretending compilation executes the runtime matrix.
Hidden eager work → source inspection, allocation guard and one-item-per-call
terminal/interleaving checks. No timing benchmark substitutes for this bound.

## Evidence and unresolved obligations

The reducer's no-default compatibility floor remains inherited; this cursor is
an additive API against the actual current parent. Radio remains part_of soft3,
with the same direct Cargo owners; the registry's Radio clause and runtime
contract are byte-identical at their current origin refs to the predecessor's
frozen inputs. This remains a rung prerequisite, not a ring-0-only assertion.
The existing last-tag no-default major floor still applies to releases.
This plan does not assert a new green repository/rung result. General legacy
unchecked geometry, eager consumers, multi-range proofs, empty-proof policy and
authenticated root/particle association remain visibly open.

## Required gates and attribution

Use matched Rust 1.95 Cargo/rustc/rustdoc, jobs 2, incremental 0, private targets;
cap owned compiled targets at 20 GiB and staging at 30 GiB. Preserve raw failures
and input manifests before removing obsolete compiled targets. Run owning
`cargo test -p cyber-bao --locked` in debug/release for default/all/no-default;
strict owning Clippy/docs/format; std/serde/tokio_fsm feature checks. An isolated
no_std consumer directly calls the new cursor with defaults disabled, no dev
dependencies, and checks thumbv7em-none-eabi plus the actual normal feature graph.
This provides 32-bit compilation, not a 32-bit runtime pass. Host tests alone
establish no embedded property.

Run direct owner checks and actual repository workflow gates: nextest workspace
default/none/all, all-feature doctests, MSRV 1.89 workspace/all-targets, exact
nightly-2025-10-09 private docs environment, all three strict workspace Clippy
variants, format and deny. Keep broken registry selectors visible and check
actual workspace owners separately. New or differing failures require focused
parent/candidate pairs; inherited receipts keep their exact source/tool epochs.
Never classify all runtime timeouts as inherited because some statuses match.
Wider platform, minimal-version, netsim and product/specification/Kelvin obligations
remain explicit if unexecuted; no full closure follows from this prerequisite.

Fresh-target default/no-default API comparisons use the actual parent and the
applicable tag, with exact source/symlink inventories. Default and no-default
against the new parent should be additive; the last-tag no-default red belongs
to the predecessor's intentional major floor. Rejected CLI invocations establish
no API result. Root owns decision/wip accounting, final vendor review and ordinary
merge. Rollback is an ordinary revert of this additive API; stored bytes and old
consumers remain unchanged. No dependency, version, tag or publication action.
