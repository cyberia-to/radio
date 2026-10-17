# CODE Review — bounded BAO range traversal

**Verdict: APPROVE**

Reviewed from the supplied frozen brief only: candidate `traversal.rs`, `lib.rs`, both new test files, parent `tree.rs`/`tree/traversal.rs`/`slice.rs`/`fsm.rs`, Hemera `specs/tree.md`, the frozen PLAN/literals, the approved PLAN verdict, and the exact gate records/raw streams. I did not run tools and did not read the hash-indexed omitted bodies.

## Correctness of the new cursor

I checked the algorithm against the frozen literals and the Hemera left-balanced shape rule, independently of the implementation's own comments.

**Split.** `left_count = 1 << (count-1).ilog2()` is the largest power of two strictly below `count` for `count >= 2` (for `count = 2^k` exactly, `(count-1).ilog2() = k-1`). This matches Hemera `split = 2^(⌈log₂ N⌉ − 1)`: for N=3 → 2, N=5 → 4, N=7 → 4, N=17 → 16. Those are exactly the midpoints implied by the literal preorder rows. `count == 1` is the leaf case and `ilog2` is never evaluated on `0`, so no panic path exists there.

**Parent index.** `2*middle - 1` with `middle = first + left_count`. Spot-checking the literals: 3 groups → middle 2 → node 3 ✓, then left frame (0,2) → middle 1 → node 1 ✓. 7 groups → root middle 4 → node 7 ✓; right frame (4,3) → middle 6 → node 11 ✓; its left (4,2) → middle 5 → node 9 ✓, giving the literal `P7:R P11:R L6` and `P7:R P11:L P9:R L5`. 17 groups → middle 16 → node 31 ✓. Since `middle >= 1` whenever `count >= 2`, `2*middle - 1` cannot underflow, and `middle < N <= 2^52` bounds it under 2^53.

**Selection flags.** `selected = start/g .. ((end-1)/g + 1)` is the correct whole-group cover of a nonempty half-open byte interval, and crucially never forms `end + g - 1` (no wrap at `u64::MAX`). Intersection is done on group intervals: `left = selected.start < middle && first < selected.end`, `right = selected.start < end_groups && middle < selected.end`. Both are the standard half-open overlap test against `[first, middle)` and `[middle, end)`. Because only intersecting children are pushed, and the root frame is only pushed when the request is nonempty, every stored frame intersects the request — so a pending `next` always returns `Some`, matching the claimed no-filter-loop invariant. `end = first + count <= N <= 2^52`, no overflow.

**ROOT.** `is_root` is carried only on the initially pushed frame and set `false` on every child, so exactly the first emitted item (parent or sole leaf) is root. The `P3:R L2` and `P31:R L16` literals confirm a selected leaf in a larger tree is non-root; the cursor cannot produce that because any pushed child has `is_root: false`.

**Leaf clipping.** `start = first * group_bytes` with `first < N = ceil(size/g)` implies `start <= size - 1`, so `size - start >= 1` and the subtraction cannot underflow. `min(group_bytes, size-start)` clips only the last group. `group_bytes` already passed `usize::try_from`, so the `as usize` cast is lossless for the `group_bytes` branch, and the `size-start` branch is `< group_bytes`. This is the correct ordering the PLAN demanded (subtract before clipping; never form `(first+1)*g`).

**Admission.** `block_size.0 > 51` is rejected before the shift, so `(CHUNK_SIZE as u64) << log` never shifts by ≥64. `usize::try_from` then gives 0..=19 on 32-bit and 0..=51 on 64-bit, and the test exhausts all 256 `BlockSize` values with its own independently derived boundary (`match usize::BITS`), panicking on unexpected widths rather than silently passing. Geometry precedence over range is enforced by ordering and is asserted directly (`new(1, BlockSize(log), 2..2)` yields `InvalidBlockSize` for rejected logs). `size.div_ceil(group_bytes)` is overflow-safe, satisfying the PLAN-review advice. An empty admitted request pushes nothing, so `is_complete()` is immediately true and `next` returns `None` — a geometry result, not an authentication claim; the doc comment and test names say exactly that.

**Stack bound.** `push` writes `frames[self.pending]` then increments. `next` decrements *before* pushing children (the advised pop-before-push), so the peak occupancy is `(depth of deferred rights) + 1`. The `maximum_left_prefix_requires_fifty_three_pending_slots` test walks the full `u64::MAX` left spine — 52 parents then leaf 0 — which is precisely the worst case, and index `52` is the last valid slot of `[Frame; 53]`. Any off-by-one would panic on index out of bounds in debug and is covered by the allocation witness's `(u64::MAX, 0, 0..u64::MAX, 54, false)` case too. The array is `Copy`-initialized inline, no allocation.

**Trait surface.** `FusedIterator` is implemented and the `fused()` helper in the test statically witnesses it; `is_complete()` makes it honest (`next` returns `None` unconditionally once `pending == 0`). No `Clone`/`ExactSizeIterator`/`size_hint` was added, matching scope. `RangeTraversalError` derives the required set, `Display` strings match the PLAN byte-for-byte, `core::error::Error` is implemented and statically witnessed by `core_error::<RangeTraversalError>()`. Manual `Debug` on `RangeTraversal` satisfies the workspace `missing_debug_implementations = "warn"` lint and reports geometry/progress as specified.

## Tests as independent oracles

The literal parser in `range_traversal.rs` does token parsing only — no splitting, no `ilog2`, no recursion, no production call. Expected leaf sizes come from the caller-supplied `final_size`, not from the cursor. The complete-shape table is byte-identical to `literal-cases.md`, and the length assertion `expected.len() == 2*groups - 1` is an independent structural check. `MAX_LEFT`/`MAX_RIGHT` are literal constants (`2^k-1` and `2^53-2^k-1`), not generated. The eager comparison is explicitly labeled supplemental and is not the sole oracle for any shape. `check()` also verifies `is_complete()` transitions at every step and three terminal polls — the fused contract is actually exercised, not just declared.

The allocation witness installs a real `#[global_allocator]` with a thread-local counter, proves the harness can observe allocations via a positive control (`vec![17u8;17]` > 0), uses `black_box` to defeat elision, and covers construction, steps, terminal polls, drop, and the two error paths at zero. Scope is honest: it says nothing about linking.

## Evidence discipline

- Parent `E0432` for both test files is in the raw stderr at `01`/`02`, exit 101, with no test body run — the required negative control, recorded *before* production edits per the freeze manifest.
- The witness freeze → lint-allow → formatter chain is each hashed before/after, and `verify.rb` reconstructs both transforms textually (the exact `allow` line and the exact import regrouping) rather than trusting the claim. That is a stronger check than I expected and it bounds the delta to imports plus one attribute.
- The `771518d6` → `53f29b5b` bridge is stated, and all owning outcomes (`03c`–`08c`, `19c`, `21c`, `42c`) were rerun at the final digest. Workspace runtime (`25b`/`26b`) stayed at `771518d6`; since the bridge touches only two test import blocks in `cyber-bao`, that is a defensible, explicitly-labeled gap rather than a hidden one.
- Red gates are reported red and paired: all-feature owning Clippy red on both sides with the 11 pre-existing lib diagnostics visible in the parent's raw output; nightly docs, workspace Clippy ×3, cargo-make format, cargo-deny, and all-features nextest (`iroh-gossip` E0599) all fail identically at parent and candidate. The 3 extra candidate libtest diagnostics at `16c` are disclosed with the scheduling explanation rather than suppressed.
- The no_std story is stated correctly: library `cargo check` for `thumbv7em-none-eabi` passes, the binary link fails `no global memory allocator found`, and the **parent pure-`ChunkNum` control reproduces the same failure** (`22`). That isolates the boundary to pinned Hemera's `extern crate alloc` and not to this change. No substitute allocator was added, no 32-bit runtime pass is claimed.
- Last-tag no-default exit 100 is the predecessor's intentional major floor; every listed removed item is `io::*`/`tree` surface untouched here, and parent default/none both pass with no update required — the API delta is purely additive.

## Blockers

None.

## Advice (non-blocking)

1. **`BlockSize(0) > 51` admits widths the rest of the crate rejects.** `BaoTree::blocks()`/`shifted()` use unchecked `1u64 << self.block_size.0`. A caller who successfully constructs a `RangeTraversal` at log 40 may assume the same `BlockSize` is safe elsewhere. The module doc says "integer geometry, not allocation layout validity" — consider also saying the admitted range is *this cursor's* limit, not a crate-wide `BlockSize` validity claim.
2. **`selected` is dead for empty requests** (`0..0` with `pending == 0`). Harmless, but the `Debug` output will show `0..0` for an admitted empty cursor, which reads like "selects group 0" rather than "selects nothing". A one-word doc note or an `is_complete` field in `Debug` would remove the ambiguity.
3. **Workspace runtime at the pre-format digest.** Cheap to close on a future pass: rerun `25b`/`26b` at `53f29b5b` so the full matrix sits on one source epoch.
4. **`42c` allow-list.** The supplemental std-test Clippy run masks four categories that are red in the strict gate. It's labeled supplemental and the strict gate stays red, which is correct — but if those four ever get fixed upstream, drop the allow-list so the supplement stops hiding regressions in the new files.
5. **Multi-range is still one-cursor-per-range.** Fine for this unit, but note that two cursors over adjacent ranges will emit overlapping parent chains; whoever builds the union layer should not assume dedup.

Scope held: two production files (one new module, one `pub mod` line), two new test files, no dependency/lock/version/wire/consumer change, 172 lines, each file under 500. Nothing here asserts a proof parser, particle/root authority, consumer migration, empty-proof policy, or phase/rung/release closure.
