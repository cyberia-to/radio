# Bounded BAO group reducer — proposed PLAN

Serves: owner's Kadek phase-1 closure · Radio/soft3 · foundation row 4,
bounded authenticated-range prerequisite. Source research is pinned in
research-inputs.json at Radio `a11d342594949d4ea542b26366f71d56ef21662d` and Hemera
`d5f0a09539360934fb32db9b2e15a91995607db6`. Current parent is Radio `dacd030c9d6301b316a96b5bc6e4ea1e1cec79f1` (PR37),
ordinarily integrated with unchanged owning Rust/tests; the exact bridge is
retained. Pin approval does not approve this unit. No reducer production edit or
build has run; this PLAN awaits fresh independent approval.

## Surface and scope

Add `cyber_bao::group::{GroupHasher, GroupHashError}`; preserve legacy `hash_group`
and default-feature I/O. No proof parser, lazy range traversal, Kadek owner,
particle/root association or cryptographic algorithm change. Reuse HashBackend
and pinned Hemera `chunk_cv`/`parent_cv`; output is a calculated hash, carrying
no authentication authority.

- `GroupHasher::new(backend: &B, data: &[u8], start_chunk: u64, is_root: bool)
  -> Result<Self, GroupHashError>` borrows both input and backend. Keep the
  existing non-Copy backend/hash contract; add no B: Clone/Copy/Debug bound.
- `step(&mut self) -> Option<B::Hash>` runs exactly one leaf or parent kernel
  while pending. It returns the completed hash exactly once, during that final
  kernel step. Subsequent polls return None and call no backend method.
- `is_complete(&self) -> bool` starts false (including empty input), becomes true
  with the returned result, and remains true. The caller tests it before charging
  each nonterminal step; no separate publication charge or budget dependency.
- `GroupHashError::{InputTooLarge, CounterOverflow}` are constructor errors:
  first check input length into u64, then last absolute counter. Derive Debug,
  Clone, Copy, Eq/PartialEq; implement core Display/Error. No error is deferred
  into step. GroupHasher Debug prints progress without requiring B: Debug.

Each leaf reads at most CHUNK_SIZE=4096 bytes; each parent combines two hashes.
These are bounded algorithmic units, with different CPU costs. Fixed internal
storage does not bound arbitrary backend methods/hash destructors. The concrete
Poseidon2 path gets a separate allocation witness. Backend panics are outside the
machine's successful-step contract; this unit adds no panic recovery protocol.

## Fixed frontier and arithmetic

Let N=max(1,len/4096 + [len%4096 != 0]); check `start_chunk + (N-1)` before any
backend call. The constructor initializes 53 optional hashes with no placeholder
hash or Clone call. N <= 2^52 for u64 lengths. Immediately before a new leaf there
are popcount(processed) complete peaks, at most 52; appending it needs at most
53 slots. Parent steps replace the top two slots with one. No shifts or indexing
use an unvalidated public BlockSize/TreeNode value.

After each nonfinal leaf, schedule trailing_zeros(processed_leaves) reductions,
one per step, before reading another leaf. After the final leaf, fold the peaks
from right to left, one parent per step. This produces the same left-balanced
shape as pinned Hemera: for seven leaves, ((01)(23))((45)6). Only the final parent
receives the requested ROOT flag; a sole leaf receives it directly. All other
kernels receive false. The N leaves and N-1 parents take exactly 2*N-1 steps,
at most 2^53-1, including one step for empty input. Constructor and terminal polls
perform no kernel; no input-dependent loop/copy/scan/allocation occurs in step.

Slice using `take = remaining.len().min(CHUNK_SIZE)`; advance by take, retaining
a valid subslice or checked in-bounds cursor. Do not form offset+4096 at a partial
last leaf. Compute only counters actually used; after the final leaf never form
last_counter+1. Thus an empty/single leaf at u64::MAX and two leaves starting at
u64::MAX-1 are valid; two starting at u64::MAX fail before hashing. A private
u64 geometry helper tests maximal representable lengths without fabricated
oversized slices. InputTooLarge is an explicit conversion guard; it cannot be
triggered by a real slice on the present <=64-bit platforms.

## no_std and compatibility

`default=["std"]`; std enables Hemera/std and optional bytes, smallvec,
range-collections, iroh-io, genawaiter via `dep:` entries. Inherit the merged pin's
workspace Hemera with default-features=false and remove cyber-bao's unconditional
features=["std"]. `tokio_fsm` and existing serde explicitly imply std; no no_std
serde claim. Gate io, allocation-backed range aliases and RangeSetEntry. Switch
pure formatting/operators to core. Hemera itself uses alloc: no_std here means
no std dependency in the isolated library graph, not removal of alloc from Hemera.

Move unchanged eager traversal methods, three eager offset/iterator helpers and
PostOrderChunkIter from the 914-line tree.rs to private std-gated tree/traversal.rs;
re-export its public iterator at the existing tree and crate-root paths. Move
existing tests to tree/tests.rs; gate only the four traversal tests on std, retain
geometry tests without std. Pure BaoTree/TreeNode/ChunkNum/BlockSize/BaoChunk and
the group machine remain available. Existing unchecked geometry behavior remains;
the new reducer uses none of those unchecked bounds. Keep each resulting source
file below 500 lines. Capture mechanical moves and necessary formatting separately
from algorithm changes; do not reformat unrelated I/O/workspace source.

Touched production: cyber-bao/Cargo.toml, src/{lib,hash,tree}.rs, new src/group.rs,
src/tree/{traversal,tests}.rs; focused tests/group.rs and tests/group_allocation.rs,
and std gates on existing root_policy.rs/slice_traversal.rs. Cargo.lock changes
only if the approved optional-feature resolution requires them. Root Cargo and
Hemera pin remain unchanged. One directly relevant docs/bao.md correction replaces
`pair size: 128 bytes (two 64-byte ... hashes concatenated)` with
`pair size: 64 bytes (two 32-byte ... hashes concatenated)`, derived from pinned
Hemera OUTPUT_ELEMENTS=4, OUTPUT_BYTES=32 and Radio PAIR_SIZE=OUTPUT_BYTES*2.
No wider identity/partial-download prose rewrite or association claim is included.

Default APIs remain compatible. Removing old std-dependent APIs from the
no-default surface is deliberate and sets a major compatibility floor. Known
direct owners use defaults or serde/tokio_fsm; their exact manifests and runtime
receipts must be retained. External no-default consumers remain unknown.

## Steps → verification

1. Parent bridge completed: actual dacd merge equals source 1375da9; owning
   Rust/tests/docs are unchanged from a11 → preserve 12 raw command records and
   the eleven-path production delta, then freeze direct inputs/tools. Historical
   research and pin gates retain their original epochs; no reducer gate ran.
2. Freeze independent tests and literal expectations before production → run them
   against actual parent and retain missing-API compile errors honestly. Separately
   run actual parent embedded no_std failure with a cyber-bao-only isolated
   consumer; workspace feature unification must not mask std. No runtime-red claim
   for an API that does not exist.
3. Implement group + feature boundary → finite public witnesses below pass in
   debug/release, default and isolated no-default modes. Preserve old std test
   bodies; std-only integration files need only crate-level feature gates.
4. Freeze candidate, exact source/feature graphs and gates → fresh different-vendor
   CODE review; portable audit preserves raw outcomes and blocked/inconclusive
   checks. Root owns final decision, explicit staging, commit and ordinary PR.

## Independent finite witnesses

- Recording backend: lengths 0 and `N*4096` / `(N-1)*4096+1` for N in
  [1,2,3,5,7,16,17], start counters 0/37 and ROOT false/true. These are 60 cases.
  Tree literals use leaves L0..L16: T2=(L0 L1), T3=(T2 L2),
  T5=(((L0 L1)(L2 L3))L4), T7=(((L0 L1)(L2 L3))((L4 L5)L6)),
  T16=((((L0 L1)(L2 L3))((L4 L5)(L6 L7)))(((L8 L9)(L10 L11))((L12 L13)(L14 L15)))),
  T17=(T16 L16); parentheses denote ordered parent kernels.
  Explicit symbolic expected trees and ordered leaf/parent events, not another
  frontier implementation, assert exactly one event per pending step and literal
  totals 1/3/5/9/13/31/33 for N. Two post-completion polls add no event. Every
  parent checks left/right identities; a non-Copy hash with panicking Clone and
  panicking placeholder/deserialize methods proves moves and no hidden helper use.
- Finite concrete data: empty, hello and D8192 canonical roots use existing literal
  strings; D8192 ROOT differs from old internal CV. Match pinned fixed_chunk_root
  for [0,1,4095,4096,4097,8192,12288,16385,28672,65536,65537] deterministic bytes.
  Counter37/ROOTfalse cases use explicitly partitioned chunk_cv/parent_cv expressions.
  Common kernels are disclosed; this is not an independent cryptographic proof.
- Caller wrapper: one-action calls and exact/one-below persistent totals on 1/3/7
  leaves. At every possible pause, no step runs before admission; final output
  arrives on the exact final unit. Paused/uninterrupted outputs match the literal
  symbolic tree. A completed result remains available to the caller without
  re-running the machine. Radio itself enforces no caller budget.
- Limits: empty/one-byte/full single chunk at MAX; two chunks at MAX-1; two at MAX
  refused with CounterOverflow and zero calls. Private helper table uses lengths
  0,1,4095,4096,4097,u64::MAX-4095,u64::MAX and exact expected N/last-counter;
  max N and 2*N-1 assertions establish arithmetic bounds, not huge-input execution.
- Concrete allocation trap: precreate finite input outside the measured region;
  guard construction, all steps, terminal polls and drop of the real Poseidon2
  machine. Cover empty/hello/4097/65537. Use one dedicated integration test with
  thread-local allocator tracking so harness allocations are excluded explicitly.
  Include an allocation-positive control outside the no-allocation assertion.

## Exact gates and limits

Matched Rust 1.95 tools, jobs 2, incremental 0, separate owned targets. Owning
`cargo test -p cyber-bao --locked` in debug/release, with default, --all-features
and --no-default-features. Explicit std/serde/tokio_fsm single-feature checks;
strict owning Clippy/rustdoc/format. Freeze isolated consumer manifest+lock and
`cargo check --target thumbv7em-none-eabi --locked` plus its normal dependency
feature tree; its sole Radio dependency disables defaults and no dev dependency
may unify Hemera/std. Host integration tests alone establish no embedded claim.

Run actual direct owner checks and required repository workflow commands:
workspace nextest default/none/all, all-feature doctests, MSRV1.89 workspace/all
-targets, matched private nightly docs, three workspace feature Clippy variants,
format and deny. New/resolution-sensitive reds require actual parent/candidate
pairs. Retain inherited broken selectors; correct-owner gates are additional,
not replacement evidence. Minimal-version, wider platform, netsim and product
matrices remain explicit obligations if not executed. No CI deployment/messages.

Compare cyber-bao default and no-default APIs against exact parent and applicable
last tag, in fresh targets; parent/tag dependency closure must be disclosed and
symlink/byte verified. Record actual yanked-core2 helper failure if it recurs;
partial package completion is no completed workspace comparison. Do not infer
semver compatibility from a blocked tool, or treat the intended no-default break
as an additive-only change. No version, release pin, tag or publication action.

Radio part_of soft3 and this API break reach rings 1/2. Pin receipts can support
unchanged source facts, but cannot establish this feature candidate's integration.
Product metadata, specification/Kelvin/fleet and red/inconclusive gate obligations
remain visible. Root owns decision/wip accounting within the ordinary source
merge authorization; no rung/phase/release closure is claimed.

Most likely failures: early ROOT; wrong odd-right fold; absolute counter wrap;
multiple hidden kernels/allocations per step; workspace unification hiding std.
The witnesses above target each. Rollback is an ordinary revert; stored bytes and
existing default-feature producers remain unchanged.
