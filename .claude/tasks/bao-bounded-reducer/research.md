# Bounded BAO prerequisite: read-only handoff

Serves Kadek foundation row 4. This is source exploration, not an approved
implementation plan, gate result, or proof of cold partial provenance.

## Exact inputs

Fresh `git ls-remote origin HEAD` reported Radio
`a11d342594949d4ea542b26366f71d56ef21662d` and Hemera
`d5f0a09539360934fb32db9b2e15a91995607db6`. All subsequent source reads use those
Git objects. Kadek contracts/research use
`3db005002cc340b815f1c8d72fbfe73ad87cbc78`. `research-inputs.json` records each selected
path, full revision, Git blob, SHA-256, bytes and exact export command. No original
working tree enters the evidence or receives an edit. No build/probe was run.

Radio ROOT finalization, right-only slice traversal, parent widths and empty
status have since been repaired; the old Kadek proof research remains useful for
its wire, ownership and boundedness analysis, not as a current assertion of
those repaired defects. Current source and committed receipts were inspected.

## Smallest useful prerequisite

Recommend one upstream `cyber-bao` unit: a resumable fixed-chunk/group root
reducer with fixed storage, and the no_std feature boundary needed to consume it.
Its output is a calculated tree hash. It grants no particle or byte authority.
Keep the slice parser/lazy range walker and Kadek sealed owners as subsequent
units; combining all three introduces unrelated framing and lifetime decisions.

The reducer borrows immutable input and tracks its cursor, absolute chunk counter,
ROOT policy and fixed hash frontier. Constructor checks counter/length arithmetic;
each step performs at most one existing leaf or parent hash kernel or a bounded
control/completion action. The eventual caller charges that action before it
runs, retains the total across yields, and separately enforces its per-call cap.
Do not introduce a dependency from Radio back into Kadek's WorkBudget.

An at-most-4096-byte `hemera::tree::chunk_cv` is sufficient for Kadek's present
runtime contract: runtime.md:249–260 requires bounded total/per-call work and
checked progress, without mandating RATE_BYTES or CPU-cycle-equivalent units.
One leaf and one parent are different documented bounded work actions. Whole
groups must be resumable: actual Radio log4 groups contain up to 16 leaves
(65536 bytes). Kadek BodyVerifier's RATE_BYTES accounting is its own plain-hash
unit; it does not require a new Hemera leaf-finalization API for this proposal.
If the owner later requires yielding within a leaf, that is an additional Hemera
API task. Current StepSponge only traces rounds: its capacity stays zero and its
squeeze returns one element; it cannot replace canonical tree finalization.

Reuse HashBackend/Poseidon2Backend, CHUNK_SIZE and Hemera's public chunk_cv /
parent_cv. Preserve absolute counters, odd-right promotion, and ROOT only on the
final node. Never reproduce private capacity/flag arithmetic. A generic reducer
can promise no internal heap allocation; arbitrary external HashBackend methods
or Hash::Clone may allocate. The stronger allocation-free claim is measured with
the concrete Poseidon2Backend/Copy Hemera Hash. Retrofitting the old generic
infallible hash_group to a checked fallible machine needs a deliberate decision:
do not silently add a panic for its newly rejected inputs or narrow its non-Copy
HashBackend contract. It is acceptable for this first public prerequisite to have
direct concrete-kernel tests while legacy adapters remain unchanged and labelled.

## Concrete no_std boundary

Current `default=[]` does not mean no_std: lib.rs always exposes std I/O; hash.rs
uses std::fmt; tree.rs imports std and contains Vec/RangeSet traversal; all I/O
support dependencies are unconditional, and Hemera enables its std default.

The smallest coherent feature design is:

- `default=["std"]`; `std` enables Hemera/std plus optional bytes, smallvec,
  range-collections, iroh-io and genawaiter. Hemera has default-features=false.
- `tokio_fsm=["std","dep:tokio"]`; existing serde support explicitly implies
  std and its current dependency features. No new no_std serde claim is needed.
- lib.rs declares no_std when std is disabled, gates io and RangeSet aliases,
  and gates PostOrderChunkIter's re-export. HashBackend uses core::fmt.
- tree.rs pure imports/operators use core. Gate RangeSetEntry, Vec-backed
  PostOrderChunkIter and its Iterator impl, the three eager offset/iterator
  helpers, and the later traversal impl containing Vec/RangeSet recursion under
  std. Preserve existing public geometry types and default-feature APIs.
- Add the bounded reducer and focused tests; do not rewrite generic I/O,
  serde formats, native stores, transport or complete tree geometry in this unit.

The exact current direct Cargo consumers are iroh-blobs (tokio_fsm+serde),
particle, radio-cli and tests/integration (default features). Their full manifests
are retained. Source scan found no local no-default consumer; external ones are
unknown. Changing no-default API availability is a real compatibility boundary:
freeze feature-specific API comparisons and semver floor in the eventual PLAN,
not merely the default-feature comparison. This feature design is proposed,
not approved or measured by a no_std build yet.

Radio still has a cross-repository path-only Hemera dependency. Source extraction
can pin committed Radio/Hemera for gates; a standalone Kadek dependency requires
a reviewed reproducible delivery mechanism. Published cyber-bao availability and
registry/current-Hemera identity were not established here. Do not use a dirty
path or silently claim identical source because both Hemera manifests say 0.3.1.

## Remaining verifier unit and choices

Current sync slice verification still allocates a complete traversal, an expected
hash stack, nested output vectors and group-reduction vectors. FSM similarly
allocates a traversal Vec, spillable SmallVec and leaf Bytes, then hashes the
whole group. Async I/O therefore does not satisfy bounded algorithmic stepping.

The next verifier can use trusted external root+length, a checked selected group
profile, one contiguous nonempty requested byte range and a complete borrowed
proof buffer. Lazy preorder geometry needs only a depth-bounded frontier and
prunes excluded subtrees. It should reuse BlockSize/ChunkNum/TreeNode/BaoChunk as
descriptors where valid, while checking arithmetic before existing unchecked
methods. For u64 file lengths, ceil(length/4096) is at most 2^52 and log4 group
count at most 2^48: these are source-derived bounds, not measurements. Final
partial byte endpoints must clamp without first multiplying to 2^64.

Choose explicitly before that PLAN:

1. Accept only Radio log4 first, or a checked bounded profile set including log0
   fixtures; arbitrary public BlockSize(u8) cannot reach unchecked shifts.
2. Header equals independently trusted complete length before any traversal.
   Source-derived counterexample today: LE64(4)||"hello" reaches the one-block
   branch, hashes all five payload bytes, and can accept the hello root; header
   length is not thereby authenticated. This was not executed as a new probe.
3. Exactly one framed proof versus a consumed-count API; trailing bytes permitted
   by upstream BAO are a framing choice, not automatically a generic hash defect.
4. Empty-file proof and nonempty empty-range behavior. A narrow initial API can
   reject empty requests rather than inherit the inconsistent shortcut/FSM rules.
5. Output ownership: verifier returns proof-relative authenticated spans only
   after success, or copies requested bytes into caller storage. Byte authority
   must never be recreated from mutable/unverified replacement payload.

The bounded-core feature/reducer unit can proceed to a formal PLAN without
answering cold provenance; the above verifier decisions must be pinned before
its own implementation. No proof decoder or canonical spec change is approved.

## Independent oracle strategy

Use existing literal current root_policy.rs oracles, including D8192 canonical
`2abf65dd26465a7352707d79d18ff3aab9ee5d97614a774619c79ed527e20190`
and the rejected old internal CV
`11890a7e7cf1e4de463a04bf53bfdf269d627983a221daaf9029a3ff43297389`.
Preserve empty/hello published tree literals and their separate plain particles.
For reducer structure, a recording backend should assert exact counters, ROOT
flags and independently written trees for 1/2/3/5/7 leaves; HashBackend need not
be Copy. Concrete Hemera tests compare with fixed_chunk_root at pinned source,
plus literal fixtures. This is independent reduction/wire construction over the
shared hash kernel, not an independent cryptographic audit or merely self-roundtrip.

Exercise one-action yields, split vs uninterrupted equality, exact/below total
caps in the consuming wrapper, checked counter overflow and empty input; verify
no allocator call with concrete Hemera and a no_std target with no default
features. Preserve default-feature Radio consumers and existing root tests.
Later slice oracles must construct exact preorder pairs/payload independently,
retain right/interior/non-power-of-two/partial-last cases and malformed boundaries,
and prove bounded refusal of tiny headers naming huge geometry. Do not run an
unbounded old decoder on that hostile header merely to demonstrate resource use.

## Warm versus cold provenance

A later sealed anchor can derive (plain particle, canonical tree root, complete
length, exact profile) from the same immutable VerifiedBody, with bounded hashing,
then release the body. No raw constructor/Deserialize may mint this authority.
It only enables warm in-process subsequent range verification. Cold partial-only
fetch, restart/persistence and externally supplied particle/root pairs still need
an authenticated association contract or renewed complete-body verification.
Runtime also requires retaining slice proofs; their owners and exact distinct
allocation layouts must enter Packet/PCM budget accounting. Existing assembly
and codec-state preservation remain constraints. Foundation row 4 stays partial.

## Independent PLAN critique, 2026-10-11

The source-only replay in `/tmp/radio-bao-bounded-reducer-plan-critique/` verifies
all 38 manifest entries against exact Git objects; no build was run. Original
research/PLAN/manifest bytes remain in its `draft-original/` with hashes. The
proposed reducer bound is coherent: complete peaks encode set bits of the count
of processed leaves; at most 52 peaks plus the newly appended leaf fit 53 slots.
Reducing one pair per step yields N leaves and N-1 parents. The right-fold after
the final leaf matches Hemera tree.rs:282–300's complete-left-subtree recursion.
These are source/algorithm arguments, not results from a candidate.

The refined PLAN closes finite omissions: exact constructor/result/error names;
no final counter increment (single leaf at MAX is valid); slicing by remaining
length; a non-Copy hash whose Clone panics; constructor-through-drop allocation
measurement. Hemera lib.rs explicitly imports alloc under no_std, so the library
feature claim and concrete reducer allocation claim are distinct. Existing
HashBackend::Hash requires Clone, but the new reducer need not invoke it.

Geometry boundary oracle: u64::MAX-4095 bytes gives N=4503599627370495;
u64::MAX bytes gives N=4503599627370496 and total steps=9007199254740991.
These are exact integer bounds, not fabricated slices or huge-body measurements.
The forthcoming private helper can test them independently of allocation.

Actual feature source inspected: the pending pin branch stores Hemera
`default-features=false` in workspace dependencies, while cyber-bao explicitly
requests std. The reducer removes only that member's unconditional request and
moves it into its std feature. Final pin source/merge identity and its exact
manifest delta are still required before freezing this PLAN. No no_std build,
API comparison, source-pin merge or implementation is claimed here.

## Actual pin integration

PR37 merged as `dacd030c9d6301b316a96b5bc6e4ea1e1cec79f1` (source
`1375da962eb91be6e8791e2c2e5250370a0e0a15`; reviewed production `d90a784...`).
The ordinary fetch/fast-forward bridge completed at 2026-10-11T22:00:03Z;
12 commands/24 raw streams now reside in
`/tmp/radio-bao-bounded-reducer-parent-bridge/`. Owning Rust, tests and docs/bao.md
have an empty a11→dacd diff; the merged tree equals the final source exactly.
The complete eleven-file production delta is manifests, lock and deny policy;
record 10 is a named subset, record 12 contains the complete patch. No reducer
source or build result exists yet.

Inherited evidence is source-pinned at dacd: the source-pin execution/audit records
local Rust1.95 results, while hosted/README.md binds hosted Rust1.99 jobs to the
synthetic merge `2d606fbc2638c52c9613ea7d712a6f35ee32a48c`, tree-equal to reviewed
production d90. Preserve the actual red/inconclusive outcomes; no parent hosted
rerun or future reducer pass follows from unchanged inputs. Root's decision/wip
source acceptance does not close any release/product obligation.

One inherited explainer mismatch requires a minimal proposed correction: docs/bao.md says
128-byte pairs of two 64-byte hashes. Current HashBackend/OUTPUT_BYTES use 32-byte
hashes and 64-byte pairs. This reducer emits a Hash, never proof wire bytes; its
primary kernel/source contracts govern. Root requested the one-line 64=2×32
correction as part of this proposed PLAN, pending review; actual source is unchanged. Pinned Hemera tree.md's fixed-chunk sections apply here;
its broad identity language does not override lib/tree.rs's separate CDC root API.
