# Bounded complete-buffer BAO proof verification

Proposed PLAN; no production implementation or approval. Serves Kadek foundation
row 4 through Radio, declared part of soft3; the future Kadek adapter reaches Cyb.
Radio implementation parent is b933829cbe273d2f31fe75ca83125f3ddd8917a2 (PR39);
research probes remain attributed to a96d86e28d384cdf656aadc4282c78c0c170c102.
Hemera is d5f0a09539360934fb32db9b2e15a91995607db6. The prerequisite RangeTraversal
is merged; an ordinary fast-forward and exact source/lock/consumer bridge preserve
the research identities. Its source equals the previously frozen candidate. Kadek's
sealed BaoAnchor is now committed at 4d9ca9ab3498238b9c1e03f6d6f160e1ec729912.

## Result and boundary

Add one concrete no_std Poseidon2 proof reader borrowing an immutable complete
proof buffer. It verifies one nonempty half-open byte request, or the empty file,
against an externally trusted complete-root/length pair. It returns a private-field
borrowed view only after every selected group, every required parent and exact
encoded EOF have passed. The view can replay one geometry item per output action
without allocating spans or copying payload. Legacy std readers/producers remain
unchanged. This is an additive minor API, with ring 1 reach, not a patch/ring-0-only
claim. The canonical-wire requirement is an intentional new-profile tightening.

Radio does not derive particle authority. The future Kadek adapter must use the
committed BaoAnchor's root, length and HemeraFixed4096V1 profile, retain that sealed
association, charge persistent work, own bounded proof/output storage and publish
only after full verification. A caller-created root or Radio view cannot create a
Kadek VerifiedRange. No Kadek adapter, network fetch, incremental byte feeding,
serialized anchor, first-partial authentication, multi-range set or legacy-reader
migration belongs to this unit.

## Carrier and admission

The borrowed carrier is exactly: eight-byte LE complete u64 length, followed by
the selected preorder parent pairs and whole selected group payloads. Both 32-byte
children are present for every visited parent, even when only one child is selected.
Request and BlockSize are separate trusted operation inputs, not wire fields.
The supplied length must equal the header. A file-backed slice's in-memory length
does not substitute for this complete file length. No suffix or concatenated proof
is permitted. A final short group consumes exactly its remaining file bytes.

ROOT, absolute 4096-byte counters, complete-left shape and concrete kernels follow
Hemera d5's tree/capacity/encoding contracts and parameters, already used by Radio
a96's GroupHasher. Grouping changes the carrier, never the canonical complete root.
Historical grouped internal CVs without ROOT are not accepted as canonical roots.
This does not equate the tree root with the separately pinned plain particle hash.

Constructor order is deterministic: RangeTraversal geometry admission (BlockSize
before range), reject an empty request when length > 0, then check the four expected
root words in ascending order. The constructor reads no proof bytes and hashes none.
Each hash word is one LE u64 and must be strictly below exported `hemera::field::P`;
check all four words in the supplied root and both children of every wire pair.
Use public Hemera constants for widths. `Hash::from_bytes` itself is a raw wrapper;
the proof reader must perform the canonical check before parent arithmetic.

Block log admits exactly the RangeTraversal range: 0..=51 on 64-bit, 0..=19 on
32-bit. This is integer geometry, not an allocation/Layout promise. Range requires
start <= end <= length. Empty file only admits 0..0: header must be zero, one empty
ROOT leaf is hashed, and EOF must be byte 8. It yields a verified empty view with
no output items. A nonempty file's empty request is rejected, including at EOF;
there is no successful mode with an unchecked root.

## Small public surface and lifetime

Names below are proposed, to be frozen by review:

```rust
ProofVerifier::new(proof: &[u8], root: [u8; 32], size: u64,
                   block: BlockSize, request: Range<u64>) -> Result<Self, ProofError>
ProofVerifier::is_finished(&self) -> bool
ProofVerifier::step(&mut self) -> Result<Option<VerifiedProof<'a>>, ProofError>
VerifiedProof::{root, size, block_size, request} // exact admitted operation inputs
VerifiedProof::items(&self) -> ProofItems<'a>
ProofItems::is_complete(&self) -> bool
impl Iterator<Item = ProofItem<'a>> + FusedIterator for ProofItems<'a>
enum ProofItem<'a> {
    Parent,
    Leaf { file_offset: u64, proof_offset: usize, bytes: &'a [u8] },
}
```

The implementation supplies explicit named lifetimes; this sketch abbreviates them.
VerifiedProof has private fields and no public constructor, conversion from raw
bytes, Deserialize, attestation or mutable-byte escape. Its accessors return the
root/size/block by value, and a cloned range. It borrows only the original immutable
proof, not the verifier. It can outlive a dropped verifier but not the proof bytes.
No allocation owner/clone is acquired. Debug prints coordinates/state, not payload.
Public ProofItem values carry slices/coordinates, not independent sealed authority;
consumers obtain trusted items through a successfully completed view and its root.

Pending successful steps return None with is_finished=false. Exact EOF completion
returns Some(view) once and sets is_finished=true. Later successful polls return
None without work. Any processing error becomes sticky and sets is_finished=true;
later polls return that same Copy error without work. Dropping cancels a pending job.
No push/flush/reset/request reuse or hidden quota renewal exists.

## Bounded machine and work

Use one RangeTraversal, one fixed 53-slot expected-hash stack, and at most one
GroupHasher borrowing the current proof group and a static Poseidon2Backend. The
expected stack follows the same frontier bound as traversal: at most 52 deferred
siblings plus one current value. Parent processing pops exactly one expectation,
hashes the pair using that node's ROOT bit, compares it, then pushes only selected
right/left expectations in that order. It does not traverse or authenticate the
unselected sibling payload. Never clone an arbitrary generic backend hash.

After constructor setup, each pending call admits exactly one of these actions:

| Action | Exact bounded work and transition |
| --- | --- |
| Header | Read at most 8 bytes, compare declared/trusted size, seed expected root. |
| Parent | Obtain one traversal item, consume exactly 64 bytes, validate left words then right words, one parent kernel, compare, push at most two expectations. |
| Group setup | Obtain one leaf item, take exactly its checked payload slice, pop its expectation, initialize the fixed reducer; no kernel. |
| Group kernel | Exactly one GroupHasher step: one <=4096-byte leaf or one two-child parent. On completing hash, compare the pending expected hash in this same action. |
| Commit | Geometry and expected stack must be empty and no group pending; check cursor == proof.len, emit the view. |

The empty file substitutes one synthetic zero-length ROOT group setup for geometry,
then one kernel. No generic reducer, traversal scan, proof-sized buffer initialization
or payload copy may be hidden in any action or constructor. Fixed 53-slot setup and
small scalar checks are bounded setup. GroupHasher admission cannot fail after
checked traversal: real group bytes fit usize/u64 and final absolute chunk counters
are <=2^52-1; use an internal invariant assertion rather than inventing a reachable
new external failure class. Stack/geometry invariants likewise follow private state.

For a valid nonempty proof let P be visited parents, L selected groups, and C the
number of 4096-byte chunks across those groups. Total actions are
`2 + P + L + sum(2*N_group-1) = 2 + P + 2*C`. Empty-file total is 4. This is an
exact oracle, not an uncharged constructor traversal. Across a u64-sized file with
N=ceil(size/4096), P <= groups-1 <= N-1, so total <=3*N+1 <2^54. Counts cannot
overflow u64. Error attempts cost their one admitted action; terminal polls cost 0.
Radio owns no budget type. The caller checks is_finished, admits one persistent
unit, then steps; it may abort on total exhaustion with no published result. A
future Kadek adapter must not reset totals on yields, completed groups or the
transition from verification to output/copy. No exact-total preflight is promised
by this Radio API; a separate charged planning walk would be an adapter choice.

Read extents use `needed <= proof.len()-cursor` before slicing/advancing. Leaf
coordinates come from the checked traversal; multiply its absolute chunk start
by 4096 only under that bound. Keep proof usize offsets distinct from file u64
offsets. No unchecked BaoTree byte helpers are used for large geometry.

## Errors and output actions

ProofError derives Debug, Clone, Copy, PartialEq and Eq, and implements Display
and core::error::Error. Its exact variants and precedence are:

| Location | Error and coordinate |
| --- | --- |
| Constructor | Geometry(RangeTraversalError), then EmptyRequest, then NonCanonicalRoot { word: u8 }. |
| Header | Truncated { offset: 0, needed: 8 }, then SizeMismatch { expected, declared }. |
| Parent | Truncated { offset: cursor, needed: 64 }, then NonCanonicalHash { offset: offending LE word's absolute proof offset } scanning left then right, then ParentMismatch { node: TreeNode }. |
| Group setup | Truncated { offset: cursor, needed: exact group size }. |
| Completing group | LeafMismatch { start_chunk: u64 }; zero for empty file. |
| Commit | TrailingBytes { offset: consumed proof length }. |

No EOF publication on a matching last group alone. An invalid suffix makes the
whole proof fail. No partially verified view is accessible on any failure.
Freeze exact Display messages and variant/coordinate assertions with tests before
implementation; do not make diagnostic strings the only oracle.

`items()` creates a fresh checked geometry cursor in bounded fixed setup and starts
its proof cursor at 8; construction scans/hashes/copies no proof. Each pending next
obtains exactly one geometry item. Parent advances 64 bytes and returns Parent;
leaf advances its exact size and returns that immutable slice plus file/proof
coordinates. It must not loop across parents to find a leaf. Verified immutable
input permits infallible replay; assert private invariants rather than rehash.
P+L output actions, zero for empty file. The cursor is immediately complete after
the final item and all later polls return None without work. Caller charges each
pending output action separately, then charges any byte copying separately; no
free collect/copy helper. Whole groups may extend outside the request. Copy only
their intersection with the view's exact requested range for a requested-range
packet; do not confuse wire offsets with authenticated file offsets.

## Steps, files, and gates

1. Preserve research probes and fixtures and the completed actual traversal bridge.
   → verify: exact Git identities, retained a96d measurements, identical prerequisite
   candidate/merged source, unchanged lock and owning consumers except module wiring.
2. Freeze manual fixtures and tests from finite-cases.md, then demonstrate API
   absence on the exact parent. → verify: expected missing-module compiler class,
   separated from the measured legacy behavior; no false new runtime baseline.
3. Add only concrete proof module, output view and re-export/module wiring. → verify:
   all literal cases, exact costs/coordinates, step pauses/failures, no early result.
4. Exercise lifetime/field seals, allocation and feature/build contracts. → verify:
   positive control compiler case, expected compile-error classes, host allocation
   observer, debug/release, actual no-default count, no_std cross check; no final-link
   allocator-free claim based only on a library compile.
5. Freeze gate receipts, source delta and bounded fresh CODE context. → verify:
   independent exact-parent/raw/source replay, different-vendor CODE approval before
   root's commit/merge. No production CODE review is claimed by this PLAN.

Expected production paths: cyber-bao/src/lib.rs, new cyber-bao/src/proof.rs and
cyber-bao/src/proof/output.rs. Tests: new cyber-bao/tests/proof.rs,
proof_failures.rs, proof_allocation.rs and support/proof.rs (split by contract if
needed; every file <500 lines). Rustdoc is the API/carrier/work contract; README
gets at most a module link. No dependency/feature/wire-producer/kernel changes.
Task and audit paths are owned here; other source paths require a justified scope
amendment. No Kadek source or shared fixture ledger changes in this unit.

Required owner gates: strict warning-free cyber-bao debug/release tests for default,
no-default and all-features; doctests; Clippy and formatting; exact library no_std
cross check and measured MSRV. Semver against v0.1.0 plus actual-parent comparison
if needed; additive API requires minor acceptance regardless of no breaking findings.
Radio CI argv/config are frozen as support: workspace all/default/none test, Clippy,
docs, MSRV, formatting, deny and applicable native consumer gates are retained as
required gate rows, not silently replaced by the small owner suite. External/rung
closure and unavailable platform/toolchain rows must be explicit. Current parent
failure comparisons use exact failing cases/commands and identical env/profile,
never stale ancestor reds or an unnecessary second whole matrix. Local --locked,
offline, jobs=2, incremental=0 and bounded-time configuration are labeled local
strengthening, with raw command/timeout receipts. CI profile termination must be
read from actual config, not inferred. Research runs no broad CI matrix.

## Five likely failures

1. A trusted size/root becomes an arbitrary authority escape: keep Radio result
   conditional on supplied root, borrow original bytes, publish only at strict EOF;
   Kadek integration is separately sealed and outside this change.
2. ROOT or absolute counters change with grouping/selection: explicit three-leaf,
   sole-group, right-only and final-short manual carriers and historical-CV rejection.
3. Unbounded work hides in a traversal/leaf/output call: exact action schedules,
   largest-depth finite prefixes, one-item output events and source invariant review.
4. Canonical validation normalizes/reduces instead of rejecting: four independent
   word positions, both child sides and root, p-1/p/MAX boundaries before hashing.
5. Completion, failure or borrowed retention leaks partial authority: late suffix
   and last-leaf failures, sticky terminal polls, interleaved jobs, output exact ranges,
   successful/failed/cancelled drop and compile-time lifetime/field seals.
