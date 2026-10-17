# Finite proof-verifier acceptance table

Proposed tests, frozen before the new API exists. Research fixtures are under
audit/2026-10-12-bao-proof-research/fixtures. Rust primary-probe builds the wire
manually, uses explicit chunk/parent expressions, then checks legacy producer and
reader agreement as supplemental evidence. It does not implement the proposed
reader. Its printed expected_actions are PLAN literals, not measured new-reader work.

For D[n], byte i = (31*i + floor(i/4096)) mod 256. Let Li be the non-ROOT hash of
the actual chunk at absolute counter i; P01=parent(L0,L1,false). Three-chunk ROOT
is parent(P01,L2,true). No recursive test helper infers these small tree shapes.
Future five/seven-group cases spell their parent expressions independently:
R5=P(P(P(L0,L1),P(L2,L3)),L4,ROOT);
R7=P(P(P(L0,L1),P(L2,L3)),P(P(L4,L5),L6),ROOT), inner P never ROOT.

## Literal successful carriers

Offsets below refer to payload in the encoded proof; file coordinates are separate.
H=header, P=one parent, S=group setup, K=one reducer kernel, E=EOF commit. Every
proper prefix of each action sequence must return no completed view. Output Parent
events consume one action each; output leaves borrow exactly the listed proof bytes.

| Fixture | File/request/log | Payload (proof offset; file offset; bytes) | Verification | Output |
| --- | --- | --- | --- | --- |
| empty | 0 / 0..0 / 0 | none | H S K E = 4 | 0 |
| hello | 5 / 1..4 / 0 | 8; 0; 5 | H S K E = 4 | Leaf |
| three-right | 12288 / 8192..8193 / 0 | 72; 8192; 4096 | H P S K E = 5 | Parent, Leaf |
| three-interior | 12288 / 4097..4100 / 0 | 136; 4096; 4096 | H P P S K E = 6 | Parent, Parent, Leaf |
| three-boundary | 12288 / 4095..4097 / 0 | 136; 0; 4096 and 4232; 4096; 4096 | H P P S K S K E = 8 | Parent, Parent, Leaf, Leaf |
| grouped-left | 12288 / 4095..4097 / 1 | 72; 0; 8192 | H P S K K K E = 7 | Parent, Leaf |
| final-short | 8193 / 8192..8193 / 1 | 72; 8192; 1 | H P S K E = 5 | Parent, Leaf |
| sole-group | 8192 / 1..8191 / 1 | 8; 0; 8192 | H S K K K E = 6 | Leaf |

Root literals: empty ea57b2e6b1ec7d2de11b15cb6d7060dd61d247fe0fbf5f7d3fb97a7be9328552;
hello 626fa46e4e7bd5c87d630eef8333931a0b9198587400a0191eae7821692880d7;
D8192 2abf65dd26465a7352707d79d18ff3aab9ee5d97614a774619c79ed527e20190;
D12288 373d0ded6b2bd351ba575cdc690ca79bbc04af1a49844f67140ce7a10e672992;
D8193 40c6bd68b6e89443753bce2dd95fd159da63a7399340fa6070a762d102d9e3ae.
D8192 historical internal CV is
11890a7e7cf1e4de463a04bf53bfdf269d627983a221daaf9029a3ff43297389.
It must fail sole-group LeafMismatch { start_chunk: 0 }, not normalize to ROOT.

Complete the pre-implementation fixture set with explicit full-three, right/interior
five/seven, all groupings 0/1/2/4 where their wire differs, one-byte final group and
nonaligned requests. Freeze expected pair order/ranges before coding; roundtrip is
never their sole oracle. Freeze source files before failure-first API-absence run.

## Admission, malformed proof, and precedence

| Case | Required result |
| --- | --- |
| Exhaust all 256 logs, including short/empty file | Geometry InvalidBlockSize outside host range; compile-only 32-bit evidence labeled separately. |
| Reversed range, EOF+1, both invalid log/range | Geometry InvalidRange; bad log takes precedence. |
| Nonempty file 0..0, interior empty, EOF empty | EmptyRequest before root/proof parsing. |
| Empty file valid 0..0 / invalid 0..1 | Four-step root verification / InvalidRange. |
| Expected root has p or MAX in each word independently | NonCanonicalRoot { word: 0/1/2/3 }; ascending first error, before header. |
| Root word 0 or p-1 | Canonical admission, then ordinary proof mismatch if not the matching root; no false validity claim. |
| Hello header declared 0, 4, 6, 4096, MAX, trusted length 5 | Header SizeMismatch with exact expected/declared. LE 5 succeeds. |
| Every header prefix 0..7 bytes | Truncated { offset:0, needed:8 }. |
| Every truncated prefix of three-interior, grouped-left | Stage-specific Truncated cursor/needed; complete bytes required before examining a pair or starting a group. |
| Pair word p/MAX, left and right, all four positions | NonCanonicalHash at 8+word*8 or 40+word*8 for first pair, before parent hashing; second parent starts at 72. |
| Noncanonical left followed by incomplete right pair | Pair Truncated takes precedence over canonical validation. |
| Canonical pair order swap, canonical wrong root, modified canonical sibling | ParentMismatch at literal node3 or1, before group output. |
| Three-boundary first/last payload mutation | LeafMismatch counter 0/1; completed earlier group never yields a view. |
| Same selected data computed at wrong absolute counter | LeafMismatch of selected start counter. |
| Single/multiple group suffix 1 byte / concatenated valid proof | TrailingBytes at exact original carrier length after hashing, no view. |
| Empty-file correct root + suffix / canonical wrong root | TrailingBytes offset 8 / LeafMismatch counter 0. |
| Nonempty file header-only, nonempty request | First parent or leaf setup Truncated, never success with an unchecked root. |
| u64MAX file, log 51 on 64-bit, first-byte query, short carrier | Bounded Parent processing then leaf Truncated with exact large needed; no allocation or overflowing end. |

The synthetic-canonical and four synthetic-alias fixtures bind a supplied parent
commitment with an arbitrary zero unselected sibling. Each alias changes only one
right child's LE word from 0 to p. Legacy accepts all under the same supplied root;
the new profile must reject each at offsets 40, 48, 56, 64. No actual complete file
with this synthetic root has been witnessed; these fixtures prove encoding behavior,
not a particle bypass or a complete-file collision.

## Work, state, retention, and bounds

- Exact valid action sequences above under per-call schedules 1,2,total,total+1;
  an external test budget with total exact and exact+1 completes at identical paid
  count; total one below prevents final commit and yields no authority. Radio has
  no WorkBudget constructor, so the harness must not pretend to test Kadek's adapter.
- Interleave two jobs and pause after every stage. No kernel repeats on resumption.
  Every error becomes sticky; repeat 10 failed polls returns identical variant/offset,
  no additional state work. Repeat 10 completed polls returns None. Drop at every
  pending stage performs no additional hashing or output.
- Rewalk each completed view twice, interleave its output cursors, assert exact
  event counts, slices, pointer offsets, file offsets and request intersections.
  Retain a borrowed view/leaf after verifier/cursor drop while proof stays alive.
  Empty view has 0 events and immediately complete. Final next makes complete true.
- Field/constructor seal compiler probes: a valid public API control succeeds;
  raw VerifiedProof struct literal fails E0451; no From/raw constructor/Deserialize
  escape exists; destroying or mutating borrowed proof storage before use fails
  the expected borrow-check class. Capture actual compiler diagnostics, not only
  generic compile_fail. No test claims aliases imply extra allocation charges.
- A host counting allocator test has an allocating positive control and observes
  constructor, each verifier stage, completed output replay, errors/terminal polls
  and cancellation/drop separately. Build and retain fixture storage outside observation; exclude its later deallocation. Concrete
  Poseidon2 scope only; a library cross compile does not prove allocator-free linking.
- Largest-depth fixed prefix uses u64MAX geometry, 52 explicit parent levels and
  one 4096-byte first leaf. Compute only those explicit synthetic commitments with
  zero deferred sibling CVs; a full-range request builds the 53-entry expected frontier
  then runs out of supplied proof. Observe Truncated and no result; do not enumerate
  the file or call this a real complete-file proof. This is separate from the already
  reviewed traversal boundary witness. Exact large coordinate/multiplication checks
  are asserted. Proof input retains no proof-sized output vector.

Canonical errors proposed Display strings (freeze with variants before coding):
geometry delegates to RangeTraversal; EmptyRequest = "empty request for nonempty file";
NonCanonicalRoot = "noncanonical expected root word {word}";
Truncated = "truncated proof at {offset}: need {needed} bytes";
SizeMismatch = "proof size {declared} differs from expected {expected}";
NonCanonicalHash = "noncanonical proof hash word at {offset}";
ParentMismatch = "proof parent mismatch at node {node_index}";
LeafMismatch = "proof leaf mismatch at chunk {start_chunk}";
TrailingBytes = "trailing proof bytes at {offset}".
