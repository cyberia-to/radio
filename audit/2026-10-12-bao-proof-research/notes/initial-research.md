# Bounded BAO proof research

Serves: owner's Kadek phase-1 closure · Radio/Cyb · Kadek foundation row 4,
authenticated source ranges. Stage: active research; evidence: open. Root owns
this task in `research/bao-bounded-proof`. Discovered from `bao-bounded-traversal`
and Kadek `proof-provenance`; production is blocked on a merged traversal and a
fresh different-vendor PLAN review. No implementation or gate result is claimed.

Inspected Radio parent: `a96d86e28d384cdf656aadc4282c78c0c170c102`.
Pinned Hemera: `d5f0a09539360934fb32db9b2e15a91995607db6`.
Reads use `git show <revision>:<path>`, never a dirty sibling source. The files
below are the basis of this preliminary source review; execution evidence and
the final source manifest must be frozen before PLAN submission.

## Existing carrier and ownership

`cyber-bao/src/io/slice.rs` emits an eight-byte little-endian complete length,
then selected preorder child pairs and whole selected group payloads. The
request and BlockSize arrive separately. Poseidon2 pairs are 64 bytes through
`src/hash.rs` and Hemera's 32-byte output. A multi-group request filters the
tree; the single-group extraction shortcut emits the complete body even for an
empty request. The decoder's single-group shortcut hashes every remaining byte;
its multi-group path returns owned leaf vectors without requiring encoded EOF.
These existing APIs therefore do not specify a strict complete-proof carrier.

The old reader materializes traversal, expected-hash and output vectors, and
hashes a whole group in one call. The merged `GroupHasher` bounds one call to
one leaf or parent kernel. The pending `RangeTraversal` bounds geometry to one
node per call. Neither primitive parses the wire or establishes a particle/root
association. A new bounded reader must compose these responsibilities and leave
legacy std convenience APIs unchanged unless a separate migration is approved.

Kadek's concurrent sealed-anchor task owns the complete-body association. Radio
should accept an explicitly trusted root and complete length; Kadek retains the
sealed capability and owns allocation, persistent WorkBudget, exact source
coordinates and publication of VerifiedRange/Packet. Caller-supplied roots alone
must never manufacture Kadek authority. Whole-proof verification must finish
before that adapter publishes source authority. Network fetching, first-partial
authentication and serialized-anchor restoration remain outside this unit.

## Hash encoding boundary

At the pinned Hemera source, `rs/src/sponge.rs` defines `Hash::from_bytes` as a
raw array wrapper and derives bytewise equality. It does not normalize words.
`rs/src/encoding.rs::hash_to_bytes` emits canonical little-endian field words;
`bytes_to_cv` separately reduces each input word through `Goldilocks::new`.
Its `bytes_to_cv_with_above_prime_value` test explicitly describes that behavior.
Parent hashing calls that conversion. Thus wire parsing and parent arithmetic
have different representation boundaries. This is a source observation, not a
measured accepted proof mutation or a particle/root forgery.

The future PLAN must state whether this reader accepts existing raw hash
representations or imposes a new canonical wire rule. It must test that choice
without changing Hemera arithmetic or silently claiming canonical validation
from `Hash::from_bytes`. A generic backend also controls Hash storage, cloning,
parsing and kernel cost; unconditional allocation/work guarantees cannot be
inferred from the trait. Concrete Poseidon2 guarantees need explicit scope.

## Questions to close before PLAN

1. Freeze one complete-buffer carrier: header equality against trusted length,
   exact EOF or an explicit consumed-length result, and empty-file/empty-request
   behavior. An empty geometry traversal alone proves no root or payload.
2. Define terminal and failure states and one bounded processing action, including
   header admission, parent comparison, group setup, each reducer kernel and
   completion. No traversal scan or proof-sized copy may hide in construction.
3. Bound the expected-hash stack, geometry cursor and pending reducer separately;
   prove checked byte extents on 32/64-bit hosts. Restrict grouping before shifts.
4. Choose the smallest output that lets Kadek verify the whole proof before
   publishing and copy only requested intersections under its own work/pool
   limits. Keep encoded-proof positions distinct from authenticated file ranges.
5. Freeze independent finite proofs: literal empty/hello roots; manual pair
   order for right/interior/non-power-of-two paths; grouped and final-short
   leaves; malformed header, parent, payload, truncation, suffix and exact quota
   boundaries. Existing producer/consumer roundtrips are supplemental evidence.

No API shape, empty-query policy or canonical-wire tightening is accepted by
this preliminary note. Those choices belong to the reviewed PLAN, with actual
source/fixture probes and direct-consumer reach recorded before implementation.

## Legacy carrier probe

The standalone Rust probe under `audit/2026-10-12-bao-proof-research/probe/`
characterizes the existing std API at a96d86e. It supplies a literal `hello`
carrier, varies only its declared length, appends bytes to a two-chunk carrier,
and compares empty requests in single/multiple groups. Root's initial debug run
accepted declared lengths 0, 4, 5, 6 and 4096 for the same five payload bytes;
accepted a six-byte suffix after the 8264-byte two-chunk proof; and returned an
empty result for a header-only multi-group request even with a wrong root.
The single-group empty request still carries all five payload bytes.

Command: `cargo run --locked --offline --manifest-path
audit/2026-10-12-bao-proof-research/probe/Cargo.toml`, Rust 1.95 with
`RUSTFLAGS=-Dwarnings`, Radio a96d86e and Git Hemera d5f0a095. Raw initial
receipts are `/tmp/radio-bao-proof-legacy-debug-v1.{json,stdout,stderr}` pending
the final portable research pack. These observations concern legacy carrier
admission, not a demonstrated hash forgery or Kadek authority bypass.
