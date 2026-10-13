# Bounded BAO proof research

Serves Kadek foundation row 4 through Radio (declared part of soft3) and a future Kadek adapter in Cyb. Stage: research complete;
PLAN proposed, not approved. Owned branch research/bao-bounded-proof; no production
changes, commit, push or vendor dispatch. Original preliminary note is retained in
`audit/2026-10-12-bao-proof-research/notes/initial-research.md`.

Source identities: Radio a96d86e28d384cdf656aadc4282c78c0c170c102; Hemera
d5f0a09539360934fb32db9b2e15a91995607db6; committed Kadek anchor
4d9ca9ab3498238b9c1e03f6d6f160e1ec729912. RangeTraversal merged as Radio PR39,
b933829cbe273d2f31fe75ca83125f3ddd8917a2. Ordinary fetch/fast-forward and an exact
source bridge confirm candidate identity and unchanged kernels/carrier/lock/consumers,
except module wiring. New implementation will use b933; all research measurements
remain attributed to a96d. No broad Radio matrix was run
for research. This research does not close Kadek row 4 or prove an allocator-free
final no_std application link.

## Existing carrier and measured boundary

`cyber-bao/src/io/slice.rs` writes eight LE complete-length bytes, selected preorder
parent pairs and complete selected groups. Multi-group verification allocates
traversal, expected-hash and output vectors, hashes an entire group in one call,
and does not require encoded EOF. The single-group shortcut hashes all remaining
bytes without checking their length against the header. Single-group extraction
includes the body even for an empty request; multi-group empty extraction is only
its header. These are existing API semantics, left unchanged by the proposed unit.

The immutable legacy probe manually supplies LE5 + hello, mutates only the header,
appends a six-byte suffix to a two-chunk carrier, and checks empty requests. At
Radio a96d and Rust 1.95, debug and release both accept declared lengths 0,4,5,6,4096
for five actual bytes; accept the suffix after an 8264-byte proof; and return an
empty result for an empty multi-group query with a wrong root. Both captured outputs
are identical 321-byte files. These are size/EOF/empty-selection admission witnesses,
not forged hashes, a particle/root substitution, or new-reader test failures.

Commands are captured verbatim in records/initial-debug.json and legacy-release.json:
`cargo run [--release] --locked --offline --manifest-path .../probe/Cargo.toml`,
Rust 1.95, jobs 2, incremental 0, RUSTFLAGS=-Dwarnings, a private target directory.
The legacy three-file freeze remains unchanged. Root's first inline source-freeze
helper used a wrong Ruby text/binary comparison and was corrected before handoff;
that helper mistake is not a production discrepancy.

## Independent carrier and encoding evidence

The separate 269-line primary-probe manually writes eight real-file carriers using
explicit small chunk/parent expressions. They cover empty/hello, three-chunk right
and interior selection, a cross-chunk request, grouped-left selection, a final
one-byte group and a sole two-chunk group. Its root/offset/action table is in
finite-cases.md. It compares with existing producer/reader only after construction;
roundtrip is supplemental, not the wire-shape oracle. Existing empty, hello,
D8192 ROOT and historical non-ROOT literals are asserted independently. New D12288
and D8193 roots are pinned kernel-expression results, not independent cryptographic
implementations. Printed action counts are proposed-machine literals, not measured
new-API work. Debug and release outputs and every generated fixture agree exactly.

At pinned Hemera, public `hemera::field::P` is 0xffff_ffff_0000_0001 and Hash stores
four LE words. `Hash::from_bytes` preserves any 32 bytes with bytewise equality.
`bytes_to_cv` calls Goldilocks::new, which stores raw u64; it does not itself reduce.
Field arithmetic and canonical hash output identify residue-equivalent values.
This corrects the preliminary shorthand that the constructor performs reduction.
The normative output encoding is canonical [0,p); parent input parsing currently
has no representation guard. The new profile must check all four words of root
and both children before hashing; it must not normalize an invalid encoding.

A synthetic parent commitment, with actual selected-left chunk CV and an arbitrary
zero unselected-right CV, demonstrates each word independently. Replacing any one
zero right word by p preserves parent output and legacy acceptance; the raw Hash
still differs. Five fixtures retain the canonical and four alias carriers. There
is no witnessed complete file for this synthetic commitment. This measures encoding
behavior, not a complete-file collision or a Kadek authority bypass. Separate
0,p-1,p,MAX raw-word controls retain their exact bytes. The proposed canonical rule
accepts the first two representations and rejects the latter two, regardless of any
later root mismatch. All checks pass in debug/release with strict warnings.

## Smallest composition

GroupHasher is already merged: one <=4096-byte leaf or one parent kernel per call,
fixed 53 frontier, absolute counters and only final ROOT. Merged RangeTraversal
supplies checked u64/usize geometry with a fixed 53-frame frontier and one selected
node per call. Parent child flags specify which paths to visit; both child hashes
remain necessary. Neither primitive parses the carrier or binds a particle.

Proposed composition is concrete Poseidon2: a borrowed whole-buffer verifier,
fixed expected-hash stack and at most one borrowed GroupHasher. Generic HashBackend
permits arbitrary allocation/cost through its associated Hash and methods, so it
cannot justify unconditional resource guarantees. No new hash arithmetic, generic
transform, allocation, byte owner or budget abstraction is needed. The verifier
checks trusted header length, all parents/groups, canonical words and exact EOF,
then seals a borrowed result. Its output cursor emits one parent event or whole
leaf slice per call; it never scans for a leaf, hashes again, or allocates a span
vector. Kadek will separately match its BaoAnchor and own quota/pool/copy/publication.

For a valid nonempty proof, exact action count is header 1 + parents P + group setups L
+ sum(2*N_group-1) + EOF 1 =2+P+2*C; empty file costs 4 and has no output items.
No exact total is computed by an uncharged traversal. Caller-supplied persistent
budgets can stop before any next action without publication. One atomic kernel
remains a bounded unit, not constant wall time. Immutable proof borrowing prevents
mutation after verification; completed views depend on proof lifetime, not verifier
lifetime. Private fields prevent fabricating a completed view through safe API.

Chosen empty policy is strict: reject any empty request to a nonempty file, including
EOF, instead of adding a successful no-authentication mode. Empty file 0..0 still
hashes canonical empty ROOT and requires an exact eight-byte header. This API is a
new strict profile; unchanged legacy single-group empty extraction does not define
its admission. A profile-preserving grouping change uses repaired canonical roots;
old grouped internal CVs are not grandfathered.

## Consumers, scope and remaining verification

Within exact Radio a96d, four manifests directly depend on cyber-bao: iroh-blobs,
particle, radio-cli, tests/integration. iroh-docs depends on local iroh-blobs. Current
particle/radio-cli use std encode/decode/outboard; the iroh-blobs slice decoder call
is in the cfg(test) export_pairs module. Other current slice callers are cyber-bao
unit/integration tests. The new additive module migrates none of those APIs. Radio
exporter writes the same size/pair carrier; its actual literal exporter tests are
relevant regression coverage. Sync/fsm transport variants can omit a size header;
they are not silently admitted as this complete-buffer profile.

Kadek now pins cyber-bao a96d with default-features=false for BaoAnchor, using the
same merged GroupHasher and Git Hemera d5; its plain particle remains registry
Hemera 0.3.1. Same immutable-body association is the authority invariant, not alleged
identity of the two source packages. A Radio result verified under an arbitrary
root cannot mint VerifiedRange. The future adapter remains a separate reviewed unit.

The prior exact-revision graph inventory is retained by hash/reference, with its
cached-default and retained-Nu distinctions; it is not a fresh network inventory.
The registry declares Radio part_of soft3 and Kadek part_of Cyb. New public API
reaches ring 1 even when existing direct calls remain unchanged. Required closure/gates and unavailable
platforms must be reported explicitly. No inherited-red assumption is attached to
this new candidate: eventual negatives need current exact-parent comparisons.

Next: freeze the bounded fresh vendor PLAN input after root's draft read and the
completed traversal merge bridge. Only approval authorizes tests-first
production. Implementation will supply exact diagnostics, allocation and lifetime
witnesses, current owner/workspace/consumer gates and a separate fresh CODE review.
