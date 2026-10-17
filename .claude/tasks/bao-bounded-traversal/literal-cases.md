# Pre-implementation finite traversal expectations

Draft companion to the bounded traversal PLAN; no implementation or executed
test result. Parent geometry inspected at Radio
`dacd030c9d6301b316a96b5bc6e4ea1e1cec79f1`. The reducer is now integrated at
`a96d86e28d384cdf656aadc4282c78c0c170c102`; these literal shapes remain the
pre-implementation oracle, not captured candidate output.

Tokens below are literal preorder expectations. `P<n>` denotes a parent at
in-order group index n; `L<n>` denotes group n. The first token alone is ROOT.
For a complete query every parent visits both children. A selected leaf in a
larger file is never ROOT. These small tables are the primary shape oracle;
agreement with the existing eager traversal is supplementary.

| Groups | Complete preorder |
| --- | --- |
| 1 | L0 |
| 2 | P1 L0 L1 |
| 3 | P3 P1 L0 L1 L2 |
| 5 | P7 P3 P1 L0 L1 P5 L2 L3 L4 |
| 7 | P7 P3 P1 L0 L1 P5 L2 L3 P11 P9 L4 L5 L6 |
| 16 | P15 P7 P3 P1 L0 L1 P5 L2 L3 P11 P9 L4 L5 P13 L6 L7 P23 P19 P17 L8 L9 P21 L10 L11 P27 P25 L12 L13 P29 L14 L15 |
| 17 | P31 P15 P7 P3 P1 L0 L1 P5 L2 L3 P11 P9 L4 L5 P13 L6 L7 P23 P19 P17 L8 L9 P21 L10 L11 P27 P25 L12 L13 P29 L14 L15 L16 |

For group width 4096, group n starts at chunk n. For width 16384 it starts
at chunk 4n. Parent indexes do not scale. Full groups have their declared
width; repeat each table with the final group truncated to one byte.

`P<n>:L/R/B` below selects the left, right or both children. The complete
file still determines ROOT. Byte ranges are half-open.

| File / request | Expected selected preorder |
| --- | --- |
| 3 groups / final byte | P3:R L2 |
| 3 groups / first byte | P3:L P1:L L0 |
| 3 groups / [4096,8192) | P3:L P1:R L1 |
| 3 groups / [4095,4097) | P3:L P1:B L0 L1 |
| 3 groups / [8191,8193) | P3:B P1:R L1 L2 |
| 7 groups / final byte | P7:R P11:R L6 |
| 7 groups / group 5 | P7:R P11:L P9:R L5 |
| 7 groups / groups 3..5 | P7:B P3:R P5:R L3 P11:L P9:L L4 |
| 17 groups / final byte | P31:R L16 |

Also pin admission boundaries before implementation:

- Empty ranges at start, interior and EOF yield no item. Empty file 0..0
  yields no item; this establishes no authentication claim.
- Reversed ranges and end beyond EOF fail. Invalid geometry takes precedence
  even when the request is also invalid.
- Exhaust all 256 BlockSize values. On 32-bit targets admit 0..19, on 64-bit
  targets 0..51. Distinguish runtime execution from a cross-compile receipt.
- A u64::MAX-byte file at log 0, final-byte query, emits 52 parents then one
  leaf. First parent is 4503599627370495 and last parent is 9007199254740989;
  every parent visits only right, and only the first is ROOT. The leaf is
  chunk 4503599627370495, length 4095, non-ROOT.
- On 64-bit targets, the same file at log 51 emits P1:R then the non-ROOT
  leaf at chunk 2251799813685248, length 9223372036854775807.
- Polling after the final item is fused and is_complete changes immediately
  after that item. Pausing/interleaving two cursors leaves both sequences intact.
- A full u64::MAX-file request is polled for only its finite left prefix: 52
  parents at literal indexes `2^k-1`, k=52..1, then leaves 0 and 1 of length
  4096. All parent child flags are true and only the first is ROOT. Immediately
  before leaf 0 there are 52 deferred right siblings, reaching the 53-frame
  boundary. This never enumerates the whole file or allocates a body.
- A separate allocator witness uses a positive control and observes
  construction, every step, terminal polls and drop. Backend kernels are absent
  from this geometric API. No throughput measurement substitutes for checking
  the one-frame/one-item source invariant.
