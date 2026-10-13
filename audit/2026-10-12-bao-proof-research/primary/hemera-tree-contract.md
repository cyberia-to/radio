# canonical tree hashing

## Chunk Size: 4 KB (4096 bytes)

Content is split into fixed 4 KB chunks (4096 bytes). Each chunk is hashed via `hash_leaf(data, counter, is_root)`. At 56 input bytes per rate block, one 4 KB chunk requires ⌈4096/56⌉ = 74 absorptions. The last chunk may be shorter. No content-defined chunking — every boundary is deterministic.

See `docs/explanation/chunk-size.md` for rationale.

## Leaf Hashing: hash_leaf(data, counter, is_root) → Hash

Two-pass construction separates content hashing from structural binding:

```
Pass 1 — content hashing:
    hasher ← Hasher::new()              (plain sponge, domain_tag = 0x00)
    hasher.absorb(data)
    base_hash ← hasher.finalize()       (32-byte sponge output)

Pass 2 — structural binding:
    state ← [0; 16]
    state[0..4] ← bytes_to_elements(base_hash)    (4 Goldilocks elements)
    state[8]    ← counter                          (chunk position, 0-based)
    state[9]    ← FLAG_CHUNK | (FLAG_ROOT if is_root)
    state ← permute(state)
    output ← elements_to_bytes(state[0..4])        (32-byte chaining value)
```

Two passes exist for three reasons. The sponge remains a pure hash — no tree metadata contaminates its input stream. Tree logic is layered on top via the capacity region. The `base_hash` is cacheable: if a chunk appears at multiple positions, the expensive 74-absorption pass runs once and the cheap 1-permutation binding runs per position.

Counter prevents chunk reordering. CHUNK flag prevents leaf/node confusion. ROOT flag distinguishes root finalization from subtree chaining.

Cost: N absorptions + 1 permutation. At 4096 bytes: 74 + 1 = 75 permutations per leaf.

## Internal Node Hashing: hash_node(left, right, is_root) → Hash

```
state ← [0; 16]
state[9] ← FLAG_PARENT | (FLAG_ROOT if is_root)

// Absorb both children (4 + 4 = 8 elements = one full rate block)
state[0..4] += bytes_to_elements(left)     (field addition, element-wise)
state[4..8] += bytes_to_elements(right)    (field addition, element-wise)
state ← permute(state)

output ← elements_to_bytes(state[0..4])    (32-byte chaining value)
```

No padding needed — inputs are always exactly two 32-byte hashes (4 + 4 = 8 elements = one rate block). PARENT flag lives in the capacity region. Order matters: `hash_node(A, B) ≠ hash_node(B, A)`.

Cost: 1 permutation per internal node.

## Namespace-Aware Parent: hash_node_nmt(left, right, ns_min, ns_max, is_root) → Hash

Same as `hash_node` but with namespace bounds in the capacity:

```
state[12] ← ns_min        (minimum namespace in subtree)
state[13] ← ns_max        (maximum namespace in subtree)
```

When `ns_min = ns_max = 0`, reduces to `hash_node`. Only NMT uses non-zero namespace bounds.

Verifier checks: `parent.ns_min ≤ left.ns_max < right.ns_min ≤ parent.ns_max` (for sorted NMT).

Cost: 1 permutation (same as `hash_node`).

## Tree Shape

Binary, left-balanced, in-order indexed:

```
If N = 1:     hash_leaf(data, 0, is_root=true)  is the root
If N > 1:     split = 2^(⌈log₂(N)⌉ - 1)
              left  = tree_hash(chunks[0..split],       is_root=false)
              right = tree_hash(chunks[split..N],        is_root=false)
              root  = hash_node(left, right, is_root=true)
```

Left-balanced: the left subtree is always a complete binary tree (power-of-2 leaves). The right subtree absorbs the remainder and recurses with the same rule.

In-order indexing: Leaves at even positions (0, 2, 4, ...). Parents at odd positions with `level = trailing_ones(index)`. This indexing is compatible with Merkle Mountain Range append operations.

## Root Finalization

| Case | Function | Flags | Value |
|---|---|---|---|
| Single-chunk file | `hash_leaf(data, 0, is_root=true)` | CHUNK \| ROOT | 0x05 |
| Multi-chunk file | `hash_node(left, right, is_root=true)` | PARENT \| ROOT | 0x03 |

The ROOT flag ensures that a file's identity hash is never equal to any internal chaining value. A subtree hash with `is_root=false` is structurally distinct from the same tree computed as a standalone file with `is_root=true`.

## Security Properties

| Attack | Defense | Mechanism |
|---|---|---|
| Leaf/node confusion | Prevented | CHUNK (0x04) vs PARENT (0x02) in capacity |
| Chunk reordering | Prevented | Counter in state[8] binds position |
| Chunk duplication | Prevented | Counter distinguishes identical chunks at different offsets |
| Subtree substitution | Prevented | ROOT flag separates file identity from subtree identity |
| Length extension | Prevented | Length in state[10] (sponge) + counter (binding) |
| Second preimage via tree | Prevented | All of the above, combined |

## Complete Example

A 12 KB file (3 chunks):

