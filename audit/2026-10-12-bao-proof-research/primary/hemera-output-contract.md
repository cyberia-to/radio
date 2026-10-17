
Output uses the full canonical u64 representation: 8 bytes per element, little-endian. Output elements are guaranteed to be in [0, p) by the permutation — no reduction needed.

```
element 0 → bytes[0..8]     (u64 to LE bytes)
element 1 → bytes[8..16]
element 2 → bytes[16..24]
element 3 → bytes[24..32]   (= 32-byte hash output)
```

The asymmetry — 7 bytes in, 8 bytes out — is deliberate. Input encoding must be injective for collision resistance. Output encoding must preserve full field element fidelity for algebraic composability. These are different constraints with different optima.

## Padding (Hemera: 0x01 ∥ 0x00*)

