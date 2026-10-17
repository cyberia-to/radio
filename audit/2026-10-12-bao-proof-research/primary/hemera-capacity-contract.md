
## layout

```
state[0..8]   rate       input absorption / output squeezing
state[8..16]  capacity   structural context, never touched by input

state[8]      counter    chunk position in file (0-based, u64)
state[9]      flags      structural role (bitfield)
state[10]     msg_length total input byte count (sponge finalization)
state[11]     domain_tag   API mode selector (PLANNED FOR REMOVAL — see roadmap/one-pure-hash.md)
state[12]     ns_min     namespace lower bound (NMT only, zero otherwise)
state[13]     ns_max     namespace upper bound (NMT only, zero otherwise)
state[14]     reserved   must be zero
state[15]     reserved   must be zero
```

## flags (state[9])

three single-bit flags, combined via bitwise OR:

```
FLAG_ROOT   = 0x01    this hash finalizes a tree root
FLAG_PARENT = 0x02    this hash combines two child hashes (internal node)
FLAG_CHUNK  = 0x04    this hash derives a leaf chaining value
```

valid combinations:

| context | flags | value |
|---|---|---|
| plain sponge hash | (none) | 0x00 |
| non-root leaf | CHUNK | 0x04 |
| root leaf (single-chunk file) | CHUNK \| ROOT | 0x05 |
| non-root internal node | PARENT | 0x02 |
| root internal node (tree root) | PARENT \| ROOT | 0x03 |

flags encode what the hash IS, not what it contains. a flag combination that does not appear in the table is invalid.
