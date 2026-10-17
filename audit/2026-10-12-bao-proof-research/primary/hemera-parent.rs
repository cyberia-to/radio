        }
    }
}

/// Combine two child chaining values into a parent chaining value.
///
/// With Hemera parameters (output=4 elements, rate=8), each child hash is 4 elements.
/// Both children together (4 + 4 = 8 elements) fit in one rate block.
/// Flags are set in the capacity before the absorption.
///
/// The `is_root` flag domain-separates the tree root from interior nodes.
pub fn hash_node(left: &Hash, right: &Hash, is_root: bool) -> Hash {
    let mut state = node_state(left, right, is_root);
    params::permute(&mut state);
    state_digest(&state)
}

/// Pre-permutation state of `hash_node`: flags in the capacity, both
/// children absorbed into the rate (4 + 4 = 8 elements = one rate block).
#[inline]
fn node_state(left: &Hash, right: &Hash, is_root: bool) -> [Goldilocks; WIDTH] {
    let left_elems = bytes_to_cv(left.as_bytes());
    let right_elems = bytes_to_cv(right.as_bytes());

    let mut state = [Goldilocks::new(0); WIDTH];

    // Set flags in capacity before absorbing.
    let mut flags = FLAG_PARENT;
    if is_root {
        flags |= FLAG_ROOT;
    }
    state[CAPACITY_FLAGS_IDX] = Goldilocks::new(flags);

    // Absorb both children (4 + 4 = 8 elements = one full rate block).
    for i in 0..OUTPUT_ELEMENTS {
        state[i] += left_elems[i];
    }
    for i in 0..OUTPUT_ELEMENTS {
        state[OUTPUT_ELEMENTS + i] += right_elems[i];
    }
    state
}

/// Digest of a permuted state: the first `OUTPUT_ELEMENTS`, canonical LE.
#[inline]
fn state_digest(state: &[Goldilocks; WIDTH]) -> Hash {
    let output: [Goldilocks; OUTPUT_ELEMENTS] = state[..OUTPUT_ELEMENTS].try_into().unwrap();
    Hash::from_bytes(hash_to_bytes(&output))
}

/// `out[i] = hash_node(&pairs[i].0, &pairs[i].1, is_root)` for every `i`.
///
/// Runs `permutation::BATCH_LANES` compressions interleaved per kernel
/// call (see `permutation::permute_batch`); no allocation. Use it where
