    }
}

/// Alias for `hash_leaf` — compatible with BAO chaining value terminology.
#[inline]
pub fn chunk_cv(data: &[u8], counter: u64, is_root: bool) -> Hash {
    hash_leaf(data, counter, is_root)
}

/// Alias for `hash_node` — compatible with BAO chaining value terminology.
#[inline]
pub fn parent_cv(left: &Hash, right: &Hash, is_root: bool) -> Hash {
    hash_node(left, right, is_root)
}

