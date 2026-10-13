}

fn encode_parent_pair(pair: &(hemera::Hash, hemera::Hash)) -> [u8; 2 * hemera::OUTPUT_BYTES] {
    let mut data = [0; 2 * hemera::OUTPUT_BYTES];
    let (left, right) = data.split_at_mut(hemera::OUTPUT_BYTES);
    left.copy_from_slice(pair.0.as_bytes());
    right.copy_from_slice(pair.1.as_bytes());
    data
}

