
/// Convert output field elements to a hash byte array.
///
/// Uses the full canonical u64 representation (8 bytes LE) per element.
pub(crate) fn hash_to_bytes(elements: &[Goldilocks; OUTPUT_ELEMENTS]) -> [u8; OUTPUT_BYTES] {
    let mut out = [0u8; OUTPUT_BYTES];
    for (i, elem) in elements.iter().enumerate() {
        let val = elem.as_canonical_u64();
        out[i * OUTPUT_BYTES_PER_ELEMENT..(i + 1) * OUTPUT_BYTES_PER_ELEMENT]
            .copy_from_slice(&val.to_le_bytes());
    }
    out
}

/// Convert a hash byte array back into Goldilocks elements.
///
/// Inverse of `hash_to_bytes`. Used by `hash_node` in the tree module.
pub(crate) fn bytes_to_cv(bytes: &[u8; OUTPUT_BYTES]) -> [Goldilocks; OUTPUT_ELEMENTS] {
    let mut out = [Goldilocks::new(0); OUTPUT_ELEMENTS];
    for (i, elem) in out.iter_mut().enumerate() {
        let start = i * OUTPUT_BYTES_PER_ELEMENT;
        let val = u64::from_le_bytes(
            bytes[start..start + OUTPUT_BYTES_PER_ELEMENT]
                .try_into()
                .unwrap(),
        );
        *elem = Goldilocks::new(val);
    }
    out
}

#[cfg(test)]
mod tests {
