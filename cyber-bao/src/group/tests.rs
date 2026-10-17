use super::*;
#[test]
fn u64_geometry_is_bounded_without_oversized_slices() {
    for (len, leaves) in [
        (0, 1),
        (1, 1),
        (4095, 1),
        (4096, 1),
        (4097, 2),
        (u64::MAX - 4095, 4_503_599_627_370_495),
        (u64::MAX, 4_503_599_627_370_496),
    ] {
        assert_eq!(leaf_count(len), leaves);
        assert_eq!(validate_counter(len, 0), Ok(leaves));
        assert_eq!(validate_counter(len, u64::MAX - (leaves - 1)), Ok(leaves));
        if leaves > 1 {
            assert_eq!(
                validate_counter(len, u64::MAX - (leaves - 2)),
                Err(GroupHashError::CounterOverflow)
            );
        }
    }
    assert_eq!(2 * leaf_count(u64::MAX) - 1, 9_007_199_254_740_991);
}
