
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// The Goldilocks prime: p = 2^64 - 2^32 + 1.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// Two's complement of P modulo 2^64: 2^32 - 1.
const NEG_ORDER: u64 = P.wrapping_neg(); // 0xFFFF_FFFF

/// A Goldilocks field element.
///
/// Internal value may be non-canonical (in `[0, 2^64)`).
/// Use `as_canonical_u64()` to reduce to `[0, p)`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Goldilocks {
    value: u64,
}

impl Goldilocks {
    pub const ZERO: Self = Self { value: 0 };

    #[inline]
    pub const fn new(value: u64) -> Self {
        Self { value }
    }

    /// Reduce to canonical form in [0, p).
    #[inline]
    pub fn as_canonical_u64(self) -> u64 {
        // Mask, not branch: hash outputs of secret inputs pass through here.
        self.value.wrapping_sub(P & u64::from(self.value >= P).wrapping_neg())
    }

    /// Compute x^2.
