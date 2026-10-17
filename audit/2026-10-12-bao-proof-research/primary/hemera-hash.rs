#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash([u8; OUTPUT_BYTES]);

impl Hash {
    /// Create a hash from a raw byte array.
    pub const fn from_bytes(bytes: [u8; OUTPUT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Return the hash as a byte slice.
    pub fn as_bytes(&self) -> &[u8; OUTPUT_BYTES] {
        &self.0
    }

    /// Convert the hash to a hex string.
    #[cfg(feature = "std")]
    #[allow(unknown_lints, rs_no_string)]
    pub fn to_hex(&self) -> alloc::string::String {
        let mut s = alloc::string::String::with_capacity(OUTPUT_BYTES * 2);
        for byte in &self.0 {
            use core::fmt::Write;
            write!(s, "{byte:02x}").unwrap();
