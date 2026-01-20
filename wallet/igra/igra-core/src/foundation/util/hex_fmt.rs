use crate::foundation::Hash32;
use std::fmt;

/// Hex formatter for arbitrary bytes.
///
/// - `Display` (`{}`) prints lowercase hex without `0x` prefix.
/// - `LowerHex` (`{:x}`) prints lowercase hex without `0x` prefix.
/// - `LowerHex` with alternate form (`{:#x}`) prints lowercase hex with `0x` prefix.
#[derive(Clone, Copy)]
pub struct HexBytes<'a>(pub &'a [u8]);

/// Hex formatter for 32-byte identifiers (`Hash32`).
#[derive(Clone, Copy)]
pub struct Hex32<'a>(pub &'a Hash32);

pub fn hx(bytes: &[u8]) -> HexBytes<'_> {
    HexBytes(bytes)
}

pub fn hx32(bytes: &Hash32) -> Hex32<'_> {
    Hex32(bytes)
}

fn fmt_lower_hex_bytes(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if f.alternate() {
        f.write_str("0x")?;
    }
    for b in bytes {
        write!(f, "{:02x}", b)?;
    }
    Ok(())
}

impl fmt::Display for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Preserve existing log style: no `0x` prefix for `{}`.
        fmt_lower_hex_bytes(self.0, f)
    }
}

impl fmt::LowerHex for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_lower_hex_bytes(self.0, f)
    }
}

impl fmt::Display for Hex32<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_lower_hex_bytes(self.0, f)
    }
}

impl fmt::LowerHex for Hex32<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_lower_hex_bytes(self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hx32_display_matches_hex_encode() {
        let value: Hash32 = [0xAB; 32];
        assert_eq!(format!("{}", hx32(&value)), hex::encode(value));
    }

    #[test]
    fn test_hx32_lowerhex_prefix() {
        let value: Hash32 = [0x01; 32];
        assert_eq!(format!("{:#x}", hx32(&value)), format!("0x{}", hex::encode(value)));
    }

    #[test]
    fn test_hx_display_matches_hex_encode() {
        let bytes = [0x00, 0x01, 0xFE, 0xFF];
        assert_eq!(format!("{}", hx(&bytes)), hex::encode(bytes));
    }
}
