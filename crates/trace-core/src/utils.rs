/// 零分配 ASCII 大小写不敏感子串搜索
#[inline]
pub fn ascii_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(h, n)| h.to_ascii_lowercase() == *n)
    })
}

/// Parse a hex address string (with or without 0x/0X prefix) to u64.
pub fn parse_hex_addr(s: &str) -> Result<u64, String> {
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(hex, 16).map_err(|_| format!("Invalid hex address: {}", s))
}

/// Parse a signed decimal or hexadecimal displacement such as `32`, `0x20`,
/// `+0x20`, or `-0x10`.
pub fn parse_signed_offset(value: &str) -> Result<i64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(0);
    }
    let lower = value.to_ascii_lowercase();
    if let Some(hex) = lower.strip_prefix("-0x") {
        let magnitude =
            i64::from_str_radix(hex, 16).map_err(|_| format!("Invalid signed offset: {value}"))?;
        magnitude
            .checked_neg()
            .ok_or_else(|| format!("Signed offset underflow: {value}"))
    } else if let Some(hex) = lower.strip_prefix("+0x") {
        i64::from_str_radix(hex, 16).map_err(|_| format!("Invalid signed offset: {value}"))
    } else if let Some(hex) = lower.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).map_err(|_| format!("Invalid signed offset: {value}"))
    } else {
        lower
            .parse::<i64>()
            .map_err(|_| format!("Invalid signed offset: {value}"))
    }
}

/// Format a signed displacement in canonical hexadecimal form.
pub fn format_signed_offset_hex(value: i64) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("0x{value:x}")
    }
}

/// Add a signed displacement to an unsigned runtime address without wrapping.
pub fn checked_add_signed_offset(base: u64, displacement: i64) -> Option<u64> {
    if displacement < 0 {
        base.checked_sub(displacement.unsigned_abs())
    } else {
        base.checked_add(displacement as u64)
    }
}

#[cfg(test)]
mod signed_offset_tests {
    use super::*;

    #[test]
    fn parses_formats_and_applies_signed_offsets_without_wrapping() {
        assert_eq!(parse_signed_offset("+0x20").unwrap(), 0x20);
        assert_eq!(parse_signed_offset("-0x10").unwrap(), -0x10);
        assert_eq!(parse_signed_offset("32").unwrap(), 32);
        assert_eq!(format_signed_offset_hex(-0x10), "-0x10");
        assert_eq!(checked_add_signed_offset(0x1000, -0x10), Some(0xff0));
        assert_eq!(checked_add_signed_offset(0, -1), None);
    }
}
