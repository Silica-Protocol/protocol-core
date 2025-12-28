//! Helper functions for Block Height formatting.
//! Format: XXX-XXX-XXX.MMM
//! - Major part (XXX): Decimal, grouped by 3 digits, representing 32^3 (32,768) block epochs.
//! - Minor part (MMM): Base32 (Crockford Safe), 3 characters, representing the offset within the epoch.

const BASE32_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const EPOCH_SIZE: u64 = 32 * 32 * 32; // 32,768

/// Formats a block height into a human-readable string (e.g., "000-000-001.00Z").
/// Optimized to minimize allocations.
pub fn format_block_height(height: u64) -> String {
    let major = height / EPOCH_SIZE;
    let minor = height % EPOCH_SIZE;

    // Pre-allocate buffer.
    // Max u64 major is ~15 digits -> ~19 chars with dashes.
    // Minor is 4 chars (.MMM).
    // 32 bytes is plenty safe.
    let mut output = String::with_capacity(32);

    // 1. Format Major (Decimal with groups)
    let s = major.to_string();
    let len = s.len();

    // Pad to at least 9 digits for consistent alignment (000-000-000)
    let target_len = std::cmp::max(len, 9);
    let padding = target_len - len;

    let mut digit_count = 0;

    // Helper closure to handle separator logic
    let mut push_digit = |c: char, count: &mut usize| {
        if *count > 0 && (target_len - *count) % 3 == 0 {
            output.push('-');
        }
        output.push(c);
        *count += 1;
    };

    // Append leading zeros
    for _ in 0..padding {
        push_digit('0', &mut digit_count);
    }

    // Append actual digits
    for c in s.chars() {
        push_digit(c, &mut digit_count);
    }

    // 2. Format Minor (Base32) - Direct calculation to avoid allocation/shifting
    output.push('.');

    // Unroll the loop for performance (3 chars fixed)
    let idx2 = (minor % 32) as usize;
    let minor = minor / 32;
    let idx1 = (minor % 32) as usize;
    let minor = minor / 32;
    let idx0 = (minor % 32) as usize;

    output.push(BASE32_ALPHABET[idx0] as char);
    output.push(BASE32_ALPHABET[idx1] as char);
    output.push(BASE32_ALPHABET[idx2] as char);

    output
}

/// Parses a human-readable block height string back into a u64.
/// Zero-copy implementation (avoids allocating intermediate strings).
pub fn parse_block_height(s: &str) -> Result<u64, String> {
    let (major_str, minor_str) = s
        .split_once('.')
        .ok_or_else(|| "Invalid format: expected Major.Minor (e.g., 123-456.789)".to_string())?;

    // Parse Major: Iterate chars, skipping separators
    let mut major: u64 = 0;
    for c in major_str.chars() {
        if c == '-' {
            continue;
        }
        let digit = c
            .to_digit(10)
            .ok_or_else(|| format!("Invalid char in major part: {}", c))?;

        major = major.checked_mul(10).ok_or("Major part overflow")?;
        major = major
            .checked_add(digit as u64)
            .ok_or("Major part overflow")?;
    }

    // Parse Minor
    let minor = parse_base32(minor_str)?;

    if minor >= EPOCH_SIZE {
        return Err("Invalid minor part: exceeds epoch size".to_string());
    }

    major
        .checked_mul(EPOCH_SIZE)
        .and_then(|m| m.checked_add(minor))
        .ok_or_else(|| "Block height overflow".to_string())
}

// Removed format_decimal_grouped and format_base32_3 as they are inlined/optimized above.

fn parse_base32(s: &str) -> Result<u64, String> {
    let mut value: u64 = 0;
    for c in s.chars() {
        let digit = match c {
            '0' => 0,
            '1' => 1,
            '2' => 2,
            '3' => 3,
            '4' => 4,
            '5' => 5,
            '6' => 6,
            '7' => 7,
            '8' => 8,
            '9' => 9,
            'A' | 'a' => 10,
            'B' | 'b' => 11,
            'C' | 'c' => 12,
            'D' | 'd' => 13,
            'E' | 'e' => 14,
            'F' | 'f' => 15,
            'G' | 'g' => 16,
            'H' | 'h' => 17,
            'J' | 'j' => 18,
            'K' | 'k' => 19,
            'M' | 'm' => 20,
            'N' | 'n' => 21,
            'P' | 'p' => 22,
            'Q' | 'q' => 23,
            'R' | 'r' => 24,
            'S' | 's' => 25,
            'T' | 't' => 26,
            'V' | 'v' => 27,
            'W' | 'w' => 28,
            'X' | 'x' => 29,
            'Y' | 'y' => 30,
            'Z' | 'z' => 31,
            _ => return Err(format!("Invalid character in Base32: {}", c)),
        };

        value = value.checked_mul(32).ok_or("Base32 overflow".to_string())?;
        value = value
            .checked_add(digit)
            .ok_or("Base32 overflow".to_string())?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_block_height() {
        assert_eq!(format_block_height(0), "000-000-000.000");
        assert_eq!(format_block_height(1), "000-000-000.001");
        assert_eq!(format_block_height(32767), "000-000-000.ZZZ"); // Max minor
        assert_eq!(format_block_height(32768), "000-000-001.000"); // 1 Epoch
        assert_eq!(format_block_height(192321323817), "005-869-181.0S9"); // User example approx
    }

    #[test]
    fn test_parse_block_height() {
        assert_eq!(parse_block_height("000-000-000.000").unwrap(), 0);
        assert_eq!(parse_block_height("000-000-000.001").unwrap(), 1);
        assert_eq!(parse_block_height("000-000-000.ZZZ").unwrap(), 32767);
        assert_eq!(parse_block_height("000-000-001.000").unwrap(), 32768);

        // Lenient parsing (no leading zeros on major, case insensitive)
        assert_eq!(parse_block_height("1.000").unwrap(), 32768);
        assert_eq!(parse_block_height("0-0-1.000").unwrap(), 32768);
        assert_eq!(parse_block_height("000-000-000.zzz").unwrap(), 32767);
    }

    #[test]
    fn test_round_trip() {
        let heights = vec![0, 1, 32767, 32768, 1000000, 1234567890123];
        for h in heights {
            let s = format_block_height(h);
            let parsed = parse_block_height(&s).unwrap();
            assert_eq!(h, parsed, "Failed round trip for {}", h);
        }
    }
}
