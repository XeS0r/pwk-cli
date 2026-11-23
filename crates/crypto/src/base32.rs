//! Passwork's Base32: alphabet `0123456789abcdefghjkmnpqrtuvwxyz`, MSB first, no padding.

/// The encoding alphabet.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrtuvwxyz";

/// Value of a (lower-cased) character, including the aliases `o i l s`.
fn lookup(c: char) -> Option<u8> {
    let c = c.to_ascii_lowercase();
    match c {
        'o' => Some(0),
        'i' | 'l' => Some(1),
        's' => Some(5),
        _ => ALPHABET
            .iter()
            .position(|&a| char::from(a) == c)
            .and_then(|p| u8::try_from(p).ok()),
    }
}

/// Encodes bytes.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u16 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[usize::from((buffer >> bits) & 31)]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(
            ALPHABET[usize::from((buffer << (5 - bits)) & 31)],
        ));
    }
    out
}

/// Decodes text: case-insensitive, aliases `o→0 i→1 l→1 s→5`, other characters skipped,
/// incomplete trailing bits dropped. Never fails.
#[must_use]
pub fn decode(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u16 = 0;
    let mut bits: u32 = 0;
    for value in text.chars().filter_map(lookup) {
        buffer = (buffer << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            // Truncation intended: the low 8 bits above `bits` form the byte.
            out.push(((buffer >> bits) & 0xff) as u8);
        }
        buffer &= (1 << bits) - 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_prefix() {
        // "U2FsdGVkX1" is the Base64 of "Salted__".
        assert!(encode(b"U2FsdGVkX1").starts_with("amt4cwv48xb6pp1h"));
    }

    #[test]
    fn round_trip_all_lengths() {
        let data: Vec<u8> = (0..=255).collect();
        for len in 0..data.len() {
            assert_eq!(decode(&encode(&data[..len])), &data[..len]);
        }
    }

    #[test]
    fn empty() {
        assert_eq!(encode(b""), "");
        assert!(decode("").is_empty());
    }

    #[test]
    fn aliases_case_and_skipping() {
        let encoded = encode(b"hello world");
        let mangled: String = encoded
            .chars()
            .map(|c| match c {
                '0' => 'O',
                '1' => 'L',
                '5' => 'S',
                c => c.to_ascii_uppercase(),
            })
            .flat_map(|c| [c, '-', ' '])
            .collect();
        assert_eq!(decode(&mangled), b"hello world");
        assert_eq!(decode("I"), decode("1"));
        assert_eq!(decode("i0"), decode("10"));
    }
}
