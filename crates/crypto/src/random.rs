//! Random keys and passwords from the OS RNG.

use rand::distributions::{Distribution as _, Uniform};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

/// Alphabet of keys and salts: `A–Z a–z 0–9 @ !`.
pub const KEY_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@!";

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?";

/// `length` characters drawn uniformly from the ASCII `alphabet`.
fn random_string(length: usize, alphabet: &str) -> crate::SecretString {
    let chars = alphabet.as_bytes();
    let mut out = Zeroizing::new(String::with_capacity(length));
    if chars.is_empty() {
        return out;
    }
    let dist = Uniform::from(0..chars.len());
    for _ in 0..length {
        out.push(char::from(chars[dist.sample(&mut OsRng)]));
    }
    out
}

/// A 100-character random key (vault passwords, item keys, attachment keys).
#[must_use]
pub fn generate_key() -> crate::SecretString {
    random_string(100, KEY_ALPHABET)
}

/// A 32-character random salt from [`KEY_ALPHABET`].
#[must_use]
pub fn generate_salt() -> String {
    random_string(32, KEY_ALPHABET).to_string()
}

/// A random password of `length` characters from letters, digits and, if `symbols`,
/// `!@#$%^&*()-_=+[]{};:,.?`. Contains at least one of each enabled class when
/// `length >= 4`. Uniformly random without modulo bias.
#[must_use]
pub fn generate_password(length: usize, symbols: bool) -> crate::SecretString {
    let mut classes = vec![LOWER, UPPER, DIGITS];
    if symbols {
        classes.push(SYMBOLS);
    }
    let alphabet: String = classes.concat();
    // Rejection sampling keeps the result uniform over all passwords that contain every
    // class. Even in the worst case (length 4 with symbols) about 7 % are accepted.
    loop {
        let candidate = random_string(length, &alphabet);
        if length < 4
            || classes
                .iter()
                .all(|class| candidate.chars().any(|c| class.contains(c)))
        {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_and_salt() {
        let key = generate_key();
        assert_eq!(key.len(), 100);
        assert!(key.chars().all(|c| KEY_ALPHABET.contains(c)));
        let salt = generate_salt();
        assert_eq!(salt.len(), 32);
        assert!(salt.chars().all(|c| KEY_ALPHABET.contains(c)));
        assert_ne!(*generate_key(), *generate_key());
    }

    #[test]
    fn password_classes() {
        for _ in 0..200 {
            let p = generate_password(4, true);
            assert_eq!(p.len(), 4);
            for class in [LOWER, UPPER, DIGITS, SYMBOLS] {
                assert!(p.chars().any(|c| class.contains(c)));
            }
            let p = generate_password(4, false);
            assert!(p.chars().all(|c| !SYMBOLS.contains(c)));
            for class in [LOWER, UPPER, DIGITS] {
                assert!(p.chars().any(|c| class.contains(c)));
            }
        }
    }

    #[test]
    fn password_lengths() {
        assert_eq!(generate_password(0, true).len(), 0);
        assert_eq!(generate_password(1, true).len(), 1);
        assert_eq!(generate_password(3, false).len(), 3);
        assert_eq!(generate_password(64, true).len(), 64);
    }
}
