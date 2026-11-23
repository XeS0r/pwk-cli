//! RFC 6238 TOTP from a Base32 secret or an `otpauth://totp/…` URI.

use hmac::{Hmac, Mac};

use crate::{Error, Result};

/// Hash algorithm of a TOTP secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// HMAC-SHA-1 (default).
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// Parameters of a TOTP generator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Totp {
    /// Raw secret bytes.
    pub secret: Vec<u8>,
    /// Algorithm.
    pub algorithm: Algorithm,
    /// Number of digits (6–10).
    pub digits: u32,
    /// Period in seconds.
    pub period: u64,
}

fn err(msg: &str) -> Error {
    Error::Totp(msg.to_owned())
}

/// RFC 4648 Base32 (case-insensitive; spaces, `-` and `=` ignored; trailing bits dropped).
fn base32_decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u16 = 0;
    let mut bits: u32 = 0;
    for c in text.chars() {
        if c.is_whitespace() || c == '-' || c == '=' {
            continue;
        }
        let value = match c.to_ascii_uppercase() {
            u @ 'A'..='Z' => u as u8 - b'A',
            d @ '2'..='7' => d as u8 - b'2' + 26,
            _ => return Err(err("secret is not valid Base32")),
        };
        buffer = (buffer << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
        buffer &= (1 << bits) - 1;
    }
    if out.is_empty() {
        return Err(err("secret is empty"));
    }
    Ok(out)
}

impl Totp {
    /// Parses an RFC 4648 Base32 secret (case-insensitive, spaces and padding ignored) or
    /// an `otpauth://totp/...` URI (`secret`, `algorithm`, `digits`, `period`).
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        let is_uri = value
            .get(..10)
            .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"));
        if !is_uri {
            return Ok(Self {
                secret: base32_decode(value)?,
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
            });
        }
        let url = url::Url::parse(value).map_err(|_| err("invalid otpauth URI"))?;
        if !url
            .host_str()
            .is_some_and(|h| h.eq_ignore_ascii_case("totp"))
        {
            return Err(err("only otpauth://totp URIs are supported"));
        }
        let mut secret = None;
        let mut algorithm = Algorithm::Sha1;
        let mut digits = 6;
        let mut period = 30;
        for (key, val) in url.query_pairs() {
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(base32_decode(&val)?),
                "algorithm" => {
                    algorithm = match val.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(err("unsupported algorithm")),
                    };
                }
                "digits" => {
                    digits = val.trim().parse().map_err(|_| err("invalid digits"))?;
                }
                "period" => {
                    period = val.trim().parse().map_err(|_| err("invalid period"))?;
                }
                _ => {}
            }
        }
        if !(6..=10).contains(&digits) {
            return Err(err("digits must be between 6 and 10"));
        }
        if period == 0 {
            return Err(err("period must be positive"));
        }
        Ok(Self {
            secret: secret.ok_or_else(|| err("otpauth URI has no secret"))?,
            algorithm,
            digits,
            period,
        })
    }

    /// The code at Unix time `unix_seconds`, zero-padded to `digits`.
    #[must_use]
    pub fn code_at(&self, unix_seconds: u64) -> String {
        let counter = (unix_seconds / self.period.max(1)).to_be_bytes();
        let mac = match self.algorithm {
            Algorithm::Sha1 => hmac_digest::<Hmac<sha1::Sha1>>(&self.secret, &counter),
            Algorithm::Sha256 => hmac_digest::<Hmac<sha2::Sha256>>(&self.secret, &counter),
            Algorithm::Sha512 => hmac_digest::<Hmac<sha2::Sha512>>(&self.secret, &counter),
        };
        let offset = usize::from(mac.last().copied().unwrap_or(0) & 0x0f);
        let binary = mac
            .get(offset..offset + 4)
            .map_or(0, |b| u32::from_be_bytes([b[0] & 0x7f, b[1], b[2], b[3]]));
        let digits = self.digits.clamp(1, 10);
        let code = u64::from(binary) % 10u64.pow(digits);
        format!("{code:0width$}", width = digits as usize)
    }

    /// Seconds until the current code expires, at `unix_seconds`.
    #[must_use]
    pub fn remaining(&self, unix_seconds: u64) -> u64 {
        self.period - unix_seconds % self.period
    }
}

fn hmac_digest<M: Mac + hmac::digest::KeyInit>(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC accepts keys of any length; an empty result would only yield the code 0.
    <M as Mac>::new_from_slice(key)
        .map(|mut mac| {
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 Base32 encoder for the tests.
    fn b32(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::new();
        let (mut buf, mut bits) = (0u32, 0u32);
        for &b in data {
            buf = (buf << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(A[((buf >> bits) & 31) as usize]));
            }
            buf &= (1 << bits) - 1;
        }
        if bits > 0 {
            out.push(char::from(A[((buf << (5 - bits)) & 31) as usize]));
        }
        out
    }

    #[test]
    fn rfc6238_vectors() {
        let seed1 = b"12345678901234567890".to_vec();
        let seed256 = b"12345678901234567890123456789012".to_vec();
        let seed512 = b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();
        let table: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (alg, seed) in [("SHA1", &seed1), ("SHA256", &seed256), ("SHA512", &seed512)] {
            let uri = format!(
                "otpauth://totp/Example:alice?secret={}&algorithm={alg}&digits=8&period=30",
                b32(seed)
            );
            let totp = Totp::parse(&uri).unwrap();
            assert_eq!(&totp.secret, seed);
            for (t, c1, c256, c512) in table {
                let expected = match alg {
                    "SHA1" => c1,
                    "SHA256" => c256,
                    _ => c512,
                };
                assert_eq!(totp.code_at(t), expected, "{alg} at {t}");
            }
        }
    }

    #[test]
    fn plain_secret() {
        let secret = b32(b"12345678901234567890");
        let lower_spaced: String = secret
            .to_lowercase()
            .chars()
            .enumerate()
            .flat_map(|(i, c)| if i % 4 == 3 { vec![c, ' '] } else { vec![c] })
            .collect();
        for s in [secret.clone(), lower_spaced, format!("{secret}====")] {
            let totp = Totp::parse(&s).unwrap();
            assert_eq!(totp.algorithm, Algorithm::Sha1);
            assert_eq!((totp.digits, totp.period), (6, 30));
            assert_eq!(totp.code_at(59), "287082");
        }
        assert_eq!(Totp::parse(&secret).unwrap().remaining(59), 1);
        assert_eq!(Totp::parse(&secret).unwrap().remaining(60), 30);
    }

    #[test]
    fn uri_defaults_and_encoding() {
        let totp = Totp::parse("otpauth://totp/A%20B?secret=GEZDGNBV%3D%3D").unwrap();
        assert_eq!(totp.secret, b"12345");
        assert_eq!(totp.algorithm, Algorithm::Sha1);
        assert_eq!((totp.digits, totp.period), (6, 30));
        let totp =
            Totp::parse("OTPAUTH://TOTP/x?SECRET=gezdgnbv&Algorithm=sha256&period=60").unwrap();
        assert_eq!(totp.algorithm, Algorithm::Sha256);
        assert_eq!(totp.period, 60);
    }

    #[test]
    fn rejects() {
        for s in [
            "",
            "   ",
            "not base32!",
            "ABC1",
            "otpauth://hotp/x?secret=GEZDGNBV",
            "otpauth://totp/x",
            "otpauth://totp/x?secret=",
            "otpauth://totp/x?secret=GEZDGNBV&digits=5",
            "otpauth://totp/x?secret=GEZDGNBV&digits=11",
            "otpauth://totp/x?secret=GEZDGNBV&period=0",
            "otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5",
        ] {
            assert!(Totp::parse(s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn ten_digits() {
        let totp = Totp::parse("otpauth://totp/x?secret=GEZDGNBV&digits=10").unwrap();
        assert_eq!(totp.code_at(0).len(), 10);
    }
}
