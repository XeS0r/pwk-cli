//! Master key derivation (PBKDF2-HMAC-SHA256) and its hash for the request header.

use zeroize::Zeroizing;

use crate::{Error, Result, SecretString};

const DEFAULT_DIGEST: &str = "sha256";
const DEFAULT_ITERATIONS: u32 = 300_000;
const DEFAULT_BYTES: usize = 64;
const MAX_BYTES: usize = 1024;

/// Lowest PBKDF2 iteration count accepted from a server by default (see
/// [`MasterKeyOptions::check_strength`]).
pub const MIN_ITERATIONS: u32 = 100_000;

/// Parsed `pbkdf:<digest>:<iterations>:<bytes>:<salt>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterKeyOptions {
    /// Digest name; only `sha256` (default) and `sha512` are supported.
    pub digest: String,
    /// PBKDF2 iterations (default 300 000).
    pub iterations: u32,
    /// Output length in bytes (default 64).
    pub bytes: usize,
    /// Salt, used as UTF-8 text.
    pub salt: String,
}

impl MasterKeyOptions {
    /// Parses the server's `masterKeyOptions` string.
    pub fn parse(options: &str) -> Result<Self> {
        let mut parts = options.trim().splitn(5, ':');
        let prefix = parts.next().unwrap_or_default();
        if prefix != "pbkdf" {
            return Err(Error::MasterKeyOptions(
                "expected prefix \"pbkdf\"".to_owned(),
            ));
        }
        let mut next = || parts.next().filter(|s| !s.is_empty());
        let digest = next().unwrap_or(DEFAULT_DIGEST).to_ascii_lowercase();
        let iterations = match next() {
            Some(s) => s
                .parse()
                .map_err(|_| Error::MasterKeyOptions("iterations is not a number".to_owned()))?,
            None => DEFAULT_ITERATIONS,
        };
        let bytes = match next() {
            Some(s) => s
                .parse()
                .map_err(|_| Error::MasterKeyOptions("bytes is not a number".to_owned()))?,
            None => DEFAULT_BYTES,
        };
        let salt = next().unwrap_or_default().to_owned();
        let parsed = Self {
            digest,
            iterations,
            bytes,
            salt,
        };
        parsed.validate()?;
        Ok(parsed)
    }

    /// Refuses options weaker than `min_iterations` PBKDF2 iterations.
    ///
    /// [`MasterKeyOptions::parse`] accepts any positive count, because the options come
    /// from the server: a hostile or compromised server could hand out a tiny count to
    /// make the master password cheap to brute-force from the master key hash it
    /// receives. Callers pass [`MIN_ITERATIONS`] unless they deliberately lower the
    /// floor (test servers).
    pub fn check_strength(&self, min_iterations: u32) -> Result<()> {
        if self.iterations < min_iterations {
            return Err(Error::MasterKeyOptions(format!(
                "the server asks for {} PBKDF2 iterations; iterations below {min_iterations} \
                 are refused: the server may be trying to weaken the key derivation",
                self.iterations
            )));
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.digest != "sha256" && self.digest != "sha512" {
            return Err(Error::MasterKeyOptions(format!(
                "unsupported digest {:?}",
                self.digest
            )));
        }
        if self.iterations == 0 {
            return Err(Error::MasterKeyOptions("iterations must be > 0".to_owned()));
        }
        if self.bytes == 0 || self.bytes > MAX_BYTES {
            return Err(Error::MasterKeyOptions(format!(
                "bytes must be between 1 and {MAX_BYTES}"
            )));
        }
        Ok(())
    }
}

/// Derives the master key string: `base64_std(PBKDF2(password, salt, iterations, bytes))`.
pub fn derive_master_key(password: &str, options: &MasterKeyOptions) -> Result<SecretString> {
    options.validate()?;
    let mut out = Zeroizing::new(vec![0u8; options.bytes]);
    let (password, salt) = (password.as_bytes(), options.salt.as_bytes());
    if options.digest == "sha512" {
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password, salt, options.iterations, &mut out);
    } else {
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, options.iterations, &mut out);
    }
    Ok(Zeroizing::new(crate::aes::b64_encode(&out)))
}

/// `sha256_hex(master_key)`, sent as `X-Master-Key-Hash`.
#[must_use]
pub fn master_key_hash(master_key: &str) -> String {
    crate::sha256_hex(master_key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full() {
        let o = MasterKeyOptions::parse("pbkdf:sha512:1000:32:salt:with:colons").unwrap();
        assert_eq!(o.digest, "sha512");
        assert_eq!(o.iterations, 1000);
        assert_eq!(o.bytes, 32);
        assert_eq!(o.salt, "salt:with:colons");
    }

    #[test]
    fn parse_defaults() {
        for s in ["pbkdf", "pbkdf::::", "pbkdf:::"] {
            let o = MasterKeyOptions::parse(s).unwrap();
            assert_eq!(o.digest, "sha256");
            assert_eq!(o.iterations, 300_000);
            assert_eq!(o.bytes, 64);
            assert_eq!(o.salt, "");
        }
        let o = MasterKeyOptions::parse("pbkdf:::16:abc").unwrap();
        assert_eq!(
            (o.iterations, o.bytes, o.salt.as_str()),
            (300_000, 16, "abc")
        );
    }

    #[test]
    fn parse_rejects() {
        for s in [
            "",
            "scrypt:sha256:1:1:s",
            "pbkdf:md5:1:1:s",
            "pbkdf:sha256:0:64:s",
            "pbkdf:sha256:x:64:s",
            "pbkdf:sha256:1:0:s",
            "pbkdf:sha256:1:1025:s",
            "pbkdf:sha256:1:-1:s",
        ] {
            assert!(MasterKeyOptions::parse(s).is_err(), "{s}");
        }
    }

    #[test]
    fn check_strength_floor() {
        let weak = MasterKeyOptions::parse("pbkdf:sha256:1000:64:s").unwrap();
        let err = weak.check_strength(MIN_ITERATIONS).unwrap_err().to_string();
        assert!(err.contains("below 100000 are refused"), "{err}");
        assert!(
            MasterKeyOptions::parse("pbkdf:sha256:99999:64:s")
                .unwrap()
                .check_strength(MIN_ITERATIONS)
                .is_err()
        );
        weak.check_strength(1000).unwrap();
        for s in ["pbkdf:sha256:100000:64:s", "pbkdf"] {
            MasterKeyOptions::parse(s)
                .unwrap()
                .check_strength(MIN_ITERATIONS)
                .unwrap();
        }
    }

    #[test]
    fn known_answer() {
        // RFC 7914 section 11: PBKDF2-HMAC-SHA256("passwd", "salt", 1, 64).
        let o = MasterKeyOptions::parse("pbkdf:sha256:1:64:salt").unwrap();
        let key = derive_master_key("passwd", &o).unwrap();
        let raw = crate::aes::b64_decode(&key).unwrap();
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
             49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
    }

    #[test]
    fn hash() {
        assert_eq!(
            master_key_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
