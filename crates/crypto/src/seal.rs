//! Sealing the master key into the local session file (AES-256-GCM with a random
//! session key, see docs/design.md). Not part of the Passwork protocol.

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore as _;
use zeroize::Zeroizing;

use crate::{Error, Result, SecretBytes};

/// Length of a session key in bytes.
pub const SESSION_KEY_LEN: usize = 32;

/// A fresh random session key.
#[must_use]
pub fn generate_session_key() -> SecretBytes {
    let mut key = Zeroizing::new(vec![0u8; SESSION_KEY_LEN]);
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Sealed data: 12-byte nonce and ciphertext with tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// Random 96-bit nonce.
    pub nonce: [u8; 12],
    /// Ciphertext followed by the 16-byte tag.
    pub ciphertext: Vec<u8>,
}

fn cipher(key: &[u8]) -> Result<Aes256Gcm> {
    if key.len() != SESSION_KEY_LEN {
        return Err(Error::InvalidKey("session key must be 32 bytes"));
    }
    Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidKey("session key must be 32 bytes"))
}

/// Encrypts `plaintext` with AES-256-GCM under `key` (32 bytes) and `aad`.
pub fn seal(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let cipher = cipher(key)?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Encrypt("AES-GCM encryption failed"))?;
    Ok(Sealed { nonce, ciphertext })
}

/// Opens [`seal`]ed data; any mismatch of key, aad or data is [`crate::Error::Decrypt`].
pub fn open(key: &[u8], aad: &[u8], sealed: &Sealed) -> Result<SecretBytes> {
    let cipher = cipher(key)?;
    cipher
        .decrypt(
            Nonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let key = generate_session_key();
        assert_eq!(key.len(), SESSION_KEY_LEN);
        let sealed = seal(&key, b"aad", b"master key").unwrap();
        assert_eq!(sealed.ciphertext.len(), 10 + 16);
        assert_eq!(&open(&key, b"aad", &sealed).unwrap()[..], b"master key");

        assert!(matches!(open(&key, b"other", &sealed), Err(Error::Decrypt)));
        let other = generate_session_key();
        assert!(matches!(open(&other, b"aad", &sealed), Err(Error::Decrypt)));
        let mut bad = sealed.clone();
        bad.ciphertext[0] ^= 1;
        assert!(matches!(open(&key, b"aad", &bad), Err(Error::Decrypt)));
        let mut bad = sealed.clone();
        bad.nonce[0] ^= 1;
        assert!(matches!(open(&key, b"aad", &bad), Err(Error::Decrypt)));
        let mut bad = sealed;
        bad.ciphertext.truncate(3);
        assert!(matches!(open(&key, b"aad", &bad), Err(Error::Decrypt)));
    }

    #[test]
    fn nonces_differ() {
        let key = generate_session_key();
        assert_ne!(
            seal(&key, b"", b"x").unwrap(),
            seal(&key, b"", b"x").unwrap()
        );
    }

    #[test]
    fn key_length() {
        assert!(matches!(
            seal(&[0; 16], b"", b"x"),
            Err(Error::InvalidKey(_))
        ));
        let sealed = seal(&[0; 32], b"", b"x").unwrap();
        assert!(matches!(
            open(&[0; 31], b"", &sealed),
            Err(Error::InvalidKey(_))
        ));
    }
}
