//! Passwork 7 client-side cryptography.
//!
//! Everything here follows `docs/protocol.md`. Keys and passphrases are strings, as in
//! the Passwork web client: the master key is the Base64 text of the PBKDF2 output, vault
//! passwords and item keys are 100-character random strings.

#![allow(clippy::missing_errors_doc)]

pub mod aes;
pub mod base32;
pub mod master_key;
pub mod random;
pub mod rsa;
pub mod seal;
pub mod totp;

use zeroize::Zeroizing;

pub use crate::aes::{decrypt, decrypt_bytes, encrypt, encrypt_bytes};
pub use crate::master_key::{MIN_ITERATIONS, MasterKeyOptions, derive_master_key, master_key_hash};
pub use crate::random::{generate_key, generate_password, generate_salt};
pub use crate::rsa::{PrivateKey, PublicKey};

/// A secret string that is wiped from memory when dropped.
pub type SecretString = Zeroizing<String>;
/// Secret bytes that are wiped from memory when dropped.
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// Errors of this crate. Messages never contain key material or plaintext.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Input is not valid Base64 / Base32 / UTF-8 or too short.
    #[error("malformed ciphertext: {0}")]
    Malformed(&'static str),
    /// Wrong key, or corrupted data (bad padding, bad tag).
    #[error("decryption failed (wrong key or corrupted data)")]
    Decrypt,
    /// A PEM key could not be parsed.
    #[error("invalid key: {0}")]
    InvalidKey(&'static str),
    /// Encryption failed (RSA message too long and similar).
    #[error("encryption failed: {0}")]
    Encrypt(&'static str),
    /// Master key options string is not `pbkdf:<digest>:<iterations>:<bytes>:<salt>`.
    #[error("invalid master key options: {0}")]
    MasterKeyOptions(String),
    /// TOTP secret or otpauth URI is unusable.
    #[error("invalid TOTP secret: {0}")]
    Totp(String),
}

/// Result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// SHA-256 of `data`, lower-case hex.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Attachment checksum: every byte becomes the code point U+00XX, the resulting string is
/// UTF-8 encoded and hashed with SHA-256 (lower-case hex).
#[must_use]
pub fn attachment_hash(data: &[u8]) -> String {
    let latin1: String = data.iter().map(|&b| char::from(b)).collect();
    sha256_hex(latin1.as_bytes())
}
