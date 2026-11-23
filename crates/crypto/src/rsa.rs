//! RSA as used by Passwork: OAEP with SHA-256 (MGF1-SHA-256), PKCS#1 v1.5 fallback on
//! decryption. Ciphertexts are standard Base64.

use rsa::pkcs1::{DecodeRsaPrivateKey as _, DecodeRsaPublicKey as _};
use rsa::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use zeroize::Zeroizing;

use crate::{Error, Result, SecretBytes};

/// A user's private key (PKCS#8 PEM).
pub struct PrivateKey {
    inner: RsaPrivateKey,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateKey(..)")
    }
}

impl PrivateKey {
    /// Parses a PKCS#8 PEM (also accepts PKCS#1 `RSA PRIVATE KEY`).
    pub fn from_pem(pem: &str) -> Result<Self> {
        let pem = pem.trim();
        RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .map(|inner| Self { inner })
            .map_err(|_| Error::InvalidKey("not an RSA private key PEM"))
    }

    /// Decrypts Base64 ciphertext: OAEP-SHA-256 first, then PKCS#1 v1.5.
    pub fn decrypt(&self, ciphertext_b64: &str) -> Result<SecretBytes> {
        let ciphertext = crate::aes::b64_decode(ciphertext_b64)?;
        self.inner
            .decrypt(Oaep::new::<sha2::Sha256>(), &ciphertext)
            .or_else(|_| self.inner.decrypt(Pkcs1v15Encrypt, &ciphertext))
            .map(Zeroizing::new)
            .map_err(|_| Error::Decrypt)
    }

    /// The matching public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.to_public_key(),
        }
    }
}

/// A public key (SPKI PEM, also accepts PKCS#1 `RSA PUBLIC KEY`).
#[derive(Debug, Clone)]
pub struct PublicKey {
    inner: RsaPublicKey,
}

impl PublicKey {
    /// Parses a PEM public key.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let pem = pem.trim();
        RsaPublicKey::from_public_key_pem(pem)
            .or_else(|_| RsaPublicKey::from_pkcs1_pem(pem))
            .map(|inner| Self { inner })
            .map_err(|_| Error::InvalidKey("not an RSA public key PEM"))
    }

    /// Encrypts with OAEP-SHA-256, returns standard Base64.
    ///
    /// Falls back to PKCS#1 v1.5 when OAEP cannot carry the message, as the Python
    /// client does: OAEP-SHA-256 fits only 62 bytes into a 1024-bit key, and vault
    /// passwords are 100 characters.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String> {
        let mut rng = rand::rngs::OsRng;
        self.inner
            .encrypt(&mut rng, Oaep::new::<sha2::Sha256>(), plaintext)
            .or_else(|_| {
                self.inner
                    .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, plaintext)
            })
            .map(|c| crate::aes::b64_encode(&c))
            .map_err(|_| Error::Encrypt("RSA encryption failed (message too long)"))
    }
}
