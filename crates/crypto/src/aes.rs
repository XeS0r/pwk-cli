//! OpenSSL-compatible "Salted__" AES-256-CBC with an MD5 `EVP_BytesToKey`, wrapped in
//! Base64 and Passwork Base32 (the "cipher string"). An empty passphrase means "no
//! client-side encryption": the value is plain Base64.

use base64::Engine as _;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut as _, BlockEncryptMut as _, KeyIvInit as _};
use md5::Digest as _;
use rand::RngCore as _;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{Error, Result, SecretBytes, SecretString};

type Aes256CbcEnc = cbc::Encryptor<::aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<::aes::Aes256>;

/// OpenSSL's header of salted ciphertexts.
const MAGIC: &[u8; 8] = b"Salted__";

/// Standard Base64 encoding.
pub(crate) fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Lenient standard Base64 decoding: whitespace is ignored, padding is optional.
pub(crate) fn b64_decode(text: &str) -> Result<SecretBytes> {
    const LENIENT: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    let compact: Zeroizing<String> =
        Zeroizing::new(text.chars().filter(|c| !c.is_ascii_whitespace()).collect());
    LENIENT
        .decode(compact.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| Error::Malformed("invalid base64"))
}

/// Encrypts UTF-8 `plaintext` with `passphrase` into a cipher string. With an empty
/// passphrase returns `base64(plaintext)`.
pub fn encrypt(plaintext: &str, passphrase: &str) -> String {
    encrypt_bytes(plaintext.as_bytes(), passphrase)
}

/// Like [`encrypt`] for arbitrary bytes.
pub fn encrypt_bytes(plaintext: &[u8], passphrase: &str) -> String {
    if passphrase.is_empty() {
        return b64_encode(plaintext);
    }
    let mut salt = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    encrypt_with_salt(plaintext, passphrase, &salt)
}

/// Deterministic core of [`encrypt_bytes`] (non-empty passphrase).
fn encrypt_with_salt(plaintext: &[u8], passphrase: &str, salt: &[u8; 8]) -> String {
    let (mut key, mut iv) = evp_bytes_to_key(passphrase.as_bytes(), salt);
    let ciphertext =
        Aes256CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    key.zeroize();
    iv.zeroize();
    let mut raw = Vec::with_capacity(16 + ciphertext.len());
    raw.extend_from_slice(MAGIC);
    raw.extend_from_slice(salt);
    raw.extend_from_slice(&ciphertext);
    crate::base32::encode(b64_encode(&raw).as_bytes())
}

/// Decrypts a cipher string to UTF-8 text. With an empty passphrase decodes plain Base64.
pub fn decrypt(cipher: &str, passphrase: &str) -> Result<SecretString> {
    let mut bytes = decrypt_bytes(cipher, passphrase)?;
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(err) => {
            let mut raw = err.into_bytes();
            raw.zeroize();
            Err(Error::Malformed("plaintext is not valid UTF-8"))
        }
    }
}

/// Like [`decrypt`] but returns raw bytes.
pub fn decrypt_bytes(cipher: &str, passphrase: &str) -> Result<SecretBytes> {
    if passphrase.is_empty() {
        return b64_decode(cipher);
    }
    let b64 = Zeroizing::new(crate::base32::decode(cipher));
    if !b64.is_ascii() {
        return Err(Error::Malformed("base32 payload is not base64 text"));
    }
    let b64 = std::str::from_utf8(&b64).map_err(|_| Error::Malformed("invalid base32"))?;
    let raw = b64_decode(b64)?;
    let (header, body) = raw
        .split_at_checked(16)
        .ok_or(Error::Malformed("too short"))?;
    let (magic, salt) = header.split_at(8);
    if magic != MAGIC {
        return Err(Error::Malformed("missing Salted__ header"));
    }
    if body.len() < 16 || body.len() % 16 != 0 {
        return Err(Error::Malformed("invalid ciphertext length"));
    }
    let salt: &[u8; 8] = salt
        .try_into()
        .map_err(|_| Error::Malformed("invalid salt"))?;
    let (mut key, mut iv) = evp_bytes_to_key(passphrase.as_bytes(), salt);
    let result = Aes256CbcDec::new(&key.into(), &iv.into()).decrypt_padded_vec_mut::<Pkcs7>(body);
    key.zeroize();
    iv.zeroize();
    result.map(Zeroizing::new).map_err(|_| Error::Decrypt)
}

/// OpenSSL `EVP_BytesToKey` with MD5 and one iteration: returns (key, iv).
#[must_use]
pub fn evp_bytes_to_key(passphrase: &[u8], salt: &[u8; 8]) -> ([u8; 32], [u8; 16]) {
    let mut material = Zeroizing::new([0u8; 48]);
    for chunk in 0..3 {
        let start = chunk * 16;
        let mut md5 = md5::Md5::new();
        if chunk > 0 {
            md5.update(&material[start - 16..start]);
        }
        md5.update(passphrase);
        md5.update(salt);
        material[start..start + 16].copy_from_slice(&md5.finalize());
    }
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&material[..32]);
    iv.copy_from_slice(&material[32..]);
    (key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for text in ["", "a", "exactly 16 bytes", "ünïcödé 🔑", &"x".repeat(1000)] {
            let cipher = encrypt(text, "passphrase");
            assert!(cipher.starts_with("amt4cwv48xb6pp1h"));
            assert_eq!(*decrypt(&cipher, "passphrase").unwrap(), text);
        }
    }

    #[test]
    fn random_salt() {
        assert_ne!(encrypt("same", "key"), encrypt("same", "key"));
    }

    #[test]
    fn bytes_round_trip() {
        let data: Vec<u8> = (0..=255).collect();
        let cipher = encrypt_bytes(&data, "k");
        assert_eq!(*decrypt_bytes(&cipher, "k").unwrap(), data);
        assert!(matches!(decrypt(&cipher, "k"), Err(Error::Malformed(_))));
    }

    #[test]
    fn empty_passphrase_is_base64() {
        assert_eq!(encrypt("hello", ""), "aGVsbG8=");
        assert_eq!(*decrypt("aGVsbG8=", "").unwrap(), "hello");
        assert_eq!(*decrypt("aGVs\nbG8", "").unwrap(), "hello");
        assert!(matches!(decrypt("!!", ""), Err(Error::Malformed(_))));
        assert!(matches!(decrypt("/w==", ""), Err(Error::Malformed(_))));
    }

    #[test]
    fn wrong_key_fails() {
        let cipher = encrypt("secret value", "right");
        // A wrong key almost always breaks the padding; if it happens to yield valid
        // padding the result is garbage, which is not the plaintext.
        match decrypt_bytes(&cipher, "wrong") {
            Err(Error::Decrypt) => {}
            Ok(bytes) => assert_ne!(&bytes[..], b"secret value"),
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn malformed_inputs() {
        assert!(matches!(decrypt("", "k"), Err(Error::Malformed(_))));
        // Base64 of "Salted__" + 8 bytes salt, no ciphertext.
        let short = crate::base32::encode(b64_encode(b"Salted__12345678").as_bytes());
        assert!(matches!(decrypt(&short, "k"), Err(Error::Malformed(_))));
        let no_magic = crate::base32::encode(b64_encode(&[0u8; 32]).as_bytes());
        assert!(matches!(decrypt(&no_magic, "k"), Err(Error::Malformed(_))));
        let mut odd = b"Salted__12345678".to_vec();
        odd.extend_from_slice(&[0u8; 17]);
        let odd = crate::base32::encode(b64_encode(&odd).as_bytes());
        assert!(matches!(decrypt(&odd, "k"), Err(Error::Malformed(_))));
        // Base32 of non-ASCII bytes.
        let binary = crate::base32::encode(&[0xff, 0xfe, 0x80]);
        assert!(matches!(decrypt(&binary, "k"), Err(Error::Malformed(_))));
    }

    #[test]
    fn openssl_compatible() {
        // printf abc | openssl enc -aes-256-cbc -md md5 -S 0102030405060708 -pass pass:test
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut raw = b"Salted__".to_vec();
        raw.extend_from_slice(&salt);
        raw.extend_from_slice(&[
            0x27, 0x1f, 0xd1, 0x61, 0x10, 0x3c, 0x3d, 0x22, 0x2f, 0x52, 0xd4, 0x9b, 0xb3, 0x57,
            0x23, 0xd7,
        ]);
        let cipher = crate::base32::encode(b64_encode(&raw).as_bytes());
        assert_eq!(encrypt_with_salt(b"abc", "test", &salt), cipher);
        assert_eq!(*decrypt(&cipher, "test").unwrap(), "abc");
    }
}
