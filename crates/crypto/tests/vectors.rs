//! Known-answer and end-to-end tests against the passwork-python fixtures.

use pwk_crypto::{Error, PrivateKey, aes, base32};
use serde_json::Value;

/// `mock_master_key` from passwork-python's `tests/conftest.py`.
const MASTER_KEY: &str =
    "/SzdXs1hNVP1H1+8m7AGrcVpbN2AaBV/cEdWYtF7TQwfizY+K1ukUNX6j6rNHvLG0v/wCICkDXSd6yQiD0ou9w==";

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("fixture readable");
    serde_json::from_str(&text).expect("fixture is JSON")
}

fn str_at<'a>(v: &'a Value, pointer: &str) -> &'a str {
    v.pointer(pointer).and_then(Value::as_str).expect(pointer)
}

fn private_key() -> PrivateKey {
    let keys = fixture("user_keys_response.json");
    let pem = aes::decrypt(str_at(&keys, "/keys/privateEncrypted"), MASTER_KEY).unwrap();
    // Deviation from the spec's "PKCS#8": the fixture key is PKCS#1 ("RSA PRIVATE KEY").
    assert!(pem.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
    PrivateKey::from_pem(&pem).unwrap()
}

#[test]
fn key_chain_end_to_end() {
    let key = private_key();
    let item = fixture("encrypted_item_response.json");
    let plain = fixture("item_response.json");

    // The fixture vault password is PKCS#1 v1.5, so this exercises the fallback after OAEP.
    let vault_password = key
        .decrypt(str_at(&item, "/vaultMasterKeyEncrypted"))
        .unwrap();
    let vault_password = std::str::from_utf8(&vault_password).unwrap();
    assert!(!vault_password.is_empty());

    let item_key = aes::decrypt(str_at(&item, "/keyEncrypted"), vault_password).unwrap();
    assert!(!item_key.is_empty());

    let password = aes::decrypt(str_at(&item, "/passwordEncrypted"), &item_key).unwrap();
    let expected = aes::decrypt(str_at(&plain, "/passwordEncrypted"), "").unwrap();
    assert_eq!(*password, *expected);
    assert_eq!(*password, "kzwugR]VH-9KF0:~d8h%");

    let customs = item["customs"].as_array().unwrap();
    let plain_customs = plain["customs"].as_array().unwrap();
    assert_eq!(customs.len(), plain_customs.len());
    for (enc, pl) in customs.iter().zip(plain_customs) {
        for field in ["name", "value", "type"] {
            let got = aes::decrypt(enc[field].as_str().unwrap(), &item_key).unwrap();
            let want = aes::decrypt(pl[field].as_str().unwrap(), "").unwrap();
            assert_eq!(*got, *want, "custom {field}");
        }
    }
    let types: Vec<String> = customs
        .iter()
        .map(|c| {
            aes::decrypt(c["type"].as_str().unwrap(), &item_key)
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(types, ["text", "password", "totp"]);

    // The attachment key decrypts with the item key, too.
    let att_key = aes::decrypt(str_at(&item, "/attachments/0/encryptedKey"), &item_key).unwrap();
    assert!(!att_key.is_empty());
}

#[test]
fn public_key_matches_and_round_trips() {
    let key = private_key();
    let keys = fixture("user_keys_response.json");
    let public = pwk_crypto::PublicKey::from_pem(str_at(&keys, "/keys/public")).unwrap();
    let cipher = public.encrypt(b"vault password").unwrap();
    assert_eq!(&key.decrypt(&cipher).unwrap()[..], b"vault password");
    let cipher = key.public_key().encrypt(b"x").unwrap();
    assert_eq!(&key.decrypt(&cipher).unwrap()[..], b"x");
    assert!(matches!(key.decrypt("AAAA"), Err(Error::Decrypt)));
    assert!(matches!(key.decrypt("@@@"), Err(Error::Malformed(_))));
    assert!(matches!(
        PrivateKey::from_pem("garbage"),
        Err(Error::InvalidKey(_))
    ));
    assert_eq!(format!("{key:?}"), "PrivateKey(..)");
}

#[test]
fn wrong_master_key_is_rejected() {
    let keys = fixture("user_keys_response.json");
    let wrong =
        "AAAAdXs1hNVP1H1+8m7AGrcVpbN2AaBV/cEdWYtF7TQwfizY+K1ukUNX6j6rNHvLG0v/wCICkDXSd6yQiD0ou9w==";
    match aes::decrypt(str_at(&keys, "/keys/privateEncrypted"), wrong) {
        Err(Error::Decrypt | Error::Malformed(_)) => {}
        Ok(text) => assert!(!text.starts_with("-----BEGIN")),
        Err(e) => panic!("unexpected {e:?}"),
    }
}

#[test]
fn encrypt_round_trips() {
    for passphrase in ["", "k", MASTER_KEY] {
        for text in ["", "hello", "ünïcödé"] {
            let c = aes::encrypt(text, passphrase);
            assert_eq!(*aes::decrypt(&c, passphrase).unwrap(), text);
        }
        let bytes: Vec<u8> = (0..=255).rev().collect();
        let c = aes::encrypt_bytes(&bytes, passphrase);
        assert_eq!(*aes::decrypt_bytes(&c, passphrase).unwrap(), bytes);
    }
    // Empty passphrase: plain Base64, even for something that looks like a cipher string.
    assert_eq!(aes::encrypt("text", ""), "dGV4dA==");
    let cipher = aes::encrypt("x", "k");
    assert!(aes::decrypt_bytes(&cipher, "").is_ok());
}

#[test]
fn base32_python_compatible() {
    // "U2FsdGVkX1" (Base64 of "Salted__") always encodes to this prefix.
    assert_eq!(base32::encode(b"U2FsdGVkX1"), "amt4cwv48xb6pp1h");
    let data = b"The quick brown fox";
    let enc = base32::encode(data);
    assert_eq!(base32::decode(&enc), data);
    // Aliases o/i/l/s, upper case and foreign characters are tolerated.
    let mangled = enc
        .to_uppercase()
        .replace('0', "o")
        .replace('1', "L")
        .replace('5', "s");
    assert_eq!(base32::decode(&format!("  {mangled}\n")), data);
    assert_eq!(base32::decode("1"), base32::decode("i"));
    // Incomplete trailing bits are dropped.
    assert!(base32::decode("z").is_empty());
}

#[test]
fn evp_bytes_to_key_matches_openssl() {
    // openssl enc -aes-256-cbc -P -md md5 -S 0102030405060708 -pass pass:test
    let (key, iv) = aes::evp_bytes_to_key(b"test", &[1, 2, 3, 4, 5, 6, 7, 8]);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02X}")).collect::<String>();
    assert_eq!(
        hex(&key),
        "D5E2AD1215FCA1925CA04478222A1851925ADB7B9BC2DC7B1E887EE1D41AFB38"
    );
    assert_eq!(hex(&iv), "424171E215213187B1D979AE24E2AB83");
}

#[test]
fn pbkdf2_known_answer() {
    // RFC 6070 test 2 is SHA-1; this is the SHA-256 counterpart
    // PBKDF2-HMAC-SHA256("password", "salt", 2, 32).
    let o = pwk_crypto::MasterKeyOptions::parse("pbkdf:sha256:2:32:salt").unwrap();
    let key = pwk_crypto::derive_master_key("password", &o).unwrap();
    assert_eq!(*key, "rk0Mla9rRtMtCt/5KPBt0CowP47zwlHf1uLYWpVHTEM=");
}

#[test]
fn attachment_hash_latin1() {
    // [0xff] → "\u{ff}" → UTF-8 c3 bf.
    assert_eq!(
        pwk_crypto::attachment_hash(&[0xff]),
        pwk_crypto::sha256_hex(&[0xc3, 0xbf])
    );
    assert_eq!(
        pwk_crypto::attachment_hash(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
