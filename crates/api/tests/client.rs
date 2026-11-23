//! Integration tests of the API client against a mockito server.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use base64::Engine as _;
use mockito::{Matcher, Server, ServerGuard};
use pwk_api::{
    Client, ClientConfig, CustomField, CustomKind, Error, ItemFilter, MemoryTokenStore,
    NewAttachment, NewItem, TokenStore, Tokens,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// `mock_master_key` of passwork-python's `tests/conftest.py` (synthetic test key).
const MASTER_KEY: &str =
    "/SzdXs1hNVP1H1+8m7AGrcVpbN2AaBV/cEdWYtF7TQwfizY+K1ukUNX6j6rNHvLG0v/wCICkDXSd6yQiD0ou9w==";
const ENC_ITEM_ID: &str = "691c354719feeca0c603c2f2";
const ENC_VAULT_ID: &str = "691c1ec0569fd4826e098512";
const PLAIN_ITEM_ID: &str = "691d7dc8decc3f3da50349d2";

const USER_KEYS: &str = include_str!("fixtures/user_keys_response.json");
const ENC_ITEM: &str = include_str!("fixtures/encrypted_item_response.json");
const ENC_VAULT: &str = include_str!("fixtures/encrypted_vault_response.json");
const PLAIN_ITEM: &str = include_str!("fixtures/item_response.json");

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn tokens(access: &str, refresh: Option<&str>) -> Tokens {
    Tokens {
        access_token: access.into(),
        refresh_token: refresh.map(Into::into),
        access_expires_at: None,
        refresh_expires_at: None,
    }
}

fn client_with(server: &ServerGuard, t: Tokens) -> (Client, Arc<MemoryTokenStore>) {
    let store = Arc::new(MemoryTokenStore::new(t));
    let mut config = ClientConfig::new(format!("{}/", server.url()));
    config.timeout = Some(Duration::from_secs(10));
    let client = Client::new(config, store.clone()).expect("client");
    (client, store)
}

fn client(server: &ServerGuard) -> Client {
    client_with(server, tokens("access-1", Some("refresh-1"))).0
}

fn master_key() -> Zeroizing<String> {
    Zeroizing::new(MASTER_KEY.to_owned())
}

/// Mocks `users/keys` and unlocks the client with the fixture master key.
fn unlock(server: &mut ServerGuard, client: &Client) -> mockito::Mock {
    let hash = pwk_crypto::master_key_hash(MASTER_KEY);
    let m = server
        .mock("GET", "/api/v1/users/keys")
        .match_header("X-Master-Key-Hash", hash.as_str())
        .match_header("Passwork-MasterKeyHash", hash.as_str())
        .with_body(USER_KEYS)
        .create();
    client.set_master_key(master_key()).expect("unlock");
    assert!(client.is_unlocked());
    m
}

/// The item key of the encrypted fixture item, computed independently of the client.
fn fixture_private_key() -> pwk_crypto::PrivateKey {
    let keys: Value = serde_json::from_str(USER_KEYS).unwrap();
    let pem = pwk_crypto::decrypt(
        keys["keys"]["privateEncrypted"].as_str().unwrap(),
        MASTER_KEY,
    )
    .unwrap();
    pwk_crypto::PrivateKey::from_pem(&pem).unwrap()
}

fn fixture_vault_password() -> String {
    let item: Value = serde_json::from_str(ENC_ITEM).unwrap();
    let bytes = fixture_private_key()
        .decrypt(item["vaultMasterKeyEncrypted"].as_str().unwrap())
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn fixture_item_key() -> Zeroizing<String> {
    let item: Value = serde_json::from_str(ENC_ITEM).unwrap();
    pwk_crypto::decrypt(
        item["keyEncrypted"].as_str().unwrap(),
        &fixture_vault_password(),
    )
    .unwrap()
}

// --------------------------------------------------------------------------------------
// Transport
// --------------------------------------------------------------------------------------

#[test]
fn sends_headers_and_unwraps_envelope() {
    let mut server = Server::new();
    let payload = json!([{ "id": "v1", "name": "Infra", "masterKeyEncrypted": "x" }]);
    let envelope = json!({ "format": "base64", "content": b64(payload.to_string().as_bytes()) });
    let m = server
        .mock("GET", "/api/v1/vaults")
        .match_header("authorization", "Bearer access-1")
        .match_header("x-response-format", "raw")
        .match_header("x-master-key-hash", Matcher::Missing)
        .with_body(envelope.to_string())
        .create();
    let vaults = client(&server).list_vaults().unwrap();
    m.assert();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].name, "Infra");
    assert_eq!(vaults[0].master_key_encrypted.as_deref(), Some("x"));
    // Key material is not serialized.
    let out = serde_json::to_value(&vaults[0]).unwrap();
    assert!(out.get("masterKeyEncrypted").is_none());
}

#[test]
fn accepts_items_wrapper_for_lists() {
    let mut server = Server::new();
    let _m = server
        .mock("GET", "/api/v1/vaults")
        .with_body(r#"{"items":[{"id":"a","name":"A"},{"id":"b","name":"B","extraField":1}]}"#)
        .create();
    let vaults = client(&server).list_vaults().unwrap();
    assert_eq!(vaults.len(), 2);
    assert_eq!(vaults[1].extra["extraField"], json!(1));
}

#[test]
fn parses_api_errors() {
    let mut server = Server::new();
    let _m = server
        .mock("POST", "/api/v1/vaults")
        .with_status(400)
        .with_body(
            r#"{"errors":[{"code":"invalidName","message":"too short","field":"name"},{"code":"other","message":"second"}]}"#,
        )
        .create();
    let err = client(&server)
        .call("POST", "/vaults", &[], Some(&json!({"name": "x"})))
        .unwrap_err();
    match err {
        Error::Api {
            method,
            path,
            status,
            code,
            message,
        } => {
            assert_eq!(method, "POST");
            assert_eq!(path, "/api/v1/vaults");
            assert_eq!(status, 400);
            assert_eq!(code.as_deref(), Some("invalidName"));
            assert_eq!(message, "name => too short; second");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn error_without_json_body() {
    let mut server = Server::new();
    let _m = server
        .mock("GET", "/api/v1/vaults/x")
        .with_status(502)
        .with_body("<html>bad gateway</html>")
        .create();
    let err = client(&server).get_vault("x").unwrap_err();
    assert!(
        matches!(err, Error::Api { status: 502, code: None, ref message, .. } if message == "Bad Gateway"),
        "{err:?}"
    );
}

#[test]
fn call_normalises_path() {
    let mut server = Server::new();
    let m = server
        .mock("GET", "/api/v1/sessions/current/info")
        .match_query(Matcher::UrlEncoded("a".into(), "b c".into()))
        .with_body(r#"{"user":{"name":"Jane","login":"jane"}}"#)
        .expect(3)
        .create();
    let c = client(&server);
    let q = [("a".to_owned(), "b c".to_owned())];
    for path in [
        "sessions/current/info",
        "/api/v1/sessions/current/info",
        "api/v1/sessions/current/info",
    ] {
        let v = c.call("get", path, &q, None).unwrap();
        assert_eq!(v["user"]["login"], "jane");
    }
    m.assert();
    let _m2 = server
        .mock("GET", "/api/v1/users/info")
        .with_body(r#"{"fullName":null,"login":"jane","email":"jane@example.com"}"#)
        .create();
    let info = c.user_info().unwrap();
    assert_eq!(info.full_name(), None);
    assert_eq!(info.login(), Some("jane"));
    assert_eq!(info.email(), Some("jane@example.com"));
}

#[test]
fn list_parameters_get_brackets() {
    let mut server = Server::new();
    let m = server
        .mock("GET", "/api/v1/items/search")
        .match_query(Matcher::Regex(
            "^query=db&tags%5B%5D=prod&colorCodes%5B%5D=3&vaultIds%5B%5D=v1&vaultIds%5B%5D=v2$"
                .into(),
        ))
        .with_body(
            r#"{"items":[{"id":"i1","name":"DB","vaultId":"v1","folderId":null,"tags":null,"passwordEncrypted":"secret","keyEncrypted":"k"}]}"#,
        )
        .create();
    let rows = client(&server)
        .search_items(&ItemFilter {
            query: Some("db".into()),
            tags: vec!["prod".into()],
            colors: vec![3],
            vault_ids: vec!["v1".into(), "v2".into()],
            folder_ids: vec![],
        })
        .unwrap();
    m.assert();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "DB");
    assert!(rows[0].tags.is_empty());
    assert!(!rows[0].extra.contains_key("passwordEncrypted"));
    assert!(!rows[0].extra.contains_key("keyEncrypted"));
}

// --------------------------------------------------------------------------------------
// Tokens
// --------------------------------------------------------------------------------------

#[test]
fn refreshes_expired_token_and_retries() {
    let mut server = Server::new();
    let expired = server
        .mock("GET", "/api/v1/vaults")
        .match_header("authorization", "Bearer access-1")
        .with_status(401)
        .with_body(r#"{"errors":[{"code":"accessTokenExpired","message":"expired"}]}"#)
        .expect(1)
        .create();
    let refresh = server
        .mock("POST", "/api/v1/sessions/refresh")
        .match_header("authorization", "Bearer access-1")
        .match_body(Matcher::Json(json!({ "refreshToken": "refresh-1" })))
        .with_body(
            r#"{"accessToken":"access-2","refreshToken":"refresh-2","accessTokenExpiredAt":1700000000,"refreshTokenExpiredAt":"1800000000"}"#,
        )
        .expect(1)
        .create();
    let retried = server
        .mock("GET", "/api/v1/vaults")
        .match_header("authorization", "Bearer access-2")
        .with_body("[]")
        .expect(1)
        .create();
    let (c, store) = client_with(&server, tokens("access-1", Some("refresh-1")));
    assert!(c.list_vaults().unwrap().is_empty());
    expired.assert();
    refresh.assert();
    retried.assert();
    let now = store.current().unwrap();
    assert_eq!(now.access_token, "access-2");
    assert_eq!(now.refresh_token.as_deref(), Some("refresh-2"));
    assert_eq!(now.access_expires_at, Some(1_700_000_000));
    assert_eq!(now.refresh_expires_at, Some(1_800_000_000));
}

#[test]
fn expired_without_refresh_token_is_session_expired() {
    let mut server = Server::new();
    let _m = server
        .mock("GET", "/api/v1/vaults")
        .with_status(401)
        .with_body(r#"{"errors":[{"code":"accessTokenExpired","message":"expired"}]}"#)
        .create();
    let (c, _) = client_with(&server, tokens("access-1", None));
    assert!(matches!(c.list_vaults(), Err(Error::SessionExpired(_))));
}

#[test]
fn failed_refresh_is_session_expired() {
    let mut server = Server::new();
    let _m = server
        .mock("GET", "/api/v1/vaults")
        .with_status(401)
        .with_body(r#"{"errors":[{"code":"accessTokenExpired","message":"expired"}]}"#)
        .create();
    let _r = server
        .mock("POST", "/api/v1/sessions/refresh")
        .with_status(401)
        .with_body(r#"{"errors":[{"code":"invalidRefreshToken","message":"nope"}]}"#)
        .create();
    let (c, store) = client_with(&server, tokens("access-1", Some("refresh-1")));
    assert!(matches!(c.list_vaults(), Err(Error::SessionExpired(_))));
    assert_eq!(store.current().unwrap().access_token, "access-1");
}

#[test]
fn explicit_refresh() {
    let mut server = Server::new();
    let _r = server
        .mock("POST", "/api/v1/sessions/refresh")
        .with_body(r#"{"accessToken":"access-9","refreshToken":"refresh-9"}"#)
        .create();
    let (c, store) = client_with(&server, tokens("access-1", Some("refresh-1")));
    let t = c.refresh_tokens().unwrap();
    assert_eq!(t.access_token, "access-9");
    assert_eq!(store.current().unwrap(), t);
}

#[test]
fn memory_store_refreshes_once_under_concurrency() {
    let stale = tokens("a1", Some("r1"));
    let store = Arc::new(MemoryTokenStore::new(stale.clone()));
    let calls = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let store = store.clone();
            let calls = calls.clone();
            let barrier = barrier.clone();
            let stale = stale.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .refresh(&stale, &mut |old: &Tokens| {
                        assert_eq!(old.access_token, "a1");
                        calls.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(50));
                        Ok(tokens("a2", Some("r2")))
                    })
                    .unwrap()
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap().access_token, "a2");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.current().unwrap().access_token, "a2");
}

// --------------------------------------------------------------------------------------
// Master key
// --------------------------------------------------------------------------------------

#[test]
fn wrong_master_key_is_rejected() {
    let mut server = Server::new();
    let _m = server
        .mock("GET", "/api/v1/users/keys")
        .with_body(USER_KEYS)
        .create();
    let c = client(&server);
    let err = c
        .set_master_key(Zeroizing::new("d3JvbmcK".to_owned()))
        .unwrap_err();
    assert!(matches!(err, Error::WrongMasterKey), "{err:?}");
    assert!(!c.is_unlocked());
}

#[test]
fn unlock_with_password_derives_and_checks() {
    let mut server = Server::new();
    let _o = server
        .mock("GET", "/api/v1/users/master-key/options")
        .with_body(r#"{"masterKeyOptions":"pbkdf:sha256:1000:64:somesalt"}"#)
        .create();
    let _k = server
        .mock("GET", "/api/v1/users/keys")
        .with_body(USER_KEYS)
        .create();
    let store = Arc::new(MemoryTokenStore::new(tokens("access-1", None)));
    let mut config = ClientConfig::new(server.url());
    config.min_kdf_iterations = 1000;
    let c = Client::new(config, store).unwrap();
    // The fixture keys belong to another master key, so this must be "wrong".
    assert!(matches!(
        c.unlock_with_password("password"),
        Err(Error::WrongMasterKey)
    ));
    assert!(c.detect_encryption().unwrap());
}

#[test]
fn missing_master_key_options_means_no_encryption() {
    let mut server = Server::new();
    let _o = server
        .mock("GET", "/api/v1/users/master-key/options")
        .with_body(r#"{"masterKeyOptions":null}"#)
        .create();
    let c = client(&server);
    assert!(matches!(
        c.unlock_with_password("x"),
        Err(Error::Invalid(_))
    ));
    assert!(!c.detect_encryption().unwrap());
    assert!(c.is_plain());
}

// --------------------------------------------------------------------------------------
// Items
// --------------------------------------------------------------------------------------

#[test]
fn get_encrypted_item_end_to_end() {
    let mut server = Server::new();
    let c = client(&server);
    let keys = unlock(&mut server, &c);
    let hash = pwk_crypto::master_key_hash(MASTER_KEY);
    let m = server
        .mock("GET", format!("/api/v1/items/{ENC_ITEM_ID}").as_str())
        .match_header("X-Master-Key-Hash", hash.as_str())
        .with_body(ENC_ITEM)
        .create();
    let item = c.get_item(ENC_ITEM_ID).unwrap();
    keys.assert();
    m.assert();
    assert!(item.is_encrypted());
    assert_eq!(item.name, "name-test");
    assert_eq!(item.login.as_deref(), Some("login-test"));
    assert_eq!(
        item.password.as_deref().map(String::as_str),
        Some("kzwugR]VH-9KF0:~d8h%")
    );
    assert_eq!(item.urls, ["https://example.com", "https://example.local"]);
    assert_eq!(item.tags, ["test", "test-2"]);
    assert_eq!(item.color, Some(5));
    assert!(item.is_favorite);
    assert_eq!(item.vault_id, ENC_VAULT_ID);
    let customs: Vec<(&str, &str, CustomKind)> = item
        .customs
        .iter()
        .map(|c| (c.name.as_str(), c.value.as_str(), c.kind.clone()))
        .collect();
    assert_eq!(
        customs,
        [
            ("Custom name", "custom-login", CustomKind::Text),
            (
                "Custom password",
                "lANeOlEzJ9f2isl$60=q",
                CustomKind::Password
            ),
            (
                "Custom TOTP",
                "RNYGXTPKMNW53KSCMLCMMYQ3Z6",
                CustomKind::Totp
            ),
        ]
    );
    assert_eq!(item.attachments.len(), 1);
    assert_eq!(item.attachments[0].name, "test.txt");
    assert_eq!(item.custom("custom totp").unwrap().kind, CustomKind::Totp);

    // JSON output: decrypted values, unknown fields, no key material.
    let out = serde_json::to_value(&item).unwrap();
    assert_eq!(out["password"], "kzwugR]VH-9KF0:~d8h%");
    assert_eq!(out["customs"][1]["value"], "lANeOlEzJ9f2isl$60=q");
    assert_eq!(out["customs"][1]["type"], "password");
    assert_eq!(out["isFavorite"], true);
    assert_eq!(out["isDeleted"], false);
    for hidden in [
        "keyEncrypted",
        "vaultMasterKeyEncrypted",
        "passwordEncrypted",
    ] {
        assert!(out.get(hidden).is_none(), "{hidden} leaked");
    }
    assert!(out["attachments"][0].get("encryptedKey").is_none());
    // Debug redacts secrets.
    let dbg = format!("{item:?}");
    assert!(!dbg.contains("kzwugR"));
    assert!(!dbg.contains("lANeOlEz"));
}

#[test]
fn encrypted_item_without_master_key_is_locked() {
    let mut server = Server::new();
    let _m = server
        .mock("GET", format!("/api/v1/items/{ENC_ITEM_ID}").as_str())
        .with_body(ENC_ITEM)
        .create();
    let c = client(&server);
    assert!(matches!(c.get_item(ENC_ITEM_ID), Err(Error::Locked)));
    c.set_no_encryption();
    assert!(matches!(c.get_item(ENC_ITEM_ID), Err(Error::Locked)));
}

#[test]
fn plain_item_decodes_without_master_key() {
    let mut server = Server::new();
    let _m = server
        .mock("GET", format!("/api/v1/items/{PLAIN_ITEM_ID}").as_str())
        .with_body(PLAIN_ITEM)
        .create();
    let c = client(&server);
    c.set_no_encryption();
    let item = c.get_item(PLAIN_ITEM_ID).unwrap();
    assert!(!item.is_encrypted());
    assert_eq!(
        item.password.as_deref().map(String::as_str),
        Some("kzwugR]VH-9KF0:~d8h%")
    );
    assert_eq!(item.customs.len(), 3);
    assert_eq!(item.customs[0].name, "Custom name");
    assert_eq!(item.customs[0].value.as_str(), "custom-login");
    assert_eq!(item.customs[2].kind, CustomKind::Totp);
    assert_eq!(item.customs[2].value.as_str(), "RNYGXTPKMNW53KSCMLCMMYQ3Z6");
}

#[test]
fn create_item_body_round_trip() {
    let mut server = Server::new();
    let c = client(&server);
    let _keys = unlock(&mut server, &c);
    let _vault = server
        .mock("GET", format!("/api/v1/vaults/{ENC_VAULT_ID}").as_str())
        .with_body(ENC_VAULT)
        .create();
    let captured = Arc::new(Mutex::new(None::<Value>));
    let sink = captured.clone();
    let create = server
        .mock("POST", "/api/v1/items")
        .match_header("content-type", "application/json")
        .with_body_from_request(move |req| {
            let body: Value = serde_json::from_slice(req.body().unwrap()).unwrap();
            *sink.lock().unwrap() = Some(body);
            br#"{"id":"new-item"}"#.to_vec()
        })
        .create();

    let file = b"\x00\x01binary\xff\xfe data".to_vec();
    let new = NewItem {
        vault_id: ENC_VAULT_ID.into(),
        folder_id: None,
        name: "DB".into(),
        login: Some("admin".into()),
        password: Some(Zeroizing::new("s3cr3t!".into())),
        url: Some("https://db.example.com".into()),
        tags: vec!["prod".into()],
        customs: vec![
            CustomField::new("API key", "k-123", CustomKind::Password),
            CustomField::new("OTP", "JBSWY3DPEHPK3PXP", CustomKind::Totp),
        ],
        attachments: vec![NewAttachment {
            name: "blob.bin".into(),
            data: Zeroizing::new(file.clone()),
        }],
        ..NewItem::default()
    };
    assert_eq!(c.create_item(&new).unwrap(), "new-item");
    create.assert();

    let body = captured.lock().unwrap().take().unwrap();
    assert_eq!(body["vaultId"], ENC_VAULT_ID);
    assert_eq!(body["name"], "DB");
    assert_eq!(body["login"], "admin");
    assert_eq!(body["folderId"], Value::Null);
    assert!(body.get("password").is_none());
    // Decrypt with keys derived independently of the client.
    let item_key = pwk_crypto::decrypt(
        body["keyEncrypted"].as_str().unwrap(),
        &fixture_vault_password(),
    )
    .unwrap();
    assert_eq!(item_key.len(), 100);
    let dec = |v: &Value| pwk_crypto::decrypt(v.as_str().unwrap(), &item_key).unwrap();
    assert_eq!(dec(&body["passwordEncrypted"]).as_str(), "s3cr3t!");
    assert_eq!(dec(&body["customs"][0]["name"]).as_str(), "API key");
    assert_eq!(dec(&body["customs"][0]["value"]).as_str(), "k-123");
    assert_eq!(dec(&body["customs"][0]["type"]).as_str(), "password");
    assert_eq!(dec(&body["customs"][1]["type"]).as_str(), "totp");
    let att = &body["attachments"][0];
    assert_eq!(att["name"], "blob.bin");
    assert_eq!(att["hash"], pwk_crypto::attachment_hash(&file));
    let att_key = dec(&att["encryptedKey"]);
    let encoded =
        pwk_crypto::decrypt_bytes(att["encryptedData"].as_str().unwrap(), &att_key).unwrap();
    let data = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_slice())
        .unwrap();
    assert_eq!(data, file);

    // And the client reads its own output back.
    let mut stored = body.clone();
    stored["id"] = json!("new-item");
    stored["vaultMasterKeyEncrypted"] =
        serde_json::from_str::<Value>(ENC_ITEM).unwrap()["vaultMasterKeyEncrypted"].clone();
    let _get = server
        .mock("GET", "/api/v1/items/new-item")
        .with_body(stored.to_string())
        .create();
    let item = c.get_item("new-item").unwrap();
    assert_eq!(
        item.password.as_deref().map(String::as_str),
        Some("s3cr3t!")
    );
    assert_eq!(item.customs[1].value.as_str(), "JBSWY3DPEHPK3PXP");
}

#[test]
fn create_item_in_plain_vault_uses_base64() {
    let mut server = Server::new();
    let _vault = server
        .mock("GET", "/api/v1/vaults/pv")
        .with_body(r#"{"id":"pv","name":"Plain","masterKeyEncrypted":null}"#)
        .create();
    let captured = Arc::new(Mutex::new(None::<Value>));
    let sink = captured.clone();
    let _create = server
        .mock("POST", "/api/v1/items")
        .with_body_from_request(move |req| {
            *sink.lock().unwrap() = Some(serde_json::from_slice(req.body().unwrap()).unwrap());
            br#"{"id":"x"}"#.to_vec()
        })
        .create();
    let c = client(&server);
    c.set_no_encryption();
    let new = NewItem {
        vault_id: "pv".into(),
        name: "n".into(),
        password: Some(Zeroizing::new("pw".into())),
        customs: vec![CustomField::new("f", "v", CustomKind::Text)],
        ..NewItem::default()
    };
    c.create_item(&new).unwrap();
    let body = captured.lock().unwrap().take().unwrap();
    assert_eq!(body["passwordEncrypted"], b64(b"pw"));
    assert_eq!(body["customs"][0]["type"], b64(b"text"));
    assert!(body.get("keyEncrypted").is_none());
}

#[test]
fn update_item_reuses_key() {
    let mut server = Server::new();
    let c = client(&server);
    let _keys = unlock(&mut server, &c);
    let _get = server
        .mock("GET", format!("/api/v1/items/{ENC_ITEM_ID}").as_str())
        .with_body(ENC_ITEM)
        .create();
    let captured = Arc::new(Mutex::new(None::<Value>));
    let sink = captured.clone();
    let patch = server
        .mock("PATCH", format!("/api/v1/items/{ENC_ITEM_ID}").as_str())
        .with_body_from_request(move |req| {
            *sink.lock().unwrap() = Some(serde_json::from_slice(req.body().unwrap()).unwrap());
            b"{}".to_vec()
        })
        .create();
    let update = pwk_api::ItemUpdate {
        password: Some(Some(Zeroizing::new("new-pw".into()))),
        customs: Some(vec![CustomField::new("a", "b", CustomKind::Text)]),
        ..Default::default()
    };
    c.update_item(ENC_ITEM_ID, &update).unwrap();
    patch.assert();
    let body = captured.lock().unwrap().take().unwrap();
    let fixture: Value = serde_json::from_str(ENC_ITEM).unwrap();
    assert_eq!(body["keyEncrypted"], fixture["keyEncrypted"]);
    assert_eq!(body["vaultId"], ENC_VAULT_ID);
    assert!(body.get("name").is_none());
    let key = fixture_item_key();
    let dec = |v: &Value| pwk_crypto::decrypt(v.as_str().unwrap(), &key).unwrap();
    assert_eq!(dec(&body["passwordEncrypted"]).as_str(), "new-pw");
    assert_eq!(dec(&body["customs"][0]["value"]).as_str(), "b");
}

#[test]
fn get_items_batches_in_chunks_of_25() {
    let mut server = Server::new();
    let sizes = Arc::new(Mutex::new(Vec::new()));
    let sink = sizes.clone();
    let m = server
        .mock("POST", "/api/v1/batch")
        .with_body_from_request(move |req| {
            let body: Value = serde_json::from_slice(req.body().unwrap()).unwrap();
            let requests = body["requests"].as_array().unwrap();
            sink.lock().unwrap().push(requests.len());
            let responses: Vec<Value> = requests
                .iter()
                .map(|r| {
                    assert_eq!(r["method"], "GET");
                    let url = r["relativeUrl"].as_str().unwrap();
                    let id = url.strip_prefix("/api/v1/items/").unwrap();
                    if id == "missing" {
                        return json!({"statusCode": 404, "body": {"errors": []}});
                    }
                    json!({"statusCode": 200, "body": {
                        "id": id, "name": format!("n-{id}"), "vaultId": "v",
                        "keyEncrypted": null, "passwordEncrypted": b64(id.as_bytes()),
                    }})
                })
                .collect();
            json!({ "responses": responses }).to_string().into_bytes()
        })
        .expect(2)
        .create();
    let mut ids: Vec<String> = (0..29).map(|i| format!("id{i}")).collect();
    ids.insert(3, "missing".into());
    let items = client(&server).get_items(&ids).unwrap();
    m.assert();
    assert_eq!(*sizes.lock().unwrap(), [25, 5]);
    assert_eq!(items.len(), 29);
    assert_eq!(items[0].id, "id0");
    assert_eq!(
        items[28].password.as_deref().map(String::as_str),
        Some("id28")
    );
}

// --------------------------------------------------------------------------------------
// Attachments
// --------------------------------------------------------------------------------------

#[test]
fn downloads_encrypted_attachment_with_hash_check() {
    let mut server = Server::new();
    let c = client(&server);
    let _keys = unlock(&mut server, &c);
    let _get = server
        .mock("GET", format!("/api/v1/items/{ENC_ITEM_ID}").as_str())
        .with_body(ENC_ITEM)
        .create();
    let item = c.get_item(ENC_ITEM_ID).unwrap();
    let att_id = item.attachments[0].id.clone();

    let data: Vec<u8> = (0..=255u8).chain(*b"hello").collect();
    let att_key = pwk_crypto::generate_key();
    let item_key = fixture_item_key();
    let attachment = |hash: String| {
        json!({
            "name": "test.txt",
            "encryptedKey": pwk_crypto::encrypt(&att_key, &item_key),
            "encryptedData": pwk_crypto::encrypt(&b64(&data), &att_key),
            "hash": hash,
        })
        .to_string()
    };
    let path = format!("/api/v1/items/{ENC_ITEM_ID}/attachment/{att_id}");
    let ok = server
        .mock("GET", path.as_str())
        .with_body(attachment(pwk_crypto::attachment_hash(&data)))
        .create();
    let (name, bytes) = c.download_attachment(&item, &att_id).unwrap();
    ok.assert();
    assert_eq!(name, "test.txt");
    assert_eq!(bytes.as_slice(), data.as_slice());

    ok.remove();
    let _bad = server
        .mock("GET", path.as_str())
        .with_body(attachment("00".repeat(32)))
        .create();
    let err = c.download_attachment(&item, &att_id).unwrap_err();
    assert!(
        matches!(err, Error::Response { ref detail, .. } if detail.contains("checksum")),
        "{err:?}"
    );
}

#[test]
fn downloads_plain_attachment() {
    let mut server = Server::new();
    let _get = server
        .mock("GET", format!("/api/v1/items/{PLAIN_ITEM_ID}").as_str())
        .with_body(PLAIN_ITEM)
        .create();
    let c = client(&server);
    let item = c.get_item(PLAIN_ITEM_ID).unwrap();
    let data = b"plain file\n";
    let _att = server
        .mock(
            "GET",
            format!("/api/v1/items/{PLAIN_ITEM_ID}/attachment/691d7dc8decc3f3da50349d3").as_str(),
        )
        .with_body(
            json!({
                "name": "test.txt",
                "encryptedKey": b64(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                "encryptedData": b64(b64(data).as_bytes()),
                "hash": pwk_crypto::attachment_hash(data),
            })
            .to_string(),
        )
        .create();
    let att = pwk_api::AttachmentRef::find(&item, "TEST.txt").unwrap();
    let (_, bytes) = c.download_attachment(&item, &att.id).unwrap();
    assert_eq!(bytes.as_slice(), data);
}

// --------------------------------------------------------------------------------------
// Shortcuts and vaults
// --------------------------------------------------------------------------------------

#[test]
fn shortcut_with_item() {
    let mut server = Server::new();
    let _s = server
        .mock("GET", "/api/v1/shortcuts/s1")
        .with_body(format!(
            r#"{{"id":"s1","itemId":"{PLAIN_ITEM_ID}","vaultId":"v2","folderId":null,"keyEncrypted":null}}"#
        ))
        .create();
    let _i = server
        .mock("GET", format!("/api/v1/items/{PLAIN_ITEM_ID}").as_str())
        .with_body(PLAIN_ITEM)
        .create();
    let c = client(&server);
    let sw = c.get_shortcut("s1").unwrap();
    assert_eq!(sw.shortcut.vault_id, "v2");
    assert_eq!(sw.item.name, "name-test");
    let out = serde_json::to_value(&sw).unwrap();
    assert!(out["shortcut"].get("keyEncrypted").is_none());

    let _search = server
        .mock("GET", "/api/v1/shortcuts/search")
        .match_query(Matcher::UrlEncoded("query".into(), "x".into()))
        .with_body(
            r#"{"items":[{"shortcut":{"id":"s1","itemId":"i","vaultId":"v2"},"name":"Item"}]}"#,
        )
        .create();
    let rows = c
        .search_shortcuts(&ItemFilter {
            query: Some("x".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(rows[0].shortcut.item_id, "i");
    assert_eq!(rows[0].extra["name"], "Item");
}

#[test]
fn create_shortcut_encrypts_item_key_for_target_vault() {
    let mut server = Server::new();
    let c = client(&server);
    let _keys = unlock(&mut server, &c);
    let _get = server
        .mock("GET", format!("/api/v1/items/{ENC_ITEM_ID}").as_str())
        .with_body(ENC_ITEM)
        .create();
    // The target vault is the fixture vault (its password is known to the test).
    let _vault = server
        .mock("GET", "/api/v1/vaults/target")
        .with_body(ENC_VAULT.replace(ENC_VAULT_ID, "target"))
        .create();
    let captured = Arc::new(Mutex::new(None::<Value>));
    let sink = captured.clone();
    let _post = server
        .mock("POST", "/api/v1/shortcuts")
        .with_body_from_request(move |req| {
            *sink.lock().unwrap() = Some(serde_json::from_slice(req.body().unwrap()).unwrap());
            br#"{"id":"s9"}"#.to_vec()
        })
        .create();
    let item = c.get_item(ENC_ITEM_ID).unwrap();
    assert_eq!(
        c.create_shortcut(&item, "target", Some("f1")).unwrap(),
        "s9"
    );
    let body = captured.lock().unwrap().take().unwrap();
    assert_eq!(body["itemId"], ENC_ITEM_ID);
    assert_eq!(body["folderId"], "f1");
    let key = pwk_crypto::decrypt(
        body["keyEncrypted"].as_str().unwrap(),
        &fixture_vault_password(),
    )
    .unwrap();
    assert_eq!(key.as_str(), fixture_item_key().as_str());
}

#[test]
fn create_vault_with_type_and_admin_keys() {
    let mut server = Server::new();
    let c = client(&server);
    let _keys = unlock(&mut server, &c);
    let _f = server
        .mock("GET", "/api/v1/app/features")
        .with_body(r#"[{"name":"vaultType"}]"#)
        .create();
    let _t = server
        .mock("GET", "/api/v1/vault-types/all")
        .with_body(r#"{"items":[{"id":"685cfa5a3d0ba75d2f041972","code":"corporate","name":"Corporate"}]}"#)
        .create();
    let public_pem = serde_json::from_str::<Value>(USER_KEYS).unwrap()["keys"]["public"].clone();
    let _a = server
        .mock(
            "GET",
            "/api/v1/vault-types/685cfa5a3d0ba75d2f041972/administrators",
        )
        .with_body(json!({"items": [{"id": "admin1", "publicKey": public_pem}]}).to_string())
        .create();
    let captured = Arc::new(Mutex::new(None::<Value>));
    let sink = captured.clone();
    let _post = server
        .mock("POST", "/api/v1/vaults")
        .with_body_from_request(move |req| {
            *sink.lock().unwrap() = Some(serde_json::from_slice(req.body().unwrap()).unwrap());
            br#"{"id":"vnew"}"#.to_vec()
        })
        .create();
    assert!(matches!(c.create_vault("X", None), Err(Error::Invalid(_))));
    assert_eq!(c.create_vault("X", Some("Corporate")).unwrap(), "vnew");
    let body = captured.lock().unwrap().take().unwrap();
    assert_eq!(body["typeId"], "685cfa5a3d0ba75d2f041972");
    let private = fixture_private_key();
    let pw = private
        .decrypt(body["masterKeyEncrypted"].as_str().unwrap())
        .unwrap();
    let admin_pw = private
        .decrypt(body["administratorsKeys"]["admin1"].as_str().unwrap())
        .unwrap();
    assert_eq!(pw.len(), 100);
    assert_eq!(pw.as_slice(), admin_pw.as_slice());
    let salt = body["salt"].as_str().unwrap();
    let mut input = pw.to_vec();
    input.extend_from_slice(salt.as_bytes());
    assert_eq!(body["masterKeyHash"], pwk_crypto::sha256_hex(&input));
}

#[test]
fn create_vault_needs_known_encryption_state() {
    let server = Server::new();
    assert!(matches!(
        client(&server).create_vault("X", None),
        Err(Error::Locked)
    ));
}

#[test]
fn rejects_bad_hosts() {
    let store = Arc::new(MemoryTokenStore::new(tokens("a", None)));
    for host in ["passwork.example.com", "ftp://x.example.com", ""] {
        assert!(matches!(
            Client::new(ClientConfig::new(host), store.clone()),
            Err(Error::Invalid(_))
        ));
    }
}

// --------------------------------------------------------------------------------------
// Review fixes: KDF floor, redirects, body limit, path segments
// --------------------------------------------------------------------------------------

#[test]
fn unlock_refuses_weak_kdf_options_by_default() {
    let mut server = Server::new();
    let _o = server
        .mock("GET", "/api/v1/users/master-key/options")
        .with_body(r#"{"masterKeyOptions":"pbkdf:sha256:99999:64:somesalt"}"#)
        .create();
    let keys = server
        .mock("GET", "/api/v1/users/keys")
        .with_body(USER_KEYS)
        .expect(0)
        .create();
    let c = client(&server);
    assert_eq!(
        ClientConfig::new("https://x.example.com").min_kdf_iterations,
        100_000
    );
    let err = c.unlock_with_password("password").unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, Error::Crypto(pwk_crypto::Error::MasterKeyOptions(_))),
        "{err:?}"
    );
    assert!(msg.contains("below 100000 are refused"), "{msg}");
    assert!(msg.contains("weaken the key derivation"), "{msg}");
    keys.assert();
    assert!(!c.is_unlocked());
}

#[test]
fn redirects_are_not_followed() {
    let mut server = Server::new();
    let redirect = server
        .mock("GET", "/api/v1/vaults")
        .with_status(307)
        .with_header(
            "location",
            "https://elsewhere.example.net:8443/api/v1/vaults",
        )
        .create();
    let err = client(&server).list_vaults().unwrap_err();
    redirect.assert();
    let msg = err.to_string();
    assert!(matches!(err, Error::Http(_)), "{err:?}");
    assert!(
        msg.contains("redirected to https://elsewhere.example.net:8443"),
        "{msg}"
    );
    assert!(
        msg.contains("set the profile host to the final URL"),
        "{msg}"
    );

    // A relative Location names the same host.
    let mut server = Server::new();
    let _r = server
        .mock("GET", "/api/v1/vaults")
        .with_status(301)
        .with_header("location", "/passwork/api/v1/vaults")
        .create();
    let target = server
        .mock("GET", "/passwork/api/v1/vaults")
        .with_body("[]")
        .expect(0)
        .create();
    let msg = client(&server).list_vaults().unwrap_err().to_string();
    assert!(
        msg.contains(&format!("redirected to {}", server.url())),
        "{msg}"
    );
    target.assert();
}

fn client_with_limit(server: &ServerGuard, limit: usize) -> Client {
    let store = Arc::new(MemoryTokenStore::new(tokens("access-1", None)));
    let mut config = ClientConfig::new(server.url());
    config.max_response_bytes = limit;
    Client::new(config, store).unwrap()
}

#[test]
fn response_body_is_limited() {
    assert_eq!(
        ClientConfig::new("https://x.example.com").max_response_bytes,
        64 * 1024 * 1024
    );
    let big = format!("[{}]", vec!["{\"id\":\"v\"}"; 200].join(","));
    assert!(big.len() > 1024);
    let mut server = Server::new();
    let _sized = server
        .mock("GET", "/api/v1/vaults")
        .with_body(&big)
        .create();
    let err = client_with_limit(&server, 1024).list_vaults().unwrap_err();
    assert!(
        matches!(err, Error::Http(ref m) if m.contains("larger than the limit of 1024 bytes")),
        "{err:?}"
    );
    // Within the limit it works.
    assert_eq!(
        client_with_limit(&server, big.len())
            .list_vaults()
            .unwrap()
            .len(),
        200
    );

    // Without Content-Length (chunked) the read itself stops at the limit.
    let mut server = Server::new();
    let chunk = big.clone();
    let _chunked = server
        .mock("GET", "/api/v1/vaults")
        .with_chunked_body(move |w| w.write_all(chunk.as_bytes()))
        .create();
    let err = client_with_limit(&server, 1024).list_vaults().unwrap_err();
    assert!(
        matches!(err, Error::Http(ref m) if m.contains("larger than the limit")),
        "{err:?}"
    );
}

#[test]
fn dot_and_empty_ids_are_rejected() {
    let mut server = Server::new();
    let any = server
        .mock("GET", Matcher::Any)
        .with_body("{}")
        .expect(0)
        .create();
    let c = client(&server);
    for id in ["", ".", ".."] {
        assert!(matches!(c.get_item(id), Err(Error::Invalid(_))), "{id:?}");
        assert!(matches!(c.get_vault(id), Err(Error::Invalid(_))), "{id:?}");
        assert!(
            matches!(c.delete_item(id), Err(Error::Invalid(_))),
            "{id:?}"
        );
    }
    any.assert();
}

// --------------------------------------------------------------------------------------
// Review fixes: items without keyEncrypted in encrypting vaults
// --------------------------------------------------------------------------------------

const KEYLESS_ID: &str = "6a0000000000000000000001";

/// An item without `keyEncrypted` in the encrypted fixture vault, with plain Base64
/// values (as other clients store items without a password).
fn keyless_item(with_vault_key: bool, attachments: bool) -> Value {
    let mut item = json!({
        "id": KEYLESS_ID,
        "name": "keyless",
        "vaultId": ENC_VAULT_ID,
        "keyEncrypted": null,
        "passwordEncrypted": b64(b"old-pw"),
        "customs": [
            { "name": b64(b"Old field"), "value": b64(b"old-value"), "type": b64(b"password") }
        ],
        "attachments": [],
    });
    if with_vault_key {
        item["vaultMasterKeyEncrypted"] =
            serde_json::from_str::<Value>(ENC_ITEM).unwrap()["vaultMasterKeyEncrypted"].clone();
    }
    if attachments {
        item["attachments"] = json!([{ "id": "a1", "name": "old.txt" }]);
    }
    item
}

fn capture_patch(server: &mut ServerGuard, id: &str) -> (mockito::Mock, Arc<Mutex<Option<Value>>>) {
    let captured = Arc::new(Mutex::new(None::<Value>));
    let sink = captured.clone();
    let m = server
        .mock("PATCH", format!("/api/v1/items/{id}").as_str())
        .with_body_from_request(move |req| {
            *sink.lock().unwrap() = Some(serde_json::from_slice(req.body().unwrap()).unwrap());
            b"{}".to_vec()
        })
        .create();
    (m, captured)
}

/// The new item key from a request body, decrypted with the fixture vault password; the
/// listed fields must be real cipher strings (not plain Base64).
fn new_item_key(body: &Value) -> Zeroizing<String> {
    let enc = body["keyEncrypted"].as_str().expect("keyEncrypted sent");
    let key = pwk_crypto::decrypt(enc, &fixture_vault_password()).unwrap();
    assert_eq!(key.len(), 100);
    key
}

fn assert_cipher(v: &Value) {
    assert!(
        v.as_str().unwrap().starts_with("amt4cwv48xb6pp1h"),
        "not encrypted: {v}"
    );
}

#[test]
fn update_keyless_item_in_encrypting_vault_gets_new_key() {
    for with_vault_key in [true, false] {
        let mut server = Server::new();
        let c = client(&server);
        let _keys = unlock(&mut server, &c);
        let _get = server
            .mock("GET", format!("/api/v1/items/{KEYLESS_ID}").as_str())
            .with_body(keyless_item(with_vault_key, false).to_string())
            .create();
        // Without vaultMasterKeyEncrypted on the item, the vault decides.
        let vault = server
            .mock("GET", format!("/api/v1/vaults/{ENC_VAULT_ID}").as_str())
            .with_body(ENC_VAULT)
            .expect(usize::from(!with_vault_key))
            .create();
        let (patch, captured) = capture_patch(&mut server, KEYLESS_ID);

        // Only the custom fields change: the stored password is re-encrypted too.
        let update = pwk_api::ItemUpdate {
            customs: Some(vec![CustomField::new("New", "new-value", CustomKind::Text)]),
            ..Default::default()
        };
        c.update_item(KEYLESS_ID, &update).unwrap();
        patch.assert();
        vault.assert();
        let body = captured.lock().unwrap().take().unwrap();
        let key = new_item_key(&body);
        let dec = |v: &Value| {
            assert_cipher(v);
            pwk_crypto::decrypt(v.as_str().unwrap(), &key).unwrap()
        };
        assert_eq!(dec(&body["passwordEncrypted"]).as_str(), "old-pw");
        assert_eq!(body["customs"].as_array().unwrap().len(), 1);
        assert_eq!(dec(&body["customs"][0]["name"]).as_str(), "New");
        assert_eq!(dec(&body["customs"][0]["value"]).as_str(), "new-value");
        assert_eq!(dec(&body["customs"][0]["type"]).as_str(), "text");

        // Only the password changes: the stored custom fields are re-encrypted too.
        let update = pwk_api::ItemUpdate {
            password: Some(Some(Zeroizing::new("new-pw".into()))),
            ..Default::default()
        };
        c.update_item(KEYLESS_ID, &update).unwrap();
        let body = captured.lock().unwrap().take().unwrap();
        let key = new_item_key(&body);
        let dec = |v: &Value| {
            assert_cipher(v);
            pwk_crypto::decrypt(v.as_str().unwrap(), &key).unwrap()
        };
        assert_eq!(dec(&body["passwordEncrypted"]).as_str(), "new-pw");
        assert_eq!(dec(&body["customs"][0]["name"]).as_str(), "Old field");
        assert_eq!(dec(&body["customs"][0]["value"]).as_str(), "old-value");
        assert_eq!(dec(&body["customs"][0]["type"]).as_str(), "password");

        // And the client reads its own output back through the vault password chain.
        let mut stored = keyless_item(true, false);
        for k in ["keyEncrypted", "passwordEncrypted", "customs"] {
            stored[k] = body[k].clone();
        }
        let _reread = server
            .mock("GET", format!("/api/v1/items/{KEYLESS_ID}").as_str())
            .with_body(stored.to_string())
            .create();
        let item = c.get_item(KEYLESS_ID).unwrap();
        assert!(item.is_encrypted());
        assert_eq!(item.password.as_deref().map(String::as_str), Some("new-pw"));
        assert_eq!(item.customs[0].value.as_str(), "old-value");
    }
}

#[test]
fn update_keyless_item_without_secrets_sends_no_key() {
    let mut server = Server::new();
    let c = client(&server);
    let _keys = unlock(&mut server, &c);
    let _get = server
        .mock("GET", format!("/api/v1/items/{KEYLESS_ID}").as_str())
        .with_body(keyless_item(true, true).to_string())
        .create();
    let (patch, captured) = capture_patch(&mut server, KEYLESS_ID);
    let update = pwk_api::ItemUpdate {
        name: Some("renamed".into()),
        ..Default::default()
    };
    c.update_item(KEYLESS_ID, &update).unwrap();
    patch.assert();
    let body = captured.lock().unwrap().take().unwrap();
    assert_eq!(body, json!({ "vaultId": ENC_VAULT_ID, "name": "renamed" }));
}

#[test]
fn update_keyless_item_in_encrypting_vault_needs_master_key() {
    let mut server = Server::new();
    let _get = server
        .mock("GET", format!("/api/v1/items/{KEYLESS_ID}").as_str())
        .with_body(keyless_item(false, false).to_string())
        .create();
    let _vault = server
        .mock("GET", format!("/api/v1/vaults/{ENC_VAULT_ID}").as_str())
        .with_body(ENC_VAULT)
        .create();
    let patch = server.mock("PATCH", Matcher::Any).expect(0).create();
    let c = client(&server);
    let update = pwk_api::ItemUpdate {
        password: Some(Some(Zeroizing::new("new-pw".into()))),
        ..Default::default()
    };
    for plain in [false, true] {
        if plain {
            c.set_no_encryption();
        }
        assert!(matches!(
            c.update_item(KEYLESS_ID, &update),
            Err(Error::Locked)
        ));
    }
    let item = c.get_item(KEYLESS_ID).unwrap();
    assert!(matches!(
        c.add_attachment(&item, "f.txt", b"data"),
        Err(Error::Locked)
    ));
    patch.assert();
}

#[test]
fn update_keyless_item_in_plain_vault_stays_plain() {
    let mut server = Server::new();
    let mut item = keyless_item(false, false);
    item["vaultId"] = json!("pv");
    let _get = server
        .mock("GET", format!("/api/v1/items/{KEYLESS_ID}").as_str())
        .with_body(item.to_string())
        .create();
    let _vault = server
        .mock("GET", "/api/v1/vaults/pv")
        .with_body(r#"{"id":"pv","name":"Plain","masterKeyEncrypted":null}"#)
        .create();
    let (_patch, captured) = capture_patch(&mut server, KEYLESS_ID);
    let c = client(&server);
    c.set_no_encryption();
    let update = pwk_api::ItemUpdate {
        password: Some(Some(Zeroizing::new("pw".into()))),
        ..Default::default()
    };
    c.update_item(KEYLESS_ID, &update).unwrap();
    let body = captured.lock().unwrap().take().unwrap();
    assert_eq!(body["passwordEncrypted"], b64(b"pw"));
    assert!(body.get("keyEncrypted").is_none());
    assert!(body.get("customs").is_none());
}

#[test]
fn update_inconsistent_keyless_items_is_refused() {
    let mut server = Server::new();
    let c = client(&server);
    let _keys = unlock(&mut server, &c);
    let patch = server.mock("PATCH", Matcher::Any).expect(0).create();
    let update = pwk_api::ItemUpdate {
        password: Some(Some(Zeroizing::new("new-pw".into()))),
        ..Default::default()
    };
    // Attachments whose keys would not decrypt under a new item key.
    let get = server
        .mock("GET", format!("/api/v1/items/{KEYLESS_ID}").as_str())
        .with_body(keyless_item(true, true).to_string())
        .create();
    let err = c.update_item(KEYLESS_ID, &update).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(ref m) if m.contains("inconsistent") && m.contains("attachments")),
        "{err:?}"
    );
    get.remove();
    // Stored values encrypted with an unknown key.
    let mut item = keyless_item(true, false);
    item["passwordEncrypted"] = json!(pwk_crypto::encrypt("x", "unknown key"));
    let _get = server
        .mock("GET", format!("/api/v1/items/{KEYLESS_ID}").as_str())
        .with_body(item.to_string())
        .create();
    let err = c.update_item(KEYLESS_ID, &update).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(ref m) if m.contains("not plain Base64")),
        "{err:?}"
    );
    patch.assert();
}

#[test]
fn add_attachment_to_keyless_item_in_encrypting_vault() {
    let mut server = Server::new();
    let c = client(&server);
    let _keys = unlock(&mut server, &c);
    let get = server
        .mock("GET", format!("/api/v1/items/{KEYLESS_ID}").as_str())
        .with_body(keyless_item(true, false).to_string())
        .expect(2)
        .create();
    let (patch, captured) = capture_patch(&mut server, KEYLESS_ID);
    let item = c.get_item(KEYLESS_ID).unwrap();
    assert!(!item.is_encrypted());
    let data = b"attachment \x00 data".to_vec();
    c.add_attachment(&item, "new.bin", &data).unwrap();
    get.assert();
    patch.assert();
    let body = captured.lock().unwrap().take().unwrap();
    let key = new_item_key(&body);
    let dec = |v: &Value| {
        assert_cipher(v);
        pwk_crypto::decrypt(v.as_str().unwrap(), &key).unwrap()
    };
    assert_eq!(dec(&body["passwordEncrypted"]).as_str(), "old-pw");
    assert_eq!(dec(&body["customs"][0]["value"]).as_str(), "old-value");
    let att = &body["attachments"][0];
    assert_eq!(att["name"], "new.bin");
    let att_key = dec(&att["encryptedKey"]);
    assert_cipher(&att["encryptedData"]);
    let encoded =
        pwk_crypto::decrypt_bytes(att["encryptedData"].as_str().unwrap(), &att_key).unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(encoded.as_slice())
            .unwrap(),
        data
    );

    // With existing attachments the item is inconsistent: refused, nothing sent.
    let mut server = Server::new();
    let c = client(&server);
    let _keys = unlock(&mut server, &c);
    let _get = server
        .mock("GET", format!("/api/v1/items/{KEYLESS_ID}").as_str())
        .with_body(keyless_item(true, true).to_string())
        .create();
    let patch = server.mock("PATCH", Matcher::Any).expect(0).create();
    let item = c.get_item(KEYLESS_ID).unwrap();
    let err = c.add_attachment(&item, "new.bin", &data).unwrap_err();
    assert!(
        matches!(err, Error::Invalid(ref m) if m.contains("inconsistent")),
        "{err:?}"
    );
    patch.assert();
}

// --------------------------------------------------------------------------------------
// Review regressions
// --------------------------------------------------------------------------------------

#[test]
fn call_keeps_query_string_of_path() {
    let mut server = Server::new();
    let m = server
        .mock("GET", "/api/v1/items/search")
        .match_query(Matcher::AllOf(vec![
            Matcher::UrlEncoded("query".into(), "d&b x".into()),
            Matcher::UrlEncoded("flag".into(), String::new()),
            Matcher::UrlEncoded("tags[]".into(), "prod".into()),
        ]))
        .with_body(r#"{"items":[]}"#)
        .create();
    let c = client(&server);
    let q = [("tags[]".to_owned(), "prod".to_owned())];
    let v = c
        .call("GET", "items/search?query=d%26b+x&flag", &q, None)
        .unwrap();
    m.assert();
    assert_eq!(v["items"], json!([]));
}

#[test]
fn batch_with_too_few_responses_is_an_error() {
    let mut server = Server::new();
    let _m = server
        .mock("POST", "/api/v1/batch")
        .with_body(
            json!({"responses": [{"statusCode": 200, "body": {
                "id": "b", "name": "n-b", "vaultId": "v",
                "keyEncrypted": null, "passwordEncrypted": b64(b"b"),
            }}]})
            .to_string(),
        )
        .create();
    let ids = vec!["a".to_owned(), "b".to_owned()];
    let err = client(&server).get_items(&ids).unwrap_err();
    assert!(
        matches!(err, Error::Response { ref detail, .. } if detail.contains("responses")),
        "{err:?}"
    );
}

#[test]
fn shortcut_search_strips_nested_hidden_fields() {
    let mut server = Server::new();
    let secret = b64(b"plain-secret");
    let row = json!({
        "shortcut": {"id": "s1", "itemId": "i", "vaultId": "v2", "keyEncrypted": "sk"},
        "name": "Item",
        "item": {
            "id": "i", "name": "Item", "passwordEncrypted": secret, "keyEncrypted": "k",
            "vaultMasterKeyEncrypted": "vmk", "customs": [{"name": "c", "value": secret}],
            "nested": [{"masterKeyEncrypted": "mk", "keep": 1}],
        },
        "password": {"passwordEncrypted": secret, "customs": []},
    });
    let _search = server
        .mock("GET", "/api/v1/shortcuts/search")
        .with_body(json!({ "items": [row] }).to_string())
        .create();
    let rows = client(&server)
        .search_shortcuts(&ItemFilter::default())
        .unwrap();
    let out = serde_json::to_string(&rows).unwrap();
    for hidden in [
        "passwordEncrypted",
        "keyEncrypted",
        "vaultMasterKeyEncrypted",
        "masterKeyEncrypted",
        "customs",
    ] {
        assert!(!out.contains(hidden), "{hidden} in {out}");
    }
    assert!(!out.contains(&secret), "secret in {out}");
    assert_eq!(rows[0].extra["item"]["nested"][0]["keep"], 1);
    assert_eq!(rows[0].shortcut.item_id, "i");
}

/// Mocks `GET /folders/f1` in vault `v1` and the vaults `v1` (encrypting) and `v2`.
fn folder_move_world(server: &mut ServerGuard, v2_encrypts: bool) -> Vec<mockito::Mock> {
    let v2 = if v2_encrypts {
        json!({"id": "v2", "name": "B", "masterKeyEncrypted": "mke2"})
    } else {
        json!({"id": "v2", "name": "B", "masterKeyEncrypted": null})
    };
    vec![
        server
            .mock("GET", "/api/v1/folders/f1")
            .with_body(r#"{"id":"f1","name":"F","vaultId":"v1","parentFolderId":null}"#)
            .create(),
        server
            .mock("GET", "/api/v1/vaults/v1")
            .with_body(r#"{"id":"v1","name":"A","masterKeyEncrypted":"mke1"}"#)
            .create(),
        server
            .mock("GET", "/api/v1/vaults/v2")
            .with_body(v2.to_string())
            .create(),
    ]
}

#[test]
fn move_folder_to_other_encrypting_vault_is_refused() {
    for v2_encrypts in [true, false] {
        let mut server = Server::new();
        let _world = folder_move_world(&mut server, v2_encrypts);
        let mv = server
            .mock("POST", "/api/v1/folders/f1/move")
            .expect(0)
            .create();
        let err = client(&server).move_folder("f1", "v2", None).unwrap_err();
        assert!(
            matches!(err, Error::Invalid(ref m) if m.contains("client-side encryption")
                && m.contains("pwk item move")),
            "{err:?}"
        );
        mv.assert();
    }
}

#[test]
fn move_folder_within_vault_is_sent() {
    let mut server = Server::new();
    let _world = folder_move_world(&mut server, true);
    let mv = server
        .mock("POST", "/api/v1/folders/f1/move")
        .match_body(Matcher::Json(
            json!({"targetVaultId": "v1", "targetFolderId": "p"}),
        ))
        .with_body("{}")
        .create();
    client(&server).move_folder("f1", "v1", Some("p")).unwrap();
    mv.assert();
}

/// 403 on the master key options means "no encryption" only if the app settings say so.
#[test]
fn master_key_options_403() {
    let mut server = Server::new();
    let options = server
        .mock("GET", "/api/v1/users/master-key/options")
        .with_status(403)
        .with_body(r#"{"errors":[{"code":"forbidden","message":"Clientseitige Verschlüsselung deaktiviert"}]}"#)
        .expect(3)
        .create();
    let disabled = server
        .mock("GET", "/api/v1/app/settings")
        .with_body(r#"{"isClientSideEncryptionEnabled":false}"#)
        .create();
    let c = client(&server);
    assert!(c.master_key_options().unwrap().is_none());
    assert!(!c.detect_encryption().unwrap());
    assert!(c.is_plain());
    disabled.remove();

    let _enabled = server
        .mock("GET", "/api/v1/app/settings")
        .with_body(r#"{"isClientSideEncryptionEnabled":true}"#)
        .create();
    let err = client(&server).master_key_options().unwrap_err();
    assert!(
        matches!(err, pwk_api::Error::Api { status: 403, .. }),
        "{err:?}"
    );
    options.assert();
}

/// The folder tree is read level by level; a sub-request without a success status is an
/// error, not an empty or garbled level.
#[test]
fn list_all_folders_levels_and_failures() {
    let mut server = Server::new();
    let _root = server
        .mock("GET", "/api/v1/folders")
        .match_query(Matcher::UrlEncoded("vaultId".into(), "v".into()))
        .with_body(r#"{"items":[{"id":"f1","name":"A","vaultId":"v","parentFolderId":null}]}"#)
        .create();
    let level = server
        .mock("POST", "/api/v1/batch")
        .with_body(
            json!({"responses": [{"statusCode": 200, "body": {"items": [
                {"id": "f2", "name": "B", "vaultId": "v", "parentFolderId": "f1"}
            ]}}]})
            .to_string(),
        )
        .expect(1)
        .create();
    let _empty = server
        .mock("POST", "/api/v1/batch")
        .match_body(Matcher::Regex("parentFolderId=f2".into()))
        .with_body(json!({"responses": [{"statusCode": 200, "body": {"items": []}}]}).to_string())
        .create();
    let folders = client(&server).list_all_folders("v").unwrap();
    let ids: Vec<&str> = folders.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["f1", "f2"]);
    assert_eq!(folders[1].parent(), Some("f1"));
    level.assert();

    let mut server = Server::new();
    let _root = server
        .mock("GET", "/api/v1/folders")
        .match_query(Matcher::Any)
        .with_body(r#"{"items":[{"id":"f1","name":"A","vaultId":"v"}]}"#)
        .create();
    let _broken = server
        .mock("POST", "/api/v1/batch")
        .with_body(json!({"responses": [{"body": {"items": []}}]}).to_string())
        .create();
    let err = client(&server).list_all_folders("v").unwrap_err();
    assert!(err.to_string().contains("HTTP 0"), "{err}");
}
