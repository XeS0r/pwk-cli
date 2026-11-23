//! A fake Passwork 7 server with a small, consistently encrypted world.
//!
//! Key chain (docs/protocol.md, "Key chain"):
//!
//! ```text
//! MASTER_PASSWORD ──PBKDF2(MASTER_KEY_OPTIONS)──► master key
//! master key ──decrypt──► fixture RSA private key (re-encrypted for this master key)
//! vault.masterKeyEncrypted ──RSA──► vault password
//! item.keyEncrypted ──decrypt(vault password)──► item key ──► item fields
//! ```
//!
//! World:
//!
//! ```text
//! Infra (encrypted)
//!   Shared Mail                       password INFRA_MAIL_PASSWORD
//!   Datenbanken/
//!     Name/With Slash                 password SLASH_PASSWORD, custom "API Key"
//!     Prod/
//!       Prod DB                       login, password, url, customs Host/API Key/OTP,
//!                                     attachments dump.sql (ok), broken.bin (bad hash)
//! Team (encrypted)
//!   Shared Mail                       password TEAM_MAIL_PASSWORD
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine as _;
use serde_json::{Value, json};

use crate::http::{self, Request, Response};

// ---------------------------------------------------------------------------------------
// Constants of the world

/// The master password that unlocks this world.
pub const MASTER_PASSWORD: &str = "correct horse battery staple";
/// The smallest iteration count pwk accepts (weaker options are refused).
pub const MASTER_KEY_OPTIONS: &str = "pbkdf:sha256:100000:64:testsalt";
/// Options below pwk's floor: a server offering them must be refused.
pub const WEAK_MASTER_KEY_OPTIONS: &str = "pbkdf:sha256:1000:64:testsalt";

/// `mock_master_key` of passwork-python's tests (synthetic test key).
const FIXTURE_MASTER_KEY: &str =
    "/SzdXs1hNVP1H1+8m7AGrcVpbN2AaBV/cEdWYtF7TQwfizY+K1ukUNX6j6rNHvLG0v/wCICkDXSd6yQiD0ou9w==";
const FIXTURE_USER_KEYS: &str = include_str!("../../../api/tests/fixtures/user_keys_response.json");

/// The token pair handed to `pwk login`.
pub const ACCESS_TOKEN: &str = "access-0";
pub const REFRESH_TOKEN: &str = "refresh-0";

pub const USER_ID: &str = "65f0000000000000000000e1";

pub const VAULT_INFRA: &str = "65f000000000000000000a01";
pub const VAULT_TEAM: &str = "65f000000000000000000a02";
pub const FOLDER_DB: &str = "65f000000000000000000f01";
pub const FOLDER_PROD: &str = "65f000000000000000000f02";
pub const ITEM_PROD_DB: &str = "65f000000000000000000101";
pub const ITEM_MAIL_INFRA: &str = "65f000000000000000000102";
pub const ITEM_MAIL_TEAM: &str = "65f000000000000000000103";
pub const ITEM_SLASH: &str = "65f000000000000000000104";
pub const ATT_DUMP: &str = "65f000000000000000000201";
pub const ATT_BROKEN: &str = "65f000000000000000000202";

pub const PROD_DB_LOGIN: &str = "dbadmin";
pub const PROD_DB_PASSWORD: &str = "Pr0d-DB-s3cret!";
pub const PROD_DB_URL: &str = "https://db.example.com";
pub const PROD_DB_DESCRIPTION: &str = "Production database";
pub const PROD_DB_HOST: &str = "db1.internal";
pub const PROD_DB_API_KEY: &str = "ak-7f3e9c-hidden";
/// RFC 4648 Base32 TOTP secret of the custom field "OTP".
pub const PROD_DB_TOTP: &str = "JBSWY3DPEHPK3PXP";
pub const INFRA_MAIL_PASSWORD: &str = "infra-mail-pw-81";
pub const TEAM_MAIL_PASSWORD: &str = "team-mail-pw-27";
pub const SLASH_NAME: &str = "Name/With Slash";
pub const SLASH_PASSWORD: &str = "slash-pw-42";
pub const SLASH_API_KEY: &str = "slash-api-key-99";

pub const DUMP_NAME: &str = "dump.sql";
pub const BROKEN_NAME: &str = "broken.bin";

/// Content of `dump.sql`: text plus every byte value (exercises the Latin-1 hash).
pub fn dump_content() -> Vec<u8> {
    let mut data = b"-- dump of prod\nSELECT 1;\n".to_vec();
    data.extend(0..=255u8);
    data
}

/// The master key derived from [`MASTER_PASSWORD`] and `options`.
pub fn master_key(options: &str) -> String {
    let options = pwk_crypto::MasterKeyOptions::parse(options).unwrap();
    pwk_crypto::derive_master_key(MASTER_PASSWORD, &options)
        .unwrap()
        .to_string()
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

// ---------------------------------------------------------------------------------------
// Decrypting what pwk sends

/// A decrypted item body as sent by `pwk` (POST /items or PATCH /items/{id}).
#[derive(Debug, Clone)]
pub struct SentItem {
    pub item_key: String,
    pub password: Option<String>,
    /// `(name, value, type)` of every custom field.
    pub customs: Vec<(String, String, String)>,
}

impl SentItem {
    /// Value of the custom field `name`.
    pub fn custom(&self, name: &str) -> Option<&(String, String, String)> {
        self.customs.iter().find(|c| c.0 == name)
    }
}

/// Decrypts an item body sent by `pwk` with the vault password.
pub fn decrypt_sent_item(body: &Value, vault_password: &str) -> SentItem {
    let key_encrypted = body["keyEncrypted"]
        .as_str()
        .unwrap_or_else(|| panic!("keyEncrypted missing in {body:#}"));
    let item_key = pwk_crypto::decrypt(key_encrypted, vault_password)
        .expect("keyEncrypted decrypts with the vault password")
        .to_string();
    let dec = |v: &Value| {
        pwk_crypto::decrypt(v.as_str().expect("encrypted string"), &item_key)
            .expect("field decrypts with the item key")
            .to_string()
    };
    let password = body
        .get("passwordEncrypted")
        .filter(|v| v.is_string())
        .map(dec);
    let customs = body
        .get("customs")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(|c| (dec(&c["name"]), dec(&c["value"]), dec(&c["type"])))
                .collect()
        })
        .unwrap_or_default();
    SentItem {
        item_key,
        password,
        customs,
    }
}

// ---------------------------------------------------------------------------------------
// Building the encrypted world

struct ItemSpec<'a> {
    id: &'a str,
    vault_id: &'a str,
    folder_id: Option<&'a str>,
    name: &'a str,
    login: &'a str,
    password: &'a str,
    url: &'a str,
    description: &'a str,
    tags: &'a [&'a str],
    customs: &'a [(&'a str, &'a str, &'a str)],
}

fn encrypt_item(spec: &ItemSpec<'_>, vault_password: &str, vault_mke: &str) -> (Value, String) {
    let item_key = pwk_crypto::generate_key().to_string();
    let customs: Vec<Value> = spec
        .customs
        .iter()
        .map(|(name, value, kind)| {
            json!({
                "name": pwk_crypto::encrypt(name, &item_key),
                "value": pwk_crypto::encrypt(value, &item_key),
                "type": pwk_crypto::encrypt(kind, &item_key),
            })
        })
        .collect();
    let item = json!({
        "id": spec.id,
        "vaultId": spec.vault_id,
        "folderId": spec.folder_id,
        "name": spec.name,
        "login": spec.login,
        "url": spec.url,
        "urls": if spec.url.is_empty() { json!([]) } else { json!([spec.url]) },
        "description": spec.description,
        "tags": spec.tags,
        "color": null,
        "isFavorite": false,
        "isDeleted": false,
        "passwordEncrypted": pwk_crypto::encrypt(spec.password, &item_key),
        "keyEncrypted": pwk_crypto::encrypt(&item_key, vault_password),
        "vaultMasterKeyEncrypted": vault_mke,
        "customs": customs,
        "attachments": [],
    });
    (item, item_key)
}

/// One encrypted attachment as the download endpoint returns it.
fn encrypt_attachment(name: &str, data: &[u8], item_key: &str, hash: &str) -> (Value, Value) {
    let att_key = pwk_crypto::generate_key().to_string();
    let encrypted_key = pwk_crypto::encrypt(&att_key, item_key);
    let download = json!({
        "name": name,
        "encryptedKey": encrypted_key,
        "encryptedData": pwk_crypto::encrypt(&b64(data), &att_key),
        "hash": hash,
    });
    let reference = json!({ "name": name, "encryptedKey": encrypted_key });
    (download, reference)
}

// ---------------------------------------------------------------------------------------
// Server state

#[derive(Debug, Default)]
struct State {
    access_token: String,
    refresh_token: String,
    /// The current access token answers 401 accessTokenExpired until refreshed.
    access_expired: bool,
    rotations: u32,
    next_id: u32,
    vaults: Vec<Value>,
    folders: Vec<Value>,
    items: Vec<Value>,
    attachments: HashMap<(String, String), Value>,
    log: Vec<Request>,
}

/// The running fake server.
#[derive(Clone)]
pub struct FakePasswork {
    pub url: String,
    pub master_key: String,
    master_key_options: &'static str,
    vault_passwords: HashMap<String, String>,
    user_keys: Value,
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for FakePasswork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakePasswork")
            .field("url", &self.url)
            .finish()
    }
}

impl FakePasswork {
    /// Builds the world and starts serving it.
    pub fn start() -> Self {
        Self::start_with_options(MASTER_KEY_OPTIONS)
    }

    /// [`FakePasswork::start`] with other master key options.
    pub fn start_with_options(master_key_options: &'static str) -> Self {
        let master_key = master_key(master_key_options);

        // The fixture key pair, with the private key re-encrypted for our master key.
        let fixture: Value = serde_json::from_str(FIXTURE_USER_KEYS).unwrap();
        let private_pem = pwk_crypto::decrypt(
            fixture["keys"]["privateEncrypted"].as_str().unwrap(),
            FIXTURE_MASTER_KEY,
        )
        .expect("fixture private key decrypts with the fixture master key");
        let public_pem = fixture["keys"]["public"].as_str().unwrap().to_owned();
        let public = pwk_crypto::PublicKey::from_pem(&public_pem).unwrap();
        let user_keys = json!({
            "id": USER_ID,
            "keys": {
                "public": public_pem,
                "privateEncrypted": pwk_crypto::encrypt(&private_pem, &master_key),
            }
        });

        let mut vault_passwords = HashMap::new();
        let mut vault_mke = HashMap::new();
        let mut vaults = Vec::new();
        for (id, name) in [(VAULT_INFRA, "Infra"), (VAULT_TEAM, "Team")] {
            let password = pwk_crypto::generate_key().to_string();
            let mke = public.encrypt(password.as_bytes()).unwrap();
            vaults.push(json!({
                "id": id,
                "name": name,
                "typeId": null,
                "masterKeyEncrypted": mke,
                "permissions": ["directory:read", "directory:edit"],
            }));
            vault_passwords.insert(id.to_owned(), password);
            vault_mke.insert(id.to_owned(), mke);
        }

        let folders = vec![
            json!({ "id": FOLDER_DB, "name": "Datenbanken", "vaultId": VAULT_INFRA, "parentId": null }),
            json!({ "id": FOLDER_PROD, "name": "Prod", "vaultId": VAULT_INFRA, "parentId": FOLDER_DB }),
        ];

        let specs = [
            ItemSpec {
                id: ITEM_PROD_DB,
                vault_id: VAULT_INFRA,
                folder_id: Some(FOLDER_PROD),
                name: "Prod DB",
                login: PROD_DB_LOGIN,
                password: PROD_DB_PASSWORD,
                url: PROD_DB_URL,
                description: PROD_DB_DESCRIPTION,
                tags: &["db", "prod"],
                customs: &[
                    ("Host", PROD_DB_HOST, "text"),
                    ("API Key", PROD_DB_API_KEY, "password"),
                    ("OTP", PROD_DB_TOTP, "totp"),
                ],
            },
            ItemSpec {
                id: ITEM_MAIL_INFRA,
                vault_id: VAULT_INFRA,
                folder_id: None,
                name: "Shared Mail",
                login: "infra@example.com",
                password: INFRA_MAIL_PASSWORD,
                url: "",
                description: "",
                tags: &[],
                customs: &[],
            },
            ItemSpec {
                id: ITEM_MAIL_TEAM,
                vault_id: VAULT_TEAM,
                folder_id: None,
                name: "Shared Mail",
                login: "team@example.com",
                password: TEAM_MAIL_PASSWORD,
                url: "",
                description: "",
                tags: &[],
                customs: &[],
            },
            ItemSpec {
                id: ITEM_SLASH,
                vault_id: VAULT_INFRA,
                folder_id: Some(FOLDER_DB),
                name: SLASH_NAME,
                login: "",
                password: SLASH_PASSWORD,
                url: "",
                description: "",
                tags: &[],
                customs: &[("API Key", SLASH_API_KEY, "password")],
            },
        ];
        let mut items = Vec::new();
        let mut attachments = HashMap::new();
        for spec in &specs {
            let (mut item, item_key) = encrypt_item(
                spec,
                &vault_passwords[spec.vault_id],
                &vault_mke[spec.vault_id],
            );
            if spec.id == ITEM_PROD_DB {
                let data = dump_content();
                let mut refs = Vec::new();
                for (att_id, name, hash) in [
                    (ATT_DUMP, DUMP_NAME, pwk_crypto::attachment_hash(&data)),
                    (ATT_BROKEN, BROKEN_NAME, "0".repeat(64)),
                ] {
                    let (download, mut reference) =
                        encrypt_attachment(name, &data, &item_key, &hash);
                    reference["id"] = json!(att_id);
                    refs.push(reference);
                    attachments.insert((spec.id.to_owned(), att_id.to_owned()), download);
                }
                item["attachments"] = Value::Array(refs);
            }
            items.push(item);
        }

        let state = Arc::new(Mutex::new(State {
            access_token: ACCESS_TOKEN.to_owned(),
            refresh_token: REFRESH_TOKEN.to_owned(),
            next_id: 0x900,
            vaults,
            folders,
            items,
            attachments,
            ..State::default()
        }));

        let mut fake = Self {
            url: String::new(),
            master_key,
            master_key_options,
            vault_passwords,
            user_keys,
            state,
        };
        let handler_fake = fake.clone();
        fake.url = http::serve(Arc::new(move |req: &Request| handler_fake.handle(req)));
        fake
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    // -----------------------------------------------------------------------------------
    // Test-side accessors

    /// The password of a vault (by ID).
    pub fn vault_password(&self, vault_id: &str) -> &str {
        &self.vault_passwords[vault_id]
    }

    /// Every request received so far (batch sub-requests are not listed separately).
    pub fn requests(&self) -> Vec<Request> {
        self.state().log.clone()
    }

    /// Requests with this method whose path is `path`.
    pub fn requests_to(&self, method: &str, path: &str) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(|r| r.method == method && r.path == path)
            .collect()
    }

    /// The current token pair.
    pub fn tokens(&self) -> (String, String) {
        let s = self.state();
        (s.access_token.clone(), s.refresh_token.clone())
    }

    /// How often the tokens were refreshed.
    pub fn rotations(&self) -> u32 {
        self.state().rotations
    }

    /// From now on the current access token answers 401 `accessTokenExpired` until a
    /// refresh replaces it.
    pub fn expire_access_token(&self) {
        self.state().access_expired = true;
    }

    /// The stored server-side JSON of an item.
    pub fn item(&self, id: &str) -> Option<Value> {
        self.state().items.iter().find(|i| i["id"] == id).cloned()
    }

    // -----------------------------------------------------------------------------------
    // Request handling

    fn handle(&self, req: &Request) -> Response {
        self.state().log.push(req.clone());
        let Some(path) = req.path.strip_prefix("/api/v1/") else {
            return Response::not_found("path");
        };
        let path = path.trim_end_matches('/');

        if req.method == "POST" && path == "sessions/refresh" {
            return self.refresh(req);
        }
        if let Some(denied) = self.check_auth(req) {
            return denied;
        }
        if req.method == "POST" && path == "batch" {
            return self.batch(req);
        }
        self.route(req, path)
    }

    fn check_auth(&self, req: &Request) -> Option<Response> {
        let s = self.state();
        let bearer = req
            .header("authorization")
            .and_then(|h| h.strip_prefix("Bearer "));
        if bearer != Some(s.access_token.as_str()) {
            return Some(Response::error(401, "invalidToken", "invalid access token"));
        }
        if s.access_expired {
            return Some(Response::error(
                401,
                "accessTokenExpired",
                "access token expired",
            ));
        }
        None
    }

    fn refresh(&self, req: &Request) -> Response {
        let mut s = self.state();
        let body = req.json();
        if body["refreshToken"].as_str() != Some(s.refresh_token.as_str()) {
            return Response::error(401, "invalidRefreshToken", "invalid refresh token");
        }
        s.rotations += 1;
        s.access_token = format!("access-{}", s.rotations);
        s.refresh_token = format!("refresh-{}", s.rotations);
        s.access_expired = false;
        let now = now();
        Response::ok(json!({
            "accessToken": s.access_token,
            "refreshToken": s.refresh_token,
            "accessTokenExpiredAt": now + 3600,
            "refreshTokenExpiredAt": now + 86_400,
        }))
    }

    fn batch(&self, req: &Request) -> Response {
        let body = req.json();
        let Some(list) = body["requests"].as_array() else {
            return Response::error(400, "invalid", "requests missing");
        };
        let responses: Vec<Value> = list
            .iter()
            .map(|sub| {
                let method = sub["method"].as_str().unwrap_or("GET");
                let url = sub["relativeUrl"].as_str().unwrap_or_default();
                let sub_body = sub
                    .get("body")
                    .map(|b| serde_json::to_vec(b).unwrap())
                    .unwrap_or_default();
                let sub_req = Request::from_relative(method, url, req, sub_body);
                let path = sub_req
                    .path
                    .strip_prefix("/api/v1/")
                    .unwrap_or(&sub_req.path)
                    .trim_end_matches('/')
                    .to_owned();
                let resp = self.route(&sub_req, &path);
                json!({ "statusCode": resp.status, "body": resp.body })
            })
            .collect();
        Response::ok(json!({ "responses": responses }))
    }

    fn next_id(&self) -> String {
        let mut s = self.state();
        s.next_id += 1;
        format!("65f0000000000000000{:05x}", s.next_id)
    }

    #[allow(clippy::too_many_lines)]
    fn route(&self, req: &Request, path: &str) -> Response {
        let segments: Vec<&str> = path.split('/').collect();
        match (req.method.as_str(), segments.as_slice()) {
            ("GET", ["sessions", "current", "info"]) => Response::ok(json!({
                "user": { "id": USER_ID, "name": "Test User", "login": "tester",
                          "email": "tester@example.com" },
                "sessionId": "s-1",
            })),
            ("GET", ["users", "master-key", "options"]) => {
                Response::ok(json!({ "masterKeyOptions": self.master_key_options }))
            }
            ("GET", ["users", "keys"]) => Response::ok(self.user_keys.clone()),
            ("GET", ["app", "features"]) => Response::ok(json!([])),
            ("GET", ["vault-types", "all"]) => Response::ok(json!({ "items": [] })),

            // Vaults
            ("GET", ["vaults"]) => Response::ok(json!({ "items": self.state().vaults })),
            ("GET", ["vaults", id]) => self
                .state()
                .vaults
                .iter()
                .find(|v| v["id"] == *id)
                .cloned()
                .map_or_else(|| Response::not_found("vault"), Response::ok),
            ("POST", ["vaults"]) => {
                let id = self.next_id();
                let mut vault = req.json();
                vault["id"] = json!(id);
                self.state().vaults.push(vault);
                Response::ok(json!({ "id": id }))
            }

            // Folders
            ("GET", ["folders"]) => {
                let vault = req.query_one("vaultId");
                let parent = req.query_one("parentId");
                let list: Vec<Value> = self
                    .state()
                    .folders
                    .iter()
                    .filter(|f| vault.is_none_or(|v| f["vaultId"] == v))
                    .filter(|f| parent.is_none_or(|p| f["parentId"] == p))
                    .cloned()
                    .collect();
                Response::ok(json!({ "items": list }))
            }
            ("GET", ["folders", id]) => self
                .state()
                .folders
                .iter()
                .find(|f| f["id"] == *id)
                .cloned()
                .map_or_else(|| Response::not_found("folder"), Response::ok),
            ("POST", ["folders"]) => {
                let id = self.next_id();
                let body = req.json();
                self.state().folders.push(json!({
                    "id": id, "name": body["name"], "vaultId": body["vaultId"],
                    "parentId": body["parentId"],
                }));
                Response::ok(json!({ "id": id }))
            }
            ("POST", ["folders", id, "move"]) => {
                let body = req.json();
                let mut s = self.state();
                let Some(folder) = s.folders.iter_mut().find(|f| f["id"] == *id) else {
                    return Response::not_found("folder");
                };
                folder["vaultId"] = body["vaultId"].clone();
                folder["parentId"] = body["parentId"].clone();
                Response::ok(json!({ "id": id }))
            }

            // Items
            ("GET", ["items", "search"]) => self.search(req),
            ("GET", ["items", id]) => self
                .item(id)
                .map_or_else(|| Response::not_found("item"), Response::ok),
            ("POST", ["items"]) => {
                let id = self.next_id();
                let mut item = req.json();
                let mke = self.vault_mke(item["vaultId"].as_str().unwrap_or_default());
                item["id"] = json!(id);
                item["vaultMasterKeyEncrypted"] = json!(mke);
                self.store_new_attachments(&id, &mut item);
                self.state().items.push(item);
                Response::ok(json!({ "id": id }))
            }
            ("PATCH", ["items", id]) => {
                let Some(mut item) = self.item(id) else {
                    return Response::not_found("item");
                };
                let mut body = req.json();
                let existing = item["attachments"].as_array().cloned().unwrap_or_default();
                self.store_new_attachments(id, &mut body);
                if let (Some(map), Some(patch)) = (item.as_object_mut(), body.as_object()) {
                    for (k, v) in patch {
                        map.insert(k.clone(), v.clone());
                    }
                }
                if body.get("attachments").is_some() {
                    let mut all = existing;
                    all.extend(item["attachments"].as_array().cloned().unwrap_or_default());
                    item["attachments"] = Value::Array(all);
                }
                self.replace_item(id, item);
                Response::ok(json!({ "id": id }))
            }
            ("POST", ["items", id, "move"]) => {
                let Some(mut item) = self.item(id) else {
                    return Response::not_found("item");
                };
                let body = req.json();
                item["vaultId"] = body["vaultId"].clone();
                item["folderId"] = body["folderId"].clone();
                self.replace_item(id, item);
                Response::ok(json!({ "id": id }))
            }
            ("DELETE", ["items", id]) => {
                let mut s = self.state();
                let before = s.items.len();
                s.items.retain(|i| i["id"] != *id);
                if s.items.len() == before {
                    return Response::not_found("item");
                }
                Response::ok(json!({ "binItemId": format!("bin-{id}") }))
            }
            ("GET", ["items", item_id, "attachment", att_id]) => self
                .state()
                .attachments
                .get(&((*item_id).to_owned(), (*att_id).to_owned()))
                .cloned()
                .map_or_else(|| Response::not_found("attachment"), Response::ok),

            // Shortcuts: none in this world.
            ("GET", ["shortcuts", "search"]) => Response::ok(json!({ "items": [] })),

            _ => Response::not_found(&format!("{} /api/v1/{path}", req.method)),
        }
    }

    fn vault_mke(&self, vault_id: &str) -> String {
        self.state()
            .vaults
            .iter()
            .find(|v| v["id"] == vault_id)
            .and_then(|v| v["masterKeyEncrypted"].as_str())
            .unwrap_or_default()
            .to_owned()
    }

    fn replace_item(&self, id: &str, item: Value) {
        let mut s = self.state();
        if let Some(slot) = s.items.iter_mut().find(|i| i["id"] == id) {
            *slot = item;
        }
    }

    /// Uploaded attachments `{name, encryptedKey, encryptedData, hash}` become downloadable
    /// and are listed on the item as `{id, name, encryptedKey}`.
    fn store_new_attachments(&self, item_id: &str, item: &mut Value) {
        let Some(list) = item.get("attachments").and_then(Value::as_array).cloned() else {
            return;
        };
        let mut refs = Vec::new();
        for att in list {
            let id = self.next_id();
            self.state()
                .attachments
                .insert((item_id.to_owned(), id.clone()), att.clone());
            refs.push(
                json!({ "id": id, "name": att["name"], "encryptedKey": att["encryptedKey"] }),
            );
        }
        item["attachments"] = Value::Array(refs);
    }

    /// `items/search`: `query` (case-insensitive substring of name, login, URL or tag),
    /// `vaultIds[]`, `folderIds[]` (direct folder) and `tags[]`.
    fn search(&self, req: &Request) -> Response {
        let query = req.query_one("query").map(str::to_lowercase);
        let vaults = req.query_all("vaultIds[]");
        let folders = req.query_all("folderIds[]");
        let tags = req.query_all("tags[]");
        let text = |v: &Value| v.as_str().unwrap_or_default().to_lowercase();
        let list: Vec<Value> = self
            .state()
            .items
            .iter()
            .filter(|i| vaults.is_empty() || vaults.iter().any(|v| i["vaultId"] == *v))
            .filter(|i| folders.is_empty() || folders.iter().any(|f| i["folderId"] == *f))
            .filter(|i| {
                tags.is_empty()
                    || tags.iter().all(|t| {
                        i["tags"]
                            .as_array()
                            .is_some_and(|list| list.iter().any(|x| x == t))
                    })
            })
            .filter(|i| {
                query.as_deref().is_none_or(|q| {
                    q.is_empty()
                        || text(&i["name"]).contains(q)
                        || text(&i["login"]).contains(q)
                        || text(&i["url"]).contains(q)
                        || i["tags"]
                            .as_array()
                            .is_some_and(|t| t.iter().any(|x| text(x).contains(q)))
                })
            })
            .cloned()
            .collect();
        Response::ok(json!({ "items": list }))
    }
}

/// Unix seconds now.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
