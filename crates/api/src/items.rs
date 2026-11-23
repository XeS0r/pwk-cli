//! Items, attachments and shortcuts: decryption on read, encryption on write.

use base64::Engine as _;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::client::{Query, from_value, id_from, list_values, object};
use crate::models::{
    AttachmentRef, BatchRequest, CustomField, CustomKind, Item, ItemFilter, ItemSummary,
    ItemUpdate, NewAttachment, NewItem, RawItem, Shortcut, ShortcutSummary, ShortcutWithItem,
};
use crate::{Client, Error, Result, SecretString, endpoints};

/// Maximum attachment size (5 MiB).
pub const MAX_ATTACHMENT_SIZE: usize = 5 * 1024 * 1024;

/// Key material and encrypted values that never appear in summaries.
const HIDDEN_FIELDS: &[&str] = &[
    "passwordEncrypted",
    "keyEncrypted",
    "vaultMasterKeyEncrypted",
    "masterKeyEncrypted",
    "customs",
];

/// `encryptedKey` the official client sends for attachments without encryption.
const PLAIN_ATTACHMENT_KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Start of every cipher string (`passwork_base32("U2FsdGVkX1…")`).
const CIPHER_PREFIX: &str = "amt4cwv48xb6pp1h";

/// How to encrypt values written to an item (see `Client::write_key`).
enum WriteKey {
    /// The item's own key (from its `keyEncrypted`).
    Existing(SecretString),
    /// The vault has no key encryption: plain Base64.
    Plain,
    /// The vault encrypts but the item has no `keyEncrypted`; holds the vault password.
    NeedsNewKey(SecretString),
}

fn inconsistent_attachments(item_id: &str) -> Error {
    Error::Invalid(format!(
        "item {item_id} is inconsistent: it is in an encrypting vault and has attachments \
         but no item key (keyEncrypted); refusing to change its encrypted fields or \
         attachments, since a new item key would make the existing attachments \
         undecryptable"
    ))
}

fn nonempty(s: Option<&str>) -> Option<&str> {
    s.filter(|s| !s.is_empty())
}

fn b64() -> &'static base64::engine::GeneralPurpose {
    &base64::engine::general_purpose::STANDARD
}

/// Removes [`HIDDEN_FIELDS`] from `v` and from all objects nested in it (search rows can
/// embed the item, e.g. a shortcut row's `item` / `password`).
fn strip_hidden(mut v: Value) -> Value {
    fn strip(v: &mut Value) {
        match v {
            Value::Object(o) => {
                for k in HIDDEN_FIELDS {
                    o.remove(*k);
                }
                o.values_mut().for_each(strip);
            }
            Value::Array(a) => a.iter_mut().for_each(strip),
            _ => {}
        }
    }
    strip(&mut v);
    v
}

fn filter_query(filter: &ItemFilter) -> Query {
    let mut q = Query::default();
    q.push_opt("query", filter.query.as_deref());
    q.push_list("tags", &filter.tags);
    q.push_list("colorCodes", &filter.colors);
    q.push_list("vaultIds", &filter.vault_ids);
    q.push_list("folderIds", &filter.folder_ids);
    q
}

/// Encrypts the custom fields with `key` (`name`, `value`, `type`; other keys copied).
fn encrypt_customs(customs: &[CustomField], key: &str) -> Value {
    Value::Array(
        customs
            .iter()
            .map(|c| {
                let mut m = c.extra.clone();
                m.insert("name".into(), json!(pwk_crypto::encrypt(&c.name, key)));
                m.insert("value".into(), json!(pwk_crypto::encrypt(&c.value, key)));
                m.insert(
                    "type".into(),
                    json!(pwk_crypto::encrypt(c.kind.as_str(), key)),
                );
                Value::Object(m)
            })
            .collect(),
    )
}

/// Builds an attachment upload entry encrypted with `item_key` (empty: plain Base64).
fn encrypt_attachment(name: &str, data: &[u8], item_key: &str) -> Result<Value> {
    if data.len() > MAX_ATTACHMENT_SIZE {
        return Err(Error::Invalid(format!(
            "attachment {name:?} is larger than 5 MiB"
        )));
    }
    let encoded = Zeroizing::new(b64().encode(data));
    let (encrypted_key, encrypted_data) = if item_key.is_empty() {
        (
            pwk_crypto::encrypt(PLAIN_ATTACHMENT_KEY, ""),
            pwk_crypto::encrypt(&encoded, ""),
        )
    } else {
        let att_key = pwk_crypto::generate_key();
        (
            pwk_crypto::encrypt(&att_key, item_key),
            pwk_crypto::encrypt(&encoded, &att_key),
        )
    };
    Ok(json!({
        "name": name,
        "encryptedKey": encrypted_key,
        "encryptedData": encrypted_data,
        "hash": pwk_crypto::attachment_hash(data),
    }))
}

impl Client {
    // ----------------------------------------------------------------------------------
    // Keys
    // ----------------------------------------------------------------------------------

    /// The item key from `keyEncrypted` (empty without client-side encryption).
    fn item_key_from(
        &self,
        vault_id: &str,
        vault_master_key_encrypted: Option<&str>,
        key_encrypted: Option<&str>,
    ) -> Result<SecretString> {
        let Some(key_encrypted) = nonempty(key_encrypted) else {
            return Ok(SecretString::default());
        };
        // Fails with `Locked` when no master key is set.
        self.user_keys()?;
        let vault_password = self.vault_password_from(vault_id, vault_master_key_encrypted)?;
        Ok(pwk_crypto::decrypt(key_encrypted, &vault_password)?)
    }

    /// The key to encrypt new values of an item with, for writes.
    ///
    /// With `keyEncrypted` that is the item key. Without it, the vault decides: a plain
    /// vault (no `masterKeyEncrypted`) means plain Base64 ([`WriteKey::Plain`]); an
    /// encrypting vault yields its password, so the caller can give the item a new key
    /// ([`WriteKey::NeedsNewKey`]). Items without `keyEncrypted` exist in encrypting
    /// vaults (other clients omit it for items without a password); encrypting with an
    /// empty key there would store secrets as plain Base64. [`Error::Locked`] if the
    /// vault encrypts and no master key is set.
    fn write_key(
        &self,
        vault_id: &str,
        vault_master_key_encrypted: Option<&str>,
        key_encrypted: Option<&str>,
    ) -> Result<WriteKey> {
        if nonempty(key_encrypted).is_some() {
            let key = self.item_key_from(vault_id, vault_master_key_encrypted, key_encrypted)?;
            return Ok(WriteKey::Existing(key));
        }
        // Decrypts `vaultMasterKeyEncrypted` or fetches the vault; empty means the vault
        // has no `masterKeyEncrypted`.
        let vault_password = self.vault_password_from(vault_id, vault_master_key_encrypted)?;
        if vault_password.is_empty() {
            Ok(WriteKey::Plain)
        } else {
            Ok(WriteKey::NeedsNewKey(vault_password))
        }
    }

    /// Gives a stored item without `keyEncrypted` in an encrypting vault a new item key:
    /// puts `keyEncrypted` into `body` and re-encrypts the stored password and custom
    /// fields under the new key unless `password` / `customs` replace them. The stored
    /// values are plain Base64 then. Items with attachments are refused: their
    /// `encryptedKey` would not decrypt under a new item key. Returns the new item key.
    fn rekey_item(
        raw: RawItem,
        vault_password: &str,
        password: Option<Option<&SecretString>>,
        customs: Option<&[CustomField]>,
        body: &mut Map<String, Value>,
    ) -> Result<SecretString> {
        if !raw.attachments.is_empty() {
            return Err(inconsistent_attachments(&raw.id));
        }
        // Without an item key the stored values must be plain Base64. A cipher string
        // here was encrypted with a key we do not have; re-encrypting its Base64 decoding
        // would destroy it.
        let is_cipher = |v: Option<&str>| v.is_some_and(|v| v.starts_with(CIPHER_PREFIX));
        let ciphered = is_cipher(raw.password_encrypted.as_deref())
            || raw.customs.iter().any(|c| {
                ["name", "value", "type"]
                    .iter()
                    .any(|k| is_cipher(c.get(*k).and_then(Value::as_str)))
            });
        let id = raw.id.clone();
        let stored = match Self::decode_item_with_key(raw, "") {
            Ok(stored) if !ciphered => stored,
            _ => {
                return Err(Error::Invalid(format!(
                    "item {id} is inconsistent: it is in an encrypting vault and has no item \
                     key (keyEncrypted), but its stored values are not plain Base64; \
                     refusing to overwrite them"
                )));
            }
        };
        let item_key = pwk_crypto::generate_key();
        body.insert(
            "keyEncrypted".into(),
            json!(pwk_crypto::encrypt(&item_key, vault_password)),
        );
        let password = password.unwrap_or(stored.password.as_ref());
        if let Some(p) = password {
            body.insert(
                "passwordEncrypted".into(),
                json!(pwk_crypto::encrypt(p, &item_key)),
            );
        } else if stored.password.is_some() {
            body.insert(
                "passwordEncrypted".into(),
                json!(pwk_crypto::encrypt("", &item_key)),
            );
        }
        let customs = customs.unwrap_or(&stored.customs);
        if !customs.is_empty() || !stored.customs.is_empty() {
            body.insert("customs".into(), encrypt_customs(customs, &item_key));
        }
        Ok(item_key)
    }

    /// The key of a decrypted item.
    fn item_key(&self, item: &Item) -> Result<SecretString> {
        self.item_key_from(
            &item.vault_id,
            item.vault_master_key_encrypted.as_deref(),
            item.key_encrypted.as_deref(),
        )
    }

    fn parse_raw_item(v: Value, path: &str) -> Result<RawItem> {
        from_value(v, path)
    }

    /// Decrypts a raw item JSON with its own key material.
    fn decode_item(&self, v: Value, path: &str) -> Result<Item> {
        let raw = Self::parse_raw_item(v, path)?;
        let key = self.item_key_from(
            &raw.vault_id,
            raw.vault_master_key_encrypted.as_deref(),
            raw.key_encrypted.as_deref(),
        )?;
        Self::decode_item_with_key(raw, &key)
    }

    /// Decrypts a raw item with a known item key (empty: plain Base64).
    fn decode_item_with_key(raw: RawItem, key: &str) -> Result<Item> {
        let password = match nonempty(raw.password_encrypted.as_deref()) {
            Some(p) => Some(pwk_crypto::decrypt(p, key)?),
            None => None,
        };
        let mut customs = Vec::with_capacity(raw.customs.len());
        for mut c in raw.customs {
            let mut take = |name: &str| -> Result<SecretString> {
                match c.remove(name) {
                    Some(Value::String(s)) if !s.is_empty() => Ok(pwk_crypto::decrypt(&s, key)?),
                    _ => Ok(SecretString::default()),
                }
            };
            let name = take("name")?;
            let value = take("value")?;
            let kind = take("type")?;
            customs.push(CustomField {
                name: name.to_string(),
                value,
                kind: CustomKind::parse(&kind),
                extra: c,
            });
        }
        Ok(Item {
            id: raw.id,
            name: raw.name,
            login: raw.login,
            url: raw.url,
            urls: raw.urls,
            description: raw.description,
            tags: raw.tags,
            color: raw.color,
            is_favorite: raw.is_favorite,
            vault_id: raw.vault_id,
            folder_id: raw.folder_id,
            password,
            customs,
            attachments: raw.attachments,
            extra: raw.extra,
            key_encrypted: raw.key_encrypted,
            vault_master_key_encrypted: raw.vault_master_key_encrypted,
        })
    }

    // ----------------------------------------------------------------------------------
    // Items
    // ----------------------------------------------------------------------------------

    /// `GET /items/search` with the filter.
    pub fn search_items(&self, filter: &ItemFilter) -> Result<Vec<ItemSummary>> {
        let v = self.get(endpoints::ITEMS_SEARCH, &filter_query(filter))?;
        list_values(v, endpoints::ITEMS_SEARCH)?
            .into_iter()
            .map(|e| from_value(strip_hidden(e), endpoints::ITEMS_SEARCH))
            .collect()
    }

    /// Lists items: the search endpoint with the filter but without `query`.
    ///
    /// **(unverified)** that the search endpoint returns all items when `query` is
    /// missing; `GET /items` with `vaultId`/`folderId` is the documented alternative.
    pub fn list_items(&self, filter: &ItemFilter) -> Result<Vec<ItemSummary>> {
        let filter = ItemFilter {
            query: None,
            ..filter.clone()
        };
        self.search_items(&filter)
    }

    /// `GET /items/{id}`, decrypted. Encrypted items need the master key
    /// ([`Error::Locked`] otherwise).
    pub fn get_item(&self, id: &str) -> Result<Item> {
        let path = endpoints::item(id)?;
        let v = self.get(&path, &Query::default())?;
        self.decode_item(v, &path)
    }

    /// Several items via `POST /batch` (25 per request), decrypted, in order. Items the
    /// server does not return with a 2xx status are skipped (as the official client does).
    pub fn get_items(&self, ids: &[String]) -> Result<Vec<Item>> {
        let requests: Vec<BatchRequest> = ids
            .iter()
            .map(|id| Ok(BatchRequest::get(&endpoints::item(id)?)))
            .collect::<Result<_>>()?;
        let mut items = Vec::with_capacity(ids.len());
        for (req, resp) in requests.iter().zip(self.batch(&requests)?) {
            if resp.is_success() {
                items.push(self.decode_item(resp.body, &req.relative_url)?);
            }
        }
        Ok(items)
    }

    /// Creates an item and returns its ID.
    ///
    /// If the vault has key encryption, a new item key is generated and `keyEncrypted`
    /// is always sent; otherwise values are plain Base64.
    pub fn create_item(&self, item: &NewItem) -> Result<String> {
        let vault = self.get_vault(&item.vault_id)?;
        let (item_key, key_encrypted) = match nonempty(vault.master_key_encrypted.as_deref()) {
            Some(enc) => {
                let vault_password = self.vault_password_from(&vault.id, Some(enc))?;
                let item_key = pwk_crypto::generate_key();
                let key_encrypted = pwk_crypto::encrypt(&item_key, &vault_password);
                (item_key, Some(key_encrypted))
            }
            None => (SecretString::default(), None),
        };
        let mut body = object();
        body.insert("vaultId".into(), json!(item.vault_id));
        body.insert("folderId".into(), json!(item.folder_id));
        body.insert("name".into(), json!(item.name));
        if let Some(login) = &item.login {
            body.insert("login".into(), json!(login));
        }
        if let Some(url) = &item.url {
            body.insert("url".into(), json!(url));
        }
        if !item.urls.is_empty() {
            body.insert("urls".into(), json!(item.urls));
        }
        if let Some(d) = &item.description {
            body.insert("description".into(), json!(d));
        }
        if !item.tags.is_empty() {
            body.insert("tags".into(), json!(item.tags));
        }
        if let Some(c) = item.color {
            body.insert("color".into(), json!(c));
        }
        if let Some(f) = item.is_favorite {
            body.insert("isFavorite".into(), json!(f));
        }
        if let Some(p) = &item.password {
            body.insert(
                "passwordEncrypted".into(),
                json!(pwk_crypto::encrypt(p, &item_key)),
            );
        }
        if let Some(k) = key_encrypted {
            body.insert("keyEncrypted".into(), json!(k));
        }
        if !item.customs.is_empty() {
            body.insert("customs".into(), encrypt_customs(&item.customs, &item_key));
        }
        if !item.attachments.is_empty() {
            let atts = item
                .attachments
                .iter()
                .map(|a: &NewAttachment| encrypt_attachment(&a.name, &a.data, &item_key))
                .collect::<Result<Vec<_>>>()?;
            body.insert("attachments".into(), Value::Array(atts));
        }
        let v = self.post(endpoints::ITEMS, &Value::Object(body))?;
        id_from(&v, endpoints::ITEMS)
    }

    /// Updates an item (`PATCH /items/{id}`): reuses the item's key and sends its
    /// `keyEncrypted` and `vaultId` again. Clearing the password sends an encrypted
    /// empty string **(unverified that the server treats it as "no password")**.
    ///
    /// An item without `keyEncrypted` in an encrypting vault gets a new item key when the
    /// update sets the password or custom fields; the stored password and custom fields
    /// are then re-encrypted with it and sent too (see `rekey_item`).
    pub fn update_item(&self, id: &str, update: &ItemUpdate) -> Result<()> {
        let path = endpoints::item(id)?;
        let raw = Self::parse_raw_item(self.get(&path, &Query::default())?, &path)?;
        let mut body = object();
        body.insert("vaultId".into(), json!(raw.vault_id));
        {
            let mut put = |k: &str, v: Value| {
                body.insert(k.into(), v);
            };
            if let Some(v) = &update.name {
                put("name", json!(v));
            }
            if let Some(v) = &update.login {
                put("login", json!(v));
            }
            if let Some(v) = &update.url {
                put("url", json!(v));
            }
            if let Some(v) = &update.urls {
                put("urls", json!(v));
            }
            if let Some(v) = &update.description {
                put("description", json!(v));
            }
            if let Some(v) = &update.tags {
                put("tags", json!(v));
            }
            if let Some(v) = update.color {
                put("color", json!(v));
            }
            if let Some(v) = update.is_favorite {
                put("isFavorite", json!(v));
            }
        }
        if update.password.is_none() && update.customs.is_none() {
            // No encrypted field is sent; the key material stays as it is.
            if let Some(k) = nonempty(raw.key_encrypted.as_deref()) {
                body.insert("keyEncrypted".into(), json!(k));
            }
            return self.patch(&path, &Value::Object(body)).map(drop);
        }
        let key = match self.write_key(
            &raw.vault_id,
            raw.vault_master_key_encrypted.as_deref(),
            raw.key_encrypted.as_deref(),
        )? {
            WriteKey::Existing(key) => {
                if let Some(k) = nonempty(raw.key_encrypted.as_deref()) {
                    body.insert("keyEncrypted".into(), json!(k));
                }
                key
            }
            WriteKey::Plain => SecretString::default(),
            WriteKey::NeedsNewKey(vault_password) => {
                Self::rekey_item(
                    raw,
                    &vault_password,
                    update.password.as_ref().map(Option::as_ref),
                    update.customs.as_deref(),
                    &mut body,
                )?;
                return self.patch(&path, &Value::Object(body)).map(drop);
            }
        };
        if let Some(p) = &update.password {
            let plain = p.as_deref().map_or("", |s| s.as_str());
            body.insert(
                "passwordEncrypted".into(),
                json!(pwk_crypto::encrypt(plain, &key)),
            );
        }
        if let Some(customs) = &update.customs {
            body.insert("customs".into(), encrypt_customs(customs, &key));
        }
        self.patch(&path, &Value::Object(body)).map(drop)
    }

    /// Moves an item (`POST /items/{id}/move` `{vaultId, folderId}`, **body
    /// unverified**). When moving an encrypted item to another vault, `keyEncrypted`
    /// re-encrypted for the target vault is sent too **(unverified)**.
    pub fn move_item(&self, id: &str, vault_id: &str, folder_id: Option<&str>) -> Result<()> {
        let path = endpoints::item(id)?;
        let raw = Self::parse_raw_item(self.get(&path, &Query::default())?, &path)?;
        let mut body = object();
        body.insert("vaultId".into(), json!(vault_id));
        body.insert("folderId".into(), json!(folder_id));
        if raw.vault_id != vault_id && nonempty(raw.key_encrypted.as_deref()).is_some() {
            let key = self.item_key_from(
                &raw.vault_id,
                raw.vault_master_key_encrypted.as_deref(),
                raw.key_encrypted.as_deref(),
            )?;
            let target = self.vault_password(vault_id)?;
            if target.is_empty() {
                return Err(Error::Invalid(
                    "the target vault does not use key encryption".into(),
                ));
            }
            body.insert(
                "keyEncrypted".into(),
                json!(pwk_crypto::encrypt(&key, &target)),
            );
        }
        self.post(&endpoints::item_move(id)?, &Value::Object(body))
            .map(drop)
    }

    /// `DELETE /items/{id}` (moves the item to the bin).
    pub fn delete_item(&self, id: &str) -> Result<()> {
        self.delete(&endpoints::item(id)?).map(drop)
    }

    // ----------------------------------------------------------------------------------
    // Attachments
    // ----------------------------------------------------------------------------------

    /// Downloads and decrypts an attachment; returns its file name and content. The
    /// checksum is verified.
    pub fn download_attachment(
        &self,
        item: &Item,
        attachment_id: &str,
    ) -> Result<(String, Zeroizing<Vec<u8>>)> {
        let path = endpoints::item_attachment(&item.id, attachment_id)?;
        let v = self.get(&path, &Query::default())?;
        let field = |name: &str| -> Result<String> {
            v.get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| Error::Response {
                    path: path.clone(),
                    detail: format!("missing {name}"),
                })
        };
        let name = v
            .get("name")
            .and_then(Value::as_str)
            .map_or_else(|| attachment_id.to_owned(), str::to_owned);
        let encrypted_data = field("encryptedData")?;
        let hash = field("hash")?;
        let item_key = self.item_key(item)?;
        let att_key = if item_key.is_empty() {
            SecretString::default()
        } else {
            pwk_crypto::decrypt(&field("encryptedKey")?, &item_key)?
        };
        let encoded = pwk_crypto::decrypt_bytes(&encrypted_data, &att_key)?;
        let trimmed: Vec<u8> = encoded
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        let trimmed = Zeroizing::new(trimmed);
        let data =
            Zeroizing::new(
                b64()
                    .decode(trimmed.as_slice())
                    .map_err(|_| Error::Response {
                        path: path.clone(),
                        detail: "attachment data is not valid Base64".into(),
                    })?,
            );
        if !pwk_crypto::attachment_hash(&data).eq_ignore_ascii_case(hash.trim()) {
            return Err(Error::Response {
                path,
                detail: "attachment checksum mismatch".into(),
            });
        }
        Ok((name, data))
    }

    /// Adds an attachment (at most 5 MiB) to an item via `PATCH /items/{id}` with the new
    /// attachment in `attachments`. **(unverified)** whether existing attachments are
    /// kept when only the new one is sent.
    ///
    /// An item without `keyEncrypted` in an encrypting vault first gets a new item key
    /// (its stored password and custom fields are re-encrypted with it and sent along);
    /// if it already has attachments it is inconsistent and refused with
    /// [`Error::Invalid`].
    pub fn add_attachment(&self, item: &Item, name: &str, data: &[u8]) -> Result<()> {
        if data.len() > MAX_ATTACHMENT_SIZE {
            return Err(Error::Invalid(format!(
                "attachment {name:?} is larger than 5 MiB"
            )));
        }
        let path = endpoints::item(&item.id)?;
        let mut body = object();
        body.insert("vaultId".into(), json!(item.vault_id));
        let key = match self.write_key(
            &item.vault_id,
            item.vault_master_key_encrypted.as_deref(),
            item.key_encrypted.as_deref(),
        )? {
            WriteKey::Existing(key) => {
                if let Some(k) = nonempty(item.key_encrypted.as_deref()) {
                    body.insert("keyEncrypted".into(), json!(k));
                }
                key
            }
            WriteKey::Plain => SecretString::default(),
            WriteKey::NeedsNewKey(vault_password) => {
                if !item.attachments.is_empty() {
                    return Err(inconsistent_attachments(&item.id));
                }
                // Re-read the stored item: the caller's copy may be stale or partial,
                // and every encrypted field must be re-sent under the new key.
                let raw = Self::parse_raw_item(self.get(&path, &Query::default())?, &path)?;
                if nonempty(raw.key_encrypted.as_deref()).is_some() {
                    return Err(Error::Invalid(format!(
                        "item {} changed on the server; fetch it again and retry",
                        item.id
                    )));
                }
                Self::rekey_item(raw, &vault_password, None, None, &mut body)?
            }
        };
        let entry = encrypt_attachment(name, data, &key)?;
        body.insert("attachments".into(), json!([entry]));
        self.patch(&path, &Value::Object(body)).map(drop)
    }

    // ----------------------------------------------------------------------------------
    // Shortcuts
    // ----------------------------------------------------------------------------------

    /// `GET /shortcuts/search` with the filter. Rows are `{"shortcut": {…}, …}`; a bare
    /// shortcut object is accepted too.
    pub fn search_shortcuts(&self, filter: &ItemFilter) -> Result<Vec<ShortcutSummary>> {
        let path = endpoints::SHORTCUTS_SEARCH;
        let v = self.get(path, &filter_query(filter))?;
        list_values(v, path)?
            .into_iter()
            .map(|row| {
                let mut row = match strip_hidden(row) {
                    Value::Object(o) => o,
                    _ => {
                        return Err(Error::Response {
                            path: path.into(),
                            detail: "shortcut row is not an object".into(),
                        });
                    }
                };
                match row.remove("shortcut") {
                    Some(s) => Ok(ShortcutSummary {
                        shortcut: from_value(s, path)?,
                        extra: row,
                    }),
                    None => Ok(ShortcutSummary {
                        shortcut: from_value(Value::Object(row), path)?,
                        extra: Map::new(),
                    }),
                }
            })
            .collect()
    }

    /// `GET /shortcuts/{id}` plus its item via `GET /items/{itemId}`. If the item request
    /// is refused (403/404) and the shortcut response embeds the item (`item` or
    /// `password`), that copy is decrypted with the item key from the shortcut
    /// **(unverified fallback)**.
    pub fn get_shortcut(&self, id: &str) -> Result<ShortcutWithItem> {
        let path = endpoints::shortcut(id)?;
        let mut v = self.get(&path, &Query::default())?;
        let embedded = v
            .as_object_mut()
            .and_then(|o| o.remove("item").or_else(|| o.remove("password")))
            .filter(Value::is_object);
        let shortcut: Shortcut = from_value(v, &path)?;
        let item = match self.get_item(&shortcut.item_id) {
            Ok(item) => item,
            Err(Error::Api { status, .. })
                if (status == 403 || status == 404) && embedded.is_some() =>
            {
                let raw = Self::parse_raw_item(embedded.unwrap_or_default(), &path)?;
                let key = match nonempty(shortcut.key_encrypted.as_deref()) {
                    Some(k) => {
                        self.user_keys()?;
                        let vault_password = self.vault_password(&shortcut.vault_id)?;
                        pwk_crypto::decrypt(k, &vault_password)?
                    }
                    None => SecretString::default(),
                };
                Self::decode_item_with_key(raw, &key)?
            }
            Err(e) => return Err(e),
        };
        Ok(ShortcutWithItem { shortcut, item })
    }

    /// Creates a shortcut of `item` in `vault_id`/`folder_id`; returns its ID.
    pub fn create_shortcut(
        &self,
        item: &Item,
        vault_id: &str,
        folder_id: Option<&str>,
    ) -> Result<String> {
        let item_key = self.item_key(item)?;
        let key_encrypted = if item_key.is_empty() {
            None
        } else {
            let target = self.vault_password(vault_id)?;
            if target.is_empty() {
                return Err(Error::Invalid(
                    "the target vault does not use key encryption".into(),
                ));
            }
            Some(pwk_crypto::encrypt(&item_key, &target))
        };
        let body = json!({
            "vaultId": vault_id,
            "folderId": folder_id,
            "itemId": item.id,
            "keyEncrypted": key_encrypted,
        });
        let v = self.post(endpoints::SHORTCUTS, &body)?;
        id_from(&v, endpoints::SHORTCUTS)
    }

    /// `DELETE /shortcuts/{id}`.
    pub fn delete_shortcut(&self, id: &str) -> Result<()> {
        self.delete(&endpoints::shortcut(id)?).map(drop)
    }
}

impl AttachmentRef {
    /// Finds an attachment of `item` by ID or file name (exact, then case-insensitive).
    #[must_use]
    pub fn find<'a>(item: &'a Item, id_or_name: &str) -> Option<&'a AttachmentRef> {
        let lower = id_or_name.to_lowercase();
        item.attachments
            .iter()
            .find(|a| a.id == id_or_name)
            .or_else(|| item.attachments.iter().find(|a| a.name == id_or_name))
            .or_else(|| {
                item.attachments
                    .iter()
                    .find(|a| a.name.to_lowercase() == lower)
            })
    }
}
