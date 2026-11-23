//! Typed views of Passwork objects. Unknown fields are kept in `extra` so JSON output can
//! show everything the server sent (minus key material).

use serde::ser::SerializeMap as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::SecretString;

/// `null` (or a missing field, with `#[serde(default)]`) becomes `T::default()`.
fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Option::unwrap_or_default)
}

/// A list of strings; `null` is empty, non-string entries are skipped.
fn lenient_strings<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    let v = Option::<Vec<Value>>::deserialize(d)?.unwrap_or_default();
    Ok(v.into_iter()
        .filter_map(|e| match e {
            Value::String(s) => Some(s),
            Value::Object(o) => o.get("url").and_then(Value::as_str).map(str::to_owned),
            _ => None,
        })
        .collect())
}

/// An ID that might come as a number.
fn lenient_id<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    match Value::deserialize(d)? {
        Value::String(s) => Ok(s),
        Value::Number(n) => Ok(n.to_string()),
        Value::Null => Ok(String::new()),
        other => Err(serde::de::Error::custom(format!(
            "expected an id, got {other}"
        ))),
    }
}

/// Redacts a secret in `Debug` output.
fn redacted<T>(v: &Option<T>) -> Option<&'static str> {
    v.as_ref().map(|_| "<redacted>")
}

/// A vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vault {
    /// ID.
    #[serde(deserialize_with = "lenient_id")]
    pub id: String,
    /// Name.
    #[serde(default, deserialize_with = "null_default")]
    pub name: String,
    /// Vault password RSA-encrypted for the current user; empty/`None` without key
    /// encryption. Not serialized.
    #[serde(default, skip_serializing)]
    pub master_key_encrypted: Option<String>,
    /// Vault type ID.
    #[serde(default)]
    pub type_id: Option<String>,
    /// All other fields.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A folder.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    /// ID.
    #[serde(deserialize_with = "lenient_id")]
    pub id: String,
    /// Name.
    #[serde(default, deserialize_with = "null_default")]
    pub name: String,
    /// Vault ID.
    #[serde(default, deserialize_with = "null_default")]
    pub vault_id: String,
    /// Parent folder ID; `None` at the vault root.
    #[serde(default)]
    pub parent_id: Option<String>,
    /// All other fields.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A row of an item search or list (no secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    /// ID.
    #[serde(deserialize_with = "lenient_id")]
    pub id: String,
    /// Name.
    #[serde(default, deserialize_with = "null_default")]
    pub name: String,
    /// Login.
    #[serde(default)]
    pub login: Option<String>,
    /// Main URL.
    #[serde(default)]
    pub url: Option<String>,
    /// Vault ID.
    #[serde(default, deserialize_with = "null_default")]
    pub vault_id: String,
    /// Folder ID; `None` at the vault root.
    #[serde(default)]
    pub folder_id: Option<String>,
    /// Tags.
    #[serde(default, deserialize_with = "lenient_strings")]
    pub tags: Vec<String>,
    /// Color code.
    #[serde(default)]
    pub color: Option<i64>,
    /// All other fields (encrypted fields and key material are removed).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Type of a custom field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CustomKind {
    /// `text`.
    Text,
    /// `password` (hidden in table output).
    Password,
    /// `totp` (Base32 secret or `otpauth://` URI).
    Totp,
    /// Anything else, as sent by the server.
    Other(String),
}

impl CustomKind {
    /// The wire name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Text => "text",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Other(s) => s,
        }
    }

    /// Parses a wire name (case-insensitive for the known kinds).
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "text" | "" => Self::Text,
            "password" => Self::Password,
            "totp" => Self::Totp,
            _ => Self::Other(s.to_owned()),
        }
    }

    /// Whether values of this kind are secret (password or TOTP).
    #[must_use]
    pub fn is_secret(&self) -> bool {
        matches!(self, Self::Password | Self::Totp)
    }
}

impl std::fmt::Display for CustomKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for CustomKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CustomKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::parse(&String::deserialize(d)?))
    }
}

/// A decrypted custom field. `Debug` hides the value.
#[derive(Clone, Serialize)]
pub struct CustomField {
    /// Field name.
    pub name: String,
    /// Field value.
    #[serde(serialize_with = "ser_secret")]
    pub value: SecretString,
    /// Field type.
    #[serde(rename = "type")]
    pub kind: CustomKind,
    /// Other keys of the custom entry, sent back unchanged.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl CustomField {
    /// A new field without extra keys.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>, kind: CustomKind) -> Self {
        Self {
            name: name.into(),
            value: Zeroizing::new(value.into()),
            kind,
            extra: Map::new(),
        }
    }
}

impl std::fmt::Debug for CustomField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomField")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

fn ser_secret<S: Serializer>(v: &SecretString, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v)
}

/// An attachment as listed in an item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentRef {
    /// Attachment ID.
    #[serde(default, deserialize_with = "lenient_id")]
    pub id: String,
    /// File name.
    #[serde(default, deserialize_with = "null_default")]
    pub name: String,
}

/// A decrypted item. `Serialize` writes the decrypted values (camelCase, like the server)
/// plus all unknown fields, but no key material; `Debug` hides secrets.
///
/// `Default` is an empty, unencrypted item (useful for tests and local previews).
#[derive(Clone, Default)]
pub struct Item {
    /// ID.
    pub id: String,
    /// Name.
    pub name: String,
    /// Login.
    pub login: Option<String>,
    /// Main URL.
    pub url: Option<String>,
    /// Additional URLs.
    pub urls: Vec<String>,
    /// Description / notes.
    pub description: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Color code.
    pub color: Option<i64>,
    /// Favorite flag.
    pub is_favorite: bool,
    /// Vault ID.
    pub vault_id: String,
    /// Folder ID; `None` at the vault root.
    pub folder_id: Option<String>,
    /// Decrypted password; `None` if the item has none.
    pub password: Option<SecretString>,
    /// Decrypted custom fields.
    pub customs: Vec<CustomField>,
    /// Attachments (decrypt with [`crate::Client::download_attachment`]).
    pub attachments: Vec<AttachmentRef>,
    /// All other fields the server sent (without encrypted values and key material).
    pub extra: Map<String, Value>,
    /// `keyEncrypted`: item key encrypted with the vault password.
    pub(crate) key_encrypted: Option<String>,
    /// `vaultMasterKeyEncrypted`: vault password RSA-encrypted for the user.
    pub(crate) vault_master_key_encrypted: Option<String>,
}

impl Item {
    /// Custom field by name: exact match first, then case-insensitive.
    #[must_use]
    pub fn custom(&self, name: &str) -> Option<&CustomField> {
        let lower = name.to_lowercase();
        self.customs
            .iter()
            .find(|c| c.name == name)
            .or_else(|| self.customs.iter().find(|c| c.name.to_lowercase() == lower))
    }

    /// Whether the item's fields are encrypted with an item key (client-side encryption).
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.key_encrypted.as_deref().is_some_and(|k| !k.is_empty())
    }
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("login", &self.login)
            .field("url", &self.url)
            .field("vault_id", &self.vault_id)
            .field("folder_id", &self.folder_id)
            .field("password", &redacted(&self.password))
            .field("customs", &self.customs)
            .field("attachments", &self.attachments)
            .finish_non_exhaustive()
    }
}

impl Serialize for Item {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("id", &self.id)?;
        m.serialize_entry("name", &self.name)?;
        m.serialize_entry("login", &self.login)?;
        m.serialize_entry("password", &self.password.as_deref())?;
        m.serialize_entry("url", &self.url)?;
        m.serialize_entry("urls", &self.urls)?;
        m.serialize_entry("description", &self.description)?;
        m.serialize_entry("tags", &self.tags)?;
        m.serialize_entry("color", &self.color)?;
        m.serialize_entry("isFavorite", &self.is_favorite)?;
        m.serialize_entry("vaultId", &self.vault_id)?;
        m.serialize_entry("folderId", &self.folder_id)?;
        m.serialize_entry("customs", &self.customs)?;
        m.serialize_entry("attachments", &self.attachments)?;
        for (k, v) in &self.extra {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

/// Wire form of an item before decryption.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawItem {
    #[serde(deserialize_with = "lenient_id")]
    pub(crate) id: String,
    #[serde(default, deserialize_with = "null_default")]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) login: Option<String>,
    #[serde(default)]
    pub(crate) url: Option<String>,
    #[serde(default, deserialize_with = "lenient_strings")]
    pub(crate) urls: Vec<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default, deserialize_with = "lenient_strings")]
    pub(crate) tags: Vec<String>,
    #[serde(default)]
    pub(crate) color: Option<i64>,
    #[serde(default, deserialize_with = "null_default")]
    pub(crate) is_favorite: bool,
    #[serde(default, deserialize_with = "null_default")]
    pub(crate) vault_id: String,
    #[serde(default)]
    pub(crate) folder_id: Option<String>,
    #[serde(default)]
    pub(crate) password_encrypted: Option<String>,
    #[serde(default)]
    pub(crate) key_encrypted: Option<String>,
    #[serde(default)]
    pub(crate) vault_master_key_encrypted: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub(crate) customs: Vec<Map<String, Value>>,
    #[serde(default, deserialize_with = "null_default")]
    pub(crate) attachments: Vec<AttachmentRef>,
    #[serde(flatten)]
    pub(crate) extra: Map<String, Value>,
}

/// A shortcut (link of an item into another vault/folder).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Shortcut {
    /// Shortcut ID.
    #[serde(deserialize_with = "lenient_id")]
    pub id: String,
    /// ID of the item it points to.
    #[serde(default, deserialize_with = "null_default")]
    pub item_id: String,
    /// Vault the shortcut lives in.
    #[serde(default, deserialize_with = "null_default")]
    pub vault_id: String,
    /// Folder the shortcut lives in.
    #[serde(default)]
    pub folder_id: Option<String>,
    /// Item key encrypted with the shortcut vault's password. Not serialized.
    #[serde(default, skip_serializing)]
    pub(crate) key_encrypted: Option<String>,
    /// All other fields.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A shortcut search row: `{"shortcut": {…}, …}`.
#[derive(Debug, Clone, Serialize)]
pub struct ShortcutSummary {
    /// The shortcut.
    pub shortcut: Shortcut,
    /// Other fields of the row (typically item data, without key material).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A shortcut with its decrypted item.
#[derive(Debug, Clone, Serialize)]
pub struct ShortcutWithItem {
    /// The shortcut.
    pub shortcut: Shortcut,
    /// The item it points to.
    pub item: Item,
}

/// A vault type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultType {
    /// ID.
    #[serde(deserialize_with = "lenient_id")]
    pub id: String,
    /// Code (stable identifier).
    #[serde(default)]
    pub code: Option<String>,
    /// Display name.
    #[serde(default, deserialize_with = "null_default")]
    pub name: String,
    /// All other fields.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An enabled application feature (`GET /app/features`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feature {
    /// Feature name, e.g. `vaultType`.
    #[serde(default, deserialize_with = "null_default")]
    pub name: String,
    /// All other fields.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `GET /sessions/current/info`, kept as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionInfo(pub Value);

impl SessionInfo {
    fn user_field(&self, key: &str) -> Option<&str> {
        self.0
            .get("user")
            .and_then(|u| u.get(key))
            .or_else(|| self.0.get(key))
            .and_then(Value::as_str)
    }

    /// The user's display name, if present (`user.name` or `name`).
    #[must_use]
    pub fn user_name(&self) -> Option<&str> {
        self.user_field("name")
    }

    /// The user's login, if present (`user.login` or `login`).
    #[must_use]
    pub fn user_login(&self) -> Option<&str> {
        self.user_field("login")
    }
}

/// Filters of an item or shortcut search. Empty lists are not sent.
#[derive(Debug, Clone, Default)]
pub struct ItemFilter {
    /// Search text.
    pub query: Option<String>,
    /// Tags (`tags[]`).
    pub tags: Vec<String>,
    /// Color codes (`colorCodes[]`).
    pub colors: Vec<i64>,
    /// Vault IDs (`vaultIds[]`).
    pub vault_ids: Vec<String>,
    /// Folder IDs (`folderIds[]`).
    pub folder_ids: Vec<String>,
}

/// A file to attach.
#[derive(Clone)]
pub struct NewAttachment {
    /// File name.
    pub name: String,
    /// Content (at most 5 MiB).
    pub data: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for NewAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewAttachment")
            .field("name", &self.name)
            .field("len", &self.data.len())
            .finish()
    }
}

/// A new item for [`crate::Client::create_item`].
#[derive(Clone, Default)]
pub struct NewItem {
    /// Target vault.
    pub vault_id: String,
    /// Target folder; `None` for the vault root.
    pub folder_id: Option<String>,
    /// Name.
    pub name: String,
    /// Login.
    pub login: Option<String>,
    /// Password.
    pub password: Option<SecretString>,
    /// Main URL.
    pub url: Option<String>,
    /// Additional URLs.
    pub urls: Vec<String>,
    /// Description.
    pub description: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Color code.
    pub color: Option<i64>,
    /// Favorite flag.
    pub is_favorite: Option<bool>,
    /// Custom fields.
    pub customs: Vec<CustomField>,
    /// Attachments.
    pub attachments: Vec<NewAttachment>,
}

impl std::fmt::Debug for NewItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewItem")
            .field("vault_id", &self.vault_id)
            .field("folder_id", &self.folder_id)
            .field("name", &self.name)
            .field("login", &self.login)
            .field("password", &redacted(&self.password))
            .field("customs", &self.customs)
            .field("attachments", &self.attachments)
            .finish_non_exhaustive()
    }
}

/// Changes for [`crate::Client::update_item`]; `None` leaves a field unchanged.
#[derive(Clone, Default)]
pub struct ItemUpdate {
    /// New name.
    pub name: Option<String>,
    /// New login.
    pub login: Option<String>,
    /// `Some(Some(p))` sets, `Some(None)` clears the password.
    pub password: Option<Option<SecretString>>,
    /// New main URL.
    pub url: Option<String>,
    /// New additional URLs.
    pub urls: Option<Vec<String>>,
    /// New description.
    pub description: Option<String>,
    /// New tags.
    pub tags: Option<Vec<String>>,
    /// New color code.
    pub color: Option<i64>,
    /// New favorite flag.
    pub is_favorite: Option<bool>,
    /// Replaces the whole list of custom fields.
    pub customs: Option<Vec<CustomField>>,
}

impl std::fmt::Debug for ItemUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ItemUpdate")
            .field("name", &self.name)
            .field("login", &self.login)
            .field(
                "password",
                &self
                    .password
                    .as_ref()
                    .map(|p| if p.is_some() { "<redacted>" } else { "<clear>" }),
            )
            .field("customs", &self.customs)
            .finish_non_exhaustive()
    }
}

/// One request of a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchRequest {
    /// HTTP method, e.g. `GET`.
    pub method: String,
    /// Full path including `/api/v1`.
    pub relative_url: String,
}

impl BatchRequest {
    /// A `GET` of `path` (normalised to include `/api/v1`).
    #[must_use]
    pub fn get(path: &str) -> Self {
        Self {
            method: "GET".into(),
            relative_url: crate::endpoints::normalize(path),
        }
    }
}

/// One response of a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchResponse {
    /// HTTP status (0 if missing).
    pub status_code: u16,
    /// Response body (envelope unwrapped).
    pub body: Value,
}

impl BatchResponse {
    /// Whether the status is 2xx.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_item_is_plain() {
        let item = Item {
            name: "x".into(),
            ..Item::default()
        };
        assert!(!item.is_encrypted());
        assert!(item.custom("any").is_none());
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["name"], "x");
        assert_eq!(json["password"], serde_json::Value::Null);
    }
}
