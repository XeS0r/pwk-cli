//! Vaults, folders, vault types, features and session info.

use serde_json::{Value, json};

use crate::client::{KeyState, Query, from_value, id_from, list_values, object};
use crate::models::{Feature, Folder, SessionInfo, Vault, VaultType};
use crate::{Client, Error, Result, SecretString, endpoints};

/// Name of the feature that makes vault types mandatory.
const FEATURE_VAULT_TYPE: &str = "vaultType";

fn nonempty(s: Option<&str>) -> Option<&str> {
    s.filter(|s| !s.is_empty())
}

fn looks_like_id(s: &str) -> bool {
    s.len() == 24 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Client {
    // ----------------------------------------------------------------------------------
    // Vaults
    // ----------------------------------------------------------------------------------

    /// `GET /vaults`.
    pub fn list_vaults(&self) -> Result<Vec<Vault>> {
        let v = self.get(endpoints::VAULTS, &Query::default())?;
        list_values(v, endpoints::VAULTS)?
            .into_iter()
            .map(|e| from_value(e, endpoints::VAULTS))
            .collect()
    }

    /// `GET /vaults/{id}`.
    pub fn get_vault(&self, id: &str) -> Result<Vault> {
        let path = endpoints::vault(id)?;
        let v = self.get(&path, &Query::default())?;
        from_value(v, &path)
    }

    /// The decrypted password of a vault (empty if the vault has no key encryption).
    /// Cached per client.
    pub(crate) fn vault_password(&self, vault_id: &str) -> Result<SecretString> {
        if let Some(pw) = self.cached_vault_password(vault_id) {
            return Ok(pw);
        }
        let vault = self.get_vault(vault_id)?;
        match nonempty(vault.master_key_encrypted.as_deref()) {
            Some(enc) => self.vault_password_from(vault_id, Some(enc)),
            None => Ok(SecretString::default()),
        }
    }

    /// Decrypts a vault password RSA ciphertext (cached by vault ID). Without a
    /// ciphertext the vault is fetched.
    pub(crate) fn vault_password_from(
        &self,
        vault_id: &str,
        master_key_encrypted: Option<&str>,
    ) -> Result<SecretString> {
        if let Some(pw) = self.cached_vault_password(vault_id) {
            return Ok(pw);
        }
        let Some(enc) = nonempty(master_key_encrypted) else {
            return self.vault_password(vault_id);
        };
        let keys = self.user_keys()?;
        let bytes = keys.private_key.decrypt(enc)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| pwk_crypto::Error::Malformed("vault password is not UTF-8"))?;
        let pw = SecretString::new(text.to_owned());
        self.cache_vault_password(vault_id, &pw);
        Ok(pw)
    }

    /// Creates a vault and returns its ID.
    ///
    /// `vault_type` is a vault type ID, code or name. It is required when the server has
    /// the `vaultType` feature. With client-side encryption a vault password is
    /// generated and encrypted for the user and the type's administrators; this needs
    /// [`Client::set_master_key`] or [`Client::set_no_encryption`] first.
    pub fn create_vault(&self, name: &str, vault_type: Option<&str>) -> Result<String> {
        let keys = match self.key_state() {
            KeyState::Unlocked(keys) => Some(keys),
            KeyState::Plain => None,
            KeyState::Unknown => return Err(Error::Locked),
        };
        let type_required = self
            .features()?
            .iter()
            .any(|f| f.name == FEATURE_VAULT_TYPE);
        let type_id = match vault_type {
            Some(t) if looks_like_id(t) => Some(t.to_owned()),
            Some(t) => Some(self.find_vault_type(t)?.id),
            None if type_required => {
                let codes: Vec<String> = self
                    .vault_types()
                    .map(|types| {
                        types
                            .into_iter()
                            .map(|t| t.code.unwrap_or(t.name))
                            .collect()
                    })
                    .unwrap_or_default();
                return Err(Error::Invalid(format!(
                    "this server requires a vault type (one of: {})",
                    codes.join(", ")
                )));
            }
            None => None,
        };

        let mut body = object();
        body.insert("name".into(), json!(name));
        let mut vault_password = SecretString::default();
        if let Some(keys) = &keys {
            vault_password = pwk_crypto::generate_key();
            let salt = pwk_crypto::generate_salt();
            let public = pwk_crypto::PublicKey::from_pem(&keys.public_key_pem)?;
            let encrypted = public.encrypt(vault_password.as_bytes())?;
            let mut hash_input =
                SecretString::new(String::with_capacity(vault_password.len() + salt.len()));
            hash_input.push_str(&vault_password);
            hash_input.push_str(&salt);
            body.insert("masterKeyEncrypted".into(), json!(encrypted));
            body.insert(
                "masterKeyHash".into(),
                json!(pwk_crypto::sha256_hex(hash_input.as_bytes())),
            );
            body.insert("salt".into(), json!(salt));
        }
        if let Some(type_id) = type_id {
            let mut admin_keys = object();
            if keys.is_some() {
                let path = endpoints::vault_type_administrators(&type_id)?;
                let admins = list_values(self.get(&path, &Query::default())?, &path)?;
                for admin in admins {
                    let id = admin.get("id").and_then(Value::as_str);
                    let pem = admin.get("publicKey").and_then(Value::as_str);
                    let (Some(id), Some(pem)) = (id, pem) else {
                        return Err(Error::Response {
                            path,
                            detail: "administrator without id or publicKey".into(),
                        });
                    };
                    let key = pwk_crypto::PublicKey::from_pem(pem)?;
                    admin_keys.insert(
                        id.to_owned(),
                        json!(key.encrypt(vault_password.as_bytes())?),
                    );
                }
            }
            body.insert("typeId".into(), json!(type_id));
            body.insert("administratorsKeys".into(), Value::Object(admin_keys));
        }
        let v = self.post(endpoints::VAULTS, &Value::Object(body))?;
        let id = id_from(&v, endpoints::VAULTS)?;
        if !vault_password.is_empty() {
            self.cache_vault_password(&id, &vault_password);
        }
        Ok(id)
    }

    /// `DELETE /vaults/{id}`.
    pub fn delete_vault(&self, id: &str) -> Result<()> {
        self.delete(&endpoints::vault(id)?).map(drop)
    }

    // ----------------------------------------------------------------------------------
    // Folders
    // ----------------------------------------------------------------------------------

    /// `GET /folders` with optional `vaultId` / `parentId` filters **(filters
    /// unverified)**.
    pub fn list_folders(
        &self,
        vault_id: Option<&str>,
        parent_id: Option<&str>,
    ) -> Result<Vec<Folder>> {
        let mut q = Query::default();
        q.push_opt("vaultId", vault_id);
        q.push_opt("parentId", parent_id);
        let v = self.get(endpoints::FOLDERS, &q)?;
        list_values(v, endpoints::FOLDERS)?
            .into_iter()
            .map(|e| from_value(e, endpoints::FOLDERS))
            .collect()
    }

    /// `GET /folders/{id}`.
    pub fn get_folder(&self, id: &str) -> Result<Folder> {
        let path = endpoints::folder(id)?;
        from_value(self.get(&path, &Query::default())?, &path)
    }

    /// `POST /folders` `{vaultId, parentId, name}` **(body unverified)**; returns the ID.
    pub fn create_folder(
        &self,
        vault_id: &str,
        parent_id: Option<&str>,
        name: &str,
    ) -> Result<String> {
        let body = json!({ "vaultId": vault_id, "parentId": parent_id, "name": name });
        let v = self.post(endpoints::FOLDERS, &body)?;
        id_from(&v, endpoints::FOLDERS)
    }

    /// `POST /folders/{id}` `{name}`.
    pub fn rename_folder(&self, id: &str, name: &str) -> Result<()> {
        self.post(&endpoints::folder(id)?, &json!({ "name": name }))
            .map(drop)
    }

    /// `POST /folders/{id}/move` `{vaultId, parentId}` **(body unverified)**.
    /// `parent_id = None` moves to the vault root.
    ///
    /// A move to another vault is [`Error::Invalid`] when either vault uses client-side
    /// encryption (`masterKeyEncrypted`): the items' `keyEncrypted` would have to be
    /// re-encrypted for the target vault, which this request cannot carry (whether the
    /// server re-keys is unverified). Such items are moved one by one with
    /// [`Client::move_item`].
    pub fn move_folder(&self, id: &str, vault_id: &str, parent_id: Option<&str>) -> Result<()> {
        let folder = self.get_folder(id)?;
        if folder.vault_id != vault_id {
            let encrypts = |v: &str| -> Result<bool> {
                Ok(nonempty(self.get_vault(v)?.master_key_encrypted.as_deref()).is_some())
            };
            if encrypts(&folder.vault_id)? || encrypts(vault_id)? {
                return Err(Error::Invalid(
                    "moving a folder to another vault is not supported with client-side \
                     encryption: move its items with `pwk item move`"
                        .into(),
                ));
            }
        }
        let body = json!({ "vaultId": vault_id, "parentId": parent_id });
        self.post(&endpoints::folder_move(id)?, &body).map(drop)
    }

    /// `DELETE /folders/{id}`.
    pub fn delete_folder(&self, id: &str) -> Result<()> {
        self.delete(&endpoints::folder(id)?).map(drop)
    }

    // ----------------------------------------------------------------------------------
    // Misc
    // ----------------------------------------------------------------------------------

    /// `GET /app/features` (cached per client).
    pub fn features(&self) -> Result<Vec<Feature>> {
        if let Some(f) = self.cached_features() {
            return Ok(f);
        }
        let v = self.get(endpoints::APP_FEATURES, &Query::default())?;
        let features = list_values(v, endpoints::APP_FEATURES)?
            .into_iter()
            .map(|e| from_value(e, endpoints::APP_FEATURES))
            .collect::<Result<Vec<Feature>>>()?;
        self.cache_features(&features);
        Ok(features)
    }

    /// `GET /vault-types/all`.
    pub fn vault_types(&self) -> Result<Vec<VaultType>> {
        let v = self.get(endpoints::VAULT_TYPES_ALL, &Query::default())?;
        list_values(v, endpoints::VAULT_TYPES_ALL)?
            .into_iter()
            .map(|e| from_value(e, endpoints::VAULT_TYPES_ALL))
            .collect()
    }

    /// Vault type by ID, code (exact, then case-insensitive) or name.
    pub fn find_vault_type(&self, id_code_or_name: &str) -> Result<VaultType> {
        let types = self.vault_types()?;
        let wanted = id_code_or_name;
        let lower = wanted.to_lowercase();
        let pick = |pred: &dyn Fn(&VaultType) -> bool| types.iter().find(|t| pred(t)).cloned();
        pick(&|t| t.id == wanted)
            .or_else(|| pick(&|t| t.code.as_deref() == Some(wanted)))
            .or_else(|| pick(&|t| t.code.as_deref().map(str::to_lowercase) == Some(lower.clone())))
            .or_else(|| pick(&|t| t.name == wanted))
            .or_else(|| pick(&|t| t.name.to_lowercase() == lower))
            .ok_or_else(|| Error::NotFound(format!("vault type not found: {wanted}")))
    }

    /// `GET /sessions/current/info`.
    pub fn session_info(&self) -> Result<SessionInfo> {
        let v = self.get(endpoints::SESSIONS_CURRENT_INFO, &Query::default())?;
        Ok(SessionInfo(v))
    }
}
