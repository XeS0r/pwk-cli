//! Every Passwork endpoint path used by the client, in one place.
//!
//! All functions return full paths including the `/api/v1` prefix (batch requests need
//! them in that form). Path segments taken from callers are percent-encoded; empty and
//! dot-only segments (`.`, `..`) are rejected, so a caller value can never address
//! another path. Paths marked
//! **(unverified)** are inferred, see `docs/protocol.md`.

use crate::{Error, Result};

/// Prefix of every API path.
pub const API_PREFIX: &str = "/api/v1";

/// `POST`: refresh the token pair.
pub const SESSIONS_REFRESH: &str = "/api/v1/sessions/refresh";
/// `GET`: information about the current session.
pub const SESSIONS_CURRENT_INFO: &str = "/api/v1/sessions/current/info";
/// `GET`: the user's key pair (`{"keys": {"public", "privateEncrypted"}}`).
pub const USERS_KEYS: &str = "/api/v1/users/keys";
/// `GET`: master key derivation options.
pub const USERS_MASTER_KEY_OPTIONS: &str = "/api/v1/users/master-key/options";
/// `GET`: enabled application features.
pub const APP_FEATURES: &str = "/api/v1/app/features";
/// `GET`: all vault types.
pub const VAULT_TYPES_ALL: &str = "/api/v1/vault-types/all";
/// `POST`: batch of up to [`BATCH_LIMIT`] requests.
pub const BATCH: &str = "/api/v1/batch";
/// Maximum number of requests per batch call.
pub const BATCH_LIMIT: usize = 25;

/// `GET` list / `POST` create.
pub const VAULTS: &str = "/api/v1/vaults";
/// `GET` list **(filters `vaultId`, `parentId` unverified)** / `POST` create.
pub const FOLDERS: &str = "/api/v1/folders";
/// `POST` create.
pub const ITEMS: &str = "/api/v1/items";
/// `GET` search (`query`, `tags[]`, `colorCodes[]`, `vaultIds[]`, `folderIds[]`).
pub const ITEMS_SEARCH: &str = "/api/v1/items/search";
/// `POST` create.
pub const SHORTCUTS: &str = "/api/v1/shortcuts";
/// `GET` search, same parameters as [`ITEMS_SEARCH`].
pub const SHORTCUTS_SEARCH: &str = "/api/v1/shortcuts/search";

/// `GET` / `POST` (update) / `DELETE` a vault.
pub fn vault(id: &str) -> Result<String> {
    Ok(format!("{VAULTS}/{}", segment(id)?))
}

/// `GET`: administrators of a vault type (`{"items": [{"id", "publicKey"}]}`).
pub fn vault_type_administrators(type_id: &str) -> Result<String> {
    Ok(format!(
        "/api/v1/vault-types/{}/administrators",
        segment(type_id)?
    ))
}

/// `GET` / `POST` (rename) / `DELETE` a folder.
pub fn folder(id: &str) -> Result<String> {
    Ok(format!("{FOLDERS}/{}", segment(id)?))
}

/// `POST`: move a folder **(body unverified)**.
pub fn folder_move(id: &str) -> Result<String> {
    Ok(format!("{}/move", folder(id)?))
}

/// `GET` / `PATCH` / `DELETE` an item.
pub fn item(id: &str) -> Result<String> {
    Ok(format!("{ITEMS}/{}", segment(id)?))
}

/// `POST`: move an item **(body unverified)**.
pub fn item_move(id: &str) -> Result<String> {
    Ok(format!("{}/move", item(id)?))
}

/// `GET`: one attachment of an item.
pub fn item_attachment(item_id: &str, attachment_id: &str) -> Result<String> {
    Ok(format!(
        "{}/attachment/{}",
        item(item_id)?,
        segment(attachment_id)?
    ))
}

/// `GET`: one snapshot of an item.
pub fn item_snapshot(item_id: &str, snapshot_id: &str) -> Result<String> {
    Ok(format!(
        "{}/snapshot/{}",
        item(item_id)?,
        segment(snapshot_id)?
    ))
}

/// `GET` / `DELETE` a shortcut.
pub fn shortcut(id: &str) -> Result<String> {
    Ok(format!("{SHORTCUTS}/{}", segment(id)?))
}

/// Normalises a caller-supplied path: accepts `items/x`, `/items/x`, `api/v1/items/x`
/// and `/api/v1/items/x` and returns `/api/v1/items/x`.
#[must_use]
pub fn normalize(path: &str) -> String {
    let trimmed = path.trim().trim_start_matches('/');
    let rest = trimmed
        .strip_prefix("api/v1/")
        .or_else(|| (trimmed == "api/v1").then_some(""))
        .unwrap_or(trimmed);
    if rest.is_empty() {
        API_PREFIX.to_owned()
    } else {
        format!("{API_PREFIX}/{rest}")
    }
}

/// Percent-encodes one path segment (everything except RFC 3986 unreserved characters).
///
/// An empty segment and a segment of dots only are [`Error::Invalid`]. Encoding the
/// dots does not help: WHATWG URL parsing (used by `reqwest`) treats `%2E` and `%2E%2E`
/// as dot segments too and would resolve `items/..` to the parent path.
fn segment(value: &str) -> Result<String> {
    if value.is_empty() {
        return Err(Error::Invalid("empty ID in request path".into()));
    }
    if value.bytes().all(|b| b == b'.') {
        return Err(Error::Invalid(format!(
            "invalid ID {value:?} in request path"
        )));
    }
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_paths() {
        assert_eq!(normalize("items/x"), "/api/v1/items/x");
        assert_eq!(normalize("/items/x"), "/api/v1/items/x");
        assert_eq!(normalize("api/v1/items/x"), "/api/v1/items/x");
        assert_eq!(normalize("/api/v1/items/x"), "/api/v1/items/x");
        assert_eq!(normalize("/api/v1"), "/api/v1");
    }

    #[test]
    fn encodes_segments() {
        assert_eq!(item("a/b c").unwrap(), "/api/v1/items/a%2Fb%20c");
        assert_eq!(
            item("691c354719feeca0c603c2f2").unwrap(),
            "/api/v1/items/691c354719feeca0c603c2f2"
        );
        assert_eq!(item("a.b").unwrap(), "/api/v1/items/a.b");
        assert_eq!(item("...x").unwrap(), "/api/v1/items/...x");
    }

    #[test]
    fn dot_and_empty_segments() {
        for bad in ["", ".", "..", "..."] {
            assert!(matches!(item(bad), Err(Error::Invalid(_))), "{bad:?}");
            assert!(matches!(item_move(bad), Err(Error::Invalid(_))), "{bad:?}");
            assert!(
                matches!(item_attachment("i", bad), Err(Error::Invalid(_))),
                "{bad:?}"
            );
            assert!(matches!(vault(bad), Err(Error::Invalid(_))), "{bad:?}");
            assert!(matches!(folder(bad), Err(Error::Invalid(_))), "{bad:?}");
            assert!(matches!(shortcut(bad), Err(Error::Invalid(_))), "{bad:?}");
        }
        // Why encoding is no option: the URL parser resolves `%2E%2E` like `..`.
        let url = url::Url::parse("https://h/api/v1/items/%2E%2E").unwrap();
        assert_eq!(url.path(), "/api/v1/");
        // Dots inside a segment stay as they are.
        let url = url::Url::parse(&format!("https://h{}", item("a..b").unwrap())).unwrap();
        assert_eq!(url.path(), "/api/v1/items/a..b");
    }
}
