//! Object references: IDs or names of vaults, folders, items and shortcuts, folder
//! paths, item fields and `pw://` references. See docs/design.md, "Object references".

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use anyhow::{Context as _, bail};
use pwk_api::{Client, Folder, Item, ItemFilter, ItemSummary, Vault};
use zeroize::Zeroizing;

use crate::reference::{Attribute, Reference};

/// Whether `text` looks like a Passwork object ID (24 hex characters).
#[must_use]
pub fn is_id(text: &str) -> bool {
    text.len() == 24 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// One object that a name may refer to.
#[derive(Debug, Clone)]
pub struct Candidate<'a, T> {
    /// The object.
    pub value: &'a T,
    /// Its ID.
    pub id: &'a str,
    /// Names it answers to (e.g. its name and its folder path).
    pub names: Vec<String>,
    /// How it is shown in an ambiguity error (e.g. its full path).
    pub label: String,
}

/// Picks the candidate meant by `query`: by ID, then by exact name, then by
/// case-insensitive name. Several matches at the first stage that matches are an error
/// listing the candidates with IDs and labels.
pub fn select<'a, T>(
    what: &str,
    query: &str,
    candidates: &[Candidate<'a, T>],
) -> anyhow::Result<&'a T> {
    let lower = query.to_lowercase();
    for stage in 0..3 {
        let matches = |c: &&Candidate<'a, T>| match stage {
            0 => c.id == query,
            1 => c.names.iter().any(|n| n == query),
            _ => c.names.iter().any(|n| n.to_lowercase() == lower),
        };
        let found: Vec<&Candidate<'a, T>> = candidates.iter().filter(matches).collect();
        match found.as_slice() {
            [] => {}
            [one] => return Ok(one.value),
            many => bail!("{}", ambiguity(what, query, many)),
        }
    }
    bail!("no {what} `{query}` found")
}

fn ambiguity<T>(what: &str, query: &str, many: &[&Candidate<'_, T>]) -> String {
    let mut message = format!("{what} `{query}` is ambiguous; use one of these IDs:");
    for c in many {
        message.push_str(&format!("\n  {}  {}", c.id, c.label));
    }
    message
}

/// The folders of one vault, with paths.
#[derive(Debug, Clone)]
pub struct FolderTree {
    folders: Vec<Folder>,
}

/// A parent ID that means "vault root": missing, empty or not a folder of this vault.
fn parent_of<'a>(tree: &'a FolderTree, folder: &'a Folder) -> Option<&'a Folder> {
    let parent = folder.parent_id.as_deref().filter(|p| !p.is_empty())?;
    tree.get(parent)
}

impl FolderTree {
    /// A tree of `folders` (all of one vault).
    #[must_use]
    pub fn new(folders: Vec<Folder>) -> Self {
        Self { folders }
    }

    /// All folders.
    #[must_use]
    pub fn folders(&self) -> &[Folder] {
        &self.folders
    }

    /// Folder by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Folder> {
        self.folders.iter().find(|f| f.id == id)
    }

    /// `Parent/Child/Name` of a folder below the vault root.
    #[must_use]
    pub fn path(&self, folder: &Folder) -> String {
        let mut parts = vec![folder.name.as_str()];
        let mut current = folder;
        // Bounded by the number of folders, so a cycle cannot loop forever.
        for _ in 0..self.folders.len() {
            match parent_of(self, current) {
                Some(parent) if parent.id != folder.id => {
                    parts.push(parent.name.as_str());
                    current = parent;
                }
                _ => break,
            }
        }
        parts.reverse();
        parts.join("/")
    }

    /// Path of the folder with this ID; empty for the root or an unknown folder.
    #[must_use]
    pub fn path_of(&self, id: Option<&str>) -> String {
        id.and_then(|id| self.get(id))
            .map(|f| self.path(f))
            .unwrap_or_default()
    }

    /// Direct children of `parent` (`None`: the vault root).
    #[must_use]
    pub fn children(&self, parent: Option<&str>) -> Vec<&Folder> {
        self.folders
            .iter()
            .filter(|f| parent_of(self, f).map(|p| p.id.as_str()) == parent)
            .collect()
    }

    /// Follows `segments` (names or IDs) from the vault root.
    pub fn walk(&self, vault_name: &str, segments: &[String]) -> anyhow::Result<Option<&Folder>> {
        let mut current: Option<&Folder> = None;
        let mut path = vault_name.to_owned();
        for segment in segments {
            let children = self.children(current.map(|f| f.id.as_str()));
            let candidates: Vec<Candidate<'_, Folder>> = children
                .into_iter()
                .map(|f| Candidate {
                    value: f,
                    id: &f.id,
                    names: vec![f.name.clone()],
                    label: format!("{vault_name}/{}", self.path(f)),
                })
                .collect();
            let next =
                select("folder", segment, &candidates).with_context(|| format!("in {path}"))?;
            path = format!("{vault_name}/{}", self.path(next));
            current = Some(next);
        }
        Ok(current)
    }
}

/// Candidates for a folder name or path: each folder answers to its name, its path below
/// the vault and its path including the vault name.
#[must_use]
pub fn folder_candidates<'a>(vault: &Vault, tree: &'a FolderTree) -> Vec<Candidate<'a, Folder>> {
    tree.folders()
        .iter()
        .map(|f| {
            let path = tree.path(f);
            let full = format!("{}/{path}", vault.name);
            Candidate {
                value: f,
                id: &f.id,
                names: vec![f.name.clone(), path, full.clone()],
                label: full,
            }
        })
        .collect()
}

/// Picks a folder by name or path: path matches win over bare name matches.
pub fn select_folder<'a>(
    query: &str,
    candidates: &[Candidate<'a, Folder>],
) -> anyhow::Result<&'a Folder> {
    if query.contains('/') {
        // A path: match only paths, not names that happen to contain a slash.
        let by_path: Vec<Candidate<'a, Folder>> = candidates
            .iter()
            .map(|c| Candidate {
                names: c.names[1..].to_vec(),
                ..c.clone()
            })
            .collect();
        if let Ok(found) = select("folder", query, &by_path) {
            return Ok(found);
        }
    }
    let by_name: Vec<Candidate<'a, Folder>> = candidates
        .iter()
        .map(|c| Candidate {
            names: vec![c.names[0].clone()],
            ..c.clone()
        })
        .collect();
    select("folder", query, &by_name)
}

/// Resolves references against the server, caching vault and folder lists for the
/// duration of one command.
pub struct Resolver<'c> {
    client: &'c Client,
    vaults: OnceCell<Rc<Vec<Vault>>>,
    trees: RefCell<HashMap<String, Rc<FolderTree>>>,
    items: RefCell<HashMap<String, Rc<Item>>>,
}

impl std::fmt::Debug for Resolver<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver").finish_non_exhaustive()
    }
}

impl<'c> Resolver<'c> {
    /// A resolver using `client`.
    #[must_use]
    pub fn new(client: &'c Client) -> Self {
        Self {
            client,
            vaults: OnceCell::new(),
            trees: RefCell::new(HashMap::new()),
            items: RefCell::new(HashMap::new()),
        }
    }

    /// The client.
    #[must_use]
    pub fn client(&self) -> &'c Client {
        self.client
    }

    /// All vaults (cached).
    pub fn vaults(&self) -> anyhow::Result<Rc<Vec<Vault>>> {
        if let Some(v) = self.vaults.get() {
            return Ok(v.clone());
        }
        let list = Rc::new(self.client.list_vaults().context("cannot list vaults")?);
        Ok(self.vaults.get_or_init(|| list).clone())
    }

    /// Vault by ID or name.
    pub fn vault(&self, query: &str) -> anyhow::Result<Vault> {
        let vaults = self.vaults()?;
        let candidates: Vec<Candidate<'_, Vault>> = vaults
            .iter()
            .map(|v| Candidate {
                value: v,
                id: &v.id,
                names: vec![v.name.clone()],
                label: v.name.clone(),
            })
            .collect();
        match select("vault", query, &candidates) {
            Ok(v) => Ok(v.clone()),
            Err(e) if is_id(query) => self
                .client
                .get_vault(query)
                .with_context(|| format!("{e:#}")),
            Err(e) => Err(e),
        }
    }

    /// Name of the vault with this ID (the ID itself if unknown).
    pub fn vault_name(&self, id: &str) -> anyhow::Result<String> {
        Ok(self
            .vaults()?
            .iter()
            .find(|v| v.id == id)
            .map_or_else(|| id.to_owned(), |v| v.name.clone()))
    }

    /// The folders of a vault (cached). Folders of other vaults that a server might
    /// return despite the filter are dropped.
    pub fn tree(&self, vault_id: &str) -> anyhow::Result<Rc<FolderTree>> {
        if let Some(tree) = self.trees.borrow().get(vault_id) {
            return Ok(tree.clone());
        }
        let folders = self
            .client
            .list_folders(Some(vault_id), None)
            .context("cannot list folders")?
            .into_iter()
            .filter(|f| f.vault_id.is_empty() || f.vault_id == vault_id)
            .collect();
        let tree = Rc::new(FolderTree::new(folders));
        self.trees
            .borrow_mut()
            .insert(vault_id.to_owned(), tree.clone());
        Ok(tree)
    }

    /// `Vault/Folder/Sub` of a location.
    pub fn location(&self, vault_id: &str, folder_id: Option<&str>) -> anyhow::Result<String> {
        let vault = self.vault_name(vault_id)?;
        let folder = self.tree(vault_id)?.path_of(folder_id);
        Ok(if folder.is_empty() {
            vault
        } else {
            format!("{vault}/{folder}")
        })
    }

    /// Folder by ID, name or path, in `vault` or in every vault.
    pub fn folder(&self, query: &str, vault: Option<&Vault>) -> anyhow::Result<Folder> {
        let vaults: Vec<Vault> = match vault {
            Some(v) => vec![v.clone()],
            None => self.vaults()?.as_ref().clone(),
        };
        let trees: Vec<(Vault, Rc<FolderTree>)> = vaults
            .into_iter()
            .map(|v| self.tree(&v.id).map(|t| (v, t)))
            .collect::<anyhow::Result<_>>()?;
        let candidates: Vec<Candidate<'_, Folder>> = trees
            .iter()
            .flat_map(|(v, t)| folder_candidates(v, t))
            .collect();
        match select_folder(query, &candidates) {
            Ok(f) => Ok(f.clone()),
            Err(e) if is_id(query) => self
                .client
                .get_folder(query)
                .with_context(|| format!("{e:#}")),
            Err(e) => Err(e),
        }
    }

    /// Item by ID (fetched directly) or name (searched, optionally in a vault).
    pub fn item(&self, query: &str, vault: Option<&Vault>) -> anyhow::Result<Rc<Item>> {
        if is_id(query) {
            return self.item_by_id(query);
        }
        let filter = ItemFilter {
            query: Some(query.to_owned()),
            vault_ids: vault.map(|v| vec![v.id.clone()]).unwrap_or_default(),
            ..ItemFilter::default()
        };
        let rows = self
            .client
            .search_items(&filter)
            .context("cannot search items")?;
        let rows: Vec<ItemSummary> = rows
            .into_iter()
            .filter(|r| vault.is_none_or(|v| r.vault_id == v.id))
            .collect();
        let id = self.select_item(query, &rows)?;
        self.item_by_id(&id)
    }

    /// Picks an item among search rows by name, labelling candidates with their paths.
    pub fn select_item(&self, query: &str, rows: &[ItemSummary]) -> anyhow::Result<String> {
        let mut candidates = Vec::with_capacity(rows.len());
        for row in rows {
            candidates.push(Candidate {
                value: row,
                id: &row.id,
                names: vec![row.name.clone()],
                label: String::new(),
            });
        }
        match select("item", query, &candidates) {
            Ok(row) => Ok(row.id.clone()),
            Err(e) => {
                // Label the candidates with their paths only when it is needed.
                for c in &mut candidates {
                    c.label = format!(
                        "{}/{}",
                        self.location(&c.value.vault_id, c.value.folder_id.as_deref())?,
                        c.value.name
                    );
                }
                Err(select("item", query, &candidates).err().unwrap_or(e))
            }
        }
    }

    /// Item by ID (cached).
    pub fn item_by_id(&self, id: &str) -> anyhow::Result<Rc<Item>> {
        if let Some(item) = self.items.borrow().get(id) {
            return Ok(item.clone());
        }
        let item = Rc::new(
            self.client
                .get_item(id)
                .with_context(|| format!("cannot get item {id}"))?,
        );
        self.items.borrow_mut().insert(id.to_owned(), item.clone());
        Ok(item)
    }

    /// The item a `pw://` reference points to.
    pub fn reference_item(&self, reference: &Reference) -> anyhow::Result<Rc<Item>> {
        let vault = self.vault(&reference.vault)?;
        let tree = self.tree(&vault.id)?;
        let folder = tree.walk(&vault.name, &reference.folders)?;
        if is_id(&reference.item) {
            let item = self.item_by_id(&reference.item)?;
            let wrong_vault = item.vault_id != vault.id;
            let wrong_folder =
                folder.is_some_and(|f| item.folder_id.as_deref() != Some(f.id.as_str()));
            if wrong_vault || wrong_folder {
                let actual = self
                    .location(&item.vault_id, item.folder_id.as_deref())
                    .unwrap_or_else(|_| format!("vault {}", item.vault_id));
                let expected = if reference.folders.is_empty() {
                    vault.name.clone()
                } else {
                    format!("{}/{}", vault.name, reference.folders.join("/"))
                };
                bail!(
                    "item {} (`{}`) is in {actual}, not in {expected}",
                    item.id,
                    item.name
                );
            }
            return Ok(item);
        }
        let filter = ItemFilter {
            query: Some(reference.item.clone()),
            vault_ids: vec![vault.id.clone()],
            folder_ids: folder.map(|f| vec![f.id.clone()]).unwrap_or_default(),
            ..ItemFilter::default()
        };
        let rows = self
            .client
            .search_items(&filter)
            .context("cannot search items")?;
        let in_vault = rows.into_iter().filter(|r| r.vault_id == vault.id);
        let rows: Vec<ItemSummary> = match folder {
            Some(f) => in_vault
                .filter(|r| r.folder_id.as_deref() == Some(f.id.as_str()))
                .collect(),
            None => in_vault.collect(),
        };
        let id = match self.select_item(&reference.item, &rows) {
            Ok(id) => id,
            Err(e) if folder.is_none() => {
                // No folder path: items at the vault root take precedence.
                let root: Vec<ItemSummary> = rows
                    .into_iter()
                    .filter(|r| tree.path_of(r.folder_id.as_deref()).is_empty())
                    .collect();
                self.select_item(&reference.item, &root).map_err(|_| e)?
            }
            Err(e) => return Err(e),
        };
        self.item_by_id(&id)
    }

    /// The value a `pw://` reference points to.
    pub fn resolve(&self, reference: &Reference) -> anyhow::Result<Zeroizing<String>> {
        let item = self.reference_item(reference)?;
        let value = field_value(&item, &reference.field)?;
        match reference.attribute {
            None => Ok(value),
            Some(Attribute::Totp) => totp_code(&value).map(|(code, _)| Zeroizing::new(code)),
        }
    }
}

/// Names of the standard item fields.
pub const STANDARD_FIELDS: &[&str] = &["name", "login", "password", "url", "description", "tags"];

/// The value of a standard field (case-insensitive name) or custom field (exact, then
/// case-insensitive). A missing field is an error listing the available ones.
pub fn field_value(item: &Item, field: &str) -> anyhow::Result<Zeroizing<String>> {
    let text = |v: Option<&String>| Zeroizing::new(v.cloned().unwrap_or_default());
    let value = match field.to_lowercase().as_str() {
        "name" => Zeroizing::new(item.name.clone()),
        "login" => text(item.login.as_ref()),
        "password" => Zeroizing::new(
            item.password
                .as_ref()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_default(),
        ),
        "url" => text(item.url.as_ref()),
        "description" => text(item.description.as_ref()),
        "tags" => Zeroizing::new(item.tags.join(",")),
        _ => match item.custom(field) {
            Some(custom) => custom.value.clone(),
            None => bail!(
                "item `{}` has no field `{field}`; available: {}",
                item.name,
                available_fields(item).join(", ")
            ),
        },
    };
    Ok(value)
}

/// Standard and custom field names of an item.
#[must_use]
pub fn available_fields(item: &Item) -> Vec<String> {
    STANDARD_FIELDS
        .iter()
        .map(|s| (*s).to_owned())
        .chain(item.customs.iter().map(|c| c.name.clone()))
        .collect()
}

/// The current TOTP code of a secret (Base32 or `otpauth://` URI) and the seconds it is
/// still valid.
pub fn totp_code(secret: &str) -> anyhow::Result<(String, u64)> {
    let totp = pwk_crypto::totp::Totp::parse(secret).context("invalid TOTP secret")?;
    let now = crate::session::unix_now();
    Ok((totp.code_at(now), totp.remaining(now)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn folder(id: &str, name: &str, parent: Option<&str>) -> Folder {
        serde_json::from_value(json!({
            "id": id, "name": name, "vaultId": "v1", "parentId": parent
        }))
        .unwrap()
    }

    fn vault(id: &str, name: &str) -> Vault {
        serde_json::from_value(json!({ "id": id, "name": name })).unwrap()
    }

    fn tree() -> FolderTree {
        FolderTree::new(vec![
            folder("f1", "Infra", None),
            folder("f2", "Datenbanken", Some("f1")),
            folder("f3", "Datenbanken", None),
            folder("f4", "prod", Some("f2")),
            folder("f5", "Web", Some("v1")),
        ])
    }

    #[test]
    fn ids() {
        assert!(is_id("0123456789abcdefABCDEF01"));
        assert!(!is_id("0123456789abcdefABCDEF0"));
        assert!(!is_id("0123456789abcdefABCDEF0g"));
    }

    #[test]
    fn folder_paths() {
        let tree = tree();
        assert_eq!(tree.path_of(Some("f4")), "Infra/Datenbanken/prod");
        assert_eq!(tree.path_of(Some("f3")), "Datenbanken");
        // A parent that is not a folder (e.g. the vault ID) means the root.
        assert_eq!(tree.path_of(Some("f5")), "Web");
        assert_eq!(tree.path_of(None), "");
        let roots: Vec<&str> = tree.children(None).iter().map(|f| f.id.as_str()).collect();
        assert_eq!(roots, vec!["f1", "f3", "f5"]);
    }

    #[test]
    fn folder_cycle_terminates() {
        let tree = FolderTree::new(vec![
            folder("a", "A", Some("b")),
            folder("b", "B", Some("a")),
        ]);
        let path = tree.path_of(Some("a"));
        assert!(path.ends_with("A"), "{path}");
    }

    #[test]
    fn walk_paths() {
        let tree = tree();
        let segs = |s: &[&str]| s.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            tree.walk("V", &segs(&["Infra", "datenbanken", "prod"]))
                .unwrap()
                .unwrap()
                .id,
            "f4"
        );
        assert!(tree.walk("V", &[]).unwrap().is_none());
        assert_eq!(
            tree.walk("V", &segs(&["Datenbanken"])).unwrap().unwrap().id,
            "f3"
        );
        let err = tree.walk("V", &segs(&["Infra", "nope"])).unwrap_err();
        assert!(format!("{err:#}").contains("in V/Infra"), "{err:#}");
    }

    #[test]
    fn select_folder_by_path_and_name() {
        let tree = tree();
        let v = vault("v1", "Ops");
        let candidates = folder_candidates(&v, &tree);
        assert_eq!(
            select_folder("Infra/Datenbanken", &candidates).unwrap().id,
            "f2"
        );
        assert_eq!(
            select_folder("Ops/Datenbanken", &candidates).unwrap().id,
            "f3"
        );
        assert_eq!(select_folder("prod", &candidates).unwrap().id, "f4");
        assert_eq!(select_folder("INFRA", &candidates).unwrap().id, "f1");
        let err = select_folder("Datenbanken", &candidates)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ambiguous"), "{err}");
        assert!(err.contains("f2  Ops/Infra/Datenbanken"), "{err}");
        assert!(err.contains("f3  Ops/Datenbanken"), "{err}");
        assert!(select_folder("missing", &candidates).is_err());
    }

    #[test]
    fn select_stages() {
        let names = ["Mail", "mail", "Web", "web2"];
        let values: Vec<String> = names.iter().map(|s| (*s).to_owned()).collect();
        let ids = ["1", "2", "3", "4"];
        let candidates: Vec<Candidate<'_, String>> = values
            .iter()
            .zip(ids)
            .map(|(v, id)| Candidate {
                value: v,
                id,
                names: vec![v.clone()],
                label: format!("V/{v}"),
            })
            .collect();
        // Exact match wins over case-insensitive ones.
        assert_eq!(select("item", "Mail", &candidates).unwrap(), "Mail");
        // Case-insensitive.
        assert_eq!(select("item", "WEB", &candidates).unwrap(), "Web");
        // Ambiguous case-insensitive match lists candidates.
        let err = select("item", "MAIL", &candidates).unwrap_err().to_string();
        assert!(err.contains("item `MAIL` is ambiguous"), "{err}");
        assert!(
            err.contains("1  V/Mail") && err.contains("2  V/mail"),
            "{err}"
        );
        // By ID.
        assert_eq!(select("item", "4", &candidates).unwrap(), "web2");
        assert_eq!(
            select("item", "nope", &candidates).unwrap_err().to_string(),
            "no item `nope` found"
        );
    }

    #[test]
    fn fields() {
        let item: Item = {
            // Items are built by the API crate; go through a serialized custom list.
            let mut item = test_item();
            item.customs = vec![
                pwk_api::CustomField::new("API Key", "k1", pwk_api::CustomKind::Password),
                pwk_api::CustomField::new("api key", "k2", pwk_api::CustomKind::Text),
            ];
            item
        };
        assert_eq!(field_value(&item, "login").unwrap().as_str(), "bob");
        assert_eq!(field_value(&item, "Password").unwrap().as_str(), "pw");
        assert_eq!(field_value(&item, "tags").unwrap().as_str(), "a,b");
        assert_eq!(field_value(&item, "api key").unwrap().as_str(), "k2");
        assert_eq!(field_value(&item, "API KEY").unwrap().as_str(), "k1");
        // No undocumented aliases: `username` and `notes` are custom field names.
        assert!(field_value(&item, "username").is_err());
        assert!(field_value(&item, "notes").is_err());
        let mut with_customs = item.clone();
        with_customs.customs.push(pwk_api::CustomField::new(
            "username",
            "custom-user",
            pwk_api::CustomKind::Text,
        ));
        with_customs.customs.push(pwk_api::CustomField::new(
            "Notes",
            "custom-notes",
            pwk_api::CustomKind::Text,
        ));
        assert_eq!(
            field_value(&with_customs, "username").unwrap().as_str(),
            "custom-user"
        );
        assert_eq!(
            field_value(&with_customs, "notes").unwrap().as_str(),
            "custom-notes"
        );
        let err = field_value(&item, "pin").unwrap_err().to_string();
        assert!(err.contains("available: name, login"), "{err}");
        assert!(err.contains("API Key"), "{err}");
    }

    pub(crate) fn test_item() -> Item {
        crate::commands::item::tests::sample_item()
    }

    #[test]
    fn totp_codes() {
        let (code, remaining) = totp_code("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(code.len(), 6);
        assert!((1..=30).contains(&remaining));
        assert!(totp_code("not base32!").is_err());
    }
}
