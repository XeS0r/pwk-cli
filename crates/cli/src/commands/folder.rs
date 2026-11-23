//! `folder list|get|create|rename|move|delete`.

use std::process::ExitCode;

use anyhow::{Context as _, bail};
use pwk_api::{Folder, Vault};
use serde::Serialize;

use super::Context;
use super::client::with_api;
use super::item::{print_id, report_deleted};
use super::resolve::{FolderTree, Resolver};
use super::vault::scalar_extras;
use crate::cli::FolderCommand;
use crate::output::{self, Format, Table};

/// A folder with its location, for output.
#[derive(Debug, Serialize)]
struct FolderView<'a> {
    #[serde(flatten)]
    folder: &'a Folder,
    /// `Parent/Name` below the vault.
    path: String,
    /// Name of the vault.
    vault: String,
}

/// `folder …`.
pub fn run(ctx: &Context, cmd: &FolderCommand) -> anyhow::Result<ExitCode> {
    with_api(ctx, |api| {
        let r = Resolver::new(&api.client);
        match cmd {
            FolderCommand::List { vault, parent } => {
                list(ctx, &r, vault.as_deref(), parent.as_deref())
            }
            FolderCommand::Get { folder } => {
                let folder = r.folder(folder, None)?;
                let view = view(&r, &folder)?;
                if ctx.format == Format::Json {
                    output::print_json(&view)?;
                } else {
                    let mut pairs = vec![
                        ("id".to_owned(), folder.id.clone()),
                        ("name".to_owned(), folder.name.clone()),
                        ("vault".to_owned(), view.vault.clone()),
                        ("path".to_owned(), view.path.clone()),
                    ];
                    if let Some(parent) = folder.parent_id.as_deref().filter(|p| !p.is_empty()) {
                        pairs.push(("parentId".to_owned(), parent.to_owned()));
                    }
                    pairs.extend(scalar_extras(&folder.extra));
                    output::write_stdout(&output::render_pairs(&pairs))?;
                }
                Ok(ExitCode::SUCCESS)
            }
            FolderCommand::Create {
                name,
                vault,
                parent,
            } => {
                let vault = r.vault(vault)?;
                let parent = parent
                    .as_deref()
                    .map(|p| r.folder(p, Some(&vault)))
                    .transpose()?;
                let id = api
                    .client
                    .create_folder(&vault.id, parent.as_ref().map(|p| p.id.as_str()), name)
                    .with_context(|| format!("cannot create folder `{name}`"))?;
                ctx.info(&format!(
                    "created folder `{name}` in {}",
                    r.location(&vault.id, parent.as_ref().map(|p| p.id.as_str()))?
                ));
                print_id(ctx, &id)?;
                Ok(ExitCode::SUCCESS)
            }
            FolderCommand::Rename { folder, name } => {
                let folder = r.folder(folder, None)?;
                api.client
                    .rename_folder(&folder.id, name)
                    .with_context(|| format!("cannot rename folder `{}`", folder.name))?;
                ctx.info(&format!("renamed folder `{}` to `{name}`", folder.name));
                print_id(ctx, &folder.id)?;
                Ok(ExitCode::SUCCESS)
            }
            FolderCommand::Move {
                folder,
                vault,
                parent,
            } => move_folder(ctx, &r, folder, vault.as_deref(), parent.as_deref()),
            FolderCommand::Delete { folder } => {
                let folder = r.folder(folder, None)?;
                api.client
                    .delete_folder(&folder.id)
                    .with_context(|| format!("cannot delete folder `{}`", folder.name))?;
                report_deleted(ctx, "folder", &folder.name, &folder.id)
            }
        }
    })
}

fn view<'a>(r: &Resolver<'_>, folder: &'a Folder) -> anyhow::Result<FolderView<'a>> {
    Ok(FolderView {
        folder,
        path: r.tree(&folder.vault_id)?.path_of(Some(&folder.id)),
        vault: r.vault_name(&folder.vault_id)?,
    })
}

fn list(
    ctx: &Context,
    r: &Resolver<'_>,
    vault: Option<&str>,
    parent: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let vault = vault.map(|v| r.vault(v)).transpose()?;
    let parent = parent.map(|p| r.folder(p, vault.as_ref())).transpose()?;
    let vaults: Vec<Vault> = match (&vault, &parent) {
        (Some(v), _) => vec![v.clone()],
        (None, Some(p)) => vec![r.vault(&p.vault_id)?],
        (None, None) => r.vaults()?.as_ref().clone(),
    };
    let mut folders = Vec::new();
    for v in &vaults {
        let tree = r.tree(&v.id)?;
        let selected: Vec<Folder> = match &parent {
            Some(p) => tree.children(Some(&p.id)).into_iter().cloned().collect(),
            None => tree.folders().to_vec(),
        };
        folders.extend(selected);
    }
    let mut views = folders
        .iter()
        .map(|f| view(r, f))
        .collect::<anyhow::Result<Vec<_>>>()?;
    views.sort_by(|a, b| (&a.vault, &a.path).cmp(&(&b.vault, &b.path)));
    if ctx.format == Format::Json {
        output::print_json(&views)?;
        return Ok(ExitCode::SUCCESS);
    }
    let mut table = Table::new(["NAME", "PATH", "ID"]);
    for v in &views {
        table.push([
            v.folder.name.clone(),
            format!("{}/{}", v.vault, v.path),
            v.folder.id.clone(),
        ]);
    }
    table.print()?;
    Ok(ExitCode::SUCCESS)
}

/// Whether folder `start` is `ancestor` or lies below it: walks the parent chain of
/// `start` in `tree`, bounded by the number of folders so a cycle cannot loop forever.
fn is_within(tree: &FolderTree, start: &str, ancestor: &str) -> bool {
    let mut current = Some(start);
    for _ in 0..=tree.folders().len() {
        match current {
            Some(id) if id == ancestor => return true,
            Some(id) => {
                current = tree
                    .get(id)
                    .and_then(|f| f.parent_id.as_deref())
                    .filter(|p| !p.is_empty());
            }
            None => return false,
        }
    }
    false
}

fn move_folder(
    ctx: &Context,
    r: &Resolver<'_>,
    folder: &str,
    vault: Option<&str>,
    parent: Option<&str>,
) -> anyhow::Result<ExitCode> {
    if vault.is_none() && parent.is_none() {
        bail!("give --vault and/or --parent as the target");
    }
    let folder = r.folder(folder, None)?;
    let target_vault = match vault {
        Some(v) => r.vault(v)?,
        None => r.vault(&folder.vault_id)?,
    };
    let target_parent = parent
        .map(|p| r.folder(p, Some(&target_vault)))
        .transpose()?;
    let into_itself = match &target_parent {
        Some(p) => is_within(&*r.tree(&p.vault_id)?, &p.id, &folder.id),
        None => false,
    };
    if into_itself {
        bail!(
            "cannot move folder `{}` into itself or one of its subfolders",
            folder.name
        );
    }
    let parent_id = target_parent.as_ref().map(|p| p.id.as_str());
    r.client()
        .move_folder(&folder.id, &target_vault.id, parent_id)
        .with_context(|| format!("cannot move folder `{}`", folder.name))?;
    ctx.info(&format!(
        "moved folder `{}` to {}",
        folder.name,
        r.location(&target_vault.id, parent_id)?
    ));
    print_id(ctx, &folder.id)?;
    Ok(ExitCode::SUCCESS)
}
