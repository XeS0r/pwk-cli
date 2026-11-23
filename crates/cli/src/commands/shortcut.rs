//! `shortcut list|get|create|delete`.

use std::process::ExitCode;

use anyhow::Context as _;
use pwk_api::{ItemFilter, ShortcutSummary};

use super::Context;
use super::client::with_api;
use super::item::{item_pairs, print_id, report_deleted};
use super::resolve::{Candidate, Resolver, is_id, select};
use crate::cli::ShortcutCommand;
use crate::output::{self, Format, Table};

/// `shortcut …`.
pub fn run(ctx: &Context, cmd: &ShortcutCommand) -> anyhow::Result<ExitCode> {
    with_api(ctx, |api| {
        let r = Resolver::new(&api.client);
        match cmd {
            ShortcutCommand::List { query } => {
                let rows = search(&r, query.as_deref())?;
                print_rows(ctx, &r, &rows)?;
            }
            ShortcutCommand::Get { shortcut } => {
                let id = find(&r, shortcut)?;
                let found = api
                    .client
                    .get_shortcut(&id)
                    .with_context(|| format!("cannot get shortcut {id}"))?;
                if ctx.format == Format::Json {
                    output::print_json(&found)?;
                } else {
                    let s = &found.shortcut;
                    let item = &found.item;
                    let mut pairs = vec![
                        ("shortcut".to_owned(), s.id.clone()),
                        (
                            "shortcut path".to_owned(),
                            r.location(&s.vault_id, s.folder_id.as_deref())?,
                        ),
                    ];
                    let location = r
                        .location(&item.vault_id, item.folder_id.as_deref())
                        .unwrap_or_default();
                    pairs.extend(
                        item_pairs(item, &location, false)
                            .into_iter()
                            .map(|(k, v)| (k, v.as_str().to_owned())),
                    );
                    output::write_stdout(&output::render_pairs(&pairs))?;
                }
            }
            ShortcutCommand::Create {
                item,
                vault,
                folder,
            } => {
                let item = r.item(item, None)?;
                let vault = r.vault(vault)?;
                let folder = folder
                    .as_deref()
                    .map(|f| r.folder(f, Some(&vault)))
                    .transpose()?;
                let folder_id = folder.as_ref().map(|f| f.id.as_str());
                let id = api
                    .client
                    .create_shortcut(&item, &vault.id, folder_id)
                    .with_context(|| format!("cannot create a shortcut to `{}`", item.name))?;
                ctx.info(&format!(
                    "created shortcut to `{}` in {}",
                    item.name,
                    r.location(&vault.id, folder_id)?
                ));
                print_id(ctx, &id)?;
            }
            ShortcutCommand::Delete { shortcut } => {
                let id = find(&r, shortcut)?;
                api.client
                    .delete_shortcut(&id)
                    .with_context(|| format!("cannot delete shortcut {id}"))?;
                return report_deleted(ctx, "shortcut", shortcut, &id);
            }
        }
        Ok(ExitCode::SUCCESS)
    })
}

/// The display name of a shortcut row (the item name the server sends along).
#[must_use]
pub fn shortcut_name(row: &ShortcutSummary) -> String {
    row.extra
        .get("name")
        .or_else(|| row.shortcut.extra.get("name"))
        .or_else(|| row.extra.get("item").and_then(|i| i.get("name")))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned()
}

fn search(r: &Resolver<'_>, query: Option<&str>) -> anyhow::Result<Vec<ShortcutSummary>> {
    let filter = ItemFilter {
        query: query.map(str::to_owned),
        ..ItemFilter::default()
    };
    r.client()
        .search_shortcuts(&filter)
        .context("cannot search shortcuts")
}

/// Shortcut ID for an ID or a name.
fn find(r: &Resolver<'_>, query: &str) -> anyhow::Result<String> {
    if is_id(query) {
        return Ok(query.to_owned());
    }
    let rows = search(r, Some(query))?;
    let mut candidates = Vec::with_capacity(rows.len());
    for row in &rows {
        candidates.push(Candidate {
            value: row,
            id: &row.shortcut.id,
            names: vec![shortcut_name(row)],
            label: format!(
                "{}/{}",
                r.location(&row.shortcut.vault_id, row.shortcut.folder_id.as_deref())?,
                shortcut_name(row)
            ),
        });
    }
    Ok(select("shortcut", query, &candidates)?.shortcut.id.clone())
}

fn print_rows(ctx: &Context, r: &Resolver<'_>, rows: &[ShortcutSummary]) -> anyhow::Result<()> {
    if ctx.format == Format::Json {
        return output::print_json(rows);
    }
    let mut table = Table::new(["NAME", "PATH", "ITEM", "ID"]);
    for row in rows {
        let s = &row.shortcut;
        table.push([
            shortcut_name(row),
            r.location(&s.vault_id, s.folder_id.as_deref())?,
            s.item_id.clone(),
            s.id.clone(),
        ]);
    }
    Ok(table.print()?)
}
