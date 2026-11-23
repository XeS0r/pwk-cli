//! `item list|search|get|create|edit|move|delete`.

use std::process::ExitCode;

use anyhow::{Context as _, bail};
use pwk_api::{Item, ItemFilter, ItemSummary, ItemUpdate, NewItem, SecretString};
use zeroize::Zeroizing;

use super::Context;
use super::client::with_api;
use super::item_fields::{FieldChanges, plan_changes};
use super::resolve::{Resolver, field_value};
use crate::cli::{self, ItemCommand, ItemCreateArgs, ItemEditArgs, ItemFieldArgs, ItemGetArgs};
use crate::output::{self, Format, Table, masked};
use crate::prompt;

/// `item …`.
pub fn run(ctx: &Context, cmd: &ItemCommand) -> anyhow::Result<ExitCode> {
    with_api(ctx, |api| {
        let resolver = Resolver::new(&api.client);
        match cmd {
            ItemCommand::List(filter) => list(ctx, &resolver, None, filter),
            ItemCommand::Search { query, filter } => list(ctx, &resolver, Some(query), filter),
            ItemCommand::Get(args) => get(ctx, &resolver, args),
            ItemCommand::Create(args) => create(ctx, &resolver, args),
            ItemCommand::Edit(args) => edit(ctx, &resolver, args),
            ItemCommand::Move {
                item,
                vault,
                folder,
            } => move_item(ctx, &resolver, item, vault.as_deref(), folder.as_deref()),
            ItemCommand::Delete { item } => delete(ctx, &resolver, item),
        }
    })
}

/// Turns `--vault`/`--folder`/`--tag` into an API filter.
fn api_filter(
    resolver: &Resolver<'_>,
    query: Option<&String>,
    filter: &cli::ItemFilter,
) -> anyhow::Result<ItemFilter> {
    let vault = filter
        .vault
        .as_deref()
        .map(|v| resolver.vault(v))
        .transpose()?;
    let folder = filter
        .folder
        .as_deref()
        .map(|f| resolver.folder(f, vault.as_ref()))
        .transpose()?;
    let vault_id = vault
        .map(|v| v.id)
        .or_else(|| folder.as_ref().map(|f| f.vault_id.clone()))
        .filter(|id| !id.is_empty());
    Ok(ItemFilter {
        query: query.cloned(),
        tags: filter.tags.clone(),
        vault_ids: vault_id.into_iter().collect(),
        folder_ids: folder.map(|f| f.id).into_iter().collect(),
        ..ItemFilter::default()
    })
}

fn list(
    ctx: &Context,
    resolver: &Resolver<'_>,
    query: Option<&String>,
    filter: &cli::ItemFilter,
) -> anyhow::Result<ExitCode> {
    let api_filter = api_filter(resolver, query, filter)?;
    let rows = match query {
        Some(_) => resolver.client().search_items(&api_filter),
        None => resolver.client().list_items(&api_filter),
    }
    .context("cannot list items")?;
    print_summaries(ctx, resolver, &rows)?;
    Ok(ExitCode::SUCCESS)
}

/// Prints item rows: NAME, LOGIN, URL, PATH, ID (or JSON).
pub fn print_summaries(
    ctx: &Context,
    resolver: &Resolver<'_>,
    rows: &[ItemSummary],
) -> anyhow::Result<()> {
    if ctx.format == Format::Json {
        return output::print_json(rows);
    }
    let mut table = Table::new(["NAME", "LOGIN", "URL", "PATH", "ID"]);
    for row in rows {
        table.push([
            row.name.clone(),
            row.login.clone().unwrap_or_default(),
            row.url.clone().unwrap_or_default(),
            resolver.location(&row.vault_id, row.folder_id.as_deref())?,
            row.id.clone(),
        ]);
    }
    table.print()?;
    Ok(())
}

/// Resolves an item argument with an optional `--vault`.
pub fn find_item(
    resolver: &Resolver<'_>,
    item: &str,
    vault: Option<&str>,
) -> anyhow::Result<std::rc::Rc<Item>> {
    let vault = vault.map(|v| resolver.vault(v)).transpose()?;
    resolver.item(item, vault.as_ref())
}

fn get(ctx: &Context, resolver: &Resolver<'_>, args: &ItemGetArgs) -> anyhow::Result<ExitCode> {
    let item = find_item(resolver, &args.item, args.vault.as_deref())?;
    if let Some(field) = &args.field {
        let mut line = field_value(&item, field)?;
        line.push('\n');
        output::write_stdout(&line)?;
        return Ok(ExitCode::SUCCESS);
    }
    match ctx.format {
        Format::Json => output::print_json(item.as_ref())?,
        Format::Table => {
            let location = resolver.location(&item.vault_id, item.folder_id.as_deref())?;
            let pairs = item_pairs(&item, &location, args.reveal);
            let pairs: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            output::write_stdout(&output::render_pairs(&pairs))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The table view of an item: standard fields, custom fields and attachments. Secrets
/// are masked unless `reveal`.
#[must_use]
pub fn item_pairs(item: &Item, location: &str, reveal: bool) -> Vec<(String, Zeroizing<String>)> {
    let mut pairs: Vec<(String, Zeroizing<String>)> = Vec::new();
    let mut push = |key: &str, value: &str| {
        pairs.push((key.to_owned(), Zeroizing::new(value.to_owned())));
    };
    push("id", &item.id);
    push("name", &item.name);
    push("path", location);
    if let Some(login) = item.login.as_deref().filter(|l| !l.is_empty()) {
        push("login", login);
    }
    if let Some(password) = item.password.as_deref().filter(|p| !p.is_empty()) {
        push("password", masked(password, reveal));
    }
    if let Some(url) = item.url.as_deref().filter(|u| !u.is_empty()) {
        push("url", url);
    }
    for url in &item.urls {
        push("url", url);
    }
    if let Some(d) = item.description.as_deref().filter(|d| !d.is_empty()) {
        push("description", d);
    }
    if !item.tags.is_empty() {
        push("tags", &item.tags.join(", "));
    }
    if let Some(color) = item.color {
        push("color", &color.to_string());
    }
    for custom in &item.customs {
        let value = if custom.kind.is_secret() {
            masked(&custom.value, reveal)
        } else {
            &custom.value
        };
        push(&custom.name, value);
    }
    for attachment in &item.attachments {
        push(
            "attachment",
            &format!("{} ({})", attachment.name, attachment.id),
        );
    }
    pairs
}

/// The password from `--password-stdin` or `--generate-password`, if requested.
fn password_input(args: &ItemFieldArgs) -> anyhow::Result<Option<SecretString>> {
    if args.password_stdin {
        return prompt::read_secret_stdin("password").map(Some);
    }
    Ok(args
        .generate_password
        .map(|len| pwk_crypto::generate_password(usize::from(len), true)))
}

/// Prints the ID of a created or changed item (JSON: `{"id": …}`).
pub fn print_id(ctx: &Context, id: &str) -> anyhow::Result<()> {
    match ctx.format {
        Format::Json => output::print_json(&serde_json::json!({ "id": id })),
        Format::Table => Ok(output::write_stdout(&format!("{id}\n"))?),
    }
}

fn create(
    ctx: &Context,
    resolver: &Resolver<'_>,
    args: &ItemCreateArgs,
) -> anyhow::Result<ExitCode> {
    let vault = resolver.vault(&args.vault)?;
    let folder = args
        .folder
        .as_deref()
        .map(|f| resolver.folder(f, Some(&vault)))
        .transpose()?;
    let changes = plan_changes(&args.fields, password_input(&args.fields)?, &[], false)?;
    let item = new_item(&args.name, vault.id.clone(), folder.map(|f| f.id), changes);
    let id = resolver
        .client()
        .create_item(&item)
        .context("cannot create the item")?;
    let location = resolver.location(&item.vault_id, item.folder_id.as_deref())?;
    ctx.info(&format!("created item `{}` in {location}", item.name));
    print_id(ctx, &id)?;
    Ok(ExitCode::SUCCESS)
}

fn new_item(name: &str, vault_id: String, folder_id: Option<String>, c: FieldChanges) -> NewItem {
    NewItem {
        vault_id,
        folder_id,
        name: c.name.unwrap_or_else(|| name.to_owned()),
        login: c.login,
        password: c.password.flatten(),
        url: c.url,
        urls: c.urls.unwrap_or_default(),
        description: c.description,
        tags: c.tags.unwrap_or_default(),
        color: c.color,
        customs: c.customs.unwrap_or_default(),
        ..NewItem::default()
    }
}

fn edit(ctx: &Context, resolver: &Resolver<'_>, args: &ItemEditArgs) -> anyhow::Result<ExitCode> {
    let item = find_item(resolver, &args.item, args.vault.as_deref())?;
    let mut changes = plan_changes(
        &args.fields,
        password_input(&args.fields)?,
        &item.customs,
        true,
    )?;
    if let Some(name) = &args.name {
        changes.name = Some(name.clone());
    }
    if changes.is_empty() {
        bail!("nothing to change: give field options or FIELD=VALUE assignments");
    }
    let update = ItemUpdate {
        name: changes.name,
        login: changes.login,
        password: changes.password,
        url: changes.url,
        urls: changes.urls,
        description: changes.description,
        tags: changes.tags,
        color: changes.color,
        customs: changes.customs,
        ..ItemUpdate::default()
    };
    resolver
        .client()
        .update_item(&item.id, &update)
        .with_context(|| format!("cannot update item `{}`", item.name))?;
    ctx.info(&format!("updated item `{}`", item.name));
    print_id(ctx, &item.id)?;
    Ok(ExitCode::SUCCESS)
}

fn move_item(
    ctx: &Context,
    resolver: &Resolver<'_>,
    item: &str,
    vault: Option<&str>,
    folder: Option<&str>,
) -> anyhow::Result<ExitCode> {
    if vault.is_none() && folder.is_none() {
        bail!("give --vault and/or --folder as the target");
    }
    let item = resolver.item(item, None)?;
    let target_vault = match vault {
        Some(v) => resolver.vault(v)?,
        None => resolver.vault(&item.vault_id)?,
    };
    let target_folder = folder
        .map(|f| resolver.folder(f, Some(&target_vault)))
        .transpose()?;
    let folder_id = target_folder.as_ref().map(|f| f.id.as_str());
    resolver
        .client()
        .move_item(&item.id, &target_vault.id, folder_id)
        .with_context(|| format!("cannot move item `{}`", item.name))?;
    let location = resolver.location(&target_vault.id, folder_id)?;
    ctx.info(&format!("moved item `{}` to {location}", item.name));
    print_id(ctx, &item.id)?;
    Ok(ExitCode::SUCCESS)
}

fn delete(ctx: &Context, resolver: &Resolver<'_>, item: &str) -> anyhow::Result<ExitCode> {
    let found = resolver.item(item, None)?;
    resolver
        .client()
        .delete_item(&found.id)
        .with_context(|| format!("cannot delete item `{}`", found.name))?;
    report_deleted(ctx, "item", &found.name, &found.id)
}

/// Reports a deletion: JSON `{"deleted": "<kind>", "id", "name"}` on stdout, else a
/// notice on stderr.
pub fn report_deleted(ctx: &Context, kind: &str, name: &str, id: &str) -> anyhow::Result<ExitCode> {
    match ctx.format {
        Format::Json => output::print_json(&serde_json::json!({
            "deleted": kind, "id": id, "name": name
        }))?,
        Format::Table => ctx.info(&format!("deleted {kind} `{name}` ({id})")),
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
pub(crate) mod tests {
    use pwk_api::{CustomField, CustomKind};

    use super::*;

    pub(crate) fn sample_item() -> Item {
        let mut item = Item::default();
        item.id = "0123456789abcdef01234567".into();
        item.name = "Mail".into();
        item.login = Some("bob".into());
        item.password = Some(Zeroizing::new("pw".into()));
        item.tags = vec!["a".into(), "b".into()];
        item.vault_id = "v".into();
        item.customs = vec![
            CustomField::new("PIN", "1234", CustomKind::Password),
            CustomField::new("note", "hi", CustomKind::Text),
        ];
        item
    }

    #[test]
    fn pairs_mask_secrets() {
        let item = sample_item();
        let pairs = item_pairs(&item, "V/F", false);
        let get = |k: &str| {
            pairs
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str().to_owned())
        };
        assert_eq!(get("password").as_deref(), Some(output::MASK));
        assert_eq!(get("PIN").as_deref(), Some(output::MASK));
        assert_eq!(get("note").as_deref(), Some("hi"));
        assert_eq!(get("path").as_deref(), Some("V/F"));
        assert_eq!(get("tags").as_deref(), Some("a, b"));
        let revealed = item_pairs(&item, "V", true);
        assert!(
            revealed
                .iter()
                .any(|(k, v)| k == "PIN" && v.as_str() == "1234")
        );
        assert!(
            revealed
                .iter()
                .any(|(k, v)| k == "password" && v.as_str() == "pw")
        );
    }
}
