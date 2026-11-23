//! `vault list|get|create|delete`.

use std::process::ExitCode;

use anyhow::Context as _;
use pwk_api::Vault;
use serde_json::Value;

use super::Context;
use super::client::with_api;
use super::item::{print_id, report_deleted};
use super::resolve::Resolver;
use crate::cli::VaultCommand;
use crate::output::{self, Format, Table};

/// `vault …`.
pub fn run(ctx: &Context, cmd: &VaultCommand) -> anyhow::Result<ExitCode> {
    with_api(ctx, |api| {
        let resolver = Resolver::new(&api.client);
        match cmd {
            VaultCommand::List => {
                let vaults = resolver.vaults()?;
                print_vaults(ctx, &vaults)?;
            }
            VaultCommand::Get { vault } => {
                let vault = resolver.vault(vault)?;
                print_vault(ctx, &vault)?;
            }
            VaultCommand::Create { name, vault_type } => {
                api.require_encryption_state()?;
                let id = api
                    .client
                    .create_vault(name, vault_type.as_deref())
                    .with_context(|| format!("cannot create vault `{name}`"))?;
                ctx.info(&format!("created vault `{name}`"));
                print_id(ctx, &id)?;
            }
            VaultCommand::Delete { vault } => {
                let vault = resolver.vault(vault)?;
                api.client
                    .delete_vault(&vault.id)
                    .with_context(|| format!("cannot delete vault `{}`", vault.name))?;
                return report_deleted(ctx, "vault", &vault.name, &vault.id);
            }
        }
        Ok(ExitCode::SUCCESS)
    })
}

fn print_vaults(ctx: &Context, vaults: &[Vault]) -> anyhow::Result<()> {
    if ctx.format == Format::Json {
        return output::print_json(vaults);
    }
    let mut table = Table::new(["NAME", "ID"]);
    for vault in vaults {
        table.push([vault.name.clone(), vault.id.clone()]);
    }
    Ok(table.print()?)
}

fn print_vault(ctx: &Context, vault: &Vault) -> anyhow::Result<()> {
    if ctx.format == Format::Json {
        return output::print_json(vault);
    }
    let mut pairs = vec![
        ("id".to_owned(), vault.id.clone()),
        ("name".to_owned(), vault.name.clone()),
    ];
    if let Some(type_id) = &vault.type_id {
        pairs.push(("typeId".to_owned(), type_id.clone()));
    }
    pairs.extend(scalar_extras(&vault.extra));
    Ok(output::write_stdout(&output::render_pairs(&pairs))?)
}

/// Extra string, number and boolean fields of an object, for table views.
pub fn scalar_extras(extra: &serde_json::Map<String, Value>) -> Vec<(String, String)> {
    extra
        .iter()
        .filter_map(|(key, value)| match value {
            Value::String(s) if !s.is_empty() => Some((key.clone(), s.clone())),
            Value::Number(n) => Some((key.clone(), n.to_string())),
            Value::Bool(b) => Some((key.clone(), b.to_string())),
            _ => None,
        })
        .collect()
}
