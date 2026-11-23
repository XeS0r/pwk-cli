//! Secrets in scripts: `read`, `run`, `inject`, `totp`.

use std::collections::HashMap;
use std::io::Read as _;
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use pwk_api::{CustomKind, Item};
use zeroize::Zeroizing;

use super::client::with_api;
use super::item::find_item;
use super::resolve::{Resolver, available_fields, totp_code};
use super::{Context, child_exit_code};
use crate::cli::{InjectArgs, ReadArgs, RunArgs, TotpArgs};
use crate::output::{self, Format};
use crate::reference::{self, Reference};
use crate::run::{Masker, run_command};
use crate::{dotenv, fsutil};

/// `read`: one value on stdout, followed by a newline.
pub fn read(ctx: &Context, args: &ReadArgs) -> anyhow::Result<ExitCode> {
    with_api(ctx, |api| {
        let resolver = Resolver::new(&api.client);
        let mut value = resolver.resolve(&args.reference)?;
        value.push('\n');
        output::write_stdout(&value)?;
        Ok(ExitCode::SUCCESS)
    })
}

/// The variables `run` sets for the child: each `--env-file` (later files and lines
/// win) plus the process variables whose whole value is a reference. Values are
/// unresolved here.
pub fn run_environment(
    env_files: &[(String, String)],
    process: impl IntoIterator<Item = (String, String)>,
) -> Vec<(String, String)> {
    let mut vars: Vec<(String, String)> = process
        .into_iter()
        .filter(|(_, v)| Reference::is_reference(v))
        .collect();
    for (key, value) in env_files {
        vars.retain(|(k, _)| k != key);
        vars.push((key.clone(), value.clone()));
    }
    vars
}

fn read_env_files(args: &RunArgs) -> anyhow::Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for path in &args.env_files {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let parsed = dotenv::parse(&text).with_context(|| format!("{}", path.display()))?;
        pairs.extend(parsed);
    }
    Ok(pairs)
}

/// `run`: resolves references in the environment and runs the command.
pub fn run(ctx: &Context, args: &RunArgs) -> anyhow::Result<ExitCode> {
    let process = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)));
    let vars = run_environment(&read_env_files(args)?, process);
    let mut references = Vec::new();
    for (key, value) in &vars {
        if Reference::is_reference(value) {
            let reference: Reference = value.parse().with_context(|| format!("variable {key}"))?;
            references.push((key.clone(), reference));
        }
    }
    let launch = |env: Vec<(String, Zeroizing<String>)>, secrets: Vec<Zeroizing<String>>| {
        let masker = (!args.no_masking).then(|| Masker::new(secrets.iter().map(|s| s.as_bytes())));
        let code = run_command(&args.command, &env, masker.as_ref())?;
        Ok(child_exit_code(code))
    };
    let plain = |vars: &[(String, String)]| -> Vec<(String, Zeroizing<String>)> {
        vars.iter()
            .filter(|(_, v)| !Reference::is_reference(v))
            .map(|(k, v)| (k.clone(), Zeroizing::new(v.clone())))
            .collect()
    };
    if references.is_empty() {
        return launch(plain(&vars), Vec::new());
    }
    with_api(ctx, |api| {
        let resolver = Resolver::new(&api.client);
        let mut env = plain(&vars);
        let mut resolved: HashMap<&Reference, Zeroizing<String>> = HashMap::new();
        for (key, reference) in &references {
            if !resolved.contains_key(reference) {
                let value = resolver
                    .resolve(reference)
                    .with_context(|| format!("cannot resolve {key}={reference}"))?;
                resolved.insert(reference, value);
            }
            env.push((key.clone(), resolved[reference].clone()));
        }
        launch(env, resolved.into_values().collect())
    })
}

/// `inject`: replaces `{{ pw://… }}` in a template.
pub fn inject(ctx: &Context, args: &InjectArgs) -> anyhow::Result<ExitCode> {
    let template = match &args.input {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?,
        None => {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .context("cannot read the template from stdin")?;
            text
        }
    };
    let template = Zeroizing::new(template);
    let rendered = if reference::find_placeholders(&template)?.is_empty() {
        template
    } else {
        with_api(ctx, |api| {
            let resolver = Resolver::new(&api.client);
            reference::replace_placeholders(&template, |r| {
                resolver.resolve(r).map(|v| v.to_string())
            })
        })?
    };
    match &args.output {
        Some(path) => {
            fsutil::write_atomic(path, rendered.as_bytes())
                .with_context(|| format!("cannot write {}", path.display()))?;
            ctx.info(&format!("wrote {}", path.display()));
        }
        None => output::write_stdout(&rendered)?,
    }
    Ok(ExitCode::SUCCESS)
}

/// The TOTP secret of an item: the named custom field, else the first TOTP field.
pub fn totp_secret<'a>(item: &'a Item, field: Option<&str>) -> anyhow::Result<&'a str> {
    match field {
        Some(name) => match item.custom(name) {
            Some(c) => Ok(&c.value),
            None => bail!(
                "item `{}` has no field `{name}`; available: {}",
                item.name,
                available_fields(item).join(", ")
            ),
        },
        None => item
            .customs
            .iter()
            .find(|c| c.kind == CustomKind::Totp)
            .map(|c| c.value.as_str())
            .with_context(|| format!("item `{}` has no TOTP field", item.name)),
    }
}

/// `totp`: the current code (JSON: `{"code", "remaining"}`).
pub fn totp(ctx: &Context, args: &TotpArgs) -> anyhow::Result<ExitCode> {
    with_api(ctx, |api| {
        let resolver = Resolver::new(&api.client);
        let item = find_item(&resolver, &args.item, args.vault.as_deref())?;
        let secret = totp_secret(&item, args.field.as_deref())?;
        let (code, remaining) = totp_code(secret)?;
        match ctx.format {
            Format::Json => output::print_json(&serde_json::json!({
                "code": code, "remaining": remaining
            }))?,
            Format::Table => output::write_stdout(&format!("{code}\n"))?,
        }
        Ok(ExitCode::SUCCESS)
    })
}

#[cfg(test)]
mod tests {
    use pwk_api::CustomField;

    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn environment_merging() {
        let process = pairs(&[
            ("HOME", "/h"),
            ("DB", "pw://V/db/password"),
            ("X", "pw://V/x/login"),
        ]);
        let files = pairs(&[
            ("A", "1"),
            ("X", "plain"),
            ("A", "2"),
            ("T", "pw://V/t/otp"),
        ]);
        let vars = run_environment(&files, process);
        assert_eq!(
            vars,
            pairs(&[
                ("DB", "pw://V/db/password"),
                ("X", "plain"),
                ("A", "2"),
                ("T", "pw://V/t/otp")
            ])
        );
    }

    #[test]
    fn totp_field_selection() {
        let mut item = Item::default();
        item.name = "I".into();
        item.customs = vec![
            CustomField::new("note", "n", CustomKind::Text),
            CustomField::new("2fa", "JBSWY3DPEHPK3PXP", CustomKind::Totp),
        ];
        assert_eq!(totp_secret(&item, None).unwrap(), "JBSWY3DPEHPK3PXP");
        assert_eq!(totp_secret(&item, Some("NOTE")).unwrap(), "n");
        assert!(
            totp_secret(&item, Some("x"))
                .unwrap_err()
                .to_string()
                .contains("available")
        );
        item.customs.truncate(1);
        assert!(totp_secret(&item, None).is_err());
    }
}
