//! `login`, `unlock` and `status`.

use std::io::{BufRead as _, IsTerminal as _, Read as _, Write as _};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use pwk_api::{MemoryTokenStore, SecretString, SessionInfo, TokenStore, Tokens};
use serde::Serialize;
use zeroize::Zeroizing;

use super::Context;
use super::client::{Api, Mode, build_client, client_config};
use crate::cli::{LoginArgs, UnlockArgs};
use crate::config::{self, parse_host};
use crate::output::{self, Format, format_timestamp};
use crate::prompt;
use crate::session::{self, CredentialSource, SessionFile};

/// Default lifetime of an unlock.
pub const DEFAULT_UNLOCK_TIMEOUT: Duration = Duration::from_secs(12 * 3600);

/// `user name (login)`, whatever the session info provides.
#[must_use]
pub fn user_label(info: &SessionInfo) -> String {
    match (info.user_name(), info.user_login()) {
        (Some(name), Some(login)) if name != login => format!("{name} ({login})"),
        (Some(name), _) => name.to_owned(),
        (None, Some(login)) => login.to_owned(),
        (None, None) => "unknown user".to_owned(),
    }
}

/// The access token (first line) and optional refresh token (second line) of
/// `login --access-token-stdin`.
pub fn parse_token_lines(text: &str) -> anyhow::Result<(String, Option<String>)> {
    let mut lines = text.lines().map(str::trim);
    let access = lines.next().unwrap_or_default();
    if access.is_empty() {
        bail!("no access token on stdin");
    }
    let refresh = lines.next().filter(|r| !r.is_empty()).map(str::to_owned);
    Ok((access.to_owned(), refresh))
}

fn read_tokens(from_stdin: bool) -> anyhow::Result<(String, Option<String>)> {
    if from_stdin {
        let mut text = Zeroizing::new(String::new());
        std::io::stdin()
            .read_to_string(&mut text)
            .context("cannot read the tokens from stdin")?;
        return parse_token_lines(&text);
    }
    let access = prompt::read_hidden("Access token: ")?;
    if access.trim().is_empty() {
        bail!("no access token given");
    }
    let refresh = prompt::read_hidden("Refresh token (Enter to skip): ")?;
    let refresh = Some(refresh.trim().to_owned()).filter(|r| !r.is_empty());
    Ok((access.trim().to_owned(), refresh))
}

fn prompt_host() -> anyhow::Result<String> {
    if !std::io::stdin().is_terminal() {
        bail!("no host: pass --host URL or set one with `pwk config set host URL`");
    }
    eprint!("Passwork URL (e.g. https://passwork.example.com): ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    parse_host(&line)
}

/// The command that unlocks `profile`.
fn unlock_hint(profile: &str, is_default: bool) -> String {
    if is_default {
        "eval \"$(pwk unlock)\"".to_owned()
    } else {
        format!("eval \"$(pwk --profile {profile} unlock)\"")
    }
}

/// `login`: verifies the token pair against the server and stores it.
pub fn login(ctx: &Context, args: &LoginArgs) -> anyhow::Result<ExitCode> {
    if ctx.stateless()? {
        bail!(
            "PASSWORK_HOST and PASSWORK_TOKEN are set (stateless mode); `pwk login` is not needed"
        );
    }
    let (path, mut config) = ctx.load_config()?;
    let profile = ctx.profile(&config)?;
    ctx.check_new_profile(&config, &profile)?;
    let settings = config.profile(&profile);
    let host = match args.host.as_deref().or(settings.host.as_deref()) {
        Some(host) => parse_host(host)?,
        None => prompt_host()?,
    };
    let (access_token, refresh_token) = read_tokens(args.access_token_stdin)?;
    let store = Arc::new(MemoryTokenStore::new(Tokens {
        access_token,
        refresh_token,
        access_expires_at: None,
        refresh_expires_at: None,
    }));
    let client = build_client(
        client_config(&host, &settings)?,
        store.clone() as Arc<dyn TokenStore>,
    )?;
    let info = client
        .session_info()
        .with_context(|| format!("cannot log in to {host}: the server rejected the tokens"))?;
    // Unknown (error) counts as encrypted: the unlock hint is the safe advice.
    let encrypted = client.master_key_options().map_or(true, |o| o.is_some());
    // The check may have refreshed the pair.
    let tokens = store.current()?;

    config.profiles.entry(profile.clone()).or_default().host = Some(host.clone());
    if config.default_profile.is_none() {
        config.default_profile = Some(profile.clone());
    }
    config.save(&path)?;
    ctx.session(&profile)?
        .store(&SessionFile::new(host.clone(), tokens))?;

    let mut message = format!(
        "Logged in to {host} as {} (profile {profile}).",
        user_label(&info)
    );
    if encrypted {
        let hint = unlock_hint(&profile, config.is_default_profile(&profile));
        message.push_str(&format!(" Next: {hint}"));
    } else {
        message.push_str(" The server uses no client-side encryption; no unlock is needed.");
    }
    ctx.info(&message);
    Ok(ExitCode::SUCCESS)
}

fn read_master_password(args: &UnlockArgs) -> anyhow::Result<SecretString> {
    if args.password_stdin {
        prompt::read_secret_stdin("master password")
    } else {
        prompt::read_hidden("Master password: ")
    }
}

/// `unlock`: derives the master key, seals it and prints the session key.
pub fn unlock(ctx: &Context, args: &UnlockArgs) -> anyhow::Result<ExitCode> {
    if ctx.stateless()? {
        bail!(
            "stateless mode (PASSWORK_HOST/PASSWORK_TOKEN): set PASSWORK_MASTER_KEY instead of unlocking"
        );
    }
    let api = Api::connect_raw(ctx)?;
    unlock_with(ctx, &api, args).map_err(|e| api.explain(e))
}

fn unlock_with(ctx: &Context, api: &Api, args: &UnlockArgs) -> anyhow::Result<ExitCode> {
    let Mode::Profile {
        profile,
        is_default,
        session,
        settings,
        ..
    } = &api.mode
    else {
        bail!("unlock needs a profile session");
    };
    if !api.client.detect_encryption()? {
        ctx.info("the server uses no client-side encryption; no unlock is needed");
        return Ok(ExitCode::SUCCESS);
    }
    let password = read_master_password(args)?;
    let master_key = api
        .client
        .unlock_with_password(&password)
        .map_err(|e| match e {
            pwk_api::Error::WrongMasterKey => anyhow::anyhow!("wrong master password"),
            other => anyhow::Error::new(other).context("cannot unlock"),
        })?;
    let timeout = args
        .timeout
        .or(settings.session_timeout)
        .map_or(DEFAULT_UNLOCK_TIMEOUT, |t| t.get());
    let (session_key, unlock) = session::seal_master_key(profile, &master_key, timeout)?;
    let expires_at = unlock.expires_at;
    session.modify(|file| {
        file.unlock = Some(unlock);
        Ok(())
    })?;
    let line = if args.raw {
        Zeroizing::new(format!("{}\n", session_key.as_str()))
    } else {
        let var = session::session_env_var(profile, *is_default);
        Zeroizing::new(session::shell_export(args.shell, &var, &session_key))
    };
    output::write_stdout(&line)?;
    ctx.info(&format!(
        "unlocked profile {profile} until {}",
        format_timestamp(expires_at)
    ));
    Ok(ExitCode::SUCCESS)
}

/// What `status` reports.
#[derive(Debug, Default, Serialize)]
pub struct Status {
    /// `profile` or `stateless`.
    pub mode: &'static str,
    /// Profile name (profile mode).
    pub profile: Option<String>,
    /// Server URL.
    pub host: Option<String>,
    /// Whether a token pair is stored or given.
    pub logged_in: bool,
    /// User from `sessions/current/info`.
    pub user: Option<String>,
    /// Why the user could not be determined.
    pub user_error: Option<String>,
    /// Whether the server uses client-side encryption (`None`: unknown).
    pub encryption: Option<bool>,
    /// Whether decryption is impossible right now.
    pub locked: bool,
    /// Why it is locked.
    pub locked_reason: Option<String>,
    /// End of the unlock, Unix seconds.
    pub unlocked_until: Option<u64>,
    /// Access token expiry, Unix seconds, if known.
    pub access_expires_at: Option<u64>,
    /// Refresh token expiry, Unix seconds, if known.
    pub refresh_expires_at: Option<u64>,
}

/// `status`.
pub fn status(ctx: &Context) -> anyhow::Result<ExitCode> {
    let mut report = Status::default();
    if let CredentialSource::Stateless { host, .. } =
        session::detect_credentials(&config::process_env)?
    {
        report.mode = "stateless";
        report.host = Some(host);
    } else {
        report.mode = "profile";
        let (_, config) = ctx.load_config()?;
        let profile = ctx.profile(&config)?;
        let file = ctx.session(&profile)?.load()?;
        report.profile = Some(profile);
        report.host = file.as_ref().map(|f| f.host.clone()).or_else(|| {
            config
                .profile(report.profile.as_deref().unwrap_or_default())
                .host
        });
        if let Some(file) = &file {
            report.access_expires_at = file.tokens.access_expires_at;
            report.refresh_expires_at = file.tokens.refresh_expires_at;
        }
        if file.is_none() {
            report.locked = true;
            report.locked_reason = Some("not logged in: run `pwk login`".to_owned());
            return print_status(ctx, &report);
        }
    }
    report.logged_in = true;
    let api = Api::connect_raw(ctx)?;
    fill_from_server(&api, &mut report);
    match api.available_master_key() {
        Ok(_) => {
            if let Mode::Profile { file, .. } = &api.mode
                && !api.has_env_master_key()
            {
                report.unlocked_until = file.unlock.as_ref().map(|u| u.expires_at);
            }
        }
        Err(reason) if report.encryption != Some(false) => {
            report.locked = true;
            report.locked_reason = Some(reason);
        }
        Err(_) => {}
    }
    print_status(ctx, &report)
}

/// User and encryption from the server; errors are recorded, not fatal.
fn fill_from_server(api: &Api, report: &mut Status) {
    match api.client.session_info() {
        Ok(info) => report.user = Some(user_label(&info)),
        Err(e) => report.user_error = Some(format!("{:#}", api.explain(e.into()))),
    }
    report.encryption = api.client.master_key_options().ok().map(|o| o.is_some());
    // Tokens may have been refreshed by the calls above.
    if let Mode::Profile { session, .. } = &api.mode
        && let Ok(Some(file)) = session.load()
    {
        report.access_expires_at = file.tokens.access_expires_at;
        report.refresh_expires_at = file.tokens.refresh_expires_at;
    }
}

fn print_status(ctx: &Context, report: &Status) -> anyhow::Result<ExitCode> {
    if ctx.format == Format::Json {
        output::print_json(report)?;
        return Ok(ExitCode::SUCCESS);
    }
    let mut pairs: Vec<(String, String)> = Vec::new();
    if report.mode == "stateless" {
        pairs.push((
            "mode".into(),
            "stateless (PASSWORK_HOST/PASSWORK_TOKEN)".into(),
        ));
    }
    if let Some(p) = &report.profile {
        pairs.push(("profile".into(), p.clone()));
    }
    pairs.push((
        "host".into(),
        report.host.clone().unwrap_or_else(|| "-".into()),
    ));
    if report.logged_in {
        let user = match (&report.user, &report.user_error) {
            (Some(u), _) => u.clone(),
            (None, Some(e)) => format!("unknown ({e})"),
            (None, None) => "unknown".into(),
        };
        pairs.push(("user".into(), user));
        pairs.push(("state".into(), lock_state(report)));
    } else {
        pairs.push(("session".into(), "not logged in: run `pwk login`".into()));
    }
    if let Some(t) = report.access_expires_at {
        pairs.push(("access token expires".into(), format_timestamp(t)));
    }
    if let Some(t) = report.refresh_expires_at {
        pairs.push(("refresh token expires".into(), format_timestamp(t)));
    }
    output::write_stdout(&output::render_pairs(&pairs))?;
    Ok(ExitCode::SUCCESS)
}

fn lock_state(report: &Status) -> String {
    if report.encryption == Some(false) {
        return "no client-side encryption (no unlock needed)".into();
    }
    if report.locked {
        return report
            .locked_reason
            .clone()
            .unwrap_or_else(|| "locked".into());
    }
    match report.unlocked_until {
        Some(t) => format!("unlocked until {}", format_timestamp(t)),
        None => "unlocked (PASSWORK_MASTER_KEY)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_lines() {
        assert_eq!(
            parse_token_lines("acc\nref\n").unwrap(),
            ("acc".to_owned(), Some("ref".to_owned()))
        );
        assert_eq!(
            parse_token_lines("acc\r\n").unwrap(),
            ("acc".to_owned(), None)
        );
        assert_eq!(
            parse_token_lines("acc\n\n").unwrap(),
            ("acc".to_owned(), None)
        );
        assert!(parse_token_lines("").is_err());
        assert!(parse_token_lines("\nref").is_err());
    }

    #[test]
    fn user_labels() {
        let info = |v: serde_json::Value| SessionInfo(v);
        assert_eq!(
            user_label(&info(
                serde_json::json!({"user": {"name": "Ann", "login": "ann"}})
            )),
            "Ann (ann)"
        );
        assert_eq!(
            user_label(&info(serde_json::json!({"login": "ann"}))),
            "ann"
        );
        assert_eq!(user_label(&info(serde_json::json!({}))), "unknown user");
    }

    #[test]
    fn lock_states() {
        let mut s = Status {
            locked: true,
            locked_reason: Some("locked: x".into()),
            ..Status::default()
        };
        assert_eq!(lock_state(&s), "locked: x");
        s.encryption = Some(false);
        assert!(lock_state(&s).starts_with("no client-side encryption"));
        let s = Status {
            unlocked_until: Some(0),
            ..Status::default()
        };
        assert_eq!(lock_state(&s), "unlocked until 1970-01-01 00:00:00 UTC");
    }
}
