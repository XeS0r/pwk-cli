//! One function per command. Local commands live here; commands that talk to the
//! server are in the submodules.

pub mod attachment;
pub mod auth;
pub mod client;
pub mod folder;
pub mod item;
pub mod item_fields;
pub mod raw_api;
pub mod resolve;
pub mod secrets;
pub mod shortcut;
pub mod vault;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use clap::CommandFactory as _;

use crate::cli::{
    Cli, Command, CompletionsArgs, ConfigCommand, GenerateArgs, GenerateManArgs, ProfileCommand,
};
use crate::config::{self, Config};
use crate::output::{self, Format, Table};
use crate::session::{self, CredentialSource, Session};

/// What every command gets from the global options.
#[derive(Debug, Clone)]
pub struct Context {
    /// Effective output format.
    pub format: Format,
    /// `--quiet`.
    pub quiet: bool,
    /// `--profile` / `PWK_PROFILE`.
    pub profile_arg: Option<String>,
}

impl Context {
    /// Path of `config.toml`.
    pub fn config_path(&self) -> anyhow::Result<PathBuf> {
        config::config_path(&config::process_env)
    }

    /// The configuration and its path.
    pub fn load_config(&self) -> anyhow::Result<(PathBuf, Config)> {
        let path = self.config_path()?;
        let config = Config::load(&path)?;
        Ok((path, config))
    }

    /// The selected profile (see [`config::resolve_profile`]).
    pub fn profile(&self, config: &Config) -> anyhow::Result<String> {
        config::resolve_profile(self.profile_arg.as_deref(), config)
    }

    /// The session files of `profile`.
    pub fn session(&self, profile: &str) -> anyhow::Result<Session> {
        Ok(Session::new(
            &config::state_dir(&config::process_env)?,
            profile,
        ))
    }

    /// Checks that a profile about to be created or selected does not share its session
    /// variable with another profile (configured or with a session directory).
    pub fn check_new_profile(&self, config: &Config, name: &str) -> anyhow::Result<()> {
        let sessions = session::session_profiles(&config::state_dir(&config::process_env)?)?;
        config.check_new_profile(name, sessions.iter().map(String::as_str))
    }

    /// Prints an informational message to stderr unless `--quiet`.
    pub fn info(&self, message: &str) {
        output::info(self.quiet, message);
    }

    /// True in stateless mode (`PASSWORK_HOST` + `PASSWORK_TOKEN`).
    pub fn stateless(&self) -> anyhow::Result<bool> {
        Ok(matches!(
            session::detect_credentials(&config::process_env)?,
            CredentialSource::Stateless { .. }
        ))
    }
}

/// Runs the parsed command line.
pub fn dispatch(cli: Cli) -> anyhow::Result<ExitCode> {
    let ctx = Context {
        format: cli.format(),
        quiet: cli.quiet,
        profile_arg: cli.profile.clone(),
    };
    match &cli.command {
        Command::Login(args) => auth::login(&ctx, args),
        Command::Logout => logout(&ctx),
        Command::Unlock(args) => auth::unlock(&ctx, args),
        Command::Lock => lock(&ctx),
        Command::Status => auth::status(&ctx),
        Command::Vault(cmd) => vault::run(&ctx, cmd),
        Command::Folder(cmd) => folder::run(&ctx, cmd),
        Command::Item(cmd) => item::run(&ctx, cmd),
        Command::Attachment(cmd) => attachment::run(&ctx, cmd),
        Command::Shortcut(cmd) => shortcut::run(&ctx, cmd),
        Command::Read(args) => secrets::read(&ctx, args),
        Command::Run(args) => secrets::run(&ctx, args),
        Command::Inject(args) => secrets::inject(&ctx, args),
        Command::Totp(args) => secrets::totp(&ctx, args),
        Command::Generate(args) => generate(&ctx, args),
        Command::Api(args) => raw_api::run(&ctx, args),
        Command::Config(cmd) => config_cmd(&ctx, cmd),
        Command::Profile(cmd) => profile(&ctx, cmd),
        Command::Completions(args) => completions(args),
        Command::GenerateMan(args) => generate_man(args),
    }
}

/// Exit code of a child process for `run` (codes outside 0–255 become 1).
pub fn child_exit_code(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

// ---------------------------------------------------------------------------------------
// Session

/// `logout`: deletes the session file (the lock file stays for concurrent processes).
pub fn logout(ctx: &Context) -> anyhow::Result<ExitCode> {
    if ctx.stateless()? {
        ctx.info("stateless mode (PASSWORK_HOST/PASSWORK_TOKEN): nothing stored to forget");
        return Ok(ExitCode::SUCCESS);
    }
    let (_, config) = ctx.load_config()?;
    let profile = ctx.profile(&config)?;
    if ctx.session(&profile)?.delete()? {
        ctx.info(&format!("logged out of profile {profile}"));
    } else {
        ctx.info(&format!("profile {profile} was not logged in"));
    }
    Ok(ExitCode::SUCCESS)
}

/// `lock`: removes the sealed master key from the session file.
pub fn lock(ctx: &Context) -> anyhow::Result<ExitCode> {
    if ctx.stateless()? {
        ctx.info("stateless mode (PASSWORK_HOST/PASSWORK_TOKEN): nothing stored to lock");
        return Ok(ExitCode::SUCCESS);
    }
    let (_, config) = ctx.load_config()?;
    let profile = ctx.profile(&config)?;
    if ctx.session(&profile)?.clear_unlock()? {
        ctx.info(&format!("locked profile {profile}"));
    } else {
        ctx.info(&format!("profile {profile} is not logged in"));
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------------------
// Secrets in scripts

/// `generate`: a random password on stdout (always raw, whatever `--format`).
pub fn generate(_ctx: &Context, args: &GenerateArgs) -> anyhow::Result<ExitCode> {
    let password = pwk_crypto::generate_password(usize::from(args.length), !args.no_symbols);
    let mut line = zeroize::Zeroizing::new(String::with_capacity(password.len() + 1));
    line.push_str(&password);
    line.push('\n');
    output::write_stdout(&line)?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------------------
// Tools

/// `config show|set|unset`.
pub fn config_cmd(ctx: &Context, cmd: &ConfigCommand) -> anyhow::Result<ExitCode> {
    let (path, mut config) = ctx.load_config()?;
    match cmd {
        ConfigCommand::Show => match ctx.format {
            Format::Json => output::print_json(&config)?,
            Format::Table => {
                let entries = config.entries();
                if entries.is_empty() {
                    ctx.info(&format!("no settings in {}", path.display()));
                } else {
                    let mut table = Table::new(["KEY", "VALUE"]);
                    for (key, value) in entries {
                        table.push([key, value]);
                    }
                    table.print()?;
                }
            }
        },
        ConfigCommand::Set { key, value } => {
            let profile = ctx.profile(&config)?;
            config.set(&profile, key, value)?;
            config.save(&path)?;
        }
        ConfigCommand::Unset { key } => {
            let profile = ctx.profile(&config)?;
            config.unset(&profile, key)?;
            config.save(&path)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// One row of `profile list`.
#[derive(Debug, serde::Serialize)]
struct ProfileRow {
    name: String,
    default: bool,
    host: Option<String>,
    logged_in: bool,
}

/// `profile list|use|remove`.
pub fn profile(ctx: &Context, cmd: &ProfileCommand) -> anyhow::Result<ExitCode> {
    let (path, mut config) = ctx.load_config()?;
    match cmd {
        ProfileCommand::List => {
            let state_dir = config::state_dir(&config::process_env)?;
            let sessions = session::session_profiles(&state_dir)?;
            let mut names: Vec<String> = config.profiles.keys().cloned().collect();
            names.extend(sessions.iter().cloned());
            names.extend(config.default_profile.clone());
            names.sort();
            names.dedup();
            let rows: Vec<ProfileRow> = names
                .into_iter()
                .map(|name| {
                    let settings = config.profile(&name);
                    let host = settings.host.or_else(|| {
                        Session::new(&state_dir, &name)
                            .load()
                            .ok()
                            .flatten()
                            .map(|s| s.host)
                    });
                    ProfileRow {
                        default: config.is_default_profile(&name),
                        logged_in: sessions.contains(&name),
                        host,
                        name,
                    }
                })
                .collect();
            match ctx.format {
                Format::Json => output::print_json(&rows)?,
                Format::Table => {
                    let mut table = Table::new(["NAME", "DEFAULT", "HOST", "SESSION"]);
                    for row in rows {
                        table.push([
                            row.name,
                            if row.default { "*" } else { "" }.to_owned(),
                            row.host.unwrap_or_default(),
                            if row.logged_in { "logged in" } else { "-" }.to_owned(),
                        ]);
                    }
                    table.print()?;
                }
            }
        }
        ProfileCommand::Use { name } => {
            ctx.check_new_profile(&config, name)?;
            config.default_profile = Some(name.clone());
            config.save(&path)?;
            ctx.info(&format!("default profile is now {name}"));
        }
        ProfileCommand::Remove { name } => {
            config::validate_profile_name(name)?;
            let mut changed = config.profiles.remove(name).is_some();
            if config.default_profile.as_deref() == Some(name.as_str()) {
                config.default_profile = None;
                changed = true;
            }
            let had_session = ctx.session(name)?.delete()?;
            if changed {
                config.save(&path)?;
            }
            if !changed && !had_session {
                bail!("no profile named {name}");
            }
            ctx.info(&format!("removed profile {name}"));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `completions <shell>`: the completion script on stdout.
pub fn completions(args: &CompletionsArgs) -> anyhow::Result<ExitCode> {
    let mut command = Cli::command();
    clap_complete::generate(args.shell, &mut command, "pwk", &mut std::io::stdout());
    Ok(ExitCode::SUCCESS)
}

/// `generate-man <dir>`: one man page per command and subcommand.
pub fn generate_man(args: &GenerateManArgs) -> anyhow::Result<ExitCode> {
    std::fs::create_dir_all(&args.dir)
        .with_context(|| format!("cannot create {}", args.dir.display()))?;
    clap_mangen::generate_to(Cli::command(), &args.dir)
        .with_context(|| format!("cannot write man pages to {}", args.dir.display()))?;
    Ok(ExitCode::SUCCESS)
}
