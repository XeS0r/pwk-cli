//! The command line (clap derive). See docs/design.md, "Command line".

use std::path::PathBuf;
use std::str::FromStr;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::config::HumanDuration;
use crate::output::Format;
use crate::reference::Reference;
use crate::session::ShellSyntax;

/// Command line client for Passwork 7.
#[derive(Debug, Parser)]
#[command(name = "pwk", version, propagate_version = true, max_term_width = 100)]
pub struct Cli {
    /// Profile to use (default: default_profile from the config, else "default").
    #[arg(
        short = 'p',
        long,
        env = "PWK_PROFILE",
        global = true,
        value_name = "NAME"
    )]
    pub profile: Option<String>,

    /// Output format (default: table on a terminal, json otherwise).
    #[arg(long, env = "PWK_FORMAT", global = true, value_enum)]
    pub format: Option<Format>,

    /// Print no informational messages.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// The effective output format.
    #[must_use]
    pub fn format(&self) -> Format {
        Format::resolve(self.format)
    }
}

/// Commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Log in, unlock and manage the session.
    #[command(subcommand)]
    Auth(AuthCommand),

    // Objects
    /// Manage vaults.
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Manage folders.
    #[command(subcommand)]
    Folder(FolderCommand),
    /// Manage items (passwords), their attachments, one-time codes and shortcuts.
    #[command(subcommand)]
    Item(ItemCommand),

    // Secrets in scripts
    /// Print one secret value given by a pw:// reference.
    Read(ReadArgs),
    /// Run a command with pw:// references in its environment resolved.
    Run(RunArgs),
    /// Replace {{ pw://… }} placeholders in a template.
    Inject(InjectArgs),
    /// Print a random password (nothing is stored).
    Generate(GenerateArgs),

    // Tools
    /// Send a raw API request and print the JSON response.
    Api(ApiArgs),
    /// Show and change the configuration and the profiles.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Print a shell completion script.
    Completions(CompletionsArgs),
    /// Write man pages for pwk and its subcommands into a directory.
    #[command(hide = true)]
    GenerateMan(GenerateManArgs),

    // Hidden short forms of the session commands (`pwk unlock` = `pwk auth unlock`).
    /// Short form of `auth login`.
    #[command(hide = true)]
    Login(LoginArgs),
    /// Short form of `auth logout`.
    #[command(hide = true)]
    Logout,
    /// Short form of `auth unlock`.
    #[command(hide = true)]
    Unlock(UnlockArgs),
    /// Short form of `auth lock`.
    #[command(hide = true)]
    Lock,
    /// Short form of `auth status`.
    #[command(hide = true)]
    Status,
    /// Former name of `auth handler`; desktop entries of earlier installs call it.
    #[command(subcommand, hide = true)]
    UrlHandler(UrlHandlerCommand),
}

/// `auth` subcommands.
#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Store the host and a token pair for a profile.
    Login(LoginArgs),
    /// Forget the tokens and the session of a profile.
    Logout,
    /// Unlock with the master password and print the session key as a shell command.
    Unlock(UnlockArgs),
    /// Forget the encrypted master key.
    Lock,
    /// Show profile, host, user and whether the session is unlocked.
    Status,
    /// Route passwork:// sign-in links to `pwk auth login --web` (Linux/XDG desktops).
    #[command(subcommand)]
    Handler(UrlHandlerCommand),
}

// ---------------------------------------------------------------------------------------
// Session

/// Arguments of `login`.
#[derive(Debug, Clone, Args)]
pub struct LoginArgs {
    /// Server URL, e.g. https://passwork.example.com (default: the profile's host).
    #[arg(long, value_name = "URL")]
    pub host: Option<String>,
    /// Read the access token (first line) and the refresh token (second line, optional)
    /// from stdin instead of asking for them.
    #[arg(long, conflicts_with = "web")]
    pub access_token_stdin: bool,
    /// Sign in through the web interface instead of with an API token pair. The browser
    /// hands the sign-in back via `pwk auth handler install`, or paste the
    /// passwork://login?desktopToken=… link.
    #[arg(long)]
    pub web: bool,
    /// With --web: print the sign-in link instead of opening the browser.
    #[arg(long, requires = "web")]
    pub no_browser: bool,
    /// With --web: store the session without asking to confirm the signed-in user.
    #[arg(short = 'y', long, requires = "web")]
    pub yes: bool,
}

/// Arguments of `unlock`.
#[derive(Debug, Clone, Args)]
pub struct UnlockArgs {
    /// Read the master password from stdin instead of asking for it.
    #[arg(long)]
    pub password_stdin: bool,
    /// How long the unlock lasts, e.g. 30m, 12h, 1d (default: session_timeout or 12h).
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<HumanDuration>,
    /// Print only the session key.
    #[arg(long, conflicts_with = "shell")]
    pub raw: bool,
    /// Shell syntax of the printed command.
    #[arg(long, value_enum, default_value_t = ShellSyntax::Sh)]
    pub shell: ShellSyntax,
}

// ---------------------------------------------------------------------------------------
// Vaults

/// `vault` subcommands.
#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// List vaults.
    List,
    /// Show a vault.
    Get {
        /// Vault name or ID.
        vault: String,
    },
    /// Create a vault.
    Create {
        /// Name of the new vault.
        name: String,
        /// Vault type code (see the server's vault types).
        #[arg(long = "type", value_name = "CODE")]
        vault_type: Option<String>,
    },
    /// Delete a vault.
    Delete {
        /// Vault name or ID.
        vault: String,
    },
}

// ---------------------------------------------------------------------------------------
// Folders

/// `folder` subcommands.
#[derive(Debug, Subcommand)]
pub enum FolderCommand {
    /// List folders.
    List {
        /// Only folders of this vault.
        #[arg(long, value_name = "VAULT")]
        vault: Option<String>,
        /// Only direct subfolders of this folder.
        #[arg(long, value_name = "FOLDER")]
        parent: Option<String>,
    },
    /// Show a folder.
    Get {
        /// Folder name or ID.
        folder: String,
    },
    /// Create a folder.
    Create {
        /// Name of the new folder.
        name: String,
        /// Vault to create it in.
        #[arg(long, value_name = "VAULT")]
        vault: String,
        /// Parent folder (default: the vault root).
        #[arg(long, value_name = "FOLDER")]
        parent: Option<String>,
    },
    /// Rename a folder.
    Rename {
        /// Folder name or ID.
        folder: String,
        /// New name.
        name: String,
    },
    /// Move a folder to another vault or parent.
    Move {
        /// Folder name or ID.
        folder: String,
        /// Target vault.
        #[arg(long, value_name = "VAULT")]
        vault: Option<String>,
        /// Target parent folder.
        #[arg(long, value_name = "FOLDER")]
        parent: Option<String>,
    },
    /// Delete a folder.
    Delete {
        /// Folder name or ID.
        folder: String,
    },
}

// ---------------------------------------------------------------------------------------
// Items

/// `item` subcommands.
#[derive(Debug, Subcommand)]
pub enum ItemCommand {
    /// List items.
    List(ItemFilter),
    /// Search items by name, login, URL and tags.
    Search {
        /// Search text.
        query: String,
        #[command(flatten)]
        filter: ItemFilter,
    },
    /// Show an item.
    Get(ItemGetArgs),
    /// Create an item.
    Create(ItemCreateArgs),
    /// Change an item.
    Edit(ItemEditArgs),
    /// Move an item to another vault or folder.
    Move {
        /// Item name or ID.
        item: String,
        /// Target vault.
        #[arg(long, value_name = "VAULT")]
        vault: Option<String>,
        /// Target folder.
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,
    },
    /// Delete an item.
    Delete {
        /// Item name or ID.
        item: String,
    },
    /// Print the current one-time code of an item.
    Totp(TotpArgs),
    /// Manage the attachments of an item.
    #[command(subcommand)]
    Attachment(AttachmentCommand),
    /// Manage shortcuts to items in other vaults.
    #[command(subcommand)]
    Shortcut(ShortcutCommand),
}

/// Filters of `item list` and `item search`.
#[derive(Debug, Clone, Default, Args)]
pub struct ItemFilter {
    /// Only items in this vault.
    #[arg(long, value_name = "VAULT")]
    pub vault: Option<String>,
    /// Only items in this folder.
    #[arg(long, value_name = "FOLDER")]
    pub folder: Option<String>,
    /// Only items with this tag (repeat for several).
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
}

/// Arguments of `item get`.
#[derive(Debug, Clone, Args)]
pub struct ItemGetArgs {
    /// Item name or ID.
    pub item: String,
    /// Print only the raw value of this field.
    #[arg(long, value_name = "NAME")]
    pub field: Option<String>,
    /// Show passwords in the table view.
    #[arg(long)]
    pub reveal: bool,
    /// Vault to look the item name up in.
    #[arg(long, value_name = "VAULT")]
    pub vault: Option<String>,
}

/// Field options shared by `item create` and `item edit`.
#[derive(Debug, Clone, Default, Args)]
pub struct ItemFieldArgs {
    /// Login (user name).
    #[arg(long, value_name = "LOGIN")]
    pub login: Option<String>,
    /// Read the password from stdin.
    #[arg(long, conflicts_with = "generate_password")]
    pub password_stdin: bool,
    /// Generate a random password (default length 32).
    #[arg(
        long,
        value_name = "LEN",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "32",
        value_parser = clap::value_parser!(u16).range(4..=1024)
    )]
    pub generate_password: Option<u16>,
    /// URL (repeat for several).
    #[arg(long = "url", value_name = "URL")]
    pub urls: Vec<String>,
    /// Description.
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,
    /// Tag (repeat for several; replaces all tags on edit).
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
    /// Color code.
    #[arg(long, value_name = "N")]
    pub color: Option<u8>,
    /// Fields to set: name=value, name[password]=value, name[totp]=value; on edit,
    /// name= removes a custom field. password, login, name, url and description set
    /// the standard fields.
    #[arg(value_name = "FIELD=VALUE")]
    pub assignments: Vec<Assignment>,
}

/// Arguments of `item create`.
#[derive(Debug, Clone, Args)]
pub struct ItemCreateArgs {
    /// Vault to create the item in.
    #[arg(long, value_name = "VAULT")]
    pub vault: String,
    /// Folder to create the item in (default: the vault root).
    #[arg(long, value_name = "FOLDER")]
    pub folder: Option<String>,
    /// Name of the item.
    #[arg(long, value_name = "NAME")]
    pub name: String,
    #[command(flatten)]
    pub fields: ItemFieldArgs,
}

/// Arguments of `item edit`.
#[derive(Debug, Clone, Args)]
pub struct ItemEditArgs {
    /// Item name or ID.
    pub item: String,
    /// Vault to look the item name up in.
    #[arg(long, value_name = "VAULT")]
    pub vault: Option<String>,
    /// New name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    #[command(flatten)]
    pub fields: ItemFieldArgs,
}

/// Type of a custom field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
pub enum FieldKind {
    /// Plain text.
    Text,
    /// Hidden secret.
    Password,
    /// TOTP secret (Base32 or otpauth:// URI).
    Totp,
}

impl FieldKind {
    /// The custom field `type` used by Passwork.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Password => "password",
            Self::Totp => "totp",
        }
    }
}

/// Standard (non-custom) item fields addressable by `field=value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StandardField {
    /// `password`
    Password,
    /// `login`
    Login,
    /// `name`
    Name,
    /// `url`
    Url,
    /// `description`
    Description,
}

impl StandardField {
    /// The standard field called `name` (exact, lower case).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "password" => Self::Password,
            "login" => Self::Login,
            "name" => Self::Name,
            "url" => Self::Url,
            "description" => Self::Description,
            _ => return None,
        })
    }
}

/// A trailing `field=value`, `field[kind]=value` or `field=` (remove) argument.
#[derive(Clone, PartialEq, Eq)]
pub struct Assignment {
    /// Field name.
    pub name: String,
    /// `[kind]`, if given (custom fields only).
    pub kind: Option<FieldKind>,
    /// New value; `None` removes the field (`field=`).
    pub value: Option<String>,
}

impl std::fmt::Debug for Assignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Assignment")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &self.value.as_ref().map(|_| ".."))
            .finish()
    }
}

impl Assignment {
    /// The standard field this assignment sets, if its name is reserved.
    #[must_use]
    pub fn standard(&self) -> Option<StandardField> {
        StandardField::from_name(&self.name)
    }
}

impl FromStr for Assignment {
    type Err = String;

    /// Error messages name the field only; the value (or an argument without `=`,
    /// which may be a mistyped secret) is never echoed.
    fn from_str(arg: &str) -> Result<Self, String> {
        let (lhs, value) = arg.split_once('=').ok_or_else(|| {
            "expected FIELD=VALUE, got an argument without `=` (not shown, it may be a \
             secret)"
                .to_owned()
        })?;
        let (name, kind) = match lhs.strip_suffix(']') {
            Some(head) => {
                let (name, kind) = head
                    .rsplit_once('[')
                    .ok_or_else(|| format!("`{lhs}`: unbalanced `]`"))?;
                let kind = FieldKind::from_str(kind, true).map_err(|_| {
                    format!("`{lhs}`: unknown field type `{kind}` (use text, password or totp)")
                })?;
                (name, Some(kind))
            }
            None => (lhs, None),
        };
        if name.is_empty() {
            return Err("field name is empty in a FIELD=VALUE argument".to_owned());
        }
        if name.contains(['[', ']']) {
            return Err(format!("`{lhs}`: field name must not contain `[` or `]`"));
        }
        if kind.is_some() && StandardField::from_name(name).is_some() {
            return Err(format!(
                "`{lhs}`: {name} is a standard field and takes no type"
            ));
        }
        Ok(Self {
            name: name.to_owned(),
            kind,
            value: (!value.is_empty()).then(|| value.to_owned()),
        })
    }
}

// ---------------------------------------------------------------------------------------
// Attachments and shortcuts

/// `attachment` subcommands.
#[derive(Debug, Subcommand)]
pub enum AttachmentCommand {
    /// List the attachments of an item.
    List {
        /// Item name or ID.
        item: String,
    },
    /// Download an attachment.
    Get {
        /// Item name or ID.
        item: String,
        /// Attachment ID or file name.
        attachment: String,
        /// Output file, or - for stdout (default: the attachment's name).
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Upload a file as attachment.
    Add {
        /// Item name or ID.
        item: String,
        /// File to upload.
        file: PathBuf,
        /// Attachment name (default: the file name).
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },
}

/// `shortcut` subcommands.
#[derive(Debug, Subcommand)]
pub enum ShortcutCommand {
    /// List shortcuts, optionally matching a search text.
    List {
        /// Search text.
        query: Option<String>,
    },
    /// Show a shortcut.
    Get {
        /// Shortcut name or ID.
        shortcut: String,
    },
    /// Create a shortcut to an item.
    Create {
        /// Item name or ID.
        item: String,
        /// Vault to put the shortcut in.
        #[arg(long, value_name = "VAULT")]
        vault: String,
        /// Folder to put the shortcut in.
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,
    },
    /// Delete a shortcut.
    Delete {
        /// Shortcut name or ID.
        shortcut: String,
    },
}

// ---------------------------------------------------------------------------------------
// Secrets in scripts

/// Arguments of `read`.
#[derive(Debug, Clone, Args)]
pub struct ReadArgs {
    /// Reference: pw://vault/[folder/…/]item/field[?attribute=totp].
    #[arg(value_name = "REFERENCE", value_parser = parse_reference)]
    pub reference: Reference,
}

fn parse_reference(text: &str) -> Result<Reference, String> {
    text.parse()
        .map_err(|e: crate::reference::ReferenceError| e.reason)
}

/// Arguments of `run`.
#[derive(Debug, Clone, Args)]
pub struct RunArgs {
    /// Read variables from a dotenv file (repeat for several; later files win).
    #[arg(long = "env-file", value_name = "FILE")]
    pub env_files: Vec<PathBuf>,
    /// Do not mask secrets in the command's output.
    #[arg(long)]
    pub no_masking: bool,
    /// The command and its arguments, after `--`.
    #[arg(last = true, required = true, value_name = "CMD")]
    pub command: Vec<String>,
}

/// Arguments of `inject`.
#[derive(Debug, Clone, Args)]
pub struct InjectArgs {
    /// Template file (default: stdin).
    #[arg(short, long, value_name = "FILE")]
    pub input: Option<PathBuf>,
    /// Output file, created with mode 0600 (default: stdout).
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// Arguments of `totp`.
#[derive(Debug, Clone, Args)]
pub struct TotpArgs {
    /// Item name or ID.
    pub item: String,
    /// TOTP field name (default: the first TOTP field).
    #[arg(long, value_name = "NAME")]
    pub field: Option<String>,
    /// Vault to look the item name up in.
    #[arg(long, value_name = "VAULT")]
    pub vault: Option<String>,
}

/// Arguments of `generate`.
#[derive(Debug, Clone, Args)]
pub struct GenerateArgs {
    /// Number of characters.
    #[arg(
        short,
        long,
        default_value_t = 32,
        value_parser = clap::value_parser!(u16).range(4..=1024)
    )]
    pub length: u16,
    /// Only letters and digits.
    #[arg(long)]
    pub no_symbols: bool,
}

// ---------------------------------------------------------------------------------------
// Tools

/// HTTP method of `api`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "UPPER")]
pub enum Method {
    /// GET
    Get,
    /// POST
    Post,
    /// PUT
    Put,
    /// PATCH
    Patch,
    /// DELETE
    Delete,
}

impl Method {
    /// Upper-case name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// Request body of `api --data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiData {
    /// Inline JSON text.
    Json(String),
    /// `@file`: JSON read from a file.
    File(PathBuf),
    /// `-`: JSON read from stdin.
    Stdin,
}

impl FromStr for ApiData {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        Ok(if text == "-" {
            Self::Stdin
        } else if let Some(path) = text.strip_prefix('@') {
            if path.is_empty() {
                return Err("`@` needs a file name".into());
            }
            Self::File(PathBuf::from(path))
        } else {
            Self::Json(text.to_owned())
        })
    }
}

/// Arguments of `api`.
#[derive(Debug, Clone, Args)]
pub struct ApiArgs {
    /// HTTP method.
    #[arg(value_enum, ignore_case = true)]
    pub method: Method,
    /// API path, e.g. /api/v1/vaults.
    pub path: String,
    /// Request body: JSON, @FILE or - for stdin.
    #[arg(long, value_name = "JSON|@FILE|-")]
    pub data: Option<ApiData>,
    /// Query parameter (repeat for several).
    #[arg(long, value_name = "KEY=VALUE", value_parser = parse_key_value)]
    pub query: Vec<(String, String)>,
}

fn parse_key_value(text: &str) -> Result<(String, String), String> {
    match text.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_owned(), value.to_owned())),
        _ => Err(format!("`{text}` is not KEY=VALUE")),
    }
}

/// `auth handler` subcommands.
#[derive(Debug, Subcommand)]
pub enum UrlHandlerCommand {
    /// Make pwk the passwork:// handler; other links go on to the previous handler.
    Install,
    /// Restore the previous passwork:// handler.
    Uninstall,
    /// Show which program handles passwork:// links.
    Status,
    /// Handle one link (the command of pwk's desktop entry).
    #[command(hide = true)]
    Open {
        /// The passwork:// link.
        url: String,
        /// State directory of the waiting `login --web` (fixed at install time).
        #[arg(long, value_name = "DIR")]
        state_dir: Option<PathBuf>,
    },
}

/// `config` subcommands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the configuration.
    Show,
    /// Set a value: default_profile, or host, ca_cert, insecure, session_timeout of the
    /// current profile (or profiles.NAME.KEY).
    Set {
        /// Key.
        key: String,
        /// Value.
        value: String,
    },
    /// Remove a value.
    Unset {
        /// Key.
        key: String,
    },
    /// List, select and remove profiles.
    #[command(subcommand)]
    Profile(ProfileCommand),
}

/// `profile` subcommands.
#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List profiles from the config and the stored sessions.
    List,
    /// Make a profile the default.
    Use {
        /// Profile name.
        name: String,
    },
    /// Remove a profile's settings and session.
    Remove {
        /// Profile name.
        name: String,
    },
}

/// Arguments of `completions`.
#[derive(Debug, Clone, Args)]
pub struct CompletionsArgs {
    /// The shell.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// Arguments of `generate-man`.
#[derive(Debug, Clone, Args)]
pub struct GenerateManArgs {
    /// Output directory (created if missing).
    pub dir: PathBuf,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("pwk").chain(args.iter().copied()))
    }

    #[test]
    fn command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn assignments() {
        let a = |s: &str| s.parse::<Assignment>();
        assert_eq!(
            a("user=bob").unwrap(),
            Assignment {
                name: "user".into(),
                kind: None,
                value: Some("bob".into())
            }
        );
        let pin = a("pin[password]=12=34").unwrap();
        assert_eq!(pin.kind, Some(FieldKind::Password));
        assert_eq!(pin.value.as_deref(), Some("12=34"));
        assert_eq!(a("otp[TOTP]=JBSW").unwrap().kind, Some(FieldKind::Totp));
        assert_eq!(a("old=").unwrap().value, None);
        let pw = a("password=x").unwrap();
        assert_eq!(pw.standard(), Some(StandardField::Password));
        assert_eq!(a("Password=x").unwrap().standard(), None);
        assert!(a("novalue").is_err());
        assert!(a("=x").is_err());
        assert!(a("x[secret]=y").is_err());
        assert!(a("x]=y").is_err());
        assert!(a("a[b][text]=y").is_err());
        assert!(a("password[text]=y").is_err());
        assert!(!format!("{pw:?}").contains('x'));
        // Errors never show the value.
        for bad in [
            "s3cr3t-value",
            "=s3cr3t-value",
            "a[b]c]=s3cr3t-value",
            "x[secret]=s3cr3t-value",
            "x]=s3cr3t-value",
            "password[text]=s3cr3t-value",
        ] {
            let err = a(bad).unwrap_err();
            assert!(!err.contains("s3cr3t"), "{bad}: {err}");
        }
    }

    #[test]
    fn item_create() {
        let cli = parse(&[
            "item",
            "create",
            "--vault",
            "V",
            "--name",
            "N",
            "--generate-password",
            "--url",
            "https://a",
            "--url",
            "https://b",
            "pin[password]=1234",
            "note=hi",
        ])
        .unwrap();
        let Command::Item(ItemCommand::Create(args)) = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(args.fields.generate_password, Some(32));
        assert_eq!(args.fields.urls.len(), 2);
        assert_eq!(args.fields.assignments.len(), 2);

        let cli = parse(&[
            "item",
            "create",
            "--vault",
            "V",
            "--name",
            "N",
            "--generate-password=20",
        ])
        .unwrap();
        let Command::Item(ItemCommand::Create(args)) = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(args.fields.generate_password, Some(20));
        assert!(
            parse(&[
                "item",
                "create",
                "--vault",
                "V",
                "--name",
                "N",
                "--password-stdin",
                "--generate-password"
            ])
            .is_err()
        );
        assert!(parse(&["item", "create", "--name", "N"]).is_err());
    }

    #[test]
    fn item_edit_removal() {
        let cli = parse(&["item", "edit", "Mail", "old=", "login=bob"]).unwrap();
        let Command::Item(ItemCommand::Edit(args)) = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(args.item, "Mail");
        assert_eq!(args.fields.assignments[0].value, None);
        assert_eq!(
            args.fields.assignments[1].standard(),
            Some(StandardField::Login)
        );
    }

    #[test]
    fn run_needs_double_dash() {
        let cli = parse(&["run", "--env-file", "a.env", "--", "env", "-i", "--x"]).unwrap();
        let Command::Run(args) = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(args.command, vec!["env", "-i", "--x"]);
        assert_eq!(args.env_files, vec![PathBuf::from("a.env")]);
        assert!(parse(&["run"]).is_err());
        assert!(parse(&["run", "env"]).is_err());
    }

    #[test]
    fn api_args() {
        let cli = parse(&[
            "api",
            "post",
            "/api/v1/x",
            "--data",
            "@body.json",
            "--query",
            "a=1",
            "--query",
            "b=",
        ])
        .unwrap();
        let Command::Api(args) = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(args.method, Method::Post);
        assert_eq!(args.data, Some(ApiData::File("body.json".into())));
        assert_eq!(
            args.query,
            vec![("a".into(), "1".into()), ("b".into(), String::new())]
        );
        assert_eq!("-".parse::<ApiData>().unwrap(), ApiData::Stdin);
        assert_eq!("{}".parse::<ApiData>().unwrap(), ApiData::Json("{}".into()));
        assert!(parse(&["api", "FETCH", "/x"]).is_err());
        assert!(parse(&["api", "GET", "/x", "--query", "novalue"]).is_err());
    }

    #[test]
    fn globals_and_read() {
        let cli = parse(&[
            "read",
            "pw://V/i/password",
            "-p",
            "work",
            "--format",
            "json",
            "-q",
        ])
        .unwrap();
        assert_eq!(cli.profile.as_deref(), Some("work"));
        assert_eq!(cli.format(), Format::Json);
        assert!(cli.quiet);
        assert!(parse(&["read", "pw://V/i"]).is_err());
    }

    #[test]
    fn unlock_args() {
        let cli = parse(&["unlock", "--timeout", "30m", "--shell", "fish"]).unwrap();
        let Command::Unlock(args) = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(args.timeout.unwrap().get().as_secs(), 1800);
        assert_eq!(args.shell, ShellSyntax::Fish);
        assert!(parse(&["unlock", "--timeout", "soon"]).is_err());
        assert!(parse(&["unlock", "--raw", "--shell", "fish"]).is_err());
    }
}
