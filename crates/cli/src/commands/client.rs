//! Building a [`pwk_api::Client`] for the current context (stateless or profile mode)
//! and setting up its master key.

use std::sync::Arc;

use anyhow::Context as _;
use pwk_api::{Client, ClientConfig, MemoryTokenStore, SecretString, TokenStore};

use super::Context;
use crate::config::{self, Config, ProfileConfig};
use crate::session::{self, CredentialSource, FileTokenStore, Locked, Session, SessionFile};

/// Where the credentials of an [`Api`] come from.
#[derive(Debug)]
pub enum Mode {
    /// `PASSWORK_HOST` + `PASSWORK_TOKEN`.
    Stateless,
    /// A profile with a stored session.
    Profile {
        /// Profile name.
        profile: String,
        /// Whether it is the default profile (decides the session variable name).
        is_default: bool,
        /// Its session files.
        session: Session,
        /// The session file as read when connecting.
        file: Box<SessionFile>,
        /// The profile's settings.
        settings: ProfileConfig,
    },
}

/// A connected client plus what is needed to explain a locked state.
pub struct Api {
    /// The API client.
    pub client: Client,
    /// Credential mode.
    pub mode: Mode,
    /// `PASSWORK_MASTER_KEY`, if set.
    env_master_key: Option<SecretString>,
    /// Why no master key is available (set by [`Api::setup_keys`]).
    locked: Option<String>,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("client", &self.client)
            .field("mode", &self.mode)
            .field("locked", &self.locked)
            .finish_non_exhaustive()
    }
}

/// Security warnings for a connection to `host` with `settings`: plain `http://` and
/// disabled certificate verification. Shown on every use, even with `--quiet`.
#[must_use]
pub fn security_warnings(host: &str, settings: &ProfileConfig) -> Vec<&'static str> {
    let mut warnings = Vec::new();
    if host.starts_with("http://") {
        warnings.push(
            "the server URL uses plain http://; tokens and data are sent unencrypted \
             (use https://)",
        );
    }
    if settings.insecure == Some(true) {
        warnings.push("TLS certificate verification is disabled (insecure)");
    }
    warnings
}

/// Client settings of a profile: CA certificate and TLS verification. Prints the
/// [`security_warnings`].
pub fn client_config(host: &str, settings: &ProfileConfig) -> anyhow::Result<ClientConfig> {
    let mut config = ClientConfig::new(host);
    if let Some(path) = &settings.ca_cert {
        let pem = std::fs::read(path)
            .with_context(|| format!("cannot read CA certificate {}", path.display()))?;
        config.ca_cert_pem = Some(pem);
    }
    config.insecure = settings.insecure == Some(true);
    for warning in security_warnings(host, settings) {
        eprintln!("pwk: warning: {warning}");
    }
    Ok(config)
}

/// The TLS settings of stateless mode: `PWK_CA_CERT` (path of a PEM file) and
/// `PWK_INSECURE=1`.
pub fn stateless_settings(env: config::EnvLookup<'_>) -> anyhow::Result<ProfileConfig> {
    let ca_cert = env("PWK_CA_CERT")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from);
    let insecure = match env("PWK_INSECURE").as_deref().and_then(|v| v.to_str()) {
        None | Some("" | "0") => None,
        Some("1") => Some(true),
        Some(other) => anyhow::bail!("PWK_INSECURE must be 1 or 0, not `{other}`"),
    };
    Ok(ProfileConfig {
        ca_cert,
        insecure,
        ..ProfileConfig::default()
    })
}

/// Builds a client from `config` and a token store.
pub fn build_client(config: ClientConfig, store: Arc<dyn TokenStore>) -> anyhow::Result<Client> {
    Client::new(config, store).context("cannot set up the HTTP client")
}

impl Api {
    /// Connects without touching the master key (`unlock`, `status`, `login` checks).
    pub fn connect_raw(ctx: &Context) -> anyhow::Result<Self> {
        match session::detect_credentials(&config::process_env)? {
            CredentialSource::Stateless {
                host,
                tokens,
                master_key,
            } => {
                let settings = stateless_settings(&config::process_env)?;
                let client = build_client(
                    client_config(&host, &settings)?,
                    Arc::new(MemoryTokenStore::new(tokens)),
                )?;
                Ok(Self {
                    client,
                    mode: Mode::Stateless,
                    env_master_key: master_key,
                    locked: None,
                })
            }
            CredentialSource::Profile { master_key } => {
                let (_, config) = ctx.load_config()?;
                Self::connect_profile(ctx, &config, master_key)
            }
        }
    }

    fn connect_profile(
        ctx: &Context,
        config: &Config,
        env_master_key: Option<SecretString>,
    ) -> anyhow::Result<Self> {
        let profile = ctx.profile(config)?;
        let session = ctx.session(&profile)?;
        let Some(file) = session.load()? else {
            anyhow::bail!("not logged in: run `pwk login`");
        };
        let settings = config.profile(&profile);
        let client_config = client_config(&file.host, &settings)?;
        let client = build_client(
            client_config,
            Arc::new(FileTokenStore::new(session.clone())),
        )?;
        Ok(Self {
            client,
            mode: Mode::Profile {
                is_default: config.is_default_profile(&profile),
                profile,
                session,
                file: Box::new(file),
                settings,
            },
            env_master_key,
            locked: None,
        })
    }

    /// Connects and sets the master key if one is available (see [`Api::setup_keys`]).
    pub fn connect(ctx: &Context) -> anyhow::Result<Self> {
        let mut api = Self::connect_raw(ctx)?;
        api.setup_keys()?;
        Ok(api)
    }

    /// The master key from `PASSWORK_MASTER_KEY` or the sealed session, or why there is
    /// none (a message with the unlock hint).
    pub fn available_master_key(&self) -> Result<SecretString, String> {
        if let Some(key) = &self.env_master_key {
            return Ok(key.clone());
        }
        match &self.mode {
            Mode::Stateless => Err(
                "locked: PASSWORK_MASTER_KEY is not set (stateless mode needs the derived \
                 master key)"
                    .to_owned(),
            ),
            Mode::Profile {
                profile,
                is_default,
                file,
                ..
            } => open_seal(profile, *is_default, file).map_err(|e| e.to_string()),
        }
    }

    /// Sets the master key if `PASSWORK_MASTER_KEY` or an open seal provides one; a wrong
    /// key is an error. Without a key the client stays in its "unknown" state: plain data
    /// can be read and encrypted data fails with a "locked" message.
    pub fn setup_keys(&mut self) -> anyhow::Result<()> {
        match self.available_master_key() {
            Ok(key) => {
                self.client.set_master_key(key).map_err(|e| match e {
                    pwk_api::Error::WrongMasterKey => anyhow::anyhow!(
                        "the stored master key does not match the server's keys; {}",
                        session::UNLOCK_HINT
                    ),
                    other => anyhow::Error::new(other).context("cannot load the user keys"),
                })?;
                self.locked = None;
            }
            Err(reason) => self.locked = Some(reason),
        }
        Ok(())
    }

    /// Makes sure the client can encrypt: unlocked, or the server uses no client-side
    /// encryption (then the client is switched to plain mode).
    pub fn require_encryption_state(&self) -> anyhow::Result<()> {
        if self.client.is_unlocked() || self.client.is_plain() {
            return Ok(());
        }
        if self.client.detect_encryption()? {
            anyhow::bail!("{}", self.locked_message());
        }
        Ok(())
    }

    /// The "locked" message for this context.
    #[must_use]
    pub fn locked_message(&self) -> String {
        self.locked
            .clone()
            .unwrap_or_else(|| Locked::NotUnlocked.to_string())
    }

    /// Whether `PASSWORK_MASTER_KEY` provides the master key.
    #[must_use]
    pub fn has_env_master_key(&self) -> bool {
        self.env_master_key.is_some()
    }

    /// Profile name, if in profile mode.
    #[must_use]
    pub fn profile(&self) -> Option<&str> {
        match &self.mode {
            Mode::Stateless => None,
            Mode::Profile { profile, .. } => Some(profile),
        }
    }

    /// Replaces API errors that need a user action with a friendly message.
    #[must_use]
    pub fn explain(&self, error: anyhow::Error) -> anyhow::Error {
        let api_error = error
            .chain()
            .find_map(|c| c.downcast_ref::<pwk_api::Error>());
        match api_error {
            Some(pwk_api::Error::Locked) => anyhow::anyhow!("{}", self.locked_message()),
            Some(pwk_api::Error::SessionExpired(_)) => match self.mode {
                Mode::Stateless => error.context("set a fresh PASSWORK_TOKEN"),
                Mode::Profile { .. } => {
                    anyhow::anyhow!("{error:#}; run `pwk login` again")
                }
            },
            _ => error,
        }
    }
}

/// Opens the sealed master key of a profile with the session key from the environment.
pub fn open_seal(
    profile: &str,
    is_default: bool,
    file: &SessionFile,
) -> Result<SecretString, Locked> {
    let unlock = file.unlock.as_ref().ok_or(Locked::NotUnlocked)?;
    session::open_master_key_from_env(
        profile,
        is_default,
        unlock,
        &config::process_env,
        session::unix_now(),
    )
}

/// Connects (with keys), runs `body` and turns API errors into friendly messages.
pub fn with_api<T>(
    ctx: &Context,
    body: impl FnOnce(&Api) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let api = Api::connect(ctx)?;
    body(&api).map_err(|e| api.explain(e))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn warnings() {
        let plain = ProfileConfig::default();
        assert!(security_warnings("https://pw.example", &plain).is_empty());
        let w = security_warnings("http://pw.example", &plain);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("http://"));
        let insecure = ProfileConfig {
            insecure: Some(true),
            ..ProfileConfig::default()
        };
        assert_eq!(security_warnings("http://pw.example", &insecure).len(), 2);
    }

    #[test]
    fn stateless_tls_settings() {
        let env_of = |vars: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                vars.iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        let s = stateless_settings(&env_of(&[])).unwrap();
        assert_eq!(s, ProfileConfig::default());
        let s = stateless_settings(&env_of(&[
            ("PWK_CA_CERT", "/etc/ca.pem"),
            ("PWK_INSECURE", "1"),
        ]))
        .unwrap();
        assert_eq!(s.ca_cert, Some("/etc/ca.pem".into()));
        assert_eq!(s.insecure, Some(true));
        assert_eq!(
            stateless_settings(&env_of(&[("PWK_INSECURE", "0")]))
                .unwrap()
                .insecure,
            None
        );
        assert!(stateless_settings(&env_of(&[("PWK_INSECURE", "yes")])).is_err());
        // A missing CA file is an error when building the client config.
        let missing =
            stateless_settings(&env_of(&[("PWK_CA_CERT", "/nonexistent/ca.pem")])).unwrap();
        assert!(client_config("https://h", &missing).is_err());
    }
}
