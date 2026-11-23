//! The session file (`$XDG_STATE_HOME/pwk/<profile>/session.json`): host, tokens and the
//! sealed master key; the session key environment variable; stateless mode.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use pwk_api::{TokenStore, Tokens};
use pwk_crypto::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{EnvLookup, env_string};
use crate::fsutil;

/// Current version of the session file format.
pub const SESSION_VERSION: u32 = 1;

/// Prefix of the additional authenticated data of the sealed master key.
pub const SESSION_AAD_PREFIX: &[u8] = b"pwk-session-v1";

/// Hint appended to every "locked" message.
pub const UNLOCK_HINT: &str = "run `eval \"$(pwk auth unlock)\"`";

/// Seconds since the Unix epoch.
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Contents of `session.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionFile {
    /// Format version, [`SESSION_VERSION`].
    pub version: u32,
    /// Server URL.
    pub host: String,
    /// Token pair (stored flat: `access_token`, `refresh_token`, …).
    #[serde(flatten)]
    pub tokens: Tokens,
    /// The sealed master key, or `null` when locked.
    pub unlock: Option<Unlock>,
}

impl SessionFile {
    /// A fresh, locked session for `host`.
    #[must_use]
    pub fn new(host: String, tokens: Tokens) -> Self {
        Self {
            version: SESSION_VERSION,
            host,
            tokens,
            unlock: None,
        }
    }
}

/// The master key sealed with the session key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unlock {
    /// End of the unlock, Unix seconds (authenticated as part of the AAD).
    pub expires_at: u64,
    /// AES-GCM nonce, Base64.
    pub nonce: String,
    /// Ciphertext and tag, Base64.
    pub ciphertext: String,
}

/// Files of one profile's session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    dir: PathBuf,
    file: PathBuf,
    lock: PathBuf,
}

/// Holds the exclusive lock on `session.json.lock` until dropped.
#[derive(Debug)]
pub struct SessionLock {
    _file: File,
}

impl Session {
    /// The session of `profile` under `state_dir` (see [`crate::config::state_dir`]).
    #[must_use]
    pub fn new(state_dir: &Path, profile: &str) -> Self {
        let dir = state_dir.join(profile);
        Self {
            file: dir.join("session.json"),
            lock: dir.join("session.json.lock"),
            dir,
        }
    }

    /// The profile directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path of `session.json`.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.file
    }

    /// Whether `session.json` exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.file.exists()
    }

    /// Takes the exclusive lock (blocks until other pwk processes release it).
    pub fn lock(&self) -> anyhow::Result<SessionLock> {
        fsutil::create_private_dir(&self.dir)
            .with_context(|| format!("cannot create {}", self.dir.display()))?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(&self.lock)
            .with_context(|| format!("cannot open {}", self.lock.display()))?;
        file.lock()
            .with_context(|| format!("cannot lock {}", self.lock.display()))?;
        Ok(SessionLock { _file: file })
    }

    /// Reads `session.json`; `None` if there is none (not logged in).
    pub fn load(&self) -> anyhow::Result<Option<SessionFile>> {
        let text = match fs::read_to_string(&self.file) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(e).with_context(|| format!("cannot read {}", self.file.display()));
            }
        };
        let file: SessionFile = serde_json::from_str(&text).with_context(|| {
            format!(
                "{} is damaged; run `pwk auth logout` and log in again",
                self.file.display()
            )
        })?;
        if file.version != SESSION_VERSION {
            bail!(
                "{} has unsupported version {}; run `pwk auth logout` and log in again",
                self.file.display(),
                file.version
            );
        }
        Ok(Some(file))
    }

    /// Writes `session.json` atomically (0600, directory 0700). Callers hold the lock.
    fn write(&self, session: &SessionFile, _lock: &SessionLock) -> anyhow::Result<()> {
        let text = Zeroizing::new(serde_json::to_string_pretty(session)?);
        fsutil::write_atomic(&self.file, text.as_bytes())
            .with_context(|| format!("cannot write {}", self.file.display()))
    }

    /// Replaces the session (login) under the lock.
    pub fn store(&self, session: &SessionFile) -> anyhow::Result<()> {
        let lock = self.lock()?;
        self.write(session, &lock)
    }

    /// Re-reads the session under the lock, lets `change` modify it and writes it back.
    /// Fails when not logged in.
    pub fn modify<T>(
        &self,
        change: impl FnOnce(&mut SessionFile) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let lock = self.lock()?;
        let Some(mut session) = self.load()? else {
            bail!("not logged in: run `pwk auth login`");
        };
        let result = change(&mut session)?;
        self.write(&session, &lock)?;
        Ok(result)
    }

    /// Clears the sealed master key (`lock`). Returns false when not logged in.
    pub fn clear_unlock(&self) -> anyhow::Result<bool> {
        let lock = self.lock()?;
        let Some(mut session) = self.load()? else {
            return Ok(false);
        };
        if session.unlock.is_some() {
            session.unlock = None;
            self.write(&session, &lock)?;
        }
        Ok(true)
    }

    /// Deletes the session file (`logout`). The lock file and the profile directory
    /// stay: another pwk process may be waiting on the lock, and a new lock file would
    /// let it and a later process both hold "the" lock. Returns false when there was no
    /// session file.
    pub fn delete(&self) -> anyhow::Result<bool> {
        if !self.dir.exists() {
            return Ok(false);
        }
        let _lock = self.lock()?;
        match fs::remove_file(&self.file) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("cannot delete {}", self.file.display())),
        }
    }
}

/// Profiles with a session directory under `state_dir`, sorted.
pub fn session_profiles(state_dir: &Path) -> anyhow::Result<Vec<String>> {
    let entries = match fs::read_dir(state_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", state_dir.display())),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.path().join("session.json").is_file()
            && let Ok(name) = entry.file_name().into_string()
            && crate::config::validate_profile_name(&name).is_ok()
        {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// [`TokenStore`] backed by the session file, shared between processes.
///
/// `refresh` takes the lock and re-reads the file: if another process stored a different
/// pair meanwhile, that pair is returned without a new refresh request.
#[derive(Debug, Clone)]
pub struct FileTokenStore {
    session: Session,
}

impl FileTokenStore {
    /// A store for `session`.
    #[must_use]
    pub fn new(session: Session) -> Self {
        Self { session }
    }
}

fn store_error(error: &anyhow::Error) -> pwk_api::Error {
    pwk_api::Error::TokenStore(format!("{error:#}"))
}

impl TokenStore for FileTokenStore {
    fn current(&self) -> pwk_api::Result<Tokens> {
        match self.session.load() {
            Ok(Some(file)) => Ok(file.tokens),
            Ok(None) => Err(pwk_api::Error::TokenStore(
                "not logged in: run `pwk auth login`".into(),
            )),
            Err(e) => Err(store_error(&e)),
        }
    }

    fn refresh(
        &self,
        stale: &Tokens,
        refresh: &mut dyn FnMut(&Tokens) -> pwk_api::Result<Tokens>,
    ) -> pwk_api::Result<Tokens> {
        let lock = self.session.lock().map_err(|e| store_error(&e))?;
        let mut file = match self.session.load() {
            Ok(Some(file)) => file,
            Ok(None) => {
                return Err(pwk_api::Error::TokenStore(
                    "logged out while refreshing the access token".into(),
                ));
            }
            Err(e) => return Err(store_error(&e)),
        };
        if file.tokens != *stale {
            return Ok(file.tokens);
        }
        let fresh = refresh(stale)?;
        file.tokens = fresh.clone();
        self.session
            .write(&file, &lock)
            .map_err(|e| store_error(&e))?;
        Ok(fresh)
    }
}

/// The additional authenticated data of a sealed master key:
///
/// ```text
/// b"pwk-session-v1" ‖ profile (UTF-8) ‖ b"\0" ‖ expires_at (decimal ASCII, Unix seconds)
/// ```
///
/// Binding the profile stops a seal from being copied to another profile; binding
/// `expires_at` stops the expiry in the (unencrypted) file from being extended.
#[must_use]
pub fn session_aad(profile: &str, expires_at: u64) -> Vec<u8> {
    let mut aad = SESSION_AAD_PREFIX.to_vec();
    aad.extend_from_slice(profile.as_bytes());
    aad.push(0);
    aad.extend_from_slice(expires_at.to_string().as_bytes());
    aad
}

/// Seals `master_key` with a fresh random session key for `timeout` from now. Returns the
/// session key (Base64, for the environment variable) and the [`Unlock`] to store.
pub fn seal_master_key(
    profile: &str,
    master_key: &str,
    timeout: Duration,
) -> anyhow::Result<(SecretString, Unlock)> {
    seal_master_key_at(profile, master_key, timeout, unix_now())
}

/// [`seal_master_key`] at the given time `now` (Unix seconds).
pub fn seal_master_key_at(
    profile: &str,
    master_key: &str,
    timeout: Duration,
    now: u64,
) -> anyhow::Result<(SecretString, Unlock)> {
    let expires_at = now.saturating_add(timeout.as_secs());
    let key = pwk_crypto::seal::generate_session_key();
    let sealed = pwk_crypto::seal::seal(
        &key,
        &session_aad(profile, expires_at),
        master_key.as_bytes(),
    )
    .context("cannot seal the master key")?;
    let unlock = Unlock {
        expires_at,
        nonce: BASE64.encode(sealed.nonce),
        ciphertext: BASE64.encode(&sealed.ciphertext),
    };
    Ok((Zeroizing::new(BASE64.encode(&*key)), unlock))
}

/// Why the master key is not available.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Locked {
    /// The session file holds no sealed master key.
    #[error("locked: {UNLOCK_HINT}")]
    NotUnlocked,
    /// No session key in the environment.
    #[error("locked: {var} is not set; {UNLOCK_HINT}")]
    NoSessionKey {
        /// The variable that was looked for.
        var: String,
    },
    /// The unlock has expired.
    #[error("locked: the unlock expired; {UNLOCK_HINT}")]
    Expired,
    /// The session key does not open the seal (another unlock, other profile, tampering).
    #[error("locked: the session key does not match this session; {UNLOCK_HINT}")]
    WrongKey,
    /// None of the session key variables that are set opens the seal.
    #[error("locked: the session key in {vars} does not match this session; {UNLOCK_HINT}")]
    KeyMismatch {
        /// The variables that were tried (`A` or `A or B`).
        vars: String,
    },
}

/// Opens the sealed master key with `session_key_b64` at time `now` (Unix seconds).
pub fn open_master_key(
    profile: &str,
    unlock: &Unlock,
    session_key_b64: &str,
    now: u64,
) -> Result<SecretString, Locked> {
    if now >= unlock.expires_at {
        return Err(Locked::Expired);
    }
    let key = Zeroizing::new(
        BASE64
            .decode(session_key_b64.trim())
            .map_err(|_| Locked::WrongKey)?,
    );
    if key.len() != pwk_crypto::seal::SESSION_KEY_LEN {
        return Err(Locked::WrongKey);
    }
    let nonce: [u8; 12] = BASE64
        .decode(&unlock.nonce)
        .ok()
        .and_then(|n| n.try_into().ok())
        .ok_or(Locked::WrongKey)?;
    let ciphertext = BASE64
        .decode(&unlock.ciphertext)
        .map_err(|_| Locked::WrongKey)?;
    let sealed = pwk_crypto::seal::Sealed { nonce, ciphertext };
    let plain = pwk_crypto::seal::open(&key, &session_aad(profile, unlock.expires_at), &sealed)
        .map_err(|_| Locked::WrongKey)?;
    let text = String::from_utf8(plain.to_vec()).map_err(|_| Locked::WrongKey)?;
    Ok(Zeroizing::new(text))
}

/// Name of the session key variable printed by `unlock`: `PWK_SESSION` for the default
/// profile, else `PWK_SESSION_<PROFILE>` (upper case, non-alphanumerics as `_`).
#[must_use]
pub fn session_env_var(profile: &str, is_default_profile: bool) -> String {
    if is_default_profile {
        "PWK_SESSION".to_owned()
    } else {
        profile_env_var(profile)
    }
}

fn profile_env_var(profile: &str) -> String {
    crate::config::profile_session_var(profile)
}

/// The variables that may hold the session key for `profile`, in the order they are
/// tried: first the one `unlock` prints for it now ([`session_env_var`]); for the default
/// profile also `PWK_SESSION_<PROFILE>` (printed while it was not the default). A
/// non-default profile never uses `PWK_SESSION` (the default profile's key).
#[must_use]
pub fn session_key_vars(profile: &str, is_default_profile: bool) -> Vec<String> {
    let mut vars = vec![session_env_var(profile, is_default_profile)];
    if is_default_profile {
        vars.push(profile_env_var(profile));
    }
    vars
}

/// Opens the sealed master key of `profile` with a session key from the environment:
/// each set variable of [`session_key_vars`] is tried until one opens the seal, so a
/// stale variable does not hide the fresh one.
pub fn open_master_key_from_env(
    profile: &str,
    is_default_profile: bool,
    unlock: &Unlock,
    env: EnvLookup<'_>,
    now: u64,
) -> Result<SecretString, Locked> {
    if now >= unlock.expires_at {
        return Err(Locked::Expired);
    }
    let mut tried = Vec::new();
    for var in session_key_vars(profile, is_default_profile) {
        let Some(key) = env_string(env, &var).map(Zeroizing::new) else {
            continue;
        };
        match open_master_key(profile, unlock, &key, now) {
            Ok(master_key) => return Ok(master_key),
            Err(Locked::WrongKey) => tried.push(var),
            Err(other) => return Err(other),
        }
    }
    if tried.is_empty() {
        Err(Locked::NoSessionKey {
            var: session_env_var(profile, is_default_profile),
        })
    } else {
        Err(Locked::KeyMismatch {
            vars: tried.join(" or "),
        })
    }
}

/// Shell syntax of `unlock` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ShellSyntax {
    /// POSIX sh, bash, zsh: `export NAME='value'`.
    #[default]
    Sh,
    /// bash (same as sh).
    Bash,
    /// zsh (same as sh).
    Zsh,
    /// fish: `set -gx NAME 'value'`.
    Fish,
}

/// The line that sets `var` to `value` in `shell` (with trailing newline).
#[must_use]
pub fn shell_export(shell: ShellSyntax, var: &str, value: &str) -> String {
    match shell {
        ShellSyntax::Sh | ShellSyntax::Bash | ShellSyntax::Zsh => {
            format!("export {var}='{}'\n", value.replace('\'', r"'\''"))
        }
        ShellSyntax::Fish => format!(
            "set -gx {var} '{}'\n",
            value.replace('\\', r"\\").replace('\'', r"\'")
        ),
    }
}

/// Where credentials come from.
pub enum CredentialSource {
    /// `PASSWORK_HOST` and `PASSWORK_TOKEN` are set: no config or session file is read
    /// and refreshed tokens stay in memory.
    Stateless {
        /// Server URL.
        host: String,
        /// Tokens from `PASSWORK_TOKEN` / `PASSWORK_REFRESH_TOKEN`.
        tokens: Tokens,
        /// `PASSWORK_MASTER_KEY` (the derived key), if set.
        master_key: Option<SecretString>,
    },
    /// The profile's config and session file.
    Profile {
        /// `PASSWORK_MASTER_KEY`, if set: counts as unlocked.
        master_key: Option<SecretString>,
    },
}

impl std::fmt::Debug for CredentialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hidden = |k: &Option<SecretString>| k.as_ref().map(|_| "..");
        match self {
            Self::Stateless {
                host,
                tokens,
                master_key,
            } => f
                .debug_struct("Stateless")
                .field("host", host)
                .field("tokens", tokens)
                .field("master_key", &hidden(master_key))
                .finish(),
            Self::Profile { master_key } => f
                .debug_struct("Profile")
                .field("master_key", &hidden(master_key))
                .finish(),
        }
    }
}

/// Detects stateless mode from `PASSWORK_HOST`, `PASSWORK_TOKEN`,
/// `PASSWORK_REFRESH_TOKEN` and `PASSWORK_MASTER_KEY`.
pub fn detect_credentials(env: EnvLookup<'_>) -> anyhow::Result<CredentialSource> {
    let master_key = env_string(env, "PASSWORK_MASTER_KEY").map(Zeroizing::new);
    let host = env_string(env, "PASSWORK_HOST");
    let token = env_string(env, "PASSWORK_TOKEN");
    match (host, token) {
        (Some(host), Some(access_token)) => Ok(CredentialSource::Stateless {
            host: crate::config::parse_host(&host).context("PASSWORK_HOST")?,
            tokens: Tokens {
                access_token,
                refresh_token: env_string(env, "PASSWORK_REFRESH_TOKEN"),
                access_expires_at: None,
                refresh_expires_at: None,
            },
            master_key,
        }),
        (Some(_), None) => bail!("PASSWORK_HOST is set but PASSWORK_TOKEN is not"),
        (None, Some(_)) => bail!("PASSWORK_TOKEN is set but PASSWORK_HOST is not"),
        (None, None) => Ok(CredentialSource::Profile { master_key }),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn env_of(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| {
            vars.iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| OsString::from(v))
        }
    }

    fn tokens(access: &str) -> Tokens {
        Tokens {
            access_token: access.into(),
            refresh_token: Some(format!("r-{access}")),
            access_expires_at: Some(100),
            refresh_expires_at: None,
        }
    }

    #[test]
    fn aad_layout() {
        assert_eq!(
            session_aad("work", 1_700_000_000),
            b"pwk-session-v1work\x001700000000"
        );
    }

    #[test]
    fn seal_and_open() {
        let now = 1_000_000;
        let (key, unlock) =
            seal_master_key_at("work", "master-key", Duration::from_secs(3600), now).unwrap();
        assert_eq!(unlock.expires_at, now + 3600);
        let opened = open_master_key("work", &unlock, &key, now + 10).unwrap();
        assert_eq!(opened.as_str(), "master-key");

        // Expired.
        assert_eq!(
            open_master_key("work", &unlock, &key, now + 3600),
            Err(Locked::Expired)
        );
        // Other profile: AAD differs.
        assert_eq!(
            open_master_key("home", &unlock, &key, now),
            Err(Locked::WrongKey)
        );
        // Wrong key.
        let (other_key, _) =
            seal_master_key_at("work", "master-key", Duration::from_secs(60), now).unwrap();
        assert_eq!(
            open_master_key("work", &unlock, &other_key, now),
            Err(Locked::WrongKey)
        );
        assert_eq!(
            open_master_key("work", &unlock, "not base64!", now),
            Err(Locked::WrongKey)
        );
        // Extended expiry in the file breaks the seal.
        let mut tampered = unlock.clone();
        tampered.expires_at += 3600;
        assert_eq!(
            open_master_key("work", &tampered, &key, now),
            Err(Locked::WrongKey)
        );
    }

    #[test]
    fn locked_messages() {
        assert!(Locked::Expired.to_string().contains("pwk auth unlock"));
        assert!(
            Locked::NoSessionKey {
                var: "PWK_SESSION".into()
            }
            .to_string()
            .contains("PWK_SESSION is not set")
        );
    }

    #[test]
    fn session_file_format() {
        let mut file = SessionFile::new("https://h".into(), tokens("a"));
        file.unlock = Some(Unlock {
            expires_at: 5,
            nonce: "bm9uY2U=".into(),
            ciphertext: "Y3Q=".into(),
        });
        let value = serde_json::to_value(&file).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "version": 1, "host": "https://h", "access_token": "a",
                "refresh_token": "r-a", "access_expires_at": 100,
                "refresh_expires_at": null,
                "unlock": {"expires_at": 5, "nonce": "bm9uY2U=", "ciphertext": "Y3Q="}
            })
        );
        let back: SessionFile = serde_json::from_value(value).unwrap();
        assert_eq!(back, file);
    }

    #[test]
    fn store_load_lock_delete() {
        let dir = tempfile::tempdir().unwrap();
        let session = Session::new(dir.path(), "work");
        assert_eq!(session.load().unwrap(), None);
        assert!(!session.clear_unlock().unwrap());
        assert!(session.modify(|_| Ok(())).is_err());

        let mut file = SessionFile::new("https://h".into(), tokens("a"));
        file.unlock = Some(Unlock {
            expires_at: 1,
            nonce: String::new(),
            ciphertext: String::new(),
        });
        session.store(&file).unwrap();
        assert_eq!(session.load().unwrap().as_ref(), Some(&file));
        assert_eq!(session_profiles(dir.path()).unwrap(), vec!["work"]);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(session.path()), 0o600);
            assert_eq!(mode(session.dir()), 0o700);
        }

        assert!(session.clear_unlock().unwrap());
        assert_eq!(session.load().unwrap().unwrap().unlock, None);

        // A lock held elsewhere stays valid across logout: the lock file is kept.
        let lock_path = session.dir().join("session.json.lock");
        let inode = |p: &Path| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                fs::metadata(p).unwrap().ino()
            }
            #[cfg(not(unix))]
            {
                u64::from(p.exists())
            }
        };
        let before = inode(&lock_path);
        assert!(session.delete().unwrap());
        assert!(!session.exists());
        assert!(lock_path.exists(), "logout must keep the lock file");
        assert_eq!(inode(&lock_path), before);
        assert!(!session.delete().unwrap());
        assert!(session_profiles(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn rejects_other_versions() {
        let dir = tempfile::tempdir().unwrap();
        let session = Session::new(dir.path(), "p");
        let mut file = SessionFile::new("https://h".into(), tokens("a"));
        file.version = 2;
        session.store(&file).unwrap();
        assert!(session.load().is_err());
    }

    #[test]
    fn token_store_refreshes_and_stores() {
        let dir = tempfile::tempdir().unwrap();
        let session = Session::new(dir.path(), "p");
        session
            .store(&SessionFile::new("https://h".into(), tokens("a")))
            .unwrap();
        let store = FileTokenStore::new(session.clone());
        let stale = store.current().unwrap();
        assert_eq!(stale, tokens("a"));
        let mut calls = 0;
        let fresh = store
            .refresh(&stale, &mut |old| {
                calls += 1;
                assert_eq!(old, &tokens("a"));
                Ok(tokens("b"))
            })
            .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(fresh, tokens("b"));
        assert_eq!(store.current().unwrap(), tokens("b"));
        assert_eq!(session.load().unwrap().unwrap().host, "https://h");
    }

    #[test]
    fn token_store_uses_concurrent_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let session = Session::new(dir.path(), "p");
        session
            .store(&SessionFile::new("https://h".into(), tokens("a")))
            .unwrap();
        let store = FileTokenStore::new(session.clone());
        let stale = store.current().unwrap();
        // Another process refreshes meanwhile.
        session
            .modify(|f| {
                f.tokens = tokens("other");
                Ok(())
            })
            .unwrap();
        let got = store
            .refresh(&stale, &mut |_| panic!("must not refresh again"))
            .unwrap();
        assert_eq!(got, tokens("other"));
    }

    #[test]
    fn token_store_errors() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileTokenStore::new(Session::new(dir.path(), "p"));
        assert!(matches!(
            store.current(),
            Err(pwk_api::Error::TokenStore(_))
        ));
        assert!(
            store
                .refresh(&tokens("a"), &mut |_| Ok(tokens("b")))
                .is_err()
        );
    }

    #[test]
    fn env_var_names() {
        assert_eq!(session_env_var("work", true), "PWK_SESSION");
        assert_eq!(session_env_var("default", true), "PWK_SESSION");
        assert_eq!(session_env_var("my-work_2", false), "PWK_SESSION_MY_WORK_2");
        assert_eq!(session_key_vars("work", false), vec!["PWK_SESSION_WORK"]);
        // The default profile: the variable `unlock` prints now comes first.
        assert_eq!(
            session_key_vars("home", true),
            vec!["PWK_SESSION", "PWK_SESSION_HOME"]
        );
    }

    #[test]
    fn open_from_env() {
        let now = 1_000_000;
        let ttl = Duration::from_secs(60);
        let (key, unlock) = seal_master_key_at("home", "master-key", ttl, now).unwrap();
        let (stale, _) = seal_master_key_at("home", "master-key", ttl, now).unwrap();
        let open = |is_default, vars: &[(&str, &str)]| {
            open_master_key_from_env("home", is_default, &unlock, &env_of(vars), now)
                .map(|k| k.as_str().to_owned())
        };
        let ok = Ok("master-key".to_owned());
        // Non-default profile: its own variable only.
        assert_eq!(open(false, &[("PWK_SESSION_HOME", &key)]), ok);
        assert_eq!(
            open(false, &[("PWK_SESSION", &key)]),
            Err(Locked::NoSessionKey {
                var: "PWK_SESSION_HOME".into()
            })
        );
        // Default profile: either variable; a stale one does not hide the other.
        assert_eq!(open(true, &[("PWK_SESSION", &key)]), ok);
        assert_eq!(open(true, &[("PWK_SESSION_HOME", &key)]), ok);
        assert_eq!(
            open(true, &[("PWK_SESSION", &stale), ("PWK_SESSION_HOME", &key)]),
            ok
        );
        assert_eq!(
            open(true, &[("PWK_SESSION", ""), ("PWK_SESSION_HOME", "")]),
            Err(Locked::NoSessionKey {
                var: "PWK_SESSION".into()
            })
        );
        // The message names the variables that were tried.
        let err = open(true, &[("PWK_SESSION", &stale), ("PWK_SESSION_HOME", "x")]).unwrap_err();
        assert_eq!(
            err,
            Locked::KeyMismatch {
                vars: "PWK_SESSION or PWK_SESSION_HOME".into()
            }
        );
        assert!(
            err.to_string()
                .contains("session key in PWK_SESSION or PWK_SESSION_HOME does not match")
        );
        assert_eq!(
            open(false, &[("PWK_SESSION_HOME", &stale)]),
            Err(Locked::KeyMismatch {
                vars: "PWK_SESSION_HOME".into()
            })
        );
        // Expired wins over any key.
        assert_eq!(
            open_master_key_from_env("home", true, &unlock, &env_of(&[]), unlock.expires_at),
            Err(Locked::Expired)
        );
    }

    #[test]
    fn stale_profile_variable_does_not_hide_pwk_session() {
        // `home` used to be a non-default profile (PWK_SESSION_HOME, now stale); after it
        // became the default, `unlock` printed PWK_SESSION.
        let now = 1_000_000;
        let (stale, _) =
            seal_master_key_at("home", "master-key", Duration::from_secs(60), now).unwrap();
        let (fresh, unlock) =
            seal_master_key_at("home", "master-key", Duration::from_secs(60), now).unwrap();
        let vars = [
            ("PWK_SESSION_HOME", stale.as_str()),
            ("PWK_SESSION", fresh.as_str()),
        ];
        let env = env_of(&vars);
        assert_eq!(
            open_master_key_from_env("home", true, &unlock, &env, now)
                .unwrap()
                .as_str(),
            "master-key"
        );
    }

    #[test]
    fn shell_lines() {
        assert_eq!(
            shell_export(ShellSyntax::Sh, "PWK_SESSION", "ab+/="),
            "export PWK_SESSION='ab+/='\n"
        );
        assert_eq!(
            shell_export(ShellSyntax::Zsh, "V", "it's"),
            "export V='it'\\''s'\n"
        );
        assert_eq!(
            shell_export(ShellSyntax::Fish, "V", r"a'b\c"),
            "set -gx V 'a\\'b\\\\c'\n"
        );
    }

    #[test]
    fn credential_detection() {
        let source = detect_credentials(&env_of(&[])).unwrap();
        assert!(matches!(
            source,
            CredentialSource::Profile { master_key: None }
        ));

        let source = detect_credentials(&env_of(&[("PASSWORK_MASTER_KEY", "mk")])).unwrap();
        assert!(matches!(source, CredentialSource::Profile { master_key: Some(k) } if *k == "mk"));

        let source = detect_credentials(&env_of(&[
            ("PASSWORK_HOST", "https://pw.example/"),
            ("PASSWORK_TOKEN", "t"),
            ("PASSWORK_REFRESH_TOKEN", "r"),
        ]))
        .unwrap();
        let CredentialSource::Stateless {
            host,
            tokens,
            master_key,
        } = source
        else {
            panic!("expected stateless");
        };
        assert_eq!(host, "https://pw.example");
        assert_eq!(tokens.access_token, "t");
        assert_eq!(tokens.refresh_token.as_deref(), Some("r"));
        assert!(master_key.is_none());

        assert!(detect_credentials(&env_of(&[("PASSWORK_HOST", "https://x")])).is_err());
        assert!(detect_credentials(&env_of(&[("PASSWORK_TOKEN", "t")])).is_err());
        // Debug hides secrets.
        let source = detect_credentials(&env_of(&[("PASSWORK_MASTER_KEY", "topsecret")])).unwrap();
        assert!(!format!("{source:?}").contains("topsecret"));
    }
}
