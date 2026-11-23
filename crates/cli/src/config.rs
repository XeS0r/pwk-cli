//! `config.toml`: default profile and per-profile settings, plus the XDG paths.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

use crate::fsutil;

/// Name of the profile used when nothing else selects one.
pub const DEFAULT_PROFILE: &str = "default";

/// Reads an environment variable; the process environment is [`process_env`].
pub type EnvLookup<'a> = &'a dyn Fn(&str) -> Option<OsString>;

/// The real process environment, for [`EnvLookup`] parameters.
#[must_use]
pub fn process_env(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

/// Non-empty value of `name` as a string, if it is valid UTF-8.
pub(crate) fn env_string(env: EnvLookup<'_>, name: &str) -> Option<String> {
    env(name)
        .and_then(|v| v.into_string().ok())
        .filter(|v| !v.is_empty())
}

/// An absolute path from `name` (relative values are ignored, as XDG demands).
fn env_abs_path(env: EnvLookup<'_>, name: &str) -> Option<PathBuf> {
    env(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn home(env: EnvLookup<'_>) -> anyhow::Result<PathBuf> {
    env_abs_path(env, "HOME").context("HOME is not set; cannot locate the pwk directories")
}

/// The configuration file: `$PWK_CONFIG`, else `$XDG_CONFIG_HOME/pwk/config.toml`, else
/// `~/.config/pwk/config.toml`.
pub fn config_path(env: EnvLookup<'_>) -> anyhow::Result<PathBuf> {
    if let Some(path) = env("PWK_CONFIG").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    let base = match env_abs_path(env, "XDG_CONFIG_HOME") {
        Some(base) => base,
        None => home(env)?.join(".config"),
    };
    Ok(base.join("pwk").join("config.toml"))
}

/// The state directory holding one subdirectory per profile: `$XDG_STATE_HOME/pwk`, else
/// `~/.local/state/pwk`.
pub fn state_dir(env: EnvLookup<'_>) -> anyhow::Result<PathBuf> {
    let base = match env_abs_path(env, "XDG_STATE_HOME") {
        Some(base) => base,
        None => home(env)?.join(".local").join("state"),
    };
    Ok(base.join("pwk"))
}

/// Checks a profile name: 1 to 32 characters from `A–Z a–z 0–9 _ -`.
pub fn validate_profile_name(name: &str) -> anyhow::Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !ok {
        bail!(
            "invalid profile name `{name}`: use 1 to 32 characters from A-Z, a-z, 0-9, `_` and `-`"
        );
    }
    Ok(())
}

/// The session key variable of a non-default profile: `PWK_SESSION_<PROFILE>`, the name
/// upper-cased with every character other than letters and digits replaced by `_`.
#[must_use]
pub fn profile_session_var(profile: &str) -> String {
    let suffix: String = profile
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("PWK_SESSION_{suffix}")
}

/// The profile to use: `selected` (`--profile` or `PWK_PROFILE`, clap merges both), else
/// `default_profile` from the configuration, else [`DEFAULT_PROFILE`].
pub fn resolve_profile(selected: Option<&str>, config: &Config) -> anyhow::Result<String> {
    let name = selected
        .filter(|s| !s.is_empty())
        .or(config.default_profile.as_deref())
        .unwrap_or(DEFAULT_PROFILE);
    validate_profile_name(name)?;
    Ok(name.to_owned())
}

/// The whole configuration file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Profile used without `--profile` / `PWK_PROFILE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    /// Settings per profile.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, ProfileConfig>,
}

/// Settings of one profile (`[profiles.<name>]`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    /// Server URL, e.g. `https://passwork.example.com`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Extra CA certificate (PEM) added to the system roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<PathBuf>,
    /// Skip TLS certificate verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    /// Default for `unlock --timeout`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_timeout: Option<HumanDuration>,
}

impl ProfileConfig {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Keys of a profile accepted by `config set/unset`.
pub const PROFILE_KEYS: &[&str] = &["host", "ca_cert", "insecure", "session_timeout"];

impl Config {
    /// Loads `path`; a missing file is an empty configuration.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        Self::parse(&text).with_context(|| format!("invalid configuration {}", path.display()))
    }

    /// Parses and validates configuration text.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(text)?;
        if let Some(name) = &config.default_profile {
            validate_profile_name(name).context("default_profile")?;
        }
        for name in config.profiles.keys() {
            validate_profile_name(name)?;
        }
        Ok(config)
    }

    /// Writes the configuration atomically with mode 0600 (directory created 0700).
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let text = toml::to_string(self).context("cannot serialize the configuration")?;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fsutil::create_private_dir(dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
        }
        fsutil::write_atomic(path, text.as_bytes())
            .with_context(|| format!("cannot write {}", path.display()))
    }

    /// Settings of `profile` (empty if it has none).
    #[must_use]
    pub fn profile(&self, profile: &str) -> ProfileConfig {
        self.profiles.get(profile).cloned().unwrap_or_default()
    }

    /// Whether `profile` is the configured (or implicit) default profile.
    #[must_use]
    pub fn is_default_profile(&self, profile: &str) -> bool {
        self.default_profile.as_deref().unwrap_or(DEFAULT_PROFILE) == profile
    }

    /// Every profile this configuration knows: `[profiles.*]` and `default_profile`.
    pub fn known_profiles(&self) -> impl Iterator<Item = &str> {
        self.profiles
            .keys()
            .map(String::as_str)
            .chain(self.default_profile.as_deref())
    }

    /// Checks that `name` is a valid profile name whose session variable
    /// (`PWK_SESSION_<PROFILE>`) is not already used by a different profile of this
    /// configuration or of `others` (e.g. profiles with a session directory). `a-b` and
    /// `a_b`, or `Work` and `work`, would share one variable.
    pub fn check_new_profile<'a>(
        &'a self,
        name: &str,
        others: impl IntoIterator<Item = &'a str>,
    ) -> anyhow::Result<()> {
        validate_profile_name(name)?;
        let var = profile_session_var(name);
        if let Some(clash) = self
            .known_profiles()
            .chain(others)
            .find(|p| *p != name && profile_session_var(p) == var)
        {
            bail!(
                "profile name `{name}` clashes with the existing profile `{clash}`: both \
                 would use the session variable {var}; pick another name"
            );
        }
        Ok(())
    }

    /// `config set KEY VALUE`. `KEY` is `default_profile`, a profile key (applies to
    /// `profile`) or `profiles.<name>.<key>`.
    pub fn set(&mut self, profile: &str, key: &str, value: &str) -> anyhow::Result<()> {
        match self.split_key(profile, key)? {
            None => {
                self.check_new_profile(value, [])?;
                self.default_profile = Some(value.to_owned());
            }
            Some((name, key)) => {
                self.check_new_profile(&name, [])?;
                let settings = self.profiles.entry(name).or_default();
                match key.as_str() {
                    "host" => settings.host = Some(parse_host(value)?),
                    "ca_cert" => settings.ca_cert = Some(canonical_file(value)?),
                    "insecure" => settings.insecure = Some(parse_bool(value)?),
                    "session_timeout" => settings.session_timeout = Some(value.parse()?),
                    _ => unreachable!("checked by split_key"),
                }
            }
        }
        Ok(())
    }

    /// `config unset KEY`; see [`Config::set`] for keys. Empty profiles are removed.
    pub fn unset(&mut self, profile: &str, key: &str) -> anyhow::Result<()> {
        match self.split_key(profile, key)? {
            None => self.default_profile = None,
            Some((name, key)) => {
                if let Some(settings) = self.profiles.get_mut(&name) {
                    match key.as_str() {
                        "host" => settings.host = None,
                        "ca_cert" => settings.ca_cert = None,
                        "insecure" => settings.insecure = None,
                        "session_timeout" => settings.session_timeout = None,
                        _ => unreachable!("checked by split_key"),
                    }
                    if settings.is_empty() {
                        self.profiles.remove(&name);
                    }
                }
            }
        }
        Ok(())
    }

    /// `None` for `default_profile`, else `(profile, key)`.
    fn split_key(&self, profile: &str, key: &str) -> anyhow::Result<Option<(String, String)>> {
        if key == "default_profile" {
            return Ok(None);
        }
        let (name, key) = match key.strip_prefix("profiles.") {
            Some(rest) => match rest.rsplit_once('.') {
                Some((name, key)) => (name, key),
                None => bail!("unknown key `{key}`: use profiles.<name>.<key>"),
            },
            None => (profile, key),
        };
        validate_profile_name(name)?;
        if !PROFILE_KEYS.contains(&key) {
            bail!(
                "unknown key `{key}`: expected default_profile or one of {}",
                PROFILE_KEYS.join(", ")
            );
        }
        Ok(Some((name.to_owned(), key.to_owned())))
    }

    /// Every set value as `(dotted key, value)`, for `config show`.
    #[must_use]
    pub fn entries(&self) -> Vec<(String, String)> {
        let mut entries = Vec::new();
        if let Some(name) = &self.default_profile {
            entries.push(("default_profile".to_owned(), name.clone()));
        }
        for (name, p) in &self.profiles {
            let key = |k: &str| format!("profiles.{name}.{k}");
            if let Some(v) = &p.host {
                entries.push((key("host"), v.clone()));
            }
            if let Some(v) = &p.ca_cert {
                entries.push((key("ca_cert"), v.display().to_string()));
            }
            if let Some(v) = p.insecure {
                entries.push((key("insecure"), v.to_string()));
            }
            if let Some(v) = &p.session_timeout {
                entries.push((key("session_timeout"), v.to_string()));
            }
        }
        entries
    }
}

/// Checks and normalizes a server URL (`http(s)://…`, no trailing `/`).
pub fn parse_host(value: &str) -> anyhow::Result<String> {
    let value = value.trim().trim_end_matches('/');
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"));
    match rest {
        Some(rest) if !rest.is_empty() && !rest.contains(char::is_whitespace) => {
            Ok(value.to_owned())
        }
        _ => bail!("invalid host `{value}`: expected a URL like https://passwork.example.com"),
    }
}

/// The absolute, canonical path of an existing file (`config set ca_cert`), so the
/// setting does not depend on the directory pwk is started from.
fn canonical_file(value: &str) -> anyhow::Result<PathBuf> {
    let path = std::fs::canonicalize(value)
        .with_context(|| format!("cannot use `{value}` as CA certificate"))?;
    if !path.is_file() {
        bail!("`{value}` is not a file");
    }
    Ok(path)
}

fn parse_bool(value: &str) -> anyhow::Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => bail!("invalid boolean `{value}`: use true or false"),
    }
}

/// A positive duration written like `90s`, `30m`, `12h`, `1d` or `1h30m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HumanDuration(pub Duration);

impl HumanDuration {
    /// The duration.
    #[must_use]
    pub fn get(self) -> Duration {
        self.0
    }
}

impl FromStr for HumanDuration {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> anyhow::Result<Self> {
        let invalid = || {
            anyhow::anyhow!(
                "invalid duration `{text}`: use a number with a unit s, m, h, d or w, \
                 like 30m, 12h or 1h30m"
            )
        };
        let s = text.trim();
        if s.is_empty() {
            return Err(invalid());
        }
        let mut total: u64 = 0;
        let mut rest = s;
        while !rest.is_empty() {
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                return Err(invalid());
            }
            let number: u64 = rest[..digits].parse().map_err(|_| invalid())?;
            rest = &rest[digits..];
            let unit_len = rest.bytes().take_while(u8::is_ascii_alphabetic).count();
            let factor = match &rest[..unit_len] {
                "s" | "sec" | "secs" | "second" | "seconds" => 1,
                "m" | "min" | "mins" | "minute" | "minutes" => 60,
                "h" | "hour" | "hours" => 3600,
                "d" | "day" | "days" => 86_400,
                "w" | "week" | "weeks" => 604_800,
                _ => return Err(invalid()),
            };
            rest = &rest[unit_len..];
            total = number
                .checked_mul(factor)
                .and_then(|v| total.checked_add(v))
                .ok_or_else(|| anyhow::anyhow!("duration `{text}` is too long"))?;
        }
        if total == 0 {
            bail!("invalid duration `{text}`: must be longer than zero");
        }
        Ok(Self(Duration::from_secs(total)))
    }
}

impl fmt::Display for HumanDuration {
    /// Compact form: `1d12h`, `30m`, `0s`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut secs = self.0.as_secs();
        if secs == 0 {
            return f.write_str("0s");
        }
        for (unit, size) in [("d", 86_400), ("h", 3600), ("m", 60), ("s", 1)] {
            if secs >= size {
                write!(f, "{}{unit}", secs / size)?;
                secs %= size;
            }
        }
        Ok(())
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn durations() {
        let d = |s: &str| s.parse::<HumanDuration>().map(|d| d.0.as_secs());
        assert_eq!(d("30m").unwrap(), 1800);
        assert_eq!(d("12h").unwrap(), 43_200);
        assert_eq!(d("1d").unwrap(), 86_400);
        assert_eq!(d("1h30m").unwrap(), 5400);
        assert_eq!(d(" 45s ").unwrap(), 45);
        assert_eq!(d("2w").unwrap(), 1_209_600);
        assert_eq!(d("3 h").ok(), None);
        assert!(d("").is_err());
        assert!(d("10").is_err());
        assert!(d("h").is_err());
        assert!(d("5x").is_err());
        assert!(d("0m").is_err());
        assert!(d("-5m").is_err());
        assert!(d("99999999999999999999w").is_err());
        let show = |s: &str| s.parse::<HumanDuration>().unwrap().to_string();
        assert_eq!(show("90m"), "1h30m");
        assert_eq!(show("36h"), "1d12h");
        assert_eq!(show("12h"), "12h");
    }

    #[test]
    fn parse_full_config() {
        let config = Config::parse(
            r#"
default_profile = "work"
[profiles.work]
host = "https://pw.example.com"
ca_cert = "/etc/ca.pem"
insecure = false
session_timeout = "12h"
[profiles.home]
host = "http://localhost:8080"
"#,
        )
        .unwrap();
        assert_eq!(config.default_profile.as_deref(), Some("work"));
        let work = config.profile("work");
        assert_eq!(work.host.as_deref(), Some("https://pw.example.com"));
        assert_eq!(work.ca_cert, Some(PathBuf::from("/etc/ca.pem")));
        assert_eq!(work.insecure, Some(false));
        assert_eq!(work.session_timeout.unwrap().get().as_secs(), 43_200);
        assert_eq!(config.profile("missing"), ProfileConfig::default());
        // Round trip.
        let text = toml::to_string(&config).unwrap();
        assert_eq!(Config::parse(&text).unwrap(), config);
    }

    #[test]
    fn parse_rejects_bad_config() {
        assert!(Config::parse("bogus = 1").is_err());
        assert!(Config::parse("[profiles.x]\nhots = \"a\"").is_err());
        assert!(Config::parse("[profiles.x]\nsession_timeout = \"soon\"").is_err());
        assert!(Config::parse("default_profile = \"a b\"").is_err());
        assert!(Config::parse("[profiles.\"a/b\"]").is_err());
        assert_eq!(Config::parse("").unwrap(), Config::default());
    }

    #[test]
    fn load_missing_and_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/config.toml");
        assert_eq!(Config::load(&path).unwrap(), Config::default());
        let mut config = Config::default();
        config.set("default", "host", "https://x.example/").unwrap();
        config.set("default", "session_timeout", "30m").unwrap();
        config.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded, config);
        assert_eq!(
            loaded.profile("default").host.as_deref(),
            Some("https://x.example")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn set_and_unset() {
        let mut c = Config::default();
        c.set("work", "insecure", "yes").unwrap();
        c.set("x", "profiles.home.host", "https://home").unwrap();
        c.set("x", "default_profile", "home").unwrap();
        assert_eq!(c.profile("work").insecure, Some(true));
        assert_eq!(c.profile("home").host.as_deref(), Some("https://home"));
        assert_eq!(c.default_profile.as_deref(), Some("home"));
        assert!(c.set("x", "colour", "red").is_err());
        assert!(c.set("x", "host", "ftp://x").is_err());
        assert!(c.set("x", "insecure", "maybe").is_err());
        assert!(c.set("x", "default_profile", "no way").is_err());
        assert_eq!(
            c.entries(),
            vec![
                ("default_profile".to_owned(), "home".to_owned()),
                ("profiles.home.host".to_owned(), "https://home".to_owned()),
                ("profiles.work.insecure".to_owned(), "true".to_owned()),
            ]
        );
        c.unset("work", "insecure").unwrap();
        assert!(!c.profiles.contains_key("work"));
        c.unset("x", "default_profile").unwrap();
        assert_eq!(c.default_profile, None);
        // Unsetting something missing is fine.
        c.unset("nope", "host").unwrap();
    }

    #[test]
    fn ca_cert_is_stored_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let pem = dir.path().join("ca.pem");
        std::fs::write(&pem, "pem").unwrap();
        // A non-canonical spelling of the same file.
        let spelled = dir.path().join(".").join("ca.pem");
        let mut c = Config::default();
        c.set("p", "ca_cert", spelled.to_str().unwrap()).unwrap();
        let stored = c.profile("p").ca_cert.unwrap();
        assert!(stored.is_absolute());
        assert_eq!(stored, std::fs::canonicalize(&pem).unwrap());
        let err = c
            .set(
                "p",
                "ca_cert",
                dir.path().join("missing.pem").to_str().unwrap(),
            )
            .unwrap_err();
        assert!(format!("{err:#}").contains("missing.pem"), "{err:#}");
        assert!(c.set("p", "ca_cert", dir.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn profile_resolution_order() {
        let mut config = Config::default();
        assert_eq!(resolve_profile(None, &config).unwrap(), "default");
        assert!(config.is_default_profile("default"));
        config.default_profile = Some("work".into());
        assert_eq!(resolve_profile(None, &config).unwrap(), "work");
        assert_eq!(resolve_profile(Some(""), &config).unwrap(), "work");
        assert_eq!(resolve_profile(Some("cli"), &config).unwrap(), "cli");
        assert!(resolve_profile(Some("../etc"), &config).is_err());
        assert!(config.is_default_profile("work"));
        assert!(!config.is_default_profile("default"));
    }

    #[test]
    fn colliding_profile_names_are_rejected() {
        assert_eq!(profile_session_var("my-work_2"), "PWK_SESSION_MY_WORK_2");
        let mut c = Config::default();
        c.set("a-b", "host", "https://a").unwrap();
        let err = c.set("a_b", "host", "https://b").unwrap_err().to_string();
        assert!(
            err.contains("`a-b`") && err.contains("PWK_SESSION_A_B"),
            "{err}"
        );
        assert!(c.set("x", "default_profile", "A_B").is_err());
        assert!(c.set("x", "profiles.A-b.insecure", "true").is_err());
        // The same profile again is fine.
        c.set("a-b", "insecure", "true").unwrap();
        c.set("x", "default_profile", "a-b").unwrap();
        // `others` (session directories) count too.
        assert!(c.check_new_profile("work", ["Work"]).is_err());
        assert!(c.check_new_profile("work", ["work", "home"]).is_ok());
        assert!(c.check_new_profile("bad name", []).is_err());
    }

    #[test]
    fn profile_names() {
        assert!(validate_profile_name("a-B_9").is_ok());
        assert!(validate_profile_name(&"x".repeat(32)).is_ok());
        assert!(validate_profile_name(&"x".repeat(33)).is_err());
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name("a.b").is_err());
        assert!(validate_profile_name("ä").is_err());
    }

    #[test]
    fn paths() {
        let env = env_of(&[("HOME", "/home/u")]);
        assert_eq!(
            config_path(&env).unwrap(),
            PathBuf::from("/home/u/.config/pwk/config.toml")
        );
        assert_eq!(
            state_dir(&env).unwrap(),
            PathBuf::from("/home/u/.local/state/pwk")
        );
        let env = env_of(&[
            ("HOME", "/home/u"),
            ("XDG_CONFIG_HOME", "/xdg/c"),
            ("XDG_STATE_HOME", "/xdg/s"),
        ]);
        assert_eq!(
            config_path(&env).unwrap(),
            PathBuf::from("/xdg/c/pwk/config.toml")
        );
        assert_eq!(state_dir(&env).unwrap(), PathBuf::from("/xdg/s/pwk"));
        let env = env_of(&[("PWK_CONFIG", "my.toml"), ("XDG_STATE_HOME", "relative")]);
        assert_eq!(config_path(&env).unwrap(), PathBuf::from("my.toml"));
        assert!(state_dir(&env).is_err());
        let env = env_of(&[]);
        assert!(config_path(&env).is_err());
    }
}
