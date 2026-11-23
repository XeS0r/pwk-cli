//! Running `pwk` against the fake server with an isolated environment.

use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;

use crate::server::{ACCESS_TOKEN, FakePasswork, MASTER_PASSWORD, REFRESH_TOKEN};

/// One test's world: a fake server and a temporary HOME with config and state dirs.
#[derive(Debug)]
pub struct Env {
    pub dir: tempfile::TempDir,
    pub server: FakePasswork,
}

impl Env {
    /// A fresh fake server and an empty HOME.
    pub fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
            server: FakePasswork::start(),
        }
    }

    /// A fake server offering `master_key_options` and an empty HOME.
    pub fn with_master_key_options(master_key_options: &'static str) -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
            server: FakePasswork::start_with_options(master_key_options),
        }
    }

    /// Logged in and unlocked (default profile); returns the env and the session key.
    pub fn unlocked() -> (Self, String) {
        let env = Self::new();
        env.login(None);
        let key = env.unlock_raw(None);
        (env, key)
    }

    pub fn home(&self) -> &Path {
        self.dir.path()
    }

    pub fn config_home(&self) -> PathBuf {
        self.home().join("config")
    }

    pub fn state_home(&self) -> PathBuf {
        self.home().join("state")
    }

    /// `$XDG_STATE_HOME/pwk/<profile>/session.json`.
    pub fn session_path(&self, profile: &str) -> PathBuf {
        self.state_home()
            .join("pwk")
            .join(profile)
            .join("session.json")
    }

    /// The parsed session file of `profile`.
    pub fn session_json(&self, profile: &str) -> Value {
        let text = std::fs::read_to_string(self.session_path(profile))
            .unwrap_or_else(|e| panic!("read session.json of {profile}: {e}"));
        serde_json::from_str(&text).expect("session.json is JSON")
    }

    /// `pwk` with a cleared environment: only PATH, HOME, XDG_CONFIG_HOME,
    /// XDG_STATE_HOME and `PWK_FORMAT=json`. No PWK_SESSION*, PWK_CONFIG or PASSWORK_*.
    pub fn pwk(&self) -> Command {
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("pwk");
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.home())
            .env("XDG_CONFIG_HOME", self.config_home())
            .env("XDG_STATE_HOME", self.state_home())
            .env("PWK_FORMAT", "json")
            .current_dir(self.home())
            .timeout(std::time::Duration::from_secs(60));
        cmd
    }

    /// `pwk` with `PWK_SESSION` set to `key`.
    pub fn pwk_with(&self, key: &str) -> Command {
        let mut cmd = self.pwk();
        cmd.env("PWK_SESSION", key);
        cmd
    }

    /// `pwk [--profile P] login --host URL --access-token-stdin` with the access token
    /// on the first stdin line and the refresh token on the second.
    pub fn login(&self, profile: Option<&str>) {
        let mut cmd = self.pwk();
        if let Some(p) = profile {
            cmd.args(["--profile", p]);
        }
        let out = cmd
            .args(["login", "--host", &self.server.url, "--access-token-stdin"])
            .write_stdin(format!("{ACCESS_TOKEN}\n{REFRESH_TOKEN}\n"))
            .output()
            .unwrap();
        assert_success(&out, "login");
    }

    /// `pwk [--profile P] unlock --password-stdin --raw` → session key.
    pub fn unlock_raw(&self, profile: Option<&str>) -> String {
        let mut cmd = self.pwk();
        if let Some(p) = profile {
            cmd.args(["--profile", p]);
        }
        let out = cmd
            .args(["unlock", "--password-stdin", "--raw"])
            .write_stdin(format!("{MASTER_PASSWORD}\n"))
            .output()
            .unwrap();
        assert_success(&out, "unlock --raw");
        let key = stdout(&out).trim().to_owned();
        assert!(!key.is_empty(), "unlock --raw printed nothing");
        key
    }
}

/// Stdout as text.
pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Stderr as text.
pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Stdout parsed as JSON.
pub fn stdout_json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}):\n--- stdout\n{}\n--- stderr\n{}",
            stdout(out),
            stderr(out)
        )
    })
}

/// Panics with stdout/stderr unless the command exited 0.
pub fn assert_success(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "`pwk {what}` failed with {:?}\n--- stdout\n{}\n--- stderr\n{}",
        out.status.code(),
        stdout(out),
        stderr(out)
    );
}

/// Panics unless the command failed with exit code 1 and a `pwk: ` message; returns
/// stderr.
pub fn assert_error(out: &Output, what: &str) -> String {
    let err = stderr(out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "`pwk {what}` should exit 1\n--- stdout\n{}\n--- stderr\n{err}",
        stdout(out)
    );
    assert!(
        err.starts_with("pwk: ") || err.contains("\npwk: "),
        "`pwk {what}`: error should be `pwk: <message>`, got:\n{err}"
    );
    err
}

/// Panics unless the command reported a locked session that points to `pwk unlock`.
pub fn assert_locked(out: &Output, what: &str) {
    let err = assert_error(out, what);
    assert!(
        err.contains("pwk unlock"),
        "`pwk {what}`: locked error should mention `pwk unlock`, got:\n{err}"
    );
    assert!(
        err.to_lowercase().contains("locked"),
        "`pwk {what}`: error should say locked, got:\n{err}"
    );
}

/// True if any string anywhere inside `value` equals `needle`.
pub fn json_contains_str(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(s) => s == needle,
        Value::Array(list) => list.iter().any(|v| json_contains_str(v, needle)),
        Value::Object(map) => map.values().any(|v| json_contains_str(v, needle)),
        _ => false,
    }
}

/// All maximal runs of exactly `n` ASCII digits in `text`.
pub fn digit_runs(text: &str, n: usize) -> Vec<String> {
    text.split(|c: char| !c.is_ascii_digit())
        .filter(|s| s.len() == n)
        .map(str::to_owned)
        .collect()
}

/// TOTP codes valid around now (previous, current, next period).
pub fn expected_totp_codes(secret: &str) -> Vec<String> {
    let totp = pwk_crypto::totp::Totp::parse(secret).unwrap();
    let now = crate::server::now();
    [now - totp.period, now, now + totp.period]
        .iter()
        .map(|&t| totp.code_at(t))
        .collect()
}

/// Unix permission bits of `path`.
#[cfg(unix)]
pub fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

/// Every file below `dir` (empty if `dir` does not exist).
pub fn files_below(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(files_below(&path));
        } else {
            out.push(path);
        }
    }
    out
}
