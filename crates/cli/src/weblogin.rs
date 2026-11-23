//! Signing in through the web interface (`login --web`) and the `passwork://` link
//! handler that brings the one-time token back to the waiting `pwk`.
//!
//! The web interface's desktop sign-in (`<host>/desktop?startDesktop=1`) ends with the
//! browser opening `passwork://login?desktopToken=<token>`. The token is exchanged once
//! for a token pair (`POST auth-requests/login`). The scheme is fixed by the server, so
//! `pwk auth handler install` puts pwk in front of the desktop app: while a
//! `login --web` waits (a marker file in the state directory), the link's token is
//! written next to the marker; every other link goes on to the previous handler.

use std::io::{BufRead as _, IsTerminal as _};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::fsutil;
use crate::session::unix_now;

/// The URL scheme the web interface hands sign-in tokens to.
pub const SCHEME: &str = "passwork";
/// The MIME type of that scheme for `xdg-mime`.
pub const SCHEME_MIME: &str = "x-scheme-handler/passwork";
/// How long `login --web` waits for the sign-in.
pub const WAIT: Duration = Duration::from_secs(5 * 60);

/// The page that starts the desktop sign-in on `host`.
#[must_use]
pub fn start_url(host: &str) -> String {
    format!("{host}/desktop?startDesktop=1")
}

/// The sign-in token of `passwork://login?desktopToken=…`, or `None` for any other link.
#[must_use]
pub fn token_from_link(link: &str) -> Option<String> {
    let rest = link.trim().strip_prefix("passwork://")?;
    let (target, query) = rest.split_once('?')?;
    if target.trim_end_matches('/') != "login" {
        return None;
    }
    let query = query.split('#').next().unwrap_or_default();
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        if key != "desktopToken" {
            return None;
        }
        // Percent-decoding only: `+` is not a space outside form encoding, and the web
        // interface appends the token as it is.
        let value = percent_decode_str(value)
            .decode_utf8()
            .ok()?
            .trim()
            .to_owned();
        (!value.is_empty()).then_some(value)
    })
}

/// A pasted line: the whole `passwork://` link or just the token.
#[must_use]
pub fn token_from_paste(line: &str) -> Option<String> {
    let line = line.trim();
    if line.contains("://") {
        return token_from_link(line);
    }
    (!line.is_empty() && !line.contains(char::is_whitespace)).then(|| line.to_owned())
}

// ---------------------------------------------------------------------------------------
// The waiting login and its marker

/// `<state dir>/web-login`, shared by all profiles: one `login --web` at a time.
#[must_use]
pub fn web_login_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("web-login")
}

/// Contents of `web-login/pending.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// Process ID of the waiting `pwk auth login --web`.
    pub pid: u32,
    /// The marker is void after this time (Unix seconds).
    pub expires_at: u64,
}

impl Pending {
    /// Whether the marker still belongs to a waiting login.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.expires_at > unix_now() && process_alive(self.pid)
    }
}

#[cfg(target_os = "linux")]
fn process_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_alive(pid: u32) -> bool {
    // `kill -0` checks that the process exists without signalling it.
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    true
}

fn pending_path(dir: &Path) -> PathBuf {
    dir.join("pending.json")
}

fn token_path(dir: &Path) -> PathBuf {
    dir.join("token")
}

/// The marker of a waiting login, if one is live.
pub fn live_pending(dir: &Path) -> Option<Pending> {
    let text = std::fs::read_to_string(pending_path(dir)).ok()?;
    serde_json::from_str::<Pending>(&text)
        .ok()
        .filter(Pending::is_live)
}

/// Hands a token to the waiting login. False if no login is waiting.
pub fn deliver(dir: &Path, token: &str) -> anyhow::Result<bool> {
    if live_pending(dir).is_none() {
        return Ok(false);
    }
    fsutil::write_atomic(&token_path(dir), token.as_bytes())
        .with_context(|| format!("cannot write {}", token_path(dir).display()))?;
    Ok(true)
}

/// The marker of this process's `login --web`; removes marker and token on drop.
#[derive(Debug)]
pub struct Waiting {
    dir: PathBuf,
}

impl Waiting {
    /// Writes the marker. Fails if another `login --web` is still waiting. Check and
    /// write happen under a file lock, so of two logins started at once only one waits.
    pub fn start(dir: &Path) -> anyhow::Result<Self> {
        fsutil::create_private_dir(dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        let lock_path = dir.join("pending.lock");
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let lock = options
            .open(&lock_path)
            .with_context(|| format!("cannot open {}", lock_path.display()))?;
        lock.lock()
            .with_context(|| format!("cannot lock {}", lock_path.display()))?;
        if let Some(other) = live_pending(dir) {
            bail!(
                "another `pwk auth login --web` (process {}) is waiting for a sign-in; \
                 finish or cancel it first",
                other.pid
            );
        }
        let _ = std::fs::remove_file(token_path(dir));
        let pending = Pending {
            pid: std::process::id(),
            expires_at: unix_now() + WAIT.as_secs(),
        };
        fsutil::write_atomic(&pending_path(dir), &serde_json::to_vec(&pending)?)
            .with_context(|| format!("cannot write {}", pending_path(dir).display()))?;
        drop(lock);
        Ok(Self {
            dir: dir.to_owned(),
        })
    }

    /// Takes a token delivered by the link handler, if one arrived.
    fn take_token(&self) -> Option<Zeroizing<String>> {
        let path = token_path(&self.dir);
        let text = Zeroizing::new(std::fs::read_to_string(&path).ok()?);
        let _ = std::fs::remove_file(&path);
        let token = text.trim();
        (!token.is_empty()).then(|| Zeroizing::new(token.to_owned()))
    }

    /// Waits for the token from the link handler or, with `paste`, a line on stdin.
    pub fn wait(&self, timeout: Duration, paste: bool) -> anyhow::Result<Zeroizing<String>> {
        let (tx, rx) = mpsc::channel::<Zeroizing<String>>();
        let interactive = std::io::stdin().is_terminal();
        let reader = move || {
            for line in std::io::stdin().lock().lines() {
                let Ok(line) = line.map(Zeroizing::new) else {
                    return;
                };
                match token_from_paste(&line) {
                    Some(token) => {
                        let _ = tx.send(Zeroizing::new(token));
                        return;
                    }
                    None if interactive && !line.trim().is_empty() => {
                        eprintln!(
                            "pwk: not a sign-in link; paste passwork://login?desktopToken=… \
                             or the token"
                        );
                    }
                    None => {}
                }
            }
        };
        if paste {
            std::thread::spawn(reader);
        } else {
            drop(reader);
        }
        let deadline = Instant::now() + timeout;
        let tick = Duration::from_millis(200);
        let mut stdin_open = true;
        loop {
            if let Some(token) = self.take_token() {
                return Ok(token);
            }
            if Instant::now() >= deadline {
                bail!(
                    "no sign-in within {} minutes; run `pwk auth login --web` again",
                    timeout.as_secs() / 60
                );
            }
            if stdin_open {
                match rx.recv_timeout(tick) {
                    Ok(token) => return Ok(token),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => stdin_open = false,
                }
            } else {
                std::thread::sleep(tick);
            }
        }
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(token_path(&self.dir));
        let _ = std::fs::remove_file(pending_path(&self.dir));
    }
}

/// Opens `url` in the default browser; false if no opener could be started.
pub fn open_browser(url: &str) -> bool {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(unix) {
        "xdg-open"
    } else {
        return false;
    };
    std::process::Command::new(opener)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

// ---------------------------------------------------------------------------------------
// Desktop entries (XDG)

/// File name of pwk's desktop entry for the `passwork://` scheme.
pub const DESKTOP_FILE: &str = "pwk-url-handler.desktop";

/// One argument of an `Exec` value, quoted per the quoting rule of the Desktop Entry
/// specification (applied before the string escaping of [`escape_value`]). A literal
/// `%` is written `%%`, or launchers would read it as a field code.
fn quote_arg(arg: &str) -> String {
    let mut quoted = String::from("\"");
    for c in arg.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            quoted.push('\\');
        }
        if c == '%' {
            quoted.push('%');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

/// String escaping of a desktop file value: backslash, newline, tab, carriage return.
fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            '\t' => out.push_str(r"\t"),
            '\r' => out.push_str(r"\r"),
            c => out.push(c),
        }
    }
    out
}

/// Undoes the string escapes of a desktop file value (`\s \n \t \r \\`); unknown
/// escapes stay as they are.
fn unescape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('s') => out.push(' '),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// The `Exec` value, as written to the file, that runs
/// `exe auth handler open --state-dir DIR %u`. The state directory is fixed at install
/// time: the desktop starts the handler with its own environment, which may name
/// another `XDG_STATE_HOME` than the shell waiting in `login --web`.
#[must_use]
pub fn exec_line(exe: &Path, state_dir: &Path) -> String {
    escape_value(&format!(
        "{} auth handler open --state-dir {} %u",
        quote_arg(&exe.to_string_lossy()),
        quote_arg(&state_dir.to_string_lossy())
    ))
}

/// pwk's desktop entry.
#[must_use]
pub fn desktop_entry(exe: &Path, state_dir: &Path) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=pwk (Passwork sign-in links)\n\
         Comment=Hands passwork:// sign-in links to a waiting `pwk auth login --web`, all \
         others to the previous handler\n\
         Exec={}\n\
         NoDisplay=true\n\
         Terminal=false\n\
         MimeType={SCHEME_MIME};\n",
        exec_line(exe, state_dir)
    )
}

/// Splits an `Exec` value (string escapes already undone, see [`exec_of`]) into
/// arguments with `url` in place of the field codes
/// `%u %U %f %F`; other field codes are dropped. Without a URL field code the URL is
/// appended.
pub fn exec_command(exec: &str, url: &str) -> anyhow::Result<Vec<String>> {
    let mut args: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_arg = false;
    let mut quoted = false;
    let mut chars = exec.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                in_arg = true;
            }
            '\\' if quoted => current.push(chars.next().context("Exec ends in a backslash")?),
            c if c.is_whitespace() && !quoted => {
                if in_arg {
                    args.push(std::mem::take(&mut current));
                    in_arg = false;
                }
            }
            c => {
                current.push(c);
                in_arg = true;
            }
        }
    }
    if quoted {
        bail!("unterminated quote in Exec");
    }
    if in_arg {
        args.push(current);
    }
    let mut out = Vec::with_capacity(args.len() + 1);
    let mut has_url = false;
    for arg in args {
        // Field codes also inside an argument (`--open=%u`), as GLib expands them.
        let mut expanded = String::with_capacity(arg.len());
        let mut codes_only = true;
        let mut chars = arg.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                expanded.push(c);
                codes_only = false;
                continue;
            }
            match chars.next() {
                Some('u' | 'U' | 'f' | 'F') => {
                    expanded.push_str(url);
                    has_url = true;
                    codes_only = false;
                }
                Some('%') => {
                    expanded.push('%');
                    codes_only = false;
                }
                // Other field codes (%i %c %k, deprecated ones) are dropped.
                Some(_) | None => {}
            }
        }
        // An argument that consisted of dropped field codes only disappears.
        if !(codes_only && expanded.is_empty()) {
            out.push(expanded);
        }
    }
    if out.is_empty() {
        bail!("empty Exec");
    }
    if !has_url {
        out.push(url.to_owned());
    }
    Ok(out)
}

/// The `Exec` value of the `[Desktop Entry]` group of a desktop file, string escapes
/// undone.
#[must_use]
pub fn exec_of(desktop_file: &str) -> Option<String> {
    let mut in_entry = false;
    for line in desktop_file.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
        } else if in_entry && let Some(value) = line.strip_prefix("Exec=") {
            return Some(unescape_value(value.trim()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links() {
        assert_eq!(
            token_from_link("passwork://login?desktopToken=abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            token_from_link(" passwork://login/?x=1&desktopToken=a%2Bb#frag\n").as_deref(),
            Some("a+b")
        );
        // A literal `+` stays a `+` (no form decoding).
        assert_eq!(
            token_from_link("passwork://login?desktopToken=ab+cd/ef=").as_deref(),
            Some("ab+cd/ef=")
        );
        assert_eq!(token_from_link("passwork://login?ssoToken=x"), None);
        assert_eq!(token_from_link("passwork://other?desktopToken=x"), None);
        assert_eq!(token_from_link("https://login?desktopToken=x"), None);
        assert_eq!(token_from_link("passwork://login?desktopToken="), None);
    }

    #[test]
    fn pastes() {
        assert_eq!(token_from_paste(" tok-1 \n").as_deref(), Some("tok-1"));
        assert_eq!(
            token_from_paste("passwork://login?desktopToken=tok-2").as_deref(),
            Some("tok-2")
        );
        assert_eq!(token_from_paste(""), None);
        assert_eq!(token_from_paste("two words"), None);
        assert_eq!(token_from_paste("https://example.com"), None);
    }

    #[test]
    fn exec_lines() {
        let exe = Path::new(r#"/opt/my apps/p"w\k$"#);
        let state = Path::new("/home/u/.local/state/pwk");
        // Quoting rule (\" \\ \$), then string escaping (each \ doubled).
        assert_eq!(
            exec_line(exe, state),
            r#""/opt/my apps/p\\"w\\\\k\\$" auth handler open --state-dir "/home/u/.local/state/pwk" %u"#
        );
        // Written into the desktop file and read back: the original arguments.
        let read = exec_of(&desktop_entry(exe, state)).unwrap();
        assert_eq!(
            exec_command(&read, "passwork://x").unwrap(),
            [
                r#"/opt/my apps/p"w\k$"#,
                "auth",
                "handler",
                "open",
                "--state-dir",
                "/home/u/.local/state/pwk",
                "passwork://x"
            ]
        );
        assert_eq!(
            exec_command("/opt/Passwork/passwork %U", "passwork://x").unwrap(),
            ["/opt/Passwork/passwork", "passwork://x"]
        );
        assert_eq!(
            exec_command("app --name=%c %i --flag 100%%", "u").unwrap(),
            ["app", "--name=", "--flag", "100%", "u"]
        );
        assert!(exec_command("\"open", "u").is_err());
        assert!(exec_command("  ", "u").is_err());
    }

    #[test]
    fn desktop_exec() {
        let file = "[Desktop Action x]\nExec=wrong\n[Desktop Entry]\nName=P\nExec=/opt/P/p %U\n";
        assert_eq!(exec_of(file).as_deref(), Some("/opt/P/p %U"));
        assert_eq!(exec_of("[Desktop Entry]\nName=P\n"), None);
        let entry = desktop_entry(Path::new("/bin/pwk"), Path::new("/s"));
        assert_eq!(
            exec_of(&entry).as_deref(),
            Some(r#""/bin/pwk" auth handler open --state-dir "/s" %u"#)
        );
        assert!(entry.contains("MimeType=x-scheme-handler/passwork;\n"));
    }

    #[test]
    fn field_codes_inside_arguments() {
        assert_eq!(
            exec_command("app --open=%u --name=%c %i x%%y", "passwork://z").unwrap(),
            ["app", "--open=passwork://z", "--name=", "x%y"]
        );
        // `%` in pwk's own paths is written `%%` and read back as one `%`.
        let exe = Path::new("/opt/100%/pwk");
        let state = Path::new("/home/u/50%d/pwk");
        let line = exec_line(exe, state);
        assert!(line.contains("100%%") && line.contains("50%%d"), "{line}");
        let read = exec_of(&desktop_entry(exe, state)).unwrap();
        assert_eq!(
            exec_command(&read, "u").unwrap(),
            [
                "/opt/100%/pwk",
                "auth",
                "handler",
                "open",
                "--state-dir",
                "/home/u/50%d/pwk",
                "u"
            ]
        );
    }

    #[test]
    fn concurrent_start_waits_once() {
        let dir = tempfile::tempdir().unwrap();
        let dir = web_login_dir(dir.path());
        let first = Waiting::start(&dir).unwrap();
        let err = Waiting::start(&dir).unwrap_err().to_string();
        assert!(err.contains("is waiting for a sign-in"), "{err}");
        drop(first);
        drop(Waiting::start(&dir).unwrap());
    }

    #[test]
    fn desktop_file_escapes() {
        // The specification's example: four backslashes in the file stand for one
        // literal backslash in a quoted argument; `\s` is a space.
        let file = r#"[Desktop Entry]
Exec="C:\\\\x" a\sb %u
"#;
        let exec = exec_of(file).unwrap();
        assert_eq!(exec_command(&exec, "u").unwrap(), [r"C:\x", "a", "b", "u"]);
    }

    #[test]
    fn marker_and_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let dir = web_login_dir(dir.path());
        assert!(!deliver(&dir, "early").unwrap());
        let waiting = Waiting::start(&dir).unwrap();
        assert!(live_pending(&dir).is_some());
        assert!(deliver(&dir, "tok").unwrap());
        assert_eq!(
            waiting
                .wait(Duration::from_secs(5), false)
                .unwrap()
                .as_str(),
            "tok"
        );
        drop(waiting);
        assert!(live_pending(&dir).is_none());
        assert!(!deliver(&dir, "late").unwrap());
    }

    #[test]
    fn stale_marker_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let dir = web_login_dir(dir.path());
        fsutil::create_private_dir(&dir).unwrap();
        let stale = Pending {
            pid: std::process::id(),
            expires_at: unix_now() - 1,
        };
        std::fs::write(pending_path(&dir), serde_json::to_vec(&stale).unwrap()).unwrap();
        assert!(live_pending(&dir).is_none());
        assert!(!deliver(&dir, "tok").unwrap());
    }
}
