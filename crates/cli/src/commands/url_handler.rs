//! `auth handler`: routes `passwork://` sign-in links to a waiting `pwk auth login --web`
//! (XDG desktops). See [`crate::weblogin`].

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};

use super::Context;
use crate::cli::UrlHandlerCommand;
use crate::config::{self, EnvLookup};
use crate::fsutil;
use crate::output::{self, Format};
use crate::weblogin::{self, DESKTOP_FILE, SCHEME_MIME};

/// Runs an `auth handler` subcommand.
pub fn run(ctx: &Context, cmd: &UrlHandlerCommand) -> anyhow::Result<ExitCode> {
    match cmd {
        UrlHandlerCommand::Install => install(ctx),
        UrlHandlerCommand::Uninstall => uninstall(ctx),
        UrlHandlerCommand::Status => status(ctx),
        UrlHandlerCommand::Open { url, state_dir } => {
            let state_dir = match state_dir {
                Some(dir) => dir.clone(),
                None => config::state_dir(&config::process_env)?,
            };
            open(url, &state_dir)
        }
    }
}

/// `<state dir>/url-handler.json`: the handler pwk replaced.
#[derive(Debug, Default, Serialize, Deserialize)]
struct HandlerState {
    /// Desktop file ID of the previous `passwork://` handler, if there was one.
    previous: Option<String>,
}

fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join("url-handler.json")
}

fn load_state(state_dir: &Path) -> anyhow::Result<Option<HandlerState>> {
    let path = state_path(state_dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(Some(
            serde_json::from_str(&text).with_context(|| format!("invalid {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// `$XDG_DATA_HOME`, else `~/.local/share`.
fn data_home(env: EnvLookup<'_>) -> anyhow::Result<PathBuf> {
    if let Some(dir) = config::env_string(env, "XDG_DATA_HOME").filter(|d| d.starts_with('/')) {
        return Ok(PathBuf::from(dir));
    }
    let home = config::env_string(env, "HOME").context("HOME is not set")?;
    Ok(Path::new(&home).join(".local").join("share"))
}

/// The `applications` directories, most specific first.
fn application_dirs(env: EnvLookup<'_>) -> anyhow::Result<Vec<PathBuf>> {
    let mut dirs = vec![data_home(env)?.join("applications")];
    let data_dirs = config::env_string(env, "XDG_DATA_DIRS")
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".to_owned());
    dirs.extend(
        data_dirs
            .split(':')
            .filter(|d| d.starts_with('/'))
            .map(|d| Path::new(d).join("applications")),
    );
    Ok(dirs)
}

fn xdg_mime(args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new("xdg-mime")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .context("cannot run xdg-mime (xdg-utils); the link handler needs an XDG desktop")?;
    if !out.status.success() {
        bail!(
            "xdg-mime {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The default handler of `passwork://`. GIO first: GNOME's browsers and `xdg-open`
/// open links through it, and `xdg-mime query` can disagree with it there. Without
/// `gio`, `xdg-mime` decides.
fn current_handler() -> anyhow::Result<Option<String>> {
    let gio = Command::new("gio")
        .args(["mime", SCHEME_MIME])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    if let Ok(out) = gio
        && out.status.success()
    {
        return Ok(parse_gio_default(&String::from_utf8_lossy(&out.stdout)));
    }
    let id = xdg_mime(&["query", "default", SCHEME_MIME])?;
    Ok(Some(id).filter(|id| !id.is_empty()))
}

/// The default application in the output of `LC_ALL=C gio mime TYPE`.
fn parse_gio_default(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("Default application for")?;
        let (_, id) = rest.rsplit_once(": ")?;
        let id = id.trim();
        (!id.is_empty()).then(|| id.to_owned())
    })
}

/// The handler pwk passes other links on to after `install`: the current one, unless
/// that is pwk itself (a re-install); then the one remembered by the earlier install.
/// So a handler chosen after an earlier install is taken over, and re-installing only
/// updates pwk's path.
fn previous_for_install(state: Option<HandlerState>, current: Option<&str>) -> Option<String> {
    match current {
        Some(id) if id != DESKTOP_FILE => Some(id.to_owned()),
        _ => state.and_then(|s| s.previous),
    }
}

/// Whether `uninstall` restores the previous handler: only while pwk is still the
/// default (or that cannot be told), never over a handler chosen since.
fn should_restore(current: &anyhow::Result<Option<String>>) -> bool {
    match current {
        Ok(Some(id)) => id == DESKTOP_FILE,
        Ok(None) | Err(_) => true,
    }
}

/// `auth handler install`.
fn install(ctx: &Context) -> anyhow::Result<ExitCode> {
    if !cfg!(unix) || cfg!(target_os = "macos") {
        bail!("the link handler is only available on Linux and other XDG desktops");
    }
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("cannot locate the pwk executable")?;
    let state_dir = config::state_dir(&config::process_env)?;
    let current = current_handler()?;
    let previous = previous_for_install(load_state(&state_dir)?, current.as_deref());

    let apps = data_home(&config::process_env)?.join("applications");
    std::fs::create_dir_all(&apps).with_context(|| format!("cannot create {}", apps.display()))?;
    let desktop = apps.join(DESKTOP_FILE);
    std::fs::write(&desktop, weblogin::desktop_entry(&exe, &state_dir))
        .with_context(|| format!("cannot write {}", desktop.display()))?;
    let state = state_path(&state_dir);
    fsutil::create_private_dir(&state_dir)
        .with_context(|| format!("cannot create {}", state_dir.display()))?;
    fsutil::write_atomic(
        &state,
        &serde_json::to_vec_pretty(&HandlerState {
            previous: previous.clone(),
        })?,
    )
    .with_context(|| format!("cannot write {}", state.display()))?;
    xdg_mime(&["default", DESKTOP_FILE, SCHEME_MIME])?;

    let others = previous.as_deref().map_or_else(
        || "others are refused (there was no handler before)".to_owned(),
        |prev| format!("others go on to {prev}"),
    );
    let message = format!(
        "passwork:// links now go to pwk; {others}.\n  \
         Handler: {}  (run `pwk auth handler install` again after updating pwk)\n  \
         Undo:    pwk auth handler uninstall",
        exe.display()
    );
    ctx.info(&message);
    Ok(ExitCode::SUCCESS)
}

/// `auth handler uninstall`.
fn uninstall(ctx: &Context) -> anyhow::Result<ExitCode> {
    let state_dir = config::state_dir(&config::process_env)?;
    let state = load_state(&state_dir)?;
    let previous = state.as_ref().and_then(|s| s.previous.clone());
    let current = current_handler();
    let restore = should_restore(&current);
    if restore && let Some(prev) = &previous {
        xdg_mime(&["default", prev, SCHEME_MIME])?;
    }
    let desktop = data_home(&config::process_env)?
        .join("applications")
        .join(DESKTOP_FILE);
    let removed = remove_if_exists(&desktop)?;
    if state.is_some() {
        remove_if_exists(&state_path(&state_dir))?;
    }
    // Without a previous handler xdg-mime cannot unset the default: drop pwk's entry
    // from the user's mimeapps.list, so it does not point at the removed file.
    let mut cleared = false;
    if restore && previous.is_none() {
        for list in mimeapps_lists(&config::process_env)? {
            cleared |= remove_default(&list)?;
        }
    }
    if !removed && state.is_none() && !cleared {
        ctx.info("The pwk link handler is not installed.");
    } else if !restore {
        let other = current.ok().flatten().unwrap_or_default();
        ctx.info(&format!(
            "Removed the pwk link handler; passwork:// links stay with {other}."
        ));
    } else if let Some(prev) = previous {
        ctx.info(&format!("passwork:// links go to {prev} again."));
    } else {
        ctx.info("Removed the pwk link handler; passwork:// has no handler now.");
    }
    Ok(ExitCode::SUCCESS)
}

/// Removes `path`; false if it did not exist.
fn remove_if_exists(path: &Path) -> anyhow::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("cannot remove {}", path.display())),
    }
}

/// The user's `mimeapps.list` files: `$XDG_CONFIG_HOME` (or `~/.config`) and the
/// deprecated one in the user's `applications` directory.
fn mimeapps_lists(env: EnvLookup<'_>) -> anyhow::Result<Vec<PathBuf>> {
    let config_home =
        match config::env_string(env, "XDG_CONFIG_HOME").filter(|d| d.starts_with('/')) {
            Some(dir) => PathBuf::from(dir),
            None => Path::new(&config::env_string(env, "HOME").context("HOME is not set")?)
                .join(".config"),
        };
    Ok(vec![
        config_home.join("mimeapps.list"),
        data_home(env)?.join("applications").join("mimeapps.list"),
    ])
}

/// Removes pwk's desktop file from the `passwork://` entries of a `mimeapps.list`;
/// true if the file changed.
fn remove_default(path: &Path) -> anyhow::Result<bool> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let Some(cleaned) = without_pwk_entry(&text) else {
        return Ok(false);
    };
    fsutil::write_atomic(path, cleaned.as_bytes())
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(true)
}

/// `text` (a `mimeapps.list`) without pwk's desktop file in `x-scheme-handler/passwork`
/// lines; a line left empty is dropped. `None` if there was nothing to remove.
fn without_pwk_entry(text: &str) -> Option<String> {
    let mut changed = false;
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let entry = line
            .split_once('=')
            .filter(|(key, _)| key.trim() == SCHEME_MIME);
        let Some((key, value)) = entry else {
            out.push_str(line);
            out.push('\n');
            continue;
        };
        let ids: Vec<&str> = value
            .split(';')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect();
        let kept: Vec<&str> = ids
            .iter()
            .copied()
            .filter(|id| *id != DESKTOP_FILE)
            .collect();
        if kept.len() == ids.len() {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        changed = true;
        if !kept.is_empty() {
            out.push_str(&format!("{key}={};\n", kept.join(";")));
        }
    }
    changed.then_some(out)
}

/// `auth handler status` (`--format json` for scripts).
fn status(ctx: &Context) -> anyhow::Result<ExitCode> {
    #[derive(Serialize)]
    struct Report {
        /// Desktop file ID of the current `passwork://` handler.
        handler: Option<String>,
        /// Whether that is pwk.
        pwk: bool,
        /// Where pwk passes other links on to.
        previous: Option<String>,
    }
    let state_dir = config::state_dir(&config::process_env)?;
    let current = current_handler()?;
    let previous = load_state(&state_dir)?.and_then(|s| s.previous);
    let installed = current.as_deref() == Some(DESKTOP_FILE);
    if ctx.format == Format::Json {
        output::print_json(&Report {
            handler: current,
            pwk: installed,
            previous: if installed { previous } else { None },
        })?;
        return Ok(ExitCode::SUCCESS);
    }
    let text = match (installed, current) {
        (true, _) => format!(
            "passwork:// links go to pwk; {}.\n",
            previous.map_or_else(
                || "others are refused".to_owned(),
                |prev| format!("others go on to {prev}")
            )
        ),
        (false, Some(id)) => format!(
            "passwork:// links go to {id}.\nFor `pwk auth login --web`, run `pwk auth handler install`.\n"
        ),
        (false, None) => {
            "passwork:// has no handler.\nFor `pwk auth login --web`, run `pwk auth handler install`.\n"
                .to_owned()
        }
    };
    output::write_stdout(&text)?;
    Ok(ExitCode::SUCCESS)
}

/// The other program `passwork://` links go to, if it is not pwk (best effort, for the
/// hint of `pwk auth login --web`; `None` also when that cannot be told).
#[must_use]
pub fn foreign_handler() -> Option<String> {
    match current_handler() {
        Ok(Some(id)) if id != DESKTOP_FILE => Some(id),
        Ok(None) => Some("no program".to_owned()),
        _ => None,
    }
}

/// `auth handler open URL`: the desktop entry's command. `state_dir` is the one fixed
/// at install time (see [`weblogin::exec_line`]).
fn open(url: &str, state_dir: &Path) -> anyhow::Result<ExitCode> {
    if let Some(token) = weblogin::token_from_link(url) {
        let dir = weblogin::web_login_dir(state_dir);
        if weblogin::deliver(&dir, &token)? {
            return Ok(ExitCode::SUCCESS);
        }
    }
    forward(url, state_dir)
}

/// Passes `url` on to the previous handler.
fn forward(url: &str, state_dir: &Path) -> anyhow::Result<ExitCode> {
    let previous = load_state(state_dir)?
        .and_then(|s| s.previous)
        .filter(|p| p != DESKTOP_FILE)
        .context(
            "no `pwk auth login --web` is waiting and there is no other passwork:// handler to \
             pass the link on to",
        )?;
    let file = application_dirs(&config::process_env)?
        .iter()
        .find_map(|dir| find_desktop_file(dir, &previous))
        .with_context(|| format!("cannot find the desktop file {previous}"))?;
    let text = std::fs::read_to_string(&file)
        .with_context(|| format!("cannot read {}", file.display()))?;
    let exec =
        weblogin::exec_of(&text).with_context(|| format!("{} has no Exec line", file.display()))?;
    let argv = weblogin::exec_command(&exec, url)
        .with_context(|| format!("cannot use the Exec line of {}", file.display()))?;
    Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .spawn()
        .with_context(|| format!("cannot start {}", argv[0]))?;
    Ok(ExitCode::SUCCESS)
}

/// The file of desktop file ID `id` below an `applications` directory. The ID of
/// `applications/vendor/app.desktop` is `vendor-app.desktop`, so subdirectories are
/// searched too.
fn find_desktop_file(dir: &Path, id: &str) -> Option<PathBuf> {
    let direct = dir.join(id);
    if direct.is_file() {
        return Some(direct);
    }
    let mut stack = vec![(dir.to_owned(), String::new(), 0_u8)];
    while let Some((path, prefix, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let entry_id = format!("{prefix}{name}");
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() && depth < 4 && id.starts_with(&format!("{entry_id}-")) {
                stack.push((entry.path(), format!("{entry_id}-"), depth + 1));
            } else if entry_id == id && entry.path().is_file() {
                return Some(entry.path());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gio_default() {
        let out = "Default application for \u{201c}x-scheme-handler/passwork\u{201d}: \
                   pwk-url-handler.desktop\nRegistered applications:\n\tpasswork.desktop\n";
        assert_eq!(
            parse_gio_default(out).as_deref(),
            Some("pwk-url-handler.desktop")
        );
        let none = "No default applications for \u{201c}x-scheme-handler/passwork\u{201d}\n\
                    Registered applications:\n\tpasswork.desktop\n";
        assert_eq!(parse_gio_default(none), None);
    }

    #[test]
    fn mimeapps_cleanup() {
        let text = "[Default Applications]\nx-scheme-handler/passwork=pwk-url-handler.desktop\n\
                    text/html=firefox.desktop\n[Added Associations]\n\
                    x-scheme-handler/passwork=pwk-url-handler.desktop;other.desktop;\n";
        assert_eq!(
            without_pwk_entry(text).as_deref(),
            Some(
                "[Default Applications]\ntext/html=firefox.desktop\n[Added Associations]\n\
                 x-scheme-handler/passwork=other.desktop;\n"
            )
        );
        assert_eq!(
            without_pwk_entry("[Default Applications]\ntext/html=f.desktop\n"),
            None
        );
    }

    #[test]
    fn desktop_file_ids() {
        let dir = tempfile::tempdir().unwrap();
        let apps = dir.path();
        std::fs::create_dir_all(apps.join("vendor/sub")).unwrap();
        std::fs::write(apps.join("plain.desktop"), "").unwrap();
        std::fs::write(apps.join("vendor/app.desktop"), "").unwrap();
        std::fs::write(apps.join("vendor/sub/deep.desktop"), "").unwrap();
        assert_eq!(
            find_desktop_file(apps, "plain.desktop"),
            Some(apps.join("plain.desktop"))
        );
        assert_eq!(
            find_desktop_file(apps, "vendor-app.desktop"),
            Some(apps.join("vendor/app.desktop"))
        );
        assert_eq!(
            find_desktop_file(apps, "vendor-sub-deep.desktop"),
            Some(apps.join("vendor/sub/deep.desktop"))
        );
        assert_eq!(find_desktop_file(apps, "missing.desktop"), None);
    }

    #[test]
    fn previous_handler() {
        let state = |p: Option<&str>| {
            Some(HandlerState {
                previous: p.map(str::to_owned),
            })
        };
        // First install: the current handler, never pwk itself.
        assert_eq!(
            previous_for_install(None, Some("passwork.desktop")).as_deref(),
            Some("passwork.desktop")
        );
        assert_eq!(previous_for_install(None, Some(DESKTOP_FILE)), None);
        assert_eq!(previous_for_install(None, None), None);
        // Re-install while pwk is the handler: the remembered one.
        assert_eq!(
            previous_for_install(state(Some("passwork.desktop")), Some(DESKTOP_FILE)).as_deref(),
            Some("passwork.desktop")
        );
        assert_eq!(
            previous_for_install(state(Some("passwork.desktop")), None).as_deref(),
            Some("passwork.desktop")
        );
        // A handler chosen after the earlier install is taken over.
        assert_eq!(
            previous_for_install(state(Some("passwork.desktop")), Some("other.desktop")).as_deref(),
            Some("other.desktop")
        );
    }

    #[test]
    fn restore_only_over_pwk() {
        assert!(should_restore(&Ok(Some(DESKTOP_FILE.to_owned()))));
        assert!(should_restore(&Ok(None)));
        assert!(should_restore(&Err(anyhow::anyhow!("no gio"))));
        assert!(!should_restore(&Ok(Some("other.desktop".to_owned()))));
    }
}
