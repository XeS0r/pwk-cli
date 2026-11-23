//! Integration tests of the `pwk` binary for commands that need no server.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

/// `pwk` with HOME, config and state isolated in `dir`.
fn pwk(dir: &Path) -> Command {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("pwk");
    cmd.env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("PWK_CONFIG", dir.join("config.toml"));
    for var in [
        "PWK_PROFILE",
        "PWK_FORMAT",
        "PWK_SESSION",
        "PASSWORK_HOST",
        "PASSWORK_TOKEN",
        "PASSWORK_REFRESH_TOKEN",
        "PASSWORK_MASTER_KEY",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

#[test]
fn help() {
    let dir = tempfile::tempdir().unwrap();
    pwk(dir.path())
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Command line client for Passwork 7",
        ))
        .stdout(predicate::str::contains("unlock"))
        .stdout(predicate::str::contains("generate-man").not());
}

#[test]
fn usage_error_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    pwk(dir.path()).arg("frobnicate").assert().code(2);
    pwk(dir.path()).args(["run", "env"]).assert().code(2);
}

#[test]
fn server_commands_need_login() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        &["vault", "list"][..],
        &["read", "pw://V/i/password"],
        &["status"],
    ] {
        let assert = pwk(dir.path()).args(args).assert();
        if args == ["status"] {
            assert
                .success()
                .stdout(predicate::str::contains("not logged in"));
        } else {
            assert
                .code(1)
                .stderr(predicate::str::starts_with("pwk: not logged in"));
        }
    }
}

#[test]
fn run_without_references_needs_no_login() {
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("a.env");
    std::fs::write(&env_file, "GREETING=hello\n").unwrap();
    pwk(dir.path())
        .args(["run", "--env-file"])
        .arg(&env_file)
        .args(["--", "sh", "-c", "echo $GREETING; exit 3"])
        .assert()
        .code(3)
        .stdout("hello\n");
}

#[test]
fn inject_without_placeholders_needs_no_login() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.txt");
    pwk(dir.path())
        .args(["inject", "-o"])
        .arg(&out)
        .write_stdin("plain {{ text }}\n")
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "plain {{ text }}\n");
}

#[test]
fn completions_bash() {
    let dir = tempfile::tempdir().unwrap();
    pwk(dir.path())
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("_pwk()"));
}

#[test]
fn generate_man_pages() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("man");
    pwk(dir.path())
        .arg("generate-man")
        .arg(&out)
        .assert()
        .success();
    assert!(out.join("pwk.1").is_file());
    assert!(out.join("pwk-item-create.1").is_file());
}

#[test]
fn generate_length() {
    let dir = tempfile::tempdir().unwrap();
    let output = pwk(dir.path())
        .args(["generate", "--length", "20"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    let password = text.strip_suffix('\n').unwrap();
    assert_eq!(password.chars().count(), 20);

    let output = pwk(dir.path())
        .args(["generate", "--no-symbols"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    let password = text.trim_end();
    assert_eq!(password.len(), 32);
    assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));

    pwk(dir.path())
        .args(["generate", "--length", "2"])
        .assert()
        .code(2);
}

#[test]
fn config_set_show_unset() {
    let dir = tempfile::tempdir().unwrap();
    pwk(dir.path())
        .args(["config", "set", "host", "https://pw.example.com/"])
        .assert()
        .success();
    pwk(dir.path())
        .args([
            "--profile",
            "work",
            "config",
            "set",
            "session_timeout",
            "30m",
        ])
        .assert()
        .success();
    pwk(dir.path())
        .args(["config", "set", "colour", "red"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("unknown key"));

    let text = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
    assert!(text.contains("https://pw.example.com\""), "{text}");

    pwk(dir.path())
        .args(["config", "show", "--format", "table"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "profiles.default.host          https://pw.example.com",
        ))
        .stdout(predicate::str::contains(
            "profiles.work.session_timeout  30m",
        ));

    let output = pwk(dir.path())
        .args(["config", "show"])
        .env("PWK_FORMAT", "json")
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["profiles"]["work"]["session_timeout"], "30m");

    pwk(dir.path())
        .args(["-p", "work", "config", "unset", "session_timeout"])
        .assert()
        .success();
    let output = pwk(dir.path())
        .args(["config", "show", "--format", "json"])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["profiles"].get("work").is_none());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let meta = std::fs::metadata(dir.path().join("config.toml")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn profile_list_use_remove() {
    let dir = tempfile::tempdir().unwrap();
    pwk(dir.path())
        .args(["profile", "list", "--format", "json"])
        .assert()
        .success()
        .stdout("[]\n");

    pwk(dir.path())
        .args(["-p", "work", "config", "set", "host", "https://w.example"])
        .assert()
        .success();
    pwk(dir.path())
        .args(["profile", "use", "work"])
        .assert()
        .success();
    pwk(dir.path())
        .args(["profile", "list", "--format", "table"])
        .assert()
        .success()
        .stdout("NAME  DEFAULT  HOST               SESSION\nwork  *        https://w.example  -\n");

    let output = pwk(dir.path())
        .args(["profile", "list", "--format", "json"])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json[0]["name"], "work");
    assert_eq!(json[0]["default"], true);
    assert_eq!(json[0]["logged_in"], false);

    pwk(dir.path())
        .args(["profile", "use", "bad name"])
        .assert()
        .code(1);
    pwk(dir.path())
        .args(["profile", "remove", "work"])
        .assert()
        .success();
    pwk(dir.path())
        .args(["profile", "remove", "work"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no profile named work"));
}

#[test]
fn lock_and_logout_without_session() {
    let dir = tempfile::tempdir().unwrap();
    pwk(dir.path()).arg("lock").assert().success();
    pwk(dir.path()).arg("logout").assert().success();
}
