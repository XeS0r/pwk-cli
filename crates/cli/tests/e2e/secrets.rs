//! `read`, `run`, `inject`, `totp`.

use crate::harness::{Env, assert_error, assert_success, digit_runs, expected_totp_codes, stdout};
use crate::server::*;

const PROD_DB: &str = "pw://Infra/Datenbanken/Prod/Prod DB";

fn read(env: &Env, key: &str, reference: &str) -> std::process::Output {
    env.pwk_with(key)
        .args(["read", reference])
        .output()
        .unwrap()
}

fn read_ok(env: &Env, key: &str, reference: &str) -> String {
    let out = read(env, key, reference);
    assert_success(&out, &format!("read {reference}"));
    stdout(&out).trim_end_matches('\n').to_owned()
}

/// Scenario 4: nested folder path, password.
#[test]
fn read_password_in_nested_folder() {
    let (env, key) = Env::unlocked();
    assert_eq!(
        read_ok(&env, &key, &format!("{PROD_DB}/password")),
        PROD_DB_PASSWORD
    );
}

/// Scenario 4: standard fields.
#[test]
fn read_standard_fields() {
    let (env, key) = Env::unlocked();
    assert_eq!(
        read_ok(&env, &key, &format!("{PROD_DB}/login")),
        PROD_DB_LOGIN
    );
    assert_eq!(read_ok(&env, &key, &format!("{PROD_DB}/url")), PROD_DB_URL);
    assert_eq!(read_ok(&env, &key, &format!("{PROD_DB}/name")), "Prod DB");
    assert_eq!(
        read_ok(&env, &key, &format!("{PROD_DB}/description")),
        PROD_DB_DESCRIPTION
    );
}

/// Scenario 4: custom fields, exact then case-insensitive.
#[test]
fn read_custom_fields() {
    let (env, key) = Env::unlocked();
    assert_eq!(
        read_ok(&env, &key, &format!("{PROD_DB}/Host")),
        PROD_DB_HOST
    );
    assert_eq!(
        read_ok(&env, &key, &format!("{PROD_DB}/host")),
        PROD_DB_HOST
    );
    assert_eq!(
        read_ok(&env, &key, &format!("{PROD_DB}/API Key")),
        PROD_DB_API_KEY
    );
    // Without ?attribute=totp a TOTP field gives its secret.
    assert_eq!(read_ok(&env, &key, &format!("{PROD_DB}/OTP")), PROD_DB_TOTP);
}

/// Scenario 4: `?attribute=totp` prints the current 6-digit code.
#[test]
fn read_totp_attribute_prints_current_code() {
    let (env, key) = Env::unlocked();
    let code = read_ok(&env, &key, &format!("{PROD_DB}/OTP?attribute=totp"));
    assert_eq!(code.len(), 6, "code {code:?}");
    assert!(code.chars().all(|c| c.is_ascii_digit()), "code {code:?}");
    assert!(
        expected_totp_codes(PROD_DB_TOTP).contains(&code),
        "{code} is not a current code"
    );
}

/// Scenario 4: a missing field is an error.
#[test]
fn read_missing_field_fails() {
    let (env, key) = Env::unlocked();
    let out = read(&env, &key, &format!("{PROD_DB}/nonexistent"));
    let err = assert_error(&out, "read missing field");
    assert!(
        err.contains("nonexistent"),
        "error should name the field: {err}"
    );
    assert!(stdout(&out).is_empty());
}

/// A missing item or folder is an error as well.
#[test]
fn read_missing_item_or_folder_fails() {
    let (env, key) = Env::unlocked();
    assert_error(
        &read(
            &env,
            &key,
            "pw://Infra/Datenbanken/Prod/No Such Item/password",
        ),
        "read missing item",
    );
    assert_error(
        &read(&env, &key, "pw://Infra/Nope/Prod DB/password"),
        "read missing folder",
    );
    // Prod DB is in Datenbanken/Prod, not in the vault root.
    assert_error(
        &read(&env, &key, "pw://Team/Prod DB/password"),
        "read item in the wrong vault",
    );
}

/// Scenario 4: percent-encoded segments (`%2F` in a name, `%20`).
#[test]
fn read_percent_encoded_names() {
    let (env, key) = Env::unlocked();
    assert_eq!(
        read_ok(
            &env,
            &key,
            "pw://Infra/Datenbanken/Name%2FWith%20Slash/password"
        ),
        SLASH_PASSWORD
    );
    assert_eq!(
        read_ok(
            &env,
            &key,
            "pw://Infra/Datenbanken/Name%2FWith%20Slash/API%20Key"
        ),
        SLASH_API_KEY
    );
    assert_eq!(
        read_ok(&env, &key, "pw://Infra/Datenbanken/Prod/Prod%20DB/password"),
        PROD_DB_PASSWORD
    );
}

/// Empty folder path; vault and folder by ID.
#[test]
fn read_vault_root_and_ids() {
    let (env, key) = Env::unlocked();
    assert_eq!(
        read_ok(&env, &key, "pw://Infra/Shared Mail/password"),
        INFRA_MAIL_PASSWORD
    );
    assert_eq!(
        read_ok(&env, &key, "pw://Team/Shared Mail/password"),
        TEAM_MAIL_PASSWORD
    );
    assert_eq!(
        read_ok(
            &env,
            &key,
            &format!("pw://{VAULT_INFRA}/{FOLDER_DB}/{FOLDER_PROD}/Prod DB/login")
        ),
        PROD_DB_LOGIN
    );
    assert_eq!(
        read_ok(
            &env,
            &key,
            &format!("pw://Infra/Datenbanken/Prod/{ITEM_PROD_DB}/password")
        ),
        PROD_DB_PASSWORD,
        "item ID in a reference"
    );
}

/// An item ID in a reference must sit at the path given before it.
#[test]
fn read_item_id_checks_its_location() {
    let (env, key) = Env::unlocked();
    assert_eq!(
        read_ok(&env, &key, &format!("pw://Infra/{ITEM_PROD_DB}/password")),
        PROD_DB_PASSWORD,
        "without folder segments only the vault is checked"
    );
    for wrong in [
        format!("pw://Team/{ITEM_PROD_DB}/password"),
        format!("pw://Infra/Datenbanken/{ITEM_PROD_DB}/password"),
    ] {
        let out = read(&env, &key, &wrong);
        let err = assert_error(&out, &format!("read {wrong}"));
        assert!(err.contains("Infra/Datenbanken/Prod"), "{wrong}: {err}");
        assert!(!stdout(&out).contains(PROD_DB_PASSWORD), "{wrong}");
    }
}

/// `run` does not hand the unlock material to the child; PASSWORK_HOST stays.
#[test]
fn run_hides_unlock_variables_from_the_child() {
    let (env, key) = Env::unlocked();
    let out = env
        .pwk_with(&key)
        .env("DB_PASSWORD", format!("{PROD_DB}/password"))
        .env("PWK_SESSION_OTHER", "other-session-key")
        .args(["run", "--", "sh", "-c", "env"])
        .output()
        .unwrap();
    assert_success(&out, "run env");
    let text = stdout(&out);
    assert!(!text.contains(&key), "session key leaked: {text}");
    assert!(!text.contains("PWK_SESSION"), "{text}");
    assert!(text.contains("DB_PASSWORD="), "{text}");

    // Stateless variables, without references (nothing is resolved, no masking).
    let out = env
        .pwk()
        .env("PASSWORK_HOST", &env.server.url)
        .env("PASSWORK_TOKEN", "tok-secret")
        .env("PASSWORK_REFRESH_TOKEN", "refresh-secret")
        .env("PASSWORK_MASTER_KEY", "master-secret")
        .env("PWK_SESSION", "session-secret")
        .args(["run", "--", "sh", "-c", "env"])
        .output()
        .unwrap();
    assert_success(&out, "run env (stateless)");
    let text = stdout(&out);
    for leaked in [
        "tok-secret",
        "refresh-secret",
        "master-secret",
        "session-secret",
    ] {
        assert!(!text.contains(leaked), "{leaked} leaked: {text}");
    }
    assert!(
        text.contains(&format!("PASSWORK_HOST={}", env.server.url)),
        "{text}"
    );
}

/// Output that ends like the start of a secret (a prompt) is shown without waiting for
/// more output.
#[cfg(unix)]
#[test]
fn run_masking_shows_a_held_back_prompt_soon() {
    use std::io::Read as _;
    use std::time::{Duration, Instant};

    let (env, key) = Env::unlocked();
    // "Enter Pr0d" is a prefix of PROD_DB_PASSWORD, so the masker holds it back.
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_pwk"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", env.home())
        .env("XDG_CONFIG_HOME", env.config_home())
        .env("XDG_STATE_HOME", env.state_home())
        .env("PWK_SESSION", &key)
        .env("DB_PASSWORD", format!("{PROD_DB}/password"))
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "printf 'Enter Pr0d'; sleep 3; echo",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut seen = Vec::new();
    let mut buf = [0u8; 64];
    let mut prompt_at = None;
    let start = Instant::now();
    while let Ok(n) = stdout.read(&mut buf) {
        if n == 0 {
            break;
        }
        seen.extend_from_slice(&buf[..n]);
        if prompt_at.is_none() && seen.starts_with(b"Enter Pr0d") {
            prompt_at = Some(start.elapsed());
        }
    }
    let status = child.wait().unwrap();
    assert!(status.success());
    assert_eq!(String::from_utf8_lossy(&seen), "Enter Pr0d\n");
    // Resolving the reference takes a moment too; the child sleeps 3 s after the prompt.
    let prompt_at = prompt_at.expect("prompt shown");
    let total = start.elapsed();
    assert!(
        total - prompt_at > Duration::from_millis(1500),
        "prompt only shown at {prompt_at:?} of {total:?}"
    );
}

/// A background process that keeps the output pipes open does not keep `run` waiting.
#[cfg(unix)]
#[test]
fn run_masking_returns_when_the_child_exits() {
    let (env, key) = Env::unlocked();
    let start = std::time::Instant::now();
    let out = env
        .pwk_with(&key)
        .env("DB_PASSWORD", format!("{PROD_DB}/password"))
        .args(["run", "--", "sh", "-c", "(sleep 30 &) ; echo done"])
        .output()
        .unwrap();
    assert_success(&out, "run with a background grandchild");
    assert_eq!(stdout(&out), "done\n");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(15),
        "took {:?}",
        start.elapsed()
    );
}

/// Scenario 8: secrets in the child's output are masked.
#[test]
fn run_masks_resolved_secrets() {
    let (env, key) = Env::unlocked();
    let out = env
        .pwk_with(&key)
        .env("DB_PASSWORD", format!("{PROD_DB}/password"))
        .env("PLAIN", "not-a-ref")
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "echo \"pw=$DB_PASSWORD plain=$PLAIN\"; echo \"err=$DB_PASSWORD\" >&2",
        ])
        .output()
        .unwrap();
    assert_success(&out, "run");
    let text = stdout(&out);
    let err = crate::harness::stderr(&out);
    assert!(!text.contains(PROD_DB_PASSWORD), "secret leaked: {text}");
    assert!(
        !err.contains(PROD_DB_PASSWORD),
        "secret leaked on stderr: {err}"
    );
    assert!(
        text.contains("pw=<concealed by pwk> plain=not-a-ref"),
        "stdout: {text}"
    );
    assert!(err.contains("err=<concealed by pwk>"), "stderr: {err}");
}

/// Scenario 8: --env-file variables (dotenv syntax) are resolved and masked.
#[test]
fn run_env_file_references_are_resolved() {
    let (env, key) = Env::unlocked();
    let file = env.home().join("app.env");
    std::fs::write(
        &file,
        format!(
            "# comment\nexport API_KEY=\"{PROD_DB}/API Key\"\nDB_HOST='{PROD_DB}/Host'\nGREETING=hello\n"
        ),
    )
    .unwrap();
    // The child proves it got the real value without printing it.
    let script = format!(
        "[ \"$API_KEY\" = '{PROD_DB_API_KEY}' ] && echo key-ok; echo \"host=$DB_HOST greet=$GREETING\""
    );
    let out = env
        .pwk_with(&key)
        .arg("run")
        .arg("--env-file")
        .arg(&file)
        .args(["--", "sh", "-c", &script])
        .output()
        .unwrap();
    assert_success(&out, "run --env-file");
    let text = stdout(&out);
    assert!(text.contains("key-ok"), "API_KEY not resolved: {text}");
    assert!(
        text.contains("host=<concealed by pwk> greet=hello"),
        "stdout: {text}"
    );
}

/// Scenario 8: --no-masking passes the secret through.
#[test]
fn run_no_masking_shows_secret() {
    let (env, key) = Env::unlocked();
    let out = env
        .pwk_with(&key)
        .env("DB_PASSWORD", format!("{PROD_DB}/password"))
        .args([
            "run",
            "--no-masking",
            "--",
            "sh",
            "-c",
            "echo \"$DB_PASSWORD\"",
        ])
        .output()
        .unwrap();
    assert_success(&out, "run --no-masking");
    assert_eq!(stdout(&out).trim_end(), PROD_DB_PASSWORD);
}

/// Scenario 8: the child's exit code is forwarded.
#[test]
fn run_forwards_exit_code() {
    let (env, key) = Env::unlocked();
    let out = env
        .pwk_with(&key)
        .env("DB_PASSWORD", format!("{PROD_DB}/password"))
        .args(["run", "--", "sh", "-c", "exit 7"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(7),
        "stderr: {}",
        crate::harness::stderr(&out)
    );
    let out = env
        .pwk_with(&key)
        .args(["run", "--no-masking", "--", "sh", "-c", "exit 3"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
}

/// A reference that cannot be resolved fails before the command runs.
#[test]
fn run_with_bad_reference_does_not_start_command() {
    let (env, key) = Env::unlocked();
    let marker = env.home().join("ran");
    let out = env
        .pwk_with(&key)
        .env("BAD", "pw://Infra/Datenbanken/Prod/Prod DB/nonexistent")
        .args(["run", "--", "sh", "-c"])
        .arg(format!("touch '{}'", marker.display()))
        .output()
        .unwrap();
    assert_error(&out, "run with a bad reference");
    assert!(!marker.exists(), "the command ran despite the error");
}

/// Scenario 9: inject replaces placeholders, keeps the rest, writes 0600.
#[test]
fn inject_writes_secrets_to_0600_file() {
    let (env, key) = Env::unlocked();
    let template = format!(
        "# config\nhost: {{{{ {PROD_DB}/Host }}}}\npassword: {{{{{PROD_DB}/password}}}}\n\
         api:{{{{  {PROD_DB}/API%20Key  }}}}!\nliteral: {{{{ not a reference }}}} $HOME ${{X}}\n"
    );
    let input = env.home().join("app.tpl");
    let output = env.home().join("app.conf");
    std::fs::write(&input, &template).unwrap();
    let out = env
        .pwk_with(&key)
        .arg("inject")
        .arg("-i")
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert_success(&out, "inject -i -o");
    let written = std::fs::read_to_string(&output).unwrap();
    let expected = format!(
        "# config\nhost: {PROD_DB_HOST}\npassword: {PROD_DB_PASSWORD}\n\
         api:{PROD_DB_API_KEY}!\nliteral: {{{{ not a reference }}}} $HOME ${{X}}\n"
    );
    assert_eq!(written, expected);
    #[cfg(unix)]
    assert_eq!(crate::harness::mode(&output), 0o600);
    assert!(!stdout(&out).contains(PROD_DB_PASSWORD));
}

/// inject from stdin to stdout.
#[test]
fn inject_stdin_to_stdout() {
    let (env, key) = Env::unlocked();
    let out = env
        .pwk_with(&key)
        .arg("inject")
        .write_stdin(format!("user={{{{ {PROD_DB}/login }}}}\nno newline at end"))
        .output()
        .unwrap();
    assert_success(&out, "inject (stdin)");
    assert_eq!(
        stdout(&out),
        format!("user={PROD_DB_LOGIN}\nno newline at end")
    );
}

/// Scenario 10: `totp` prints the current code of the known secret.
#[test]
fn totp_prints_current_code() {
    let (env, key) = Env::unlocked();
    let out = env
        .pwk_with(&key)
        .args(["--format", "table", "item", "totp", "Prod DB"])
        .output()
        .unwrap();
    assert_success(&out, "totp");
    let codes = digit_runs(&stdout(&out), 6);
    let expected = expected_totp_codes(PROD_DB_TOTP);
    assert!(
        codes.iter().any(|c| expected.contains(c)),
        "no current code in {:?} (expected one of {expected:?})",
        stdout(&out)
    );

    let out = env
        .pwk_with(&key)
        .args(["item", "totp", "Prod DB", "--field", "OTP"])
        .output()
        .unwrap();
    assert_success(&out, "totp --field OTP");
    assert!(
        digit_runs(&stdout(&out), 6)
            .iter()
            .any(|c| expected.contains(c)),
        "{}",
        stdout(&out)
    );
}

/// `totp` on an item without a TOTP field fails.
#[test]
fn totp_without_totp_field_fails() {
    let (env, key) = Env::unlocked();
    let out = env
        .pwk_with(&key)
        .args(["item", "totp", "Shared Mail", "--vault", "Infra"])
        .output()
        .unwrap();
    assert_error(&out, "totp on an item without TOTP");
}
