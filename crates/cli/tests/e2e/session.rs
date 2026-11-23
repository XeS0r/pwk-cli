//! Harness sanity check, login/unlock/lock/logout, stateless mode, token refresh,
//! profiles and status.

use std::sync::Arc;

use base64::Engine as _;
use pwk_api::{Client, ClientConfig, ItemFilter, MemoryTokenStore, TokenStore as _, Tokens};

use crate::harness::{
    Env, assert_error, assert_locked, assert_success, files_below, stderr, stdout, stdout_json,
};
use crate::server::*;

fn item_get_password(env: &Env, key: &str) -> std::process::Output {
    env.pwk_with(key)
        .args(["item", "get", "Prod DB", "--field", "password"])
        .output()
        .unwrap()
}

/// The fake server's world, checked with `pwk_api` directly (independent of the CLI):
/// unlock, vaults, item decryption, batch, search filters, attachments, refresh.
#[test]
fn harness_fake_server_world_decrypts_with_pwk_api() {
    let server = FakePasswork::start();
    let store = Arc::new(MemoryTokenStore::new(Tokens {
        access_token: ACCESS_TOKEN.into(),
        refresh_token: Some(REFRESH_TOKEN.into()),
        access_expires_at: None,
        refresh_expires_at: None,
    }));
    let client = Client::new(ClientConfig::new(server.url.clone()), store.clone()).unwrap();

    let mk = client.unlock_with_password(MASTER_PASSWORD).unwrap();
    assert_eq!(mk.as_str(), server.master_key);

    let names: Vec<String> = client
        .list_vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, ["Infra", "Team"]);

    let item = client.get_item(ITEM_PROD_DB).unwrap();
    assert_eq!(
        item.password.as_deref().map(String::as_str),
        Some(PROD_DB_PASSWORD)
    );
    let customs: Vec<(String, String)> = item
        .customs
        .iter()
        .map(|c| (c.name.clone(), c.value.to_string()))
        .collect();
    assert_eq!(
        customs,
        [
            ("Host".to_owned(), PROD_DB_HOST.to_owned()),
            ("API Key".to_owned(), PROD_DB_API_KEY.to_owned()),
            ("OTP".to_owned(), PROD_DB_TOTP.to_owned()),
        ]
    );

    let both = client
        .get_items(&[ITEM_MAIL_INFRA.into(), ITEM_MAIL_TEAM.into()])
        .unwrap();
    let pws: Vec<String> = both
        .iter()
        .map(|i| i.password.as_deref().unwrap().to_string())
        .collect();
    assert_eq!(pws, [INFRA_MAIL_PASSWORD, TEAM_MAIL_PASSWORD]);

    let found = client
        .search_items(&ItemFilter {
            query: Some("shared".into()),
            vault_ids: vec![VAULT_TEAM.into()],
            ..ItemFilter::default()
        })
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, ITEM_MAIL_TEAM);
    let in_prod = client
        .list_items(&ItemFilter {
            folder_ids: vec![FOLDER_PROD.into()],
            ..ItemFilter::default()
        })
        .unwrap();
    assert_eq!(in_prod.len(), 1);

    let (name, data) = client.download_attachment(&item, ATT_DUMP).unwrap();
    assert_eq!(name, DUMP_NAME);
    assert_eq!(data.as_slice(), dump_content().as_slice());
    assert!(client.download_attachment(&item, ATT_BROKEN).is_err());

    server.expire_access_token();
    assert_eq!(client.list_vaults().unwrap().len(), 2);
    assert_eq!(server.rotations(), 1);
    let (access, refresh) = server.tokens();
    let current = store.current().unwrap();
    assert_eq!(current.access_token, access);
    assert_eq!(current.refresh_token.as_deref(), Some(refresh.as_str()));
}

/// Scenario 1: login, unlock (`export PWK_SESSION='…'` and `--raw`), item get with the
/// session key.
#[test]
fn login_unlock_then_item_get_with_session_key() {
    let env = Env::new();
    env.login(None);

    let out = env
        .pwk()
        .args(["unlock", "--password-stdin"])
        .write_stdin(format!("{MASTER_PASSWORD}\n"))
        .output()
        .unwrap();
    assert_success(&out, "unlock");
    let text = stdout(&out);
    let line = text
        .lines()
        .find(|l| l.starts_with("export PWK_SESSION="))
        .unwrap_or_else(|| panic!("no `export PWK_SESSION=` line in:\n{text}"));
    let key = line
        .trim_start_matches("export PWK_SESSION=")
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .to_owned();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&key)
        .unwrap_or_else(|e| panic!("session key {key:?} is not Base64: {e}"));
    assert_eq!(raw.len(), 32, "session key should be 32 random bytes");

    let out = item_get_password(&env, &key);
    assert_success(&out, "item get --field password");
    assert_eq!(stdout(&out).trim_end_matches('\n'), PROD_DB_PASSWORD);

    // --raw: a second unlock prints the bare key, which works as well.
    let raw_key = env.unlock_raw(None);
    assert!(!raw_key.contains("export"), "--raw printed {raw_key:?}");
    let out = item_get_password(&env, &raw_key);
    assert_success(&out, "item get with the --raw key");
    assert_eq!(stdout(&out).trim_end_matches('\n'), PROD_DB_PASSWORD);
}

/// `unlock --shell fish` prints `set -gx PWK_SESSION …`.
#[test]
fn unlock_shell_fish_prints_set_gx() {
    let env = Env::new();
    env.login(None);
    let out = env
        .pwk()
        .args(["unlock", "--password-stdin", "--shell", "fish"])
        .write_stdin(format!("{MASTER_PASSWORD}\n"))
        .output()
        .unwrap();
    assert_success(&out, "unlock --shell fish");
    assert!(
        stdout(&out).contains("set -gx PWK_SESSION "),
        "got:\n{}",
        stdout(&out)
    );
}

/// Unlock with a wrong master password fails and stores no unlock.
#[test]
fn unlock_with_wrong_master_password_fails() {
    let env = Env::new();
    env.login(None);
    let out = env
        .pwk()
        .args(["unlock", "--password-stdin", "--raw"])
        .write_stdin("not the password\n")
        .output()
        .unwrap();
    assert_error(&out, "unlock (wrong password)");
    assert!(stdout(&out).trim().is_empty(), "printed a key anyway");
    assert!(env.session_json("default")["unlock"].is_null());
}

/// Scenario 1: without PWK_SESSION the item is locked.
#[test]
fn item_get_without_session_key_is_locked() {
    let (env, _key) = Env::unlocked();
    let out = env
        .pwk()
        .args(["item", "get", "Prod DB", "--field", "password"])
        .output()
        .unwrap();
    assert_locked(&out, "item get without PWK_SESSION");
    assert!(!stdout(&out).contains(PROD_DB_PASSWORD));
}

/// Scenario 1: a wrong session key is locked.
#[test]
fn item_get_with_wrong_session_key_is_locked() {
    let (env, _key) = Env::unlocked();
    let wrong = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let out = item_get_password(&env, &wrong);
    assert_locked(&out, "item get with a wrong key");
    let out = item_get_password(&env, "not base64 at all!");
    assert_locked(&out, "item get with a malformed key");
}

/// Scenario 1: an unlock whose timeout has passed is locked.
#[test]
fn item_get_after_unlock_timeout_is_locked() {
    let env = Env::new();
    env.login(None);
    let out = env
        .pwk()
        .args(["unlock", "--password-stdin", "--raw", "--timeout", "1s"])
        .write_stdin(format!("{MASTER_PASSWORD}\n"))
        .output()
        .unwrap();
    assert_success(&out, "unlock --timeout 1s");
    let key = stdout(&out).trim().to_owned();
    std::thread::sleep(std::time::Duration::from_millis(2100));
    assert_locked(&item_get_password(&env, &key), "item get after expiry");
}

/// Scenario 1: pushing `expires_at` into the future in session.json breaks the seal
/// (it is part of the AAD).
#[test]
fn tampered_session_expiry_is_locked() {
    let (env, key) = Env::unlocked();
    assert_success(&item_get_password(&env, &key), "item get before tampering");

    let mut session = env.session_json("default");
    let expires = session["unlock"]["expires_at"]
        .as_u64()
        .expect("unlock.expires_at is a number");
    session["unlock"]["expires_at"] = (expires + 3600).into();
    std::fs::write(
        env.session_path("default"),
        serde_json::to_string_pretty(&session).unwrap(),
    )
    .unwrap();
    assert_locked(&item_get_password(&env, &key), "item get after tampering");
}

/// session.json is 0600 in a 0700 directory and has the documented shape.
#[cfg(unix)]
#[test]
fn session_file_has_mode_0600_and_documented_fields() {
    let (env, _key) = Env::unlocked();
    let path = env.session_path("default");
    assert_eq!(crate::harness::mode(&path), 0o600);
    assert_eq!(crate::harness::mode(path.parent().unwrap()), 0o700);
    let s = env.session_json("default");
    assert_eq!(s["version"], 1);
    assert_eq!(s["access_token"], ACCESS_TOKEN);
    assert_eq!(s["refresh_token"], REFRESH_TOKEN);
    assert!(
        s["host"]
            .as_str()
            .is_some_and(|h| h.starts_with(&env.server.url))
    );
    for field in ["expires_at", "nonce", "ciphertext"] {
        assert!(
            !s["unlock"][field].is_null(),
            "unlock.{field} missing: {s:#}"
        );
    }
    // The master key must not be stored in the clear.
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains(&env.server.master_key));
}

/// Scenario 2: lock → locked.
#[test]
fn lock_then_item_get_is_locked() {
    let (env, key) = Env::unlocked();
    assert_success(&env.pwk().arg("lock").output().unwrap(), "lock");
    assert!(env.session_json("default")["unlock"].is_null());
    assert_locked(&item_get_password(&env, &key), "item get after lock");
}

/// Scenario 2: logout → not logged in.
#[test]
fn logout_then_item_get_is_not_logged_in() {
    let (env, key) = Env::unlocked();
    assert_success(&env.pwk().arg("logout").output().unwrap(), "logout");
    assert!(!env.session_path("default").exists());
    let out = item_get_password(&env, &key);
    let err = assert_error(&out, "item get after logout");
    let lower = err.to_lowercase();
    assert!(
        lower.contains("not logged in") || lower.contains("pwk login"),
        "error should say not logged in, got:\n{err}"
    );
}

/// Scenario 3: stateless mode reads secrets and writes no files.
#[test]
fn stateless_mode_reads_without_writing_files() {
    let env = Env::new();
    let out = env
        .pwk()
        .env("PASSWORK_HOST", &env.server.url)
        .env("PASSWORK_TOKEN", ACCESS_TOKEN)
        .env("PASSWORK_MASTER_KEY", &env.server.master_key)
        .args(["read", "pw://Infra/Datenbanken/Prod/Prod DB/password"])
        .output()
        .unwrap();
    assert_success(&out, "read (stateless)");
    assert_eq!(stdout(&out).trim_end_matches('\n'), PROD_DB_PASSWORD);
    let written: Vec<_> = files_below(env.home());
    assert!(
        written.is_empty(),
        "stateless mode wrote files: {written:?}"
    );
}

/// Stateless mode: an expired access token is refreshed with PASSWORK_REFRESH_TOKEN,
/// kept in memory only.
#[test]
fn stateless_mode_refreshes_in_memory() {
    let env = Env::new();
    env.server.expire_access_token();
    let out = env
        .pwk()
        .env("PASSWORK_HOST", &env.server.url)
        .env("PASSWORK_TOKEN", ACCESS_TOKEN)
        .env("PASSWORK_REFRESH_TOKEN", REFRESH_TOKEN)
        .env("PASSWORK_MASTER_KEY", &env.server.master_key)
        .args(["read", "pw://Infra/Shared Mail/password"])
        .output()
        .unwrap();
    assert_success(&out, "read (stateless, expired token)");
    assert_eq!(stdout(&out).trim_end_matches('\n'), INFRA_MAIL_PASSWORD);
    assert_eq!(env.server.rotations(), 1);
    assert!(files_below(env.home()).is_empty());
}

/// PASSWORK_MASTER_KEY next to a stored (locked) session counts as unlocked.
#[test]
fn master_key_env_unlocks_stored_session() {
    let env = Env::new();
    env.login(None);
    let out = env
        .pwk()
        .env("PASSWORK_MASTER_KEY", &env.server.master_key)
        .args(["item", "get", "Prod DB", "--field", "password"])
        .output()
        .unwrap();
    assert_success(&out, "item get with PASSWORK_MASTER_KEY");
    assert_eq!(stdout(&out).trim_end_matches('\n'), PROD_DB_PASSWORD);
}

/// Scenario 11: 401 accessTokenExpired → refresh, retry, rotated tokens in session.json.
#[test]
fn expired_access_token_is_refreshed_and_stored() {
    let (env, key) = Env::unlocked();
    env.server.expire_access_token();
    let out = item_get_password(&env, &key);
    assert_success(&out, "item get with an expired access token");
    assert_eq!(stdout(&out).trim_end_matches('\n'), PROD_DB_PASSWORD);

    assert_eq!(env.server.rotations(), 1, "exactly one refresh");
    let refresh_calls = env.server.requests_to("POST", "/api/v1/sessions/refresh");
    assert_eq!(refresh_calls[0].json()["refreshToken"], REFRESH_TOKEN);
    let (access, refresh) = env.server.tokens();
    let s = env.session_json("default");
    assert_eq!(s["access_token"], access.as_str());
    assert_eq!(s["refresh_token"], refresh.as_str());
    // The unlock survives the token rewrite.
    assert!(!s["unlock"].is_null());

    // And the next run uses the stored new pair without refreshing again.
    assert_success(&item_get_password(&env, &key), "item get after refresh");
    assert_eq!(env.server.rotations(), 1);
}

/// Scenario 14: a non-default profile prints PWK_SESSION_WORK and uses its own session.
#[test]
fn profile_unlock_prints_profile_variable() {
    let env = Env::new();
    env.login(None);
    env.login(Some("work"));
    assert!(env.session_path("work").is_file());

    let out = env
        .pwk()
        .args(["--profile", "work", "unlock", "--password-stdin"])
        .write_stdin(format!("{MASTER_PASSWORD}\n"))
        .output()
        .unwrap();
    assert_success(&out, "--profile work unlock");
    let text = stdout(&out);
    let line = text
        .lines()
        .find(|l| l.starts_with("export PWK_SESSION_WORK="))
        .unwrap_or_else(|| panic!("no `export PWK_SESSION_WORK=` in:\n{text}"));
    let key = line
        .trim_start_matches("export PWK_SESSION_WORK=")
        .trim()
        .trim_matches('\'')
        .to_owned();

    let out = env
        .pwk()
        .env("PWK_SESSION_WORK", &key)
        .args([
            "--profile",
            "work",
            "item",
            "get",
            "Prod DB",
            "--field",
            "login",
        ])
        .output()
        .unwrap();
    assert_success(&out, "--profile work item get");
    assert_eq!(stdout(&out).trim_end_matches('\n'), PROD_DB_LOGIN);

    // PWK_PROFILE selects the profile as well.
    let out = env
        .pwk()
        .env("PWK_PROFILE", "work")
        .env("PWK_SESSION_WORK", &key)
        .args(["item", "get", "Prod DB", "--field", "password"])
        .output()
        .unwrap();
    assert_success(&out, "PWK_PROFILE=work item get");

    // The default profile is still locked: the work key does not open it.
    let out = env
        .pwk()
        .env("PWK_SESSION_WORK", &key)
        .args(["item", "get", "Prod DB", "--field", "password"])
        .output()
        .unwrap();
    assert_locked(&out, "default profile with only PWK_SESSION_WORK");
}

/// `status` reports profile, host, user and unlocked/locked.
#[test]
fn status_reports_profile_host_and_lock_state() {
    let (env, key) = Env::unlocked();
    let out = env.pwk_with(&key).arg("status").output().unwrap();
    assert_success(&out, "status");
    let unlocked = stdout_json(&out).to_string();
    assert!(unlocked.contains("default"), "{unlocked}");
    assert!(unlocked.contains(&env.server.url), "{unlocked}");
    assert!(
        unlocked.contains("tester") || unlocked.contains("Test User"),
        "{unlocked}"
    );

    let out = env.pwk().arg("status").output().unwrap();
    assert_success(&out, "status (locked)");
    let locked = stdout_json(&out).to_string();
    assert_ne!(
        unlocked, locked,
        "status should differ between locked and unlocked"
    );
    assert!(
        locked.to_lowercase().contains("locked"),
        "status should mention locked: {locked}\n{}",
        stderr(&out)
    );
}

/// A non-default profile only reads PWK_SESSION_<PROFILE>; PWK_SESSION (the default
/// profile's key) is never tried for it.
#[test]
fn non_default_profile_ignores_pwk_session() {
    let env = Env::new();
    env.login(None);
    env.login(Some("work"));
    let key = env.unlock_raw(Some("work"));
    let out = env
        .pwk_with(&key)
        .args([
            "--profile",
            "work",
            "item",
            "get",
            "Prod DB",
            "--field",
            "login",
        ])
        .output()
        .unwrap();
    assert_locked(&out, "--profile work with only PWK_SESSION");
    let err = stderr(&out);
    assert!(err.contains("PWK_SESSION_WORK is not set"), "{err}");
}

/// Profile names that share a session variable are refused.
#[test]
fn colliding_profile_names_are_refused() {
    let env = Env::new();
    env.login(Some("a-b"));
    let out = env
        .pwk()
        .args(["--profile", "a_b", "login", "--host", &env.server.url])
        .args(["--access-token-stdin"])
        .write_stdin(format!("{ACCESS_TOKEN}\n"))
        .output()
        .unwrap();
    let err = assert_error(&out, "login --profile a_b");
    assert!(err.contains("PWK_SESSION_A_B"), "{err}");
    assert!(!env.session_path("a_b").exists());

    let out = env.pwk().args(["profile", "use", "A-B"]).output().unwrap();
    assert_error(&out, "profile use A-B");
    let out = env
        .pwk()
        .args(["config", "set", "profiles.A_b.host", "https://x.example"])
        .output()
        .unwrap();
    assert_error(&out, "config set profiles.A_b.host");
    // The profile itself is fine.
    let out = env.pwk().args(["profile", "use", "a-b"]).output().unwrap();
    assert_success(&out, "profile use a-b");
}

/// `logout` keeps the lock file (another process may wait on it).
#[test]
fn logout_keeps_the_lock_file() {
    let (env, _key) = Env::unlocked();
    let lock = env.session_path("default").with_extension("json.lock");
    assert!(lock.exists());
    assert_success(&env.pwk().arg("logout").output().unwrap(), "logout");
    assert!(!env.session_path("default").exists());
    assert!(lock.exists(), "logout deleted the lock file");
    // Logging in again works with the existing lock file.
    env.login(None);
    assert!(env.session_path("default").is_file());
}

/// A plain http:// server URL works but warns on every use.
#[test]
fn http_host_warns_on_every_use() {
    let (env, key) = Env::unlocked();
    for _ in 0..2 {
        let out = item_get_password(&env, &key);
        assert_success(&out, "item get over http");
        let err = stderr(&out);
        assert!(err.contains("warning") && err.contains("http://"), "{err}");
    }
}

/// Stateless mode honours PWK_CA_CERT (a missing file is an error) and PWK_INSECURE=1
/// (with a warning).
#[test]
fn stateless_mode_tls_variables() {
    let env = Env::new();
    let stateless = || {
        let mut cmd = env.pwk();
        cmd.env("PASSWORK_HOST", &env.server.url)
            .env("PASSWORK_TOKEN", ACCESS_TOKEN)
            .env("PASSWORK_MASTER_KEY", &env.server.master_key)
            .args(["read", "pw://Infra/Shared Mail/password"]);
        cmd
    };
    let missing = env.home().join("missing-ca.pem");
    let out = stateless().env("PWK_CA_CERT", &missing).output().unwrap();
    let err = assert_error(&out, "read with a missing PWK_CA_CERT");
    assert!(err.contains("missing-ca.pem"), "{err}");

    let out = stateless().env("PWK_INSECURE", "1").output().unwrap();
    assert_success(&out, "read with PWK_INSECURE=1");
    assert_eq!(stdout(&out).trim_end(), INFRA_MAIL_PASSWORD);
    let err = stderr(&out);
    assert!(err.contains("verification is disabled"), "{err}");
}

/// A server offering fewer PBKDF2 iterations than pwk's floor is refused: deriving the
/// key with them would make the master password cheap to brute-force.
#[test]
fn unlock_refuses_weak_key_derivation() {
    let env = Env::with_master_key_options(WEAK_MASTER_KEY_OPTIONS);
    env.login(None);
    let out = env
        .pwk()
        .args(["unlock", "--password-stdin", "--raw"])
        .write_stdin(format!("{MASTER_PASSWORD}\n"))
        .output()
        .unwrap();
    let err = assert_error(&out, "unlock against a weak server");
    let lower = err.to_lowercase();
    assert!(
        lower.contains("iterations") && lower.contains("refused"),
        "should refuse the weak key derivation, got:\n{err}"
    );
    assert!(stdout(&out).trim().is_empty(), "printed a key anyway");
    assert!(env.session_json("default")["unlock"].is_null());
}
