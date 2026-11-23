//! `item`, `vault`, `folder`, `attachment` and `api`.

use serde_json::{Value, json};

use crate::harness::{Env, assert_error, assert_success, json_contains_str, stdout, stdout_json};
use crate::server::*;

fn run(env: &Env, key: &str, args: &[&str]) -> std::process::Output {
    env.pwk_with(key).args(args).output().unwrap()
}

fn run_ok(env: &Env, key: &str, args: &[&str]) -> std::process::Output {
    let out = run(env, key, args);
    assert_success(&out, &args.join(" "));
    out
}

fn field(env: &Env, key: &str, args: &[&str]) -> String {
    let out = run_ok(env, key, args);
    stdout(&out).trim_end_matches('\n').to_owned()
}

/// The only recorded request `method path`, as JSON.
fn single_body(env: &Env, method: &str, path: &str) -> Value {
    let reqs = env.server.requests_to(method, path);
    assert_eq!(
        reqs.len(),
        1,
        "expected one {method} {path}, got {}",
        reqs.len()
    );
    reqs[0].json()
}

// ---------------------------------------------------------------------------------------
// item get

/// Scenario 5: `--field` prints the raw value of standard and custom fields.
#[test]
fn item_get_field_prints_raw_value() {
    let (env, key) = Env::unlocked();
    let get = |f: &str| field(&env, &key, &["item", "get", "Prod DB", "--field", f]);
    assert_eq!(get("password"), PROD_DB_PASSWORD);
    assert_eq!(get("login"), PROD_DB_LOGIN);
    assert_eq!(get("url"), PROD_DB_URL);
    assert_eq!(get("Host"), PROD_DB_HOST);
    assert_eq!(get("API Key"), PROD_DB_API_KEY);
}

/// Scenario 5: the table view masks password, password and TOTP customs as `********`
/// unless `--reveal`.
#[test]
fn item_get_table_masks_secrets_unless_reveal() {
    let (env, key) = Env::unlocked();
    let out = run_ok(&env, &key, &["--format", "table", "item", "get", "Prod DB"]);
    let masked = stdout(&out);
    assert!(masked.contains("********"), "no mask in:\n{masked}");
    for secret in [PROD_DB_PASSWORD, PROD_DB_API_KEY, PROD_DB_TOTP] {
        assert!(!masked.contains(secret), "{secret} visible in:\n{masked}");
    }
    for visible in ["Prod DB", PROD_DB_LOGIN, PROD_DB_HOST, "API Key", "OTP"] {
        assert!(masked.contains(visible), "{visible} missing in:\n{masked}");
    }

    let out = run_ok(
        &env,
        &key,
        &["--format", "table", "item", "get", "Prod DB", "--reveal"],
    );
    let revealed = stdout(&out);
    for secret in [PROD_DB_PASSWORD, PROD_DB_API_KEY, PROD_DB_TOTP] {
        assert!(
            revealed.contains(secret),
            "{secret} missing in:\n{revealed}"
        );
    }
}

/// Scenario 5: JSON always contains the values.
#[test]
fn item_get_json_contains_secrets() {
    let (env, key) = Env::unlocked();
    let out = run_ok(&env, &key, &["item", "get", "Prod DB"]);
    let item = stdout_json(&out);
    for value in [
        ITEM_PROD_DB,
        "Prod DB",
        PROD_DB_LOGIN,
        PROD_DB_PASSWORD,
        PROD_DB_HOST,
        PROD_DB_API_KEY,
        PROD_DB_TOTP,
    ] {
        assert!(
            json_contains_str(&item, value),
            "{value} missing in {item:#}"
        );
    }
    let text = item.to_string();
    assert!(!text.contains("********"), "JSON is masked: {text}");
}

/// Scenario 5: an ambiguous name lists both candidates with their IDs.
#[test]
fn item_get_ambiguous_name_lists_candidates() {
    let (env, key) = Env::unlocked();
    let out = run(
        &env,
        &key,
        &["item", "get", "Shared Mail", "--field", "password"],
    );
    let err = assert_error(&out, "item get (ambiguous)");
    assert!(
        err.contains(ITEM_MAIL_INFRA),
        "candidate IDs missing: {err}"
    );
    assert!(err.contains(ITEM_MAIL_TEAM), "candidate IDs missing: {err}");
    assert!(
        err.contains("Infra") && err.contains("Team"),
        "paths missing: {err}"
    );
    assert!(!stdout(&out).contains("mail-pw"));
}

/// Scenario 5: `--vault` disambiguates.
#[test]
fn item_get_vault_disambiguates() {
    let (env, key) = Env::unlocked();
    let get = |vault: &str| {
        field(
            &env,
            &key,
            &[
                "item",
                "get",
                "Shared Mail",
                "--vault",
                vault,
                "--field",
                "password",
            ],
        )
    };
    assert_eq!(get("Team"), TEAM_MAIL_PASSWORD);
    assert_eq!(get("Infra"), INFRA_MAIL_PASSWORD);
    assert_eq!(get(VAULT_TEAM), TEAM_MAIL_PASSWORD);
}

/// Scenario 5: lookup by 24-hex ID; names fall back to case-insensitive.
#[test]
fn item_get_by_id_and_case_insensitive_name() {
    let (env, key) = Env::unlocked();
    assert_eq!(
        field(
            &env,
            &key,
            &["item", "get", ITEM_MAIL_TEAM, "--field", "password"]
        ),
        TEAM_MAIL_PASSWORD
    );
    assert_eq!(
        field(&env, &key, &["item", "get", "prod db", "--field", "login"]),
        PROD_DB_LOGIN
    );
    let out = run(&env, &key, &["item", "get", "No Such Item"]);
    assert_error(&out, "item get (missing)");
}

/// `item get --field` of a missing field fails.
#[test]
fn item_get_missing_field_fails() {
    let (env, key) = Env::unlocked();
    let out = run(&env, &key, &["item", "get", "Prod DB", "--field", "nope"]);
    assert_error(&out, "item get --field nope");
}

/// `item list` / `item search` with filters.
#[test]
fn item_list_and_search_filters() {
    let (env, key) = Env::unlocked();
    let out = run_ok(&env, &key, &["item", "list", "--vault", "Team"]);
    let list = stdout_json(&out);
    assert!(json_contains_str(&list, ITEM_MAIL_TEAM), "{list:#}");
    assert!(!json_contains_str(&list, ITEM_PROD_DB), "{list:#}");
    // List output must not decrypt or show passwords.
    assert!(!list.to_string().contains(TEAM_MAIL_PASSWORD));

    let out = run_ok(&env, &key, &["item", "search", "mail"]);
    let found = stdout_json(&out);
    assert!(json_contains_str(&found, ITEM_MAIL_INFRA), "{found:#}");
    assert!(json_contains_str(&found, ITEM_MAIL_TEAM), "{found:#}");
    assert!(!json_contains_str(&found, ITEM_PROD_DB), "{found:#}");

    let out = run_ok(
        &env,
        &key,
        &["item", "list", "--vault", "Infra", "--folder", "Prod"],
    );
    let in_prod = stdout_json(&out);
    assert!(json_contains_str(&in_prod, ITEM_PROD_DB), "{in_prod:#}");
    assert!(!json_contains_str(&in_prod, ITEM_SLASH), "{in_prod:#}");
}

// ---------------------------------------------------------------------------------------
// item create / edit / delete

/// Scenario 6: create with assignments and `--password-stdin`; the POST body decrypts
/// with the vault password.
#[test]
fn item_create_encrypts_fields_and_password_from_stdin() {
    let (env, key) = Env::unlocked();
    let out = env
        .pwk_with(&key)
        .args([
            "item",
            "create",
            "--vault",
            "Infra",
            "--folder",
            "Datenbanken",
            "--name",
            "New Svc",
            "--login",
            "svc",
            "--url",
            "https://svc.example.com",
            "--password-stdin",
            "user=alice",
            "pin[password]=12=34",
            "otp[totp]=GEZDGNBVGY3TQOJQ",
        ])
        .write_stdin("pw-from-stdin\n")
        .output()
        .unwrap();
    assert_success(&out, "item create");

    let body = single_body(&env, "POST", "/api/v1/items");
    assert_eq!(body["name"], "New Svc");
    assert_eq!(body["login"], "svc");
    assert_eq!(body["vaultId"], VAULT_INFRA);
    assert_eq!(body["folderId"], FOLDER_DB);
    assert!(
        json_contains_str(&body, "https://svc.example.com"),
        "{body:#}"
    );
    assert!(
        !body.to_string().contains("pw-from-stdin"),
        "plaintext password sent"
    );
    let sent = decrypt_sent_item(&body, env.server.vault_password(VAULT_INFRA));
    assert_eq!(
        sent.item_key.len(),
        100,
        "item key should be generate_key()"
    );
    assert_eq!(sent.password.as_deref(), Some("pw-from-stdin"));
    assert_eq!(
        sent.customs,
        [
            ("user".to_owned(), "alice".to_owned(), "text".to_owned()),
            ("pin".to_owned(), "12=34".to_owned(), "password".to_owned()),
            (
                "otp".to_owned(),
                "GEZDGNBVGY3TQOJQ".to_owned(),
                "totp".to_owned()
            ),
        ]
    );

    // The created item is readable through pwk.
    assert_eq!(
        field(
            &env,
            &key,
            &["item", "get", "New Svc", "--field", "password"]
        ),
        "pw-from-stdin"
    );
}

/// Scenario 6: `--generate-password=20`, and keyEncrypted is sent even without customs.
#[test]
fn item_create_generates_password_of_given_length() {
    let (env, key) = Env::unlocked();
    run_ok(
        &env,
        &key,
        &[
            "item",
            "create",
            "--vault",
            "Team",
            "--name",
            "Gen",
            "--generate-password=20",
        ],
    );
    let body = single_body(&env, "POST", "/api/v1/items");
    assert_eq!(body["vaultId"], VAULT_TEAM);
    assert!(body["folderId"].is_null(), "vault root expected: {body:#}");
    let sent = decrypt_sent_item(&body, env.server.vault_password(VAULT_TEAM));
    let pw = sent.password.expect("passwordEncrypted sent");
    assert_eq!(pw.chars().count(), 20, "{pw:?}");
}

/// `item create` with only customs still sends keyEncrypted (protocol.md, "Writing").
#[test]
fn item_create_without_password_sends_key() {
    let (env, key) = Env::unlocked();
    run_ok(
        &env,
        &key,
        &[
            "item",
            "create",
            "--vault",
            "Infra",
            "--name",
            "Note",
            "text=hello",
        ],
    );
    let body = single_body(&env, "POST", "/api/v1/items");
    let sent = decrypt_sent_item(&body, env.server.vault_password(VAULT_INFRA));
    assert_eq!(
        sent.customs,
        [("text".to_owned(), "hello".to_owned(), "text".to_owned())]
    );
}

/// Scenario 6: `field=` removes a custom, `field=new` replaces it; the item key is
/// reused and vaultId is sent.
#[test]
fn item_edit_removes_and_replaces_customs() {
    let (env, key) = Env::unlocked();
    let original_key = env.server.item(ITEM_PROD_DB).unwrap()["keyEncrypted"].clone();
    run_ok(
        &env,
        &key,
        &[
            "item",
            "edit",
            "Prod DB",
            "Host=",
            "API Key=new-api-key-1",
            "login=root",
        ],
    );
    let body = single_body(&env, "PATCH", &format!("/api/v1/items/{ITEM_PROD_DB}"));
    assert_eq!(body["vaultId"], VAULT_INFRA);
    assert_eq!(
        body["keyEncrypted"], original_key,
        "item key must be reused"
    );
    assert_eq!(body["login"], "root");
    let sent = decrypt_sent_item(&body, env.server.vault_password(VAULT_INFRA));
    assert!(
        sent.custom("Host").is_none(),
        "Host not removed: {:?}",
        sent.customs
    );
    assert_eq!(
        sent.custom("API Key").map(|c| (c.1.as_str(), c.2.as_str())),
        Some(("new-api-key-1", "password")),
        "the replaced custom keeps its type"
    );
    assert_eq!(
        sent.custom("OTP").map(|c| c.1.as_str()),
        Some(PROD_DB_TOTP),
        "untouched customs are sent again (whole list)"
    );
    if let Some(pw) = &sent.password {
        assert_eq!(
            pw, PROD_DB_PASSWORD,
            "password changed by an unrelated edit"
        );
    }

    // The server state is consistent with what pwk reads back.
    assert_eq!(
        field(
            &env,
            &key,
            &["item", "get", "Prod DB", "--field", "API Key"]
        ),
        "new-api-key-1"
    );
    assert_eq!(
        field(
            &env,
            &key,
            &["item", "get", "Prod DB", "--field", "password"]
        ),
        PROD_DB_PASSWORD
    );
}

/// `item edit` with `--password-stdin` and a new typed custom field.
#[test]
fn item_edit_new_custom_and_password_stdin() {
    let (env, key) = Env::unlocked();
    let out = env
        .pwk_with(&key)
        .args([
            "item",
            "edit",
            "Shared Mail",
            "--vault",
            "Team",
            "--password-stdin",
            "pin[password]=0000",
        ])
        .write_stdin("rotated-pw\n")
        .output()
        .unwrap();
    assert_success(&out, "item edit --password-stdin");
    let body = single_body(&env, "PATCH", &format!("/api/v1/items/{ITEM_MAIL_TEAM}"));
    let sent = decrypt_sent_item(&body, env.server.vault_password(VAULT_TEAM));
    assert_eq!(sent.password.as_deref(), Some("rotated-pw"));
    assert_eq!(
        sent.custom("pin").map(|c| (c.1.as_str(), c.2.as_str())),
        Some(("0000", "password"))
    );
}

/// One `--url` on edit changes only the main URL and leaves the other URLs alone;
/// several `--url` replace the whole list (main URL = the first).
#[test]
fn item_edit_url_keeps_other_urls() {
    let (env, key) = Env::unlocked();
    let path = format!("/api/v1/items/{ITEM_PROD_DB}");
    run_ok(
        &env,
        &key,
        &[
            "item",
            "edit",
            ITEM_PROD_DB,
            "--url",
            "https://new.example.com",
        ],
    );
    let body = single_body(&env, "PATCH", &path);
    assert_eq!(body["url"], "https://new.example.com", "{body:#}");
    assert!(
        body.get("urls").is_none(),
        "urls must not be sent: {body:#}"
    );
    let stored = env.server.item(ITEM_PROD_DB).unwrap();
    assert_eq!(stored["urls"], json!([PROD_DB_URL]), "{stored:#}");

    run_ok(
        &env,
        &key,
        &[
            "item",
            "edit",
            ITEM_PROD_DB,
            "--url",
            "https://a",
            "--url",
            "https://b",
        ],
    );
    let patches = env.server.requests_to("PATCH", &path);
    let body = patches.last().unwrap().json();
    assert_eq!(body["url"], "https://a", "{body:#}");
    assert_eq!(body["urls"], json!(["https://a", "https://b"]), "{body:#}");
}

/// Scenario 6: delete sends DELETE /items/{id}.
#[test]
fn item_delete_by_id() {
    let (env, key) = Env::unlocked();
    run_ok(&env, &key, &["item", "delete", ITEM_MAIL_TEAM]);
    assert_eq!(
        env.server
            .requests_to("DELETE", &format!("/api/v1/items/{ITEM_MAIL_TEAM}"))
            .len(),
        1
    );
    assert!(env.server.item(ITEM_MAIL_TEAM).is_none());
    // Now the name is no longer ambiguous.
    assert_eq!(
        field(
            &env,
            &key,
            &["item", "get", "Shared Mail", "--field", "password"]
        ),
        INFRA_MAIL_PASSWORD
    );
}

/// Deleting an ambiguous name fails and deletes nothing.
#[test]
fn item_delete_ambiguous_name_deletes_nothing() {
    let (env, key) = Env::unlocked();
    assert_error(
        &run(&env, &key, &["item", "delete", "Shared Mail"]),
        "item delete (ambiguous)",
    );
    assert!(env.server.requests().iter().all(|r| r.method != "DELETE"));
}

// ---------------------------------------------------------------------------------------
// vault / folder

/// Scenario 7: vault list.
#[test]
fn vault_list_shows_vaults() {
    let (env, key) = Env::unlocked();
    let out = run_ok(&env, &key, &["vault", "list"]);
    let list = stdout_json(&out);
    for v in ["Infra", "Team", VAULT_INFRA, VAULT_TEAM] {
        assert!(json_contains_str(&list, v), "{v} missing in {list:#}");
    }
    let out = run_ok(&env, &key, &["--format", "table", "vault", "list"]);
    let table = stdout(&out);
    assert!(table.contains("Infra") && table.contains("Team"), "{table}");
}

/// Scenario 7: folder list shows nested folders with their paths.
#[test]
fn folder_list_shows_paths() {
    let (env, key) = Env::unlocked();
    let out = run_ok(&env, &key, &["folder", "list", "--vault", "Infra"]);
    let list = stdout_json(&out);
    assert!(json_contains_str(&list, FOLDER_DB), "{list:#}");
    assert!(json_contains_str(&list, FOLDER_PROD), "{list:#}");

    let out = run_ok(
        &env,
        &key,
        &["--format", "table", "folder", "list", "--vault", "Infra"],
    );
    let table = stdout(&out);
    assert!(
        table.contains("Datenbanken/Prod"),
        "nested folder path missing in:\n{table}"
    );

    let out = run_ok(
        &env,
        &key,
        &[
            "folder",
            "list",
            "--vault",
            "Infra",
            "--parent",
            "Datenbanken",
        ],
    );
    let children = stdout_json(&out);
    assert!(json_contains_str(&children, FOLDER_PROD), "{children:#}");
    assert!(
        children
            .as_array()
            .is_some_and(|list| list.iter().all(|f| f["id"] != FOLDER_DB)),
        "--parent lists only subfolders: {children:#}"
    );
}

/// Scenario 7: folder create sends vaultId, parentId and name.
#[test]
fn folder_create_sends_body() {
    let (env, key) = Env::unlocked();
    run_ok(
        &env,
        &key,
        &[
            "folder",
            "create",
            "Neu",
            "--vault",
            "Infra",
            "--parent",
            "Datenbanken",
        ],
    );
    let body = single_body(&env, "POST", "/api/v1/folders");
    assert_eq!(body["name"], "Neu");
    assert_eq!(body["vaultId"], VAULT_INFRA);
    assert_eq!(body["parentId"], FOLDER_DB);

    run_ok(&env, &key, &["folder", "create", "Top", "--vault", "Team"]);
    let reqs = env.server.requests_to("POST", "/api/v1/folders");
    let top = reqs[1].json();
    assert_eq!(top["name"], "Top");
    assert_eq!(top["vaultId"], VAULT_TEAM);
    assert!(top["parentId"].is_null(), "root folder: {top:#}");
}

/// Moving a folder within its vault sends the new parent (`null` = vault root).
#[test]
fn folder_move_within_vault_sends_body() {
    let (env, key) = Env::unlocked();
    run_ok(&env, &key, &["folder", "move", "Prod", "--vault", "Infra"]);
    let body = single_body(&env, "POST", &format!("/api/v1/folders/{FOLDER_PROD}/move"));
    assert_eq!(body["vaultId"], VAULT_INFRA);
    assert!(body["parentId"].is_null(), "vault root expected: {body:#}");
}

/// A folder cannot be moved below one of its own descendants (that would be a cycle).
#[test]
fn folder_move_into_descendant_is_refused() {
    let (env, key) = Env::unlocked();
    for parent in ["Datenbanken", "Prod"] {
        let out = run(
            &env,
            &key,
            &["folder", "move", "Datenbanken", "--parent", parent],
        );
        let err = assert_error(&out, &format!("folder move into {parent}"));
        assert!(err.contains("into itself"), "{err}");
    }
    assert!(
        env.server
            .requests_to("POST", &format!("/api/v1/folders/{FOLDER_DB}/move"))
            .is_empty(),
        "no move request may be sent"
    );
}

/// With client-side encryption a folder cannot move to another vault: the items' keys
/// would stay encrypted for the old vault.
#[test]
fn folder_move_to_other_encrypting_vault_is_refused() {
    let (env, key) = Env::unlocked();
    let out = run(&env, &key, &["folder", "move", "Prod", "--vault", "Team"]);
    let err = assert_error(&out, "folder move to another vault");
    assert!(
        err.contains("client-side encryption") && err.contains("pwk item move"),
        "{err}"
    );
    assert!(
        env.server
            .requests_to("POST", &format!("/api/v1/folders/{FOLDER_PROD}/move"))
            .is_empty(),
        "no move request may be sent"
    );
}

// ---------------------------------------------------------------------------------------
// api

/// Scenario 12: `pwk api GET /api/v1/vaults` prints the server's JSON.
#[test]
fn api_get_prints_json() {
    let (env, key) = Env::unlocked();
    let out = run_ok(&env, &key, &["api", "GET", "/api/v1/vaults"]);
    let v = stdout_json(&out);
    let names: Vec<&str> = v["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected {{\"items\": […]}}, got {v:#}"))
        .iter()
        .filter_map(|x| x["name"].as_str())
        .collect();
    assert_eq!(names, ["Infra", "Team"]);
}

/// `api` with `--query` and `--data`.
#[test]
fn api_query_and_data_are_sent() {
    let (env, key) = Env::unlocked();
    let out = run_ok(
        &env,
        &key,
        &[
            "api",
            "get",
            "/api/v1/folders",
            "--query",
            &format!("vaultId={VAULT_INFRA}"),
        ],
    );
    let v = stdout_json(&out);
    assert_eq!(v["items"].as_array().map(Vec::len), Some(2), "{v:#}");

    let data = json!({ "name": "ViaApi", "vaultId": VAULT_TEAM, "parentId": null });
    let out = run_ok(
        &env,
        &key,
        &[
            "api",
            "POST",
            "/api/v1/folders",
            "--data",
            &data.to_string(),
        ],
    );
    assert!(stdout_json(&out)["id"].is_string());
    assert_eq!(single_body(&env, "POST", "/api/v1/folders"), data);
}

/// A query string written in the path is sent, not dropped.
#[test]
fn api_query_in_path_is_sent() {
    let (env, key) = Env::unlocked();
    for (vault, count) in [(VAULT_INFRA, 2), (VAULT_TEAM, 0)] {
        let out = run_ok(
            &env,
            &key,
            &["api", "GET", &format!("/api/v1/folders?vaultId={vault}")],
        );
        let v = stdout_json(&out);
        assert_eq!(v["items"].as_array().map(Vec::len), Some(count), "{v:#}");
    }
}

// ---------------------------------------------------------------------------------------
// attachments

/// Scenario 13: attachment get writes the original bytes (by name and by ID).
#[test]
fn attachment_get_writes_original_content() {
    let (env, key) = Env::unlocked();
    let target = env.home().join("out.sql");
    let target_s = target.to_str().unwrap();
    run_ok(
        &env,
        &key,
        &["attachment", "get", "Prod DB", DUMP_NAME, "-o", target_s],
    );
    assert_eq!(std::fs::read(&target).unwrap(), dump_content());
    #[cfg(unix)]
    assert_eq!(
        crate::harness::mode(&target),
        0o600,
        "output files are 0600"
    );

    let out = run_ok(
        &env,
        &key,
        &["attachment", "get", "Prod DB", ATT_DUMP, "-o", "-"],
    );
    assert_eq!(out.stdout, dump_content());
}

/// `attachment list` shows both attachments.
#[test]
fn attachment_list_shows_names() {
    let (env, key) = Env::unlocked();
    let out = run_ok(&env, &key, &["attachment", "list", "Prod DB"]);
    let list = stdout_json(&out);
    for v in [DUMP_NAME, BROKEN_NAME, ATT_DUMP, ATT_BROKEN] {
        assert!(json_contains_str(&list, v), "{v} missing in {list:#}");
    }
}

/// Scenario 13: a checksum mismatch is an error.
#[test]
fn attachment_get_hash_mismatch_fails() {
    let (env, key) = Env::unlocked();
    let target = env.home().join("out.bin");
    let out = run(
        &env,
        &key,
        &[
            "attachment",
            "get",
            "Prod DB",
            BROKEN_NAME,
            "-o",
            target.to_str().unwrap(),
        ],
    );
    let err = assert_error(&out, "attachment get (bad hash)");
    let lower = err.to_lowercase();
    assert!(
        lower.contains("checksum") || lower.contains("hash"),
        "error should mention the checksum: {err}"
    );
    if let Ok(data) = std::fs::read(&target) {
        assert!(
            data.is_empty(),
            "unverified data written to {}",
            target.display()
        );
    }
}
