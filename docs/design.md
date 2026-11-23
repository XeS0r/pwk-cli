# pwk design

`pwk` is a command line client for Passwork 7, modelled on `op` (1Password) and `bw`
(Bitwarden). The protocol it speaks is described in [protocol.md](protocol.md).

## Crates

```text
crates/crypto  (pwk-crypto)  Passwork cipher strings, Base32, PBKDF2, RSA, TOTP,
                             random keys and passwords, session sealing. No I/O.
crates/api     (pwk-api)     Blocking HTTP client: tokens and refresh, envelope,
                             batch, typed models, decrypt/encrypt of vaults, folders,
                             items, attachments, shortcuts. No terminal, no files
                             except what the caller passes in.
crates/cli     (pwk)         The `pwk` binary: clap, config, profiles, session file,
                             references (pw://), run, inject, output formats.
```

Allowed dependency edges: `cli → api → crypto`, `cli → crypto`. Nothing else.

## Command line

```text
pwk [--profile NAME] [--format table|json] [--quiet] <command>

Session
  login   [--host URL] [--access-token-stdin]   store host and token pair for a profile
  logout                                         forget tokens and the session
  unlock  [--password-stdin] [--timeout 12h] [--raw] [--shell sh|fish]
                                                 print `export PWK_SESSION=…`
  lock                                           forget the encrypted master key
  status                                         profile, host, user, locked/unlocked, expiry

Objects (noun, then verb)
  vault      list | get <vault> | create <name> [--type CODE] | delete <vault>
  folder     list [--vault V] [--parent F] | get <folder> | create <name> --vault V [--parent F]
             | rename <folder> <name> | move <folder> [--vault V] [--parent F] | delete <folder>
  item       list [--vault V] [--folder F] [--tag T]… | search <query> [same filters]
             | get <item> [--field NAME] [--reveal]
             | create --vault V [--folder F] --name N [--login L] [--password-stdin |
               --generate-password[=LEN]] [--url U]… [--description D] [--tag T]…
               [--color N] [field=value]… [field[password]=value]…
             | edit <item> [same options] [field=value]… [field=] (remove)
               (one --url sets the main URL only; two or more set the main URL to the
               first and replace the URL list with all of them)
             | move <item> [--vault V] [--folder F] | delete <item>
  attachment list <item> | get <item> <attachment> [-o PATH|-] | add <item> <file> [--name N]
  shortcut   list [<query>] | get <shortcut> | create <item> --vault V [--folder F] | delete <shortcut>

Secrets in scripts
  read   pw://vault/folder…/item/field           one value on stdout
  run    [--env-file FILE]… [--no-masking] -- CMD…   resolve pw:// in env, run CMD
  inject [-i FILE] [-o FILE]                     replace {{ pw://… }} in a template
  totp   <item> [--field NAME]                   current one-time code
  generate [--length N] [--no-symbols]           random password, nothing stored

Tools
  api      METHOD PATH [--data JSON|@file|-] [--query k=v]…   raw call, JSON out
  config   show | set <key> <value> | unset <key>
  profile  list | use <name> | remove <name>
  completions <bash|zsh|fish|elvish|powershell>
  generate-man <dir>   (hidden)
```

`folder move` changes the parent within the vault (`--parent`, or `--vault` alone for
the vault root); a folder cannot be moved below itself or one of its subfolders. A move
to another vault is refused when either vault uses client-side encryption (the items'
keys would stay encrypted for the old vault): move the items with `pwk item move`
instead. `api` accepts a query string in PATH (`'items/search?query=db'`); it is decoded
and sent before the `--query` pairs.

### Object references

`<vault>`, `<folder>`, `<item>`, `<shortcut>` accept an ID (24 hex characters) or a
name. A name is matched exactly, then case-insensitively; more than one match is an
error that lists the candidates with their IDs and paths. `--vault` narrows an item or
folder name lookup. `<attachment>` is an ID or a file name.

### Secret references

`pw://<vault>/<folder>/…/<item>/<field>[?attribute=totp]`

- Vault and folder segments are names or IDs; the folder path may be empty
  (`pw://Infra/Prod DB/password`). Segments are percent-decoded, so `/` in a name is
  `%2F`.
- `<item>` is a name or an ID. An ID must be in the given vault (and, if folder segments
  are given, in that folder); otherwise the reference fails with an error that names the
  item's actual location.
- `<field>`: `password`, `login`, `name`, `url`, `description`, `tags` (standard fields,
  case-insensitive, no other aliases), else the name of a custom field (exact, then
  case-insensitive). `?attribute=totp` on a TOTP field prints the current code instead
  of the secret.
- `run` resolves every environment variable whose whole value is a reference, plus the
  variables of each `--env-file` (dotenv syntax: `KEY=value`, `#` comments, optional
  quotes, an optional `export` prefix). Unless `--no-masking`, child stdout/stderr are
  piped and each resolved secret value is replaced with `<concealed by pwk>`. Bytes that
  may start a secret are held back until the next output decides, at most 50 ms (then
  they are written as they are, so prompts appear); a secret split across writes within
  that window is still masked. After the child exits, its pipes are drained for at most
  200 ms, so a background process that keeps them open (even one that keeps writing)
  does not block `pwk`.
- `run` removes the unlock material from the child's environment: `PWK_SESSION`, every
  `PWK_SESSION_*`, `PASSWORK_MASTER_KEY`, `PASSWORK_TOKEN` and `PASSWORK_REFRESH_TOKEN`.
  `PASSWORK_HOST` stays. (Variables set by an `--env-file` are applied afterwards.)
- `inject` replaces `{{ pw://… }}` (whitespace inside the braces optional) and leaves
  everything else untouched. Extra braces stay: `{{{ pw://… }}}` renders as `{value}`.
  `-o` files are created with mode 0600.

### Output

- `--format table` (default on a terminal) prints aligned columns; `--format json`
  (default when stdout is not a terminal, or `PWK_FORMAT`) prints JSON.
- `item get` hides `password` and password/TOTP customs as `********` in the table view
  unless `--reveal`; JSON always contains the values. `--field` prints the raw value
  only.
- Errors go to stderr as `pwk: <message>` with exit code 1; usage errors exit 2. Errors
  about `FIELD=VALUE` arguments name the field only, never the value.

## Configuration, profiles and session

```text
$XDG_CONFIG_HOME/pwk/config.toml   (PWK_CONFIG overrides the path)
  default_profile = "default"
  [profiles.<name>]
  host = "https://passwork.example.com"
  ca_cert = "/path/to/ca.pem"        # optional, PEM, added to the system roots;
                                     # `config set` stores the canonical absolute path
                                     # and fails if the file does not exist
  insecure = false                   # optional, skips TLS verification (warns)
  session_timeout = "12h"            # optional, default for `unlock --timeout`

$XDG_STATE_HOME/pwk/<profile>/session.json   mode 0600, directory 0700
  { "version": 1, "host": …, "access_token": …, "refresh_token": …,
    "access_expires_at": …, "refresh_expires_at": …,
    "unlock": { "expires_at": <unix>, "nonce": <b64>, "ciphertext": <b64> } | null }
```

- Profile: `--profile`, else `PWK_PROFILE`, else `default_profile`, else `default`.
- `host` may be `http://`; every command using it then warns (even with `--quiet`), as
  for `insecure = true`.
- Two profiles must not map to the same `PWK_SESSION_<PROFILE>` (`a-b`/`a_b`,
  `Work`/`work`): `login`, `profile use` and `config set` refuse such a name (one check,
  `Config::check_new_profile`).
- `unlock` derives the master key, checks it against `/users/keys`, generates a random
  32-byte session key, seals the master key with AES-256-GCM (AAD = `pwk-session-v1` ‖
  profile ‖ `\0` ‖ expires_at as decimal) and prints the session key Base64 as
  `export PWK_SESSION=…` (default profile) or `export PWK_SESSION_<PROFILE>=…` (profile
  upper-cased, non-alphanumerics → `_`). `--raw` prints the key alone, `--shell fish`
  prints `set -gx …`.
- Every command that needs the master key opens the seal with that variable
  (`PWK_SESSION_<PROFILE>`, and for the default profile `PWK_SESSION`, then also
  `PWK_SESSION_<PROFILE>` as printed while it was not the default: each set variable is
  tried until one opens the seal, so a stale one does not hide the fresh one; a
  non-default profile never falls back to `PWK_SESSION`); a missing variable, a wrong
  key (the message names the variables tried) or a past `expires_at` means "locked: run
  `eval "$(pwk unlock)"`".
- `lock` sets `unlock` to null. `logout` deletes the session file; the lock file and the
  profile directory stay, since another process may be waiting on the lock.
- Refreshed tokens are written back under an exclusive `File::lock` on
  `session.json.lock`; the file is re-read after taking the lock, and replaced
  atomically (write a temp file with a random name, created exclusively with mode 0600
  so no planted file or symlink is followed, fsync, rename; the temp file is removed on
  error). Every file pwk writes (config, session, `inject -o`, attachments) is replaced
  this way; if the destination is a symlink (e.g. `config.toml` from home-manager or
  stow), the link stays and its target is replaced (a dangling link: the file is created
  at the link's target), with the temp file in the target's directory.
- Stateless mode for CI: if `PASSWORK_HOST` and `PASSWORK_TOKEN` are set, no config or
  session file is read; `PASSWORK_REFRESH_TOKEN` and `PASSWORK_MASTER_KEY` (the derived
  key, as in the official CLI) are optional. Refreshed tokens are kept in memory only.
  TLS settings come from `PWK_CA_CERT` (path of a PEM file, added to the system roots)
  and `PWK_INSECURE=1` (skips verification, warns).
- `PASSWORK_MASTER_KEY` also works next to a stored session and then counts as unlocked.

## Security

- Secrets in memory are `Zeroizing<String>`/`Zeroizing<Vec<u8>>` and are not printed by
  `Debug`. `unsafe_code = "forbid"`.
- Session and output files are created 0600.
- `unlock` refuses servers offering fewer than 100 000 PBKDF2 iterations (a hostile
  server could otherwise make the master password cheap to brute-force); there is no way
  to lower this floor.
- `attachment add` checks the file size (5 MiB) before reading the file.
- Master password and tokens are read from the terminal without echo, or from stdin with
  the `--…-stdin` flags; never from command line arguments.
- `rsa` has a known timing side channel (RUSTSEC-2023-0071); it matters for a server
  decrypting attacker-chosen ciphertexts, not for a local client. Documented in
  SECURITY.md and allowed in the audit check.
