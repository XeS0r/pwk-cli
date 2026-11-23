# pwk

**A command line client for [Passwork 7](https://passwork.pro/), in the spirit of
1Password's `op` and Bitwarden's `bw`.**

pwk is an independent, unofficial project. It is not made, endorsed or supported by
Passwork, and it is not the official `passwork-cli` that ships with Passwork's Python
package.

```sh
pwk login --host https://passwork.example.com     # once: the API token pair
eval "$(pwk unlock)"                              # master password, then 12 hours
pwk item search postgres
pwk read "pw://Infra/Databases/Prod Postgres/password"
DATABASE_PASSWORD="pw://Infra/Databases/Prod Postgres/password" pwk run -- ./migrate
```

`pwk` talks to the Passwork 7 API with an API token pair and does the client-side
encryption locally: your master password and master key never leave your machine. It
lists, reads, creates and changes vaults, folders, items, attachments and shortcuts, and
it brings secrets into scripts and CI with `pw://` references (`read`, `run`, `inject`),
without writing them to disk.

<!-- prettier-ignore -->
> [!WARNING]
> **Status: experimental.** pwk was written from the official Python client and the
> public API overview. Its cryptography is checked against the test vectors of the
> official client, but pwk itself has so far only run against a simulated server in
> its test suite, not against a real Passwork installation. A few endpoints are marked
> unverified in [docs/protocol.md](docs/protocol.md). Try it on a test vault before you
> let it write to data you care about. Commands, flags and files may still change
> between 0.x versions. Please
> [report what you run into](https://github.com/XeS0r/pwk-cli/issues).

## Install

<table>
<tr><th>Without Nix (Linux)</th><th>With Nix</th></tr>
<tr><td>

Download `pwk-<version>-x86_64-linux.tar.gz` (or `aarch64`) from the
[latest release](https://github.com/XeS0r/pwk-cli/releases/latest), then:

```sh
tar xzf pwk-*.tar.gz
./pwk-*/install.sh
```

A static binary, no dependencies, no root. Installs into `~/.local` (`--prefix DIR` for
another place, `--uninstall` to remove it).

</td><td>

No checkout needed:

```sh
nix run github:XeS0r/pwk-cli#install
```

Builds `pwk` reproducibly and links it into `~/.local`. Or run it once with
`nix run github:XeS0r/pwk-cli -- --help`, or add the flake's `packages.default` to your
system.

</td></tr>
</table>

Both install man pages and bash, zsh and fish completions. With Nix, the installer links
pwk through a GC root in `~/.local/share/pwk/package`; `nix run …#uninstall` removes it
again. Configuration and sessions are never touched by either.

## Quick start

**1. Create an API token pair** in the Passwork web interface (API tokens → "Generate
pair"). Passwork 7 has no API for a password login, so this pair is how `pwk` signs in.

**2. Log in** with the host and the pair. `pwk` asks for both tokens without echo and
stores them in the profile's session file:

```sh
pwk login --host https://passwork.example.com
```

**3. Unlock** with your master password. `pwk` derives the master key, checks it and
prints a session key for your shell:

```sh
eval "$(pwk unlock)"         # sh, bash, zsh
pwk unlock --shell fish | source
```

**4. Use it:**

```sh
pwk vault list
pwk item search postgres --vault Infra
pwk item get "Prod Postgres" --reveal
pwk read "pw://Infra/Databases/Prod Postgres/password"
pwk totp "GitHub admin"

# Resolve pw:// references in the environment, mask them in the output
DATABASE_PASSWORD="pw://Infra/Databases/Prod Postgres/password" pwk run -- ./migrate
pwk run --env-file .env.pwk -- docker compose up

# Fill {{ pw://… }} placeholders in a template; the output file gets mode 0600
pwk inject -i config.yaml.tpl -o config.yaml
```

`pwk status` shows the profile, host, user, and whether and until when the session is
unlocked.

## Sessions

`pwk` works like `bw`: the session file holds the tokens, and an unlock adds the master
key, sealed with a key that only your shell knows.

- `pwk unlock` seals the master key with a random session key and prints
  `export PWK_SESSION=…`. Every command that needs the master key opens the seal with
  that variable. Without it, with a wrong one, or after expiry, `pwk` says it is locked
  and asks you to run `eval "$(pwk unlock)"`.
- An unlock lasts **12 hours** unless you pass `--timeout` (or set `session_timeout` in
  the configuration). `--raw` prints the key alone, for your own scripts.
- `pwk lock` forgets the sealed master key; the tokens stay, so the next `pwk unlock`
  needs only the master password. `pwk logout` deletes the session file, tokens included
  (the lock file next to it stays).
- Access tokens are refreshed automatically. The refreshed pair is written back under a
  file lock, so parallel `pwk` processes do not invalidate each other's tokens.

What lies where, and what that protects against, is in [SECURITY.md](SECURITY.md).

## Profiles

Each profile has its own host, session file and session variable. Choose one with
`--profile NAME`, `PWK_PROFILE`, or `default_profile` in the configuration (otherwise it
is `default`).

```sh
pwk --profile work login --host https://passwork.work.example.com
eval "$(pwk --profile work unlock)"     # exports PWK_SESSION_WORK
pwk --profile work item list --vault Ops
pwk profile list
pwk profile use work                    # make it the default profile
```

The default profile uses `PWK_SESSION`; every other profile uses
`PWK_SESSION_<PROFILE>`, upper-cased with every character other than letters and digits
replaced by `_` (`my-team` → `PWK_SESSION_MY_TEAM`). So several profiles can be unlocked
in the same shell. A non-default profile never falls back to `PWK_SESSION`. Names that
would share a variable (`a-b` and `a_b`, `Work` and `work`) cannot both be used:
`login`, `profile use` and `config set` refuse the second one.

## CI and scripts

In CI there is no session file. If `PASSWORK_HOST` and `PASSWORK_TOKEN` are set, `pwk`
reads neither configuration nor session and takes everything from the environment, with
the same variables as the official `passwork-cli`:

| Variable                 | Required | What it is                                                                 |
| ------------------------ | -------- | -------------------------------------------------------------------------- |
| `PASSWORK_HOST`          | yes      | the server URL                                                             |
| `PASSWORK_TOKEN`         | yes      | the access token                                                           |
| `PASSWORK_REFRESH_TOKEN` | no       | lets `pwk` refresh an expired access token (kept in memory only)           |
| `PASSWORK_MASTER_KEY`    | no       | the derived master key, needed with client-side encryption; not a password |
| `PWK_CA_CERT`            | no       | path of an extra CA certificate (PEM), added to the system roots           |
| `PWK_INSECURE`           | no       | `1` skips TLS certificate verification (warns on every use)                |

```sh
export PASSWORK_HOST=https://passwork.example.com
export PASSWORK_TOKEN=… PASSWORK_REFRESH_TOKEN=… PASSWORK_MASTER_KEY=…
pwk run --env-file deploy.env -- ./deploy.sh
```

`PASSWORK_MASTER_KEY` also works next to a stored session and then counts as unlocked.
Output is JSON whenever stdout is not a terminal (or with `--format json` or
`PWK_FORMAT=json`), and `--field` prints a single raw value.

## Secret references

```text
pw://<vault>/<folder>/…/<item>/<field>[?attribute=totp]
```

- Vault and folders are given by name or ID; the folder path may be empty
  (`pw://Infra/Prod DB/password`). Segments are percent-decoded, so a `/` in a name is
  written `%2F`.
- `<field>` is `password`, `login`, `name`, `url`, `description`, `tags` or the name of
  a custom field. `?attribute=totp` on a TOTP field gives the current code.
- `pwk run` resolves every environment variable whose whole value is a reference, and
  the variables of each `--env-file` (dotenv syntax). Unless `--no-masking`, every
  resolved value in the command's output is replaced with `<concealed by pwk>`. The
  command does not get `PWK_SESSION`, `PWK_SESSION_*`, `PASSWORK_MASTER_KEY`,
  `PASSWORK_TOKEN` or `PASSWORK_REFRESH_TOKEN` (`PASSWORK_HOST` stays).
- An item given by ID must sit where the path says (vault, and folder if folder segments
  are given); otherwise the reference fails and names the item's real place.
- `pwk inject` replaces `{{ pw://… }}` and leaves everything else as it is.

Vaults, folders, items and shortcuts on the command line also take an ID (24 hex
characters) or a name: exact first, then case-insensitive. If a name matches more than
one object, `pwk` lists them with their IDs and paths; `--vault` narrows the search.

## Commands

```text
pwk [--profile NAME] [--format table|json] [--quiet] <command>

Session
  login   [--host URL] [--access-token-stdin]   store host and token pair for a profile
  logout                                         forget tokens and the session
  unlock  [--password-stdin] [--timeout 12h] [--raw] [--shell sh|fish]
                                                 print `export PWK_SESSION=…`
  lock                                           forget the encrypted master key
  status                                         profile, host, user, locked/unlocked, expiry

Objects
  vault      list | get | create | delete
  folder     list | get | create | rename | move | delete
  item       list | search | get | create | edit | move | delete
  attachment list | get | add
  shortcut   list | get | create | delete

Secrets in scripts
  read     pw://vault/folder…/item/field         one value on stdout
  run      [--env-file FILE]… [--no-masking] -- CMD…   resolve pw:// in env, run CMD
  inject   [-i FILE] [-o FILE]                   replace {{ pw://… }} in a template
  totp     <item> [--field NAME]                 current one-time code
  generate [--length N] [--no-symbols]           random password, nothing stored

Tools
  api         METHOD PATH [--data JSON|@file|-] [--query k=v]…   raw call, JSON out
  config      show | set <key> <value> | unset <key>
  profile     list | use <name> | remove <name>
  completions <bash|zsh|fish|elvish|powershell>
```

Every command has `--help`; the install adds man pages (`man pwk`). The full command
line, with every option of the object commands, is in
[docs/design.md](docs/design.md#command-line). Errors go to stderr as `pwk: <message>`
with exit code 1; usage errors exit with 2.

## Configuration

`$XDG_CONFIG_HOME/pwk/config.toml` (usually `~/.config/pwk/config.toml`; `PWK_CONFIG`
overrides the path). `pwk config set` and `pwk config unset` change it,
`pwk config show` prints it.

```toml
default_profile = "default"

[profiles.default]
host = "https://passwork.example.com"
# ca_cert = "/path/to/ca.pem"   # PEM, added to the system roots (stored as absolute path)
# insecure = false              # skips TLS verification (warns)
# session_timeout = "12h"       # default for `unlock --timeout`

[profiles.work]
host = "https://passwork.work.example.com"
```

A plain `http://` host is accepted, but `pwk` warns about it on every use, like
`insecure = true`.

Sessions live in `$XDG_STATE_HOME/pwk/<profile>/session.json` (usually
`~/.local/state/pwk/`), mode 0600.

## Verifying a release package

The release workflow builds packages only from a tagged commit on `main` that passed the
checks, and attests their build provenance with GitHub (Sigstore). The build runs with a
read-only token; a separate job without checkout or build attests and publishes the
packages. With the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify pwk-<version>-x86_64-linux.tar.gz \
  --repo XeS0r/pwk-cli \
  --signer-workflow XeS0r/pwk-cli/.github/workflows/release.yml
sha256sum --check --ignore-missing SHA256SUMS
```

The attestation says which workflow run and commit built the file; it is not a code
signature of the program.

## Development

Everything runs through Nix; `nix develop` (or direnv) gives you the toolchain and
`just`.

```sh
just test          # unit and integration tests (cargo nextest)
just lint          # clippy, prettier and markdownlint
just fmt           # rustfmt, nixfmt, prettier
just links         # lychee over every Markdown file, external links included
just check         # everything CI runs: build, tests, clippy (Linux + macOS), rustfmt,
                   # Markdown, changelog, local links, cargo audit, release package
just release       # static release packages for x86_64 and aarch64 Linux (./result)
```

Without Nix, `cargo build --release -p pwk` builds `target/release/pwk` with a Rust
toolchain of version 1.89 or later.

| Crate           | What it is                                                                                    |
| --------------- | --------------------------------------------------------------------------------------------- |
| `crates/crypto` | `pwk-crypto`: Passwork cipher strings, Base32, PBKDF2, RSA, TOTP, session sealing; no I/O     |
| `crates/api`    | `pwk-api`: blocking HTTP client, token refresh, typed models, encryption of vaults and items  |
| `crates/cli`    | `pwk`: the binary, with configuration, profiles, sessions, `pw://` references, run and inject |

How the client speaks to the server is described in
[docs/protocol.md](docs/protocol.md), the design of the command line in
[docs/design.md](docs/design.md).

## Acknowledgements

The protocol and the client-side encryption follow the official Python client
[passwork-python](https://github.com/passwork-europe/passwork-python) (MIT), whose test
data pwk uses for its own tests. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## License

[MIT](LICENSE). Not affiliated with or endorsed by Passwork; Passwork is a trademark of
its owner.
