# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). While the version is 0.x, commands, flags,
the configuration file and the session file may still change between minor versions.

The release workflow publishes the section of the tagged version as the release notes.
Until a version is released its heading reads `Unreleased` instead of a date.

## [0.1.0] - 2026-11-23

The first release: a command line client for [Passwork 7](https://passwork.pro/) in the
spirit of 1Password's `op` and Bitwarden's `bw`, with client-side encryption done
locally.

### Added

- `pwk login` stores the host and the API token pair of a profile; `pwk unlock` derives
  the master key and prints `export PWK_SESSION=…`, which keeps the master key sealed in
  the session file for 12 hours by default. `lock`, `logout` and `status` complete the
  session commands. Tokens are refreshed automatically and written back under a file
  lock.
- Several profiles (`--profile`, `PWK_PROFILE`), each with its own session variable
  `PWK_SESSION_<PROFILE>`, and a configuration file for host, CA certificate and session
  timeout.
- Stateless use in CI with `PASSWORK_HOST`, `PASSWORK_TOKEN`, `PASSWORK_REFRESH_TOKEN`
  and `PASSWORK_MASTER_KEY`, the variables of the official `passwork-cli`.
- `vault`, `folder`, `item`, `attachment` and `shortcut` commands to list, read, create,
  change, move and delete; objects are named by ID or by name.
- Secret references `pw://vault/folder/item/field`: `pwk read` prints one value,
  `pwk run` resolves them in the environment of a command and masks them in its output,
  `pwk inject` fills `{{ pw://… }}` in templates.
- `pwk totp` for one-time codes, `pwk generate` for random passwords, `pwk api` for raw
  API calls.
- Table output on a terminal, JSON otherwise (`--format`).
- Man pages and bash, zsh and fish completions.
- Static release packages for x86_64 and aarch64 Linux with `install.sh`, and a Nix
  flake (`nix run github:XeS0r/pwk-cli#install`).

### Known limitations

- Developed from the official Python client and the public API overview, not against
  every Passwork 7 version; a few endpoints are marked unverified in
  [docs/protocol.md](https://github.com/XeS0r/pwk-cli/blob/main/docs/protocol.md).
- No login with a password: Passwork 7 has no API for it, the token pair comes from the
  web interface.
- macOS is type-checked only in part and not tested; no Windows support.
- Release packages are not code-signed; check them against `SHA256SUMS` and their build
  provenance.

[0.1.0]: https://github.com/XeS0r/pwk-cli/releases/tag/v0.1.0
