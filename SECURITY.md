# Security policy

`pwk` holds API tokens for your Passwork server and decrypts your passwords with your
master key, so security reports are very welcome.

## Supported versions

Only the latest release receives security fixes. While the project is 0.x, fixes go into
a new 0.x release; there are no backports.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately instead:

1. Open
   [Report a vulnerability](https://github.com/XeS0r/pwk-cli/security/advisories/new)
   (repository tab "Security" → "Report a vulnerability").
2. Describe what is affected (which command, the session handling, the cryptography, the
   install scripts), how to reproduce it, and what an attacker could gain.

Only the maintainer and you can see the report.

## What to expect

- A first response within **7 days**, on a best-effort basis (this is a one-person
  project).
- We agree on the fix and the timing together. The fix is developed privately and
  released, and then the advisory is published, with credit to you unless you prefer
  otherwise. A CVE can be requested through GitHub if appropriate.

Vulnerabilities in the Passwork server itself belong to its vendor; reports on how `pwk`
uses the API are in scope.

## Threat model

What `pwk` protects, and what it does not. The details are in
[docs/design.md](docs/design.md#configuration-profiles-and-session).

### On disk

- The session file `$XDG_STATE_HOME/pwk/<profile>/session.json` (mode 0600,
  directory 0700) holds the host and the **API token pair in plain text**, like `bw`
  keeps its session data. Anyone who can read it as you, or as root, can call the API as
  you until the tokens expire or are revoked in the web interface. Without client-side
  encryption on the server, that is enough to read your passwords. `pwk logout` deletes
  the file.
- The **master key never lands on disk unsealed**. `pwk unlock` seals it with
  AES-256-GCM under a random 32-byte session key, bound to the profile and the expiry
  time; only the ciphertext is written to the session file.
- Files that `pwk inject -o` and `pwk attachment get -o` write are created with
  mode 0600.

### In the environment

- The session key lives only in `PWK_SESSION` (or `PWK_SESSION_<PROFILE>`) of your
  shell. Session file and variable together open the master key; each alone does not.
  Processes running as you can usually read both (`/proc/<pid>/environ`), so the session
  protects against a copied file or a leaked variable, not against malware in your
  account.
- An unlocked session expires after 12 hours by default (`unlock --timeout`,
  `session_timeout`); `pwk lock` ends it at once by removing the sealed master key.
- `PASSWORK_MASTER_KEY` in CI is the derived master key itself. Treat it like the master
  password: a masked CI secret, never in logs or images.
- Master password and tokens are read from the terminal without echo or from stdin,
  never from command line arguments, where other users could see them in `ps`.
- `pwk run` masks resolved values in the output of the command it runs, as a guard
  against accidental logging. The command itself gets the secrets in its environment and
  can do anything with them.

### In memory

Secrets are kept in buffers that are zeroed when dropped and never printed by `Debug`.
This narrows, but does not close, the window for core dumps and swap.

## Accepted advisory: RUSTSEC-2023-0071

The `rsa` crate has a timing side channel in RSA decryption, the "Marvin attack"
([RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)); there is
no fixed release yet. `pwk` uses `rsa` to decrypt vault passwords with your private key,
and the dependency audit (`checks.audit`) ignores this advisory on purpose:

- The attack needs an **oracle**: a service that decrypts many ciphertexts an attacker
  chooses and lets the attacker time each decryption, typically over a network.
- `pwk` is a local client. It decrypts only the vault keys your own server sends for
  your own account, a handful per command, and answers nobody. An attacker who could
  feed it chosen ciphertexts would already control your server or your machine, and with
  that the data the attack would reveal.

If `pwk` ever decrypts data on behalf of someone else, or `rsa` publishes a
constant-time release, this exception is revisited.
