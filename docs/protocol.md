# Passwork 7 protocol

What `pwk` relies on when it talks to a Passwork 7 server. Passwork publishes no
machine-readable API schema; the field-level reference ships with each installation
(`files/api-schema/Api reference.pdf`). This document was written from:

- the official Python connector and CLI, [passwork-python] (MIT), especially
  `passwork_client/crypto.py`, `utils.py`, `base32.py` and `modules/*.py`;
- the public API overview at <https://passwork.pro/tech-guides/api-and-integrations/>.

Statements marked **(unverified)** are inferred and not confirmed by either source.
Every endpoint path lives in one place in `crates/api/src/endpoints.rs`, so a correction
is a one-line change; `pwk api` reaches anything not covered.

[passwork-python]: https://github.com/passwork-europe/passwork-python

## Transport

- Base path `/api/v1`, JSON bodies. `GET` takes its parameters as query string; list
  parameters are repeated with a `[]` suffix (`vaultIds[]=a&vaultIds[]=b`).
- `pwk` sends `X-Response-Format: raw` to get plain JSON. Without it the server answers
  with an envelope `{"format": "base64", "content": "<base64 of the JSON>"}`; the client
  unwraps that envelope too, whatever it asked for.
- Errors: HTTP status ≥ 400 with `{"errors": [{"code", "message", "field"?}]}`.
- `POST /api/v1/batch` with
  `{"requests": [{"method": "GET", "relativeUrl": "/api/v1/items/<id>"}]}` answers
  `{"responses": [{"statusCode", "body"}]}`. At most 25 requests per call. The responses
  are matched to the requests by position; a response count that differs from the
  request count is an error.
- `pwk` does not follow redirects (a redirect would resend the bearer token and master
  key hash to another URL); a 3xx answer is an error naming the target host, and the
  profile host has to be set to the final URL. Response bodies are limited to 64 MiB.
- IDs taken into a path are percent-encoded; empty IDs and IDs of dots only (`.`, `..`)
  are refused, since URL parsers resolve `..` (also `%2E%2E`) to the parent path.

## Authentication

API tokens are created in the web UI (API tokens → "Generate pair"), which yields an
access token and a refresh token. There is no API call to log in with a password.

| Header                   | Value                                    |
| ------------------------ | ---------------------------------------- |
| `Authorization`          | `Bearer <accessToken>`                   |
| `X-Master-Key-Hash`      | `sha256_hex(master_key)` (Python client) |
| `Passwork-MasterKeyHash` | same value (name used by the docs)       |

`pwk` sends both master key hash headers, because the code and the documentation
disagree on the name. They are only sent once the master key is known.

Token refresh (Passwork 7.6+):

- An expired access token answers HTTP 401 with error code `accessTokenExpired`.
- `POST /api/v1/sessions/refresh`, header `Authorization: Bearer <old access token>`,
  body `{"refreshToken": "…"}` →
  `{"accessToken", "refreshToken", "accessTokenExpiredAt", "refreshTokenExpiredAt"}`
  (Unix seconds). The old pair is invalid afterwards, so two processes must not refresh
  at the same time; `pwk` holds a file lock on the session while it refreshes and
  re-reads the file before refreshing.
- Then retry the original request once.

Other session endpoints: `GET /api/v1/sessions/current/info`.

## Client-side encryption

A server may run with or without client-side encryption. Without it every "encrypted"
string is plain standard Base64 of the UTF-8 value, and no master key is needed.

### Master key

1. `GET /api/v1/users/master-key/options` →
   `{"masterKeyOptions": "pbkdf:sha256:<iterations>:<bytes>:<salt>"}` (split at `:` into
   at most five parts; the salt is the fifth).
2. `master_key = base64_std(PBKDF2-HMAC-SHA256(password = master password UTF-8, salt = salt UTF-8, iterations, dklen = bytes))`.
   Defaults: 300 000 iterations, 64 bytes. The options come from the server, so a
   hostile server could hand out a tiny iteration count to make the master password
   cheap to brute-force (from the master key hash it receives): `pwk` refuses fewer than
   100 000 iterations (`ClientConfig::min_kdf_iterations`; lowered only by test
   harnesses).
3. The master key is used as a **string** from here on (its Base64 text), never as raw
   bytes. `PASSWORK_MASTER_KEY` holds exactly this string.
4. Check it: `GET /api/v1/users/keys` →
   `{"keys": {"public": "<SPKI PEM>", "privateEncrypted": "<cipher string>"}}`.
   `user_private_key = decrypt(privateEncrypted, master_key)` must yield a PEM private
   key that parses (PKCS#8 or PKCS#1: the fixtures of passwork-python yield
   `BEGIN RSA PRIVATE KEY`); otherwise the master key is wrong.

### Cipher string (`encrypt_aes` / `decrypt_aes`)

Symmetric encryption with a **passphrase string**, OpenSSL-compatible:

```text
salt      = 8 random bytes
key, iv   = EVP_BytesToKey(MD5, passphrase UTF-8, salt), 32 + 16 bytes
            (D_0 = "", D_i = MD5(D_{i-1} ‖ passphrase ‖ salt), concatenated)
raw       = "Salted__" ‖ salt ‖ AES-256-CBC(key, iv, PKCS#7(plaintext))
b64       = base64_std(raw)                      -- ASCII text "U2FsdGVkX1…"
cipher    = passwork_base32(b64 as UTF-8 bytes)  -- so it always starts "amt4cwv48xb6pp1h"
```

With an empty passphrase (no client-side encryption) the result is just
`base64_std(plaintext)` without Base32.

### Passwork Base32

Alphabet `0123456789abcdefghjkmnpqrtuvwxyz` (no `i l o s`), most significant bit first,
no padding: the last group is padded with zero bits on the right. Decoding is
case-insensitive, maps the aliases `o→0 i→1 l→1 s→5` and skips any other character;
trailing bits that do not fill a byte are dropped.

### RSA

- User key pair: RSA, private key PKCS#8 or PKCS#1 PEM, public key SPKI PEM.
- `rsa_decrypt(b64)`: RSA-OAEP with SHA-256 and MGF1-SHA-256, no label; on failure fall
  back to PKCS#1 v1.5. Input is standard Base64. The fallback is needed in practice: the
  `vaultMasterKeyEncrypted` of the passwork-python fixtures decrypts only with PKCS#1
  v1.5.
- `rsa_encrypt(text)`: RSA-OAEP-SHA-256, falling back to PKCS#1 v1.5 when the message is
  too long for OAEP (1024-bit keys); output standard Base64.

### Key chain

```text
master password ──PBKDF2──► master key (string)
master key ──decrypt──► user private key (PEM)
vault.masterKeyEncrypted / item.vaultMasterKeyEncrypted ──RSA──► vault password (string)
item.keyEncrypted ──decrypt with vault password──► item key (string)
item fields ──decrypt with item key──► plaintext
```

- Vault: `GET /api/v1/vaults/{id}` has `masterKeyEncrypted` (Base64 RSA ciphertext). An
  empty value means the vault does not use key encryption.
- Item: `GET /api/v1/items/{id}` carries `vaultMasterKeyEncrypted` for the reading user,
  so one request is enough to decrypt it.
- Encrypted item fields: `passwordEncrypted`; each entry of `customs` has `name`,
  `value` and `type` encrypted (other keys of a custom are copied as they are). Plain
  fields: `name`, `login`, `url`, `urls`, `description`, `tags`, `color`, `isFavorite`,
  `folderId`, `vaultId`.
- Custom field types seen: `text`, `password`, `totp`.
- Without client-side encryption `keyEncrypted` is `null` and fields are Base64. Items
  with `keyEncrypted == null` also occur in encrypting vaults (the Python client omits
  it for items without a password); their fields are then read as plain Base64. Whether
  a vault encrypts is decided by the vault (`masterKeyEncrypted` /
  `vaultMasterKeyEncrypted` present), never by the item.

### Writing

- New random keys: 100 characters from `A–Z a–z 0–9 @ !` (`generate_key`).
- Create item (`POST /api/v1/items` → `{"id"}`): `item_key = generate_key()` if the
  vault has `masterKeyEncrypted`, otherwise the vault password (empty).
  `keyEncrypted = encrypt(item_key, vault_password)`,
  `passwordEncrypted = encrypt(password, item_key)`, customs encrypted field by field.
  `pwk` always sends `keyEncrypted` when it encrypts, also for items without a password
  (the Python client omits it then, which leaves the customs unreadable).
- Update item (`PATCH /api/v1/items/{id}`): reuse the item's key and send its
  `keyEncrypted` again; `vaultId` is required. Customs are sent as a whole list. An item
  without `keyEncrypted` in an encrypting vault is never written with an empty key: when
  `pwk` sends encrypted fields (password, customs, attachments) it generates a new item
  key, sends `keyEncrypted = encrypt(item_key, vault_password)` and re-encrypts the
  stored password and customs with it too. If such an item already has attachments
  (their `encryptedKey` would not decrypt under the new key) or its stored values are
  not plain Base64, `pwk` refuses the change.
- Delete item: `DELETE /api/v1/items/{id}` → `{"binItemId"}` (moves it to the bin).
- Move folder (`POST /api/v1/folders/{id}/move` `{"vaultId", "parentId"}`, **body
  unverified**; `parentId: null` = vault root). The request cannot carry new
  `keyEncrypted` values for the items inside, and whether the server re-keys them for
  the target vault is unverified. `pwk` therefore refuses a move to another vault when
  either vault has `masterKeyEncrypted`; the items are moved one by one with the item
  move (which sends `keyEncrypted` re-encrypted for the target vault). Moves within the
  vault (new parent) are allowed, but never below the folder itself or one of its
  subfolders.
- Create vault (`POST /api/v1/vaults` → `{"id"}`): `vault_password = generate_key()`,
  `salt = 32 chars from the same alphabet`,
  `masterKeyEncrypted = rsa_encrypt(vault_password, user public key)`,
  `masterKeyHash = sha256_hex(vault_password ‖ salt)`, `salt`. If the feature
  `vaultType` is on (`GET /api/v1/app/features` → `[{"name"}]`), `typeId` is required,
  plus `administratorsKeys = {admin id: rsa_encrypt(vault_password, admin public key)}`
  from `GET /api/v1/vault-types/{typeId}/administrators` →
  `{"items": [{"id", "publicKey"}]}`. Vault types: `GET /api/v1/vault-types/all` →
  `{"items": [{"id", "code", "name"}]}`.

### Attachments

- Download: `GET /api/v1/items/{itemId}/attachment/{attachmentId}` →
  `{"name", "encryptedKey", "encryptedData", "hash"}`.
  - Encrypted: `att_key = decrypt(encryptedKey, item_key)`;
    `data = base64_decode(decrypt_bytes(encryptedData, att_key))`.
  - Plain: `data = base64_decode(base64_decode(encryptedData))`.
  - Check: `hash == sha256_hex(utf8(latin1_string(data)))`, i.e. every byte becomes the
    code point U+00XX, then UTF-8 encoded, then SHA-256.
- Upload: as part of an item create or update,
  `attachments: [{"name", "encryptedKey", "encryptedData", "hash"}]` with
  `att_key = generate_key()`, `encryptedKey = encrypt(att_key, item_key)`,
  `encryptedData = encrypt(base64_std(data), att_key)`. Maximum 5 MiB. **(unverified)**
  whether a `PATCH` with new attachments keeps the existing ones; the item response
  lists existing attachments as `{"id", "name", "encryptedKey"}`.

### Shortcuts

- `GET /api/v1/shortcuts/{id}` → shortcut with `vaultId`, `folderId`, `itemId`,
  `keyEncrypted` (the item key encrypted with the shortcut vault's password).
- `pwk` reads the item via `GET /api/v1/items/{itemId}`; if that is refused, it decrypts
  the item with the item key from the shortcut **(unverified fallback)**.
- Create: `POST /api/v1/shortcuts`
  `{"vaultId", "folderId", "itemId", "keyEncrypted": encrypt(item_key, target vault password)}`
  → `{"id"}`. Delete: `DELETE /api/v1/shortcuts/{id}`.
- Search: `GET /api/v1/shortcuts/search` (same parameters as item search) →
  `{"items": [{"shortcut": {…}, …}]}`. Rows may embed the item (e.g. `item`,
  `password`). Search rows of items and shortcuts never keep `passwordEncrypted`,
  `keyEncrypted`, `vaultMasterKeyEncrypted`, `masterKeyEncrypted` or `customs`, at any
  nesting depth: without client-side encryption these are plain Base64 secrets.

### TOTP

A TOTP custom field holds a Base32 (RFC 4648, padding optional) secret or an
`otpauth://totp/…?secret=…&algorithm=SHA1|SHA256|SHA512&digits=6&period=30` URI. Codes
are RFC 6238.

## Endpoints

| Purpose     | Request                                                                                                                                                                                                                         |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Vaults      | `GET /vaults`, `GET/POST/DELETE /vaults/{id}`, `POST /vaults` (create)                                                                                                                                                          |
| Folders     | `GET /folders` **(filter `vaultId`, `parentId` unverified)**, `GET/POST/DELETE /folders/{id}`, `POST /folders` (create: `vaultId`, `parentId`, `name` unverified), `POST /folders/{id}/move` (`vaultId`, `parentId` unverified) |
| Items       | `GET /items/search` (`query`, `tags[]`, `colorCodes[]`, `vaultIds[]`, `folderIds[]`) → `{"items"}`, `GET/PATCH/DELETE /items/{id}`, `POST /items`, `POST /items/{id}/move` **(body unverified: `vaultId`, `folderId`)**         |
| Attachments | `GET /items/{id}/attachment/{attachmentId}`                                                                                                                                                                                     |
| Snapshots   | `GET /items/{id}/snapshot/{snapshotId}` (no list endpoint known)                                                                                                                                                                |
| Shortcuts   | `GET /shortcuts/search`, `GET/DELETE /shortcuts/{id}`, `POST /shortcuts`                                                                                                                                                        |
| User        | `GET /users/keys`, `GET /users/master-key/options`                                                                                                                                                                              |
| Sessions    | `POST /sessions/refresh`, `GET /sessions/current/info`                                                                                                                                                                          |
| Misc        | `GET /app/features`, `GET /vault-types/all`, `POST /batch`                                                                                                                                                                      |

All paths are relative to `/api/v1`. Lists may come as a bare array or as
`{"items": […]}`; the client accepts both.
