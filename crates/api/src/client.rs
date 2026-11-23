//! The HTTP client: configuration, transport, token refresh, master key state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use base64::Engine as _;
use reqwest::Method;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, LOCATION};
use serde_json::{Map, Value, json};

use crate::endpoints;
use crate::models::{BatchRequest, BatchResponse, Feature};
use crate::{Error, Result, SecretString, TokenStore, Tokens};

/// Connection settings of a [`Client`].
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Base URL of the Passwork server, e.g. `https://passwork.example.com`.
    pub host: String,
    /// Additional trusted CA certificate(s), PEM. Added to the system roots.
    pub ca_cert_pem: Option<Vec<u8>>,
    /// Skip TLS certificate verification.
    pub insecure: bool,
    /// `User-Agent` header.
    pub user_agent: String,
    /// Timeout of a whole request; `None` waits forever.
    pub timeout: Option<Duration>,
    /// Lowest PBKDF2 iteration count [`Client::unlock_with_password`] accepts from the
    /// server's master key options (default [`pwk_crypto::MIN_ITERATIONS`], 100 000).
    /// Only lower it for test servers: the options come from the server, and a low
    /// count makes the master password cheap to brute-force.
    pub min_kdf_iterations: u32,
    /// Largest response body accepted, in bytes (default [`DEFAULT_MAX_RESPONSE_BYTES`]).
    pub max_response_bytes: usize,
}

/// Default limit of a response body: 64 MiB. Attachments are at most 5 MiB raw, about
/// 2x that after Base64 and Base32.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

impl ClientConfig {
    /// Settings for `host` with defaults: system roots only, verification on,
    /// `pwk/<version>` user agent, 60 s timeout.
    #[must_use]
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            ca_cert_pem: None,
            insecure: false,
            user_agent: concat!("pwk/", env!("CARGO_PKG_VERSION")).to_owned(),
            timeout: Some(Duration::from_secs(60)),
            min_kdf_iterations: pwk_crypto::MIN_ITERATIONS,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

/// Keys available after a successful unlock.
pub(crate) struct UserKeys {
    pub(crate) master_key: SecretString,
    pub(crate) master_key_hash: String,
    pub(crate) private_key: pwk_crypto::PrivateKey,
    pub(crate) public_key_pem: String,
}

/// Whether and how the client can decrypt.
#[derive(Clone)]
pub(crate) enum KeyState {
    /// No master key and no statement about the installation: plain (Base64) data can be
    /// read, encrypted data is [`Error::Locked`], creating vaults is refused.
    Unknown,
    /// The installation runs without client-side encryption.
    Plain,
    /// Master key set and verified.
    Unlocked(Arc<UserKeys>),
}

/// Result of one HTTP exchange.
enum Outcome {
    Done(Value),
    Expired,
}

/// Blocking Passwork 7 API client. Cheap to share by reference across threads.
pub struct Client {
    host: String,
    http: reqwest::blocking::Client,
    tokens: Arc<dyn TokenStore>,
    state: RwLock<KeyState>,
    vault_passwords: Mutex<HashMap<String, SecretString>>,
    features: Mutex<Option<Vec<Feature>>>,
    min_kdf_iterations: u32,
    max_response_bytes: usize,
    debug: bool,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("host", &self.host)
            .field("unlocked", &self.is_unlocked())
            .finish_non_exhaustive()
    }
}

/// Query string builder; list parameters get the `[]` suffix.
#[derive(Debug, Default, Clone)]
pub(crate) struct Query(pub(crate) Vec<(String, String)>);

impl Query {
    pub(crate) fn push(&mut self, key: &str, value: impl Into<String>) {
        self.0.push((key.to_owned(), value.into()));
    }

    pub(crate) fn push_opt(&mut self, key: &str, value: Option<&str>) {
        if let Some(v) = value {
            self.push(key, v);
        }
    }

    pub(crate) fn push_list<T: ToString>(&mut self, key: &str, values: &[T]) {
        let name = format!("{key}[]");
        for v in values {
            self.0.push((name.clone(), v.to_string()));
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Client {
    /// Builds a client. The host must be an `http(s)://` URL; a trailing slash is removed.
    pub fn new(config: ClientConfig, tokens: Arc<dyn TokenStore>) -> Result<Self> {
        let host = normalize_host(&config.host)?;
        let mut builder = reqwest::blocking::Client::builder()
            .use_rustls_tls()
            .user_agent(config.user_agent.clone())
            .timeout(config.timeout)
            // A redirect would resend the bearer token and master key hash to wherever
            // the server points; refuse instead (see `send_once`).
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(config.insecure);
        if let Some(pem) = &config.ca_cert_pem {
            let certs = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|e| Error::Invalid(format!("invalid CA certificate: {}", chain(&e))))?;
            if certs.is_empty() {
                return Err(Error::Invalid(
                    "invalid CA certificate: no certificate found in PEM".into(),
                ));
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        let http = builder
            .build()
            .map_err(|e| Error::Http(chain(&e.without_url())))?;
        Ok(Self {
            host,
            http,
            tokens,
            state: RwLock::new(KeyState::Unknown),
            vault_passwords: Mutex::new(HashMap::new()),
            features: Mutex::new(None),
            min_kdf_iterations: config.min_kdf_iterations,
            max_response_bytes: config.max_response_bytes,
            debug: std::env::var_os("PWK_DEBUG").is_some_and(|v| !v.is_empty()),
        })
    }

    /// The normalised host (no trailing slash).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The token store this client uses.
    #[must_use]
    pub fn token_store(&self) -> &Arc<dyn TokenStore> {
        &self.tokens
    }

    // ----------------------------------------------------------------------------------
    // Key state
    // ----------------------------------------------------------------------------------

    pub(crate) fn key_state(&self) -> KeyState {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn set_state(&self, state: KeyState) {
        *self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = state;
        lock(&self.vault_passwords).clear();
    }

    /// The verified user keys, or [`Error::Locked`].
    pub(crate) fn user_keys(&self) -> Result<Arc<UserKeys>> {
        match self.key_state() {
            KeyState::Unlocked(keys) => Ok(keys),
            KeyState::Unknown | KeyState::Plain => Err(Error::Locked),
        }
    }

    /// Whether a verified master key is set.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        matches!(self.key_state(), KeyState::Unlocked(_))
    }

    /// Whether [`Client::set_no_encryption`] was called (or detected).
    #[must_use]
    pub fn is_plain(&self) -> bool {
        matches!(self.key_state(), KeyState::Plain)
    }

    /// Declares that the installation runs without client-side encryption: values are
    /// plain Base64 and new vaults are created without keys. Forgets any master key.
    pub fn set_no_encryption(&self) {
        self.set_state(KeyState::Plain);
    }

    /// The current master key (the derived Base64 string), if unlocked.
    #[must_use]
    pub fn master_key(&self) -> Option<SecretString> {
        match self.key_state() {
            KeyState::Unlocked(keys) => Some(keys.master_key.clone()),
            KeyState::Unknown | KeyState::Plain => None,
        }
    }

    /// `GET users/master-key/options`. `None` means no client-side encryption: either the
    /// server reports no options, or it refuses the call with HTTP 403 and its app
    /// settings say `isClientSideEncryptionEnabled: false` (seen on Passwork 7 with
    /// encryption turned off).
    pub fn master_key_options(&self) -> Result<Option<pwk_crypto::MasterKeyOptions>> {
        let v = match self.get(endpoints::USERS_MASTER_KEY_OPTIONS, &Query::default()) {
            Ok(v) => v,
            Err(e @ Error::Api { status: 403, .. }) => {
                return match self.client_side_encryption() {
                    Ok(Some(false)) => Ok(None),
                    _ => Err(e),
                };
            }
            Err(e) => return Err(e),
        };
        match v.get("masterKeyOptions") {
            Some(Value::String(s)) if !s.trim().is_empty() => {
                Ok(Some(pwk_crypto::MasterKeyOptions::parse(s)?))
            }
            None | Some(Value::Null) | Some(Value::String(_)) => Ok(None),
            Some(_) => Err(Error::Response {
                path: endpoints::USERS_MASTER_KEY_OPTIONS.into(),
                detail: "masterKeyOptions is not a string".into(),
            }),
        }
    }

    /// `isClientSideEncryptionEnabled` of `GET app/settings`; `None` if the server does
    /// not say.
    pub fn client_side_encryption(&self) -> Result<Option<bool>> {
        let v = self.get(endpoints::APP_SETTINGS, &Query::default())?;
        Ok(v.get("isClientSideEncryptionEnabled")
            .and_then(Value::as_bool))
    }

    /// Asks the server whether client-side encryption is in use (see
    /// [`Client::master_key_options`]). If not, switches to [`Client::set_no_encryption`]
    /// and returns `false`.
    pub fn detect_encryption(&self) -> Result<bool> {
        if self.master_key_options()?.is_some() {
            Ok(true)
        } else {
            self.set_no_encryption();
            Ok(false)
        }
    }

    /// Derives the master key from the master password, verifies and sets it (see
    /// [`Client::set_master_key`]) and returns it, so the caller can store it sealed.
    /// Options with fewer PBKDF2 iterations than [`ClientConfig::min_kdf_iterations`]
    /// are refused.
    pub fn unlock_with_password(&self, master_password: &str) -> Result<SecretString> {
        let options = self.master_key_options()?.ok_or_else(|| {
            Error::Invalid(
                "the server does not use client-side encryption; no master password is needed"
                    .into(),
            )
        })?;
        options.check_strength(self.min_kdf_iterations)?;
        let key = pwk_crypto::derive_master_key(master_password, &options)?;
        self.set_master_key(key.clone())?;
        Ok(key)
    }

    /// Sets the derived master key: fetches `users/keys` and decrypts the private key with
    /// it. A key that does not decrypt it is [`Error::WrongMasterKey`]; the client state
    /// is unchanged then.
    pub fn set_master_key(&self, master_key: SecretString) -> Result<()> {
        let hash = pwk_crypto::master_key_hash(&master_key);
        let v = match self.execute(&Method::GET, endpoints::USERS_KEYS, &[], None, Some(&hash)) {
            Ok(v) => v,
            Err(Error::Api {
                code: Some(code), ..
            }) if code.to_ascii_lowercase().contains("masterkey") => {
                return Err(Error::WrongMasterKey);
            }
            Err(e) => return Err(e),
        };
        let keys = v.get("keys").unwrap_or(&v);
        let field = |name: &str| -> Result<String> {
            keys.get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| Error::Response {
                    path: endpoints::USERS_KEYS.into(),
                    detail: format!("missing keys.{name}"),
                })
        };
        let private_encrypted = field("privateEncrypted")?;
        let public_key_pem = field("public")?;
        let pem = pwk_crypto::decrypt(&private_encrypted, &master_key)
            .map_err(|_| Error::WrongMasterKey)?;
        let private_key =
            pwk_crypto::PrivateKey::from_pem(&pem).map_err(|_| Error::WrongMasterKey)?;
        self.set_state(KeyState::Unlocked(Arc::new(UserKeys {
            master_key,
            master_key_hash: hash,
            private_key,
            public_key_pem,
        })));
        Ok(())
    }

    /// Cached vault password lookup.
    pub(crate) fn cached_vault_password(&self, vault_id: &str) -> Option<SecretString> {
        lock(&self.vault_passwords).get(vault_id).cloned()
    }

    pub(crate) fn cache_vault_password(&self, vault_id: &str, password: &SecretString) {
        lock(&self.vault_passwords).insert(vault_id.to_owned(), password.clone());
    }

    // ----------------------------------------------------------------------------------
    // Public raw access
    // ----------------------------------------------------------------------------------

    /// Raw API call. `path` may be given with or without the `/api/v1` prefix. A query
    /// string in `path` (`items/search?query=db`) is decoded (form-urlencoded) and sent
    /// before the `query` pairs; both are sent as they are (append `[]` to list keys
    /// yourself). Returns the unwrapped JSON (`null` for an empty body).
    pub fn call(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let method = Method::from_bytes(method.trim().to_ascii_uppercase().as_bytes())
            .map_err(|_| Error::Invalid(format!("invalid HTTP method: {method}")))?;
        let (path, inline) = path.split_once('?').unwrap_or((path, ""));
        let path = endpoints::normalize(path);
        let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(inline.as_bytes())
            .into_owned()
            .collect();
        pairs.extend_from_slice(query);
        self.execute(&method, &path, &pairs, body, None)
    }

    /// Sends `requests` via `POST /batch`, at most [`endpoints::BATCH_LIMIT`] per call.
    /// Returns one response per request, in order. Envelopes in bodies are unwrapped.
    pub fn batch(&self, requests: &[BatchRequest]) -> Result<Vec<BatchResponse>> {
        let mut out = Vec::with_capacity(requests.len());
        for chunk in requests.chunks(endpoints::BATCH_LIMIT) {
            let body = json!({ "requests": chunk });
            let v = self.post(endpoints::BATCH, &body)?;
            let responses = v
                .get("responses")
                .and_then(Value::as_array)
                .ok_or_else(|| Error::Response {
                    path: endpoints::BATCH.into(),
                    detail: "missing responses array".into(),
                })?;
            if responses.len() != chunk.len() {
                return Err(Error::Response {
                    path: endpoints::BATCH.into(),
                    detail: format!("{} responses for {} requests", responses.len(), chunk.len()),
                });
            }
            for r in responses {
                let status_code = r
                    .get("statusCode")
                    .and_then(Value::as_u64)
                    .and_then(|s| u16::try_from(s).ok())
                    .unwrap_or(0);
                let body = unwrap_envelope(r.get("body").cloned().unwrap_or(Value::Null)).map_err(
                    |detail| Error::Response {
                        path: endpoints::BATCH.into(),
                        detail,
                    },
                )?;
                out.push(BatchResponse { status_code, body });
            }
        }
        Ok(out)
    }

    /// Refreshes the token pair now (via the token store) and returns the new pair.
    pub fn refresh_tokens(&self) -> Result<Tokens> {
        let current = self.tokens.current()?;
        self.refresh_from(&current)
    }

    // ----------------------------------------------------------------------------------
    // Internal helpers
    // ----------------------------------------------------------------------------------

    pub(crate) fn get(&self, path: &str, query: &Query) -> Result<Value> {
        self.execute(&Method::GET, path, &query.0, None, None)
    }

    pub(crate) fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.execute(&Method::POST, path, &[], Some(body), None)
    }

    pub(crate) fn patch(&self, path: &str, body: &Value) -> Result<Value> {
        self.execute(&Method::PATCH, path, &[], Some(body), None)
    }

    pub(crate) fn delete(&self, path: &str) -> Result<Value> {
        self.execute(&Method::DELETE, path, &[], None, None)
    }

    /// Features, cached per client.
    pub(crate) fn cached_features(&self) -> Option<Vec<Feature>> {
        lock(&self.features).clone()
    }

    pub(crate) fn cache_features(&self, features: &[Feature]) {
        *lock(&self.features) = Some(features.to_vec());
    }

    /// One request with refresh-and-retry. `mk_hash` overrides the master key hash header.
    fn execute(
        &self,
        method: &Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
        mk_hash: Option<&str>,
    ) -> Result<Value> {
        let state_hash = match self.key_state() {
            KeyState::Unlocked(keys) => Some(keys.master_key_hash.clone()),
            KeyState::Unknown | KeyState::Plain => None,
        };
        let hash = mk_hash.or(state_hash.as_deref());
        let tokens = self.tokens.current()?;
        match self.send_once(method, path, query, body, Some(&tokens.access_token), hash)? {
            Outcome::Done(v) => Ok(v),
            Outcome::Expired => {
                let fresh = self.refresh_from(&tokens)?;
                match self.send_once(method, path, query, body, Some(&fresh.access_token), hash)? {
                    Outcome::Done(v) => Ok(v),
                    Outcome::Expired => Err(Error::SessionExpired(
                        "the server rejected the refreshed access token".into(),
                    )),
                }
            }
        }
    }

    fn refresh_from(&self, stale: &Tokens) -> Result<Tokens> {
        if stale.refresh_token.as_deref().is_none_or(str::is_empty) {
            return Err(Error::SessionExpired(
                "access token expired and no refresh token is available".into(),
            ));
        }
        self.tokens
            .refresh(stale, &mut |old: &Tokens| self.do_refresh(old))
    }

    /// `POST sessions/refresh` with the old access token; no retry.
    fn do_refresh(&self, old: &Tokens) -> Result<Tokens> {
        let refresh_token = old
            .refresh_token
            .clone()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Error::SessionExpired("no refresh token is available".into()))?;
        let body = json!({ "refreshToken": refresh_token });
        let outcome = self
            .send_once(
                &Method::POST,
                endpoints::SESSIONS_REFRESH,
                &[],
                Some(&body),
                Some(&old.access_token),
                None,
            )
            .map_err(|e| Error::SessionExpired(format!("token refresh failed: {e}")))?;
        let Outcome::Done(v) = outcome else {
            return Err(Error::SessionExpired(
                "token refresh failed: access token rejected".into(),
            ));
        };
        tokens_from(&v, Some(refresh_token))
            .map_err(|detail| Error::SessionExpired(format!("token refresh failed: {detail}")))
    }

    /// Exchanges a one-time sign-in token from the web interface (the `desktopToken` of
    /// `passwork://login?desktopToken=…`) for a token pair: `POST auth-requests/login`
    /// without bearer. **Unverified**: the endpoint is the desktop app's, not part of
    /// the documented API. The client's own token store is neither used nor changed.
    pub fn login_with_auth_request(&self, token: &str) -> Result<Tokens> {
        let path = endpoints::AUTH_REQUESTS_LOGIN;
        let body = json!({ "token": token });
        match self.send_once(&Method::POST, path, &[], Some(&body), None, None)? {
            Outcome::Done(v) => tokens_from(&v, None).map_err(|detail| Error::Response {
                path: path.into(),
                detail,
            }),
            Outcome::Expired => Err(Error::SessionExpired(
                "the server rejected the sign-in token".into(),
            )),
        }
    }

    fn send_once(
        &self,
        method: &Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
        bearer: Option<&str>,
        mk_hash: Option<&str>,
    ) -> Result<Outcome> {
        let url = format!("{}{}", self.host, path);
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert("X-Response-Format", HeaderValue::from_static("raw"));
        if let Some(bearer) = bearer {
            let auth = HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|_| Error::Invalid("access token contains invalid characters".into()))?;
            headers.insert(AUTHORIZATION, sensitive(auth));
        }
        if let Some(hash) = mk_hash {
            let value = HeaderValue::from_str(hash)
                .map_err(|_| Error::Invalid("invalid master key hash".into()))?;
            headers.insert("X-Master-Key-Hash", sensitive(value.clone()));
            headers.insert("Passwork-MasterKeyHash", sensitive(value));
        }
        let mut req = self
            .http
            .request(method.clone(), url.as_str())
            .headers(headers);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(body) = body {
            let bytes = serde_json::to_vec(body)
                .map_err(|e| Error::Invalid(format!("cannot encode request body: {e}")))?;
            req = req
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(bytes);
        }
        if self.debug {
            eprintln!("pwk: > {method} {path}");
        }
        let resp = req
            .send()
            .map_err(|e| Error::Http(chain(&e.without_url())))?;
        let status = resp.status();
        if self.debug {
            eprintln!("pwk: < {}", status.as_u16());
        }
        if status.is_redirection() {
            return Err(redirect_error(&url, resp.headers().get(LOCATION), status));
        }
        let bytes = read_limited(resp, self.max_response_bytes)?;
        interpret(method, path, status, &bytes)
    }
}

/// The token pair of a refresh or sign-in response; `fallback_refresh` is kept when the
/// response carries no new refresh token.
fn tokens_from(v: &Value, fallback_refresh: Option<String>) -> std::result::Result<Tokens, String> {
    let access_token = v
        .get("accessToken")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("no accessToken in response")?
        .to_owned();
    let refresh_token = v
        .get("refreshToken")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or(fallback_refresh);
    Ok(Tokens {
        access_token,
        refresh_token,
        access_expires_at: v.get("accessTokenExpiredAt").and_then(unix_seconds),
        refresh_expires_at: v.get("refreshTokenExpiredAt").and_then(unix_seconds),
    })
}

/// Reads a response body, refusing more than `limit` bytes.
fn read_limited(resp: reqwest::blocking::Response, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let too_large = || {
        Error::Http(format!(
            "response body is larger than the limit of {limit} bytes"
        ))
    };
    if resp
        .content_length()
        .is_some_and(|n| usize::try_from(n).map_or(true, |n| n > limit))
    {
        return Err(too_large());
    }
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    resp.take(cap)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::Http(chain(&e)))?;
    if bytes.len() > limit {
        return Err(too_large());
    }
    Ok(bytes)
}

/// The error for a 3xx answer (redirects are not followed).
fn redirect_error(
    request_url: &str,
    location: Option<&HeaderValue>,
    status: reqwest::StatusCode,
) -> Error {
    let target = location
        .and_then(|l| l.to_str().ok())
        .and_then(|l| url::Url::parse(request_url).ok()?.join(l).ok())
        .and_then(|u| {
            let host = u.host_str()?;
            Some(match u.port() {
                Some(port) => format!("{}://{host}:{port}", u.scheme()),
                None => format!("{}://{host}", u.scheme()),
            })
        });
    match target {
        Some(target) => Error::Http(format!(
            "server redirected to {target} (HTTP {}); redirects are not followed: set the \
             profile host to the final URL",
            status.as_u16()
        )),
        None => Error::Http(format!(
            "server answered with a redirect (HTTP {}); redirects are not followed: set the \
             profile host to the final URL",
            status.as_u16()
        )),
    }
}

fn sensitive(mut v: HeaderValue) -> HeaderValue {
    v.set_sensitive(true);
    v
}

/// Error message with its source chain.
fn chain(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        let s_msg = s.to_string();
        if !msg.contains(&s_msg) {
            msg.push_str(": ");
            msg.push_str(&s_msg);
        }
        src = s.source();
    }
    msg
}

fn normalize_host(host: &str) -> Result<String> {
    let trimmed = host.trim().trim_end_matches('/');
    let url = url::Url::parse(trimmed)
        .map_err(|e| Error::Invalid(format!("invalid host URL {trimmed:?}: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(Error::Invalid(format!(
            "invalid host URL {trimmed:?}: must start with http:// or https://"
        )));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::Invalid(format!(
            "invalid host URL {trimmed:?}: must not contain a query or fragment"
        )));
    }
    Ok(trimmed.to_owned())
}

fn unix_seconds(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n
            .as_u64()
            .or_else(|| n.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Unwraps `{"format": "base64", "content": "…"}`; anything else is returned unchanged.
pub(crate) fn unwrap_envelope(v: Value) -> std::result::Result<Value, String> {
    let is_envelope = v.get("format").and_then(Value::as_str) == Some("base64")
        && v.get("content").is_some_and(Value::is_string);
    if !is_envelope {
        return Ok(v);
    }
    let content = v.get("content").and_then(Value::as_str).unwrap_or_default();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(content.trim())
        .map_err(|_| "envelope content is not valid Base64".to_owned())?;
    if decoded.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&decoded).map_err(|_| "envelope content is not valid JSON".to_owned())
}

fn interpret(
    method: &Method,
    path: &str,
    status: reqwest::StatusCode,
    bytes: &[u8],
) -> Result<Outcome> {
    let parsed: std::result::Result<Value, String> = if bytes.iter().all(u8::is_ascii_whitespace) {
        Ok(Value::Null)
    } else {
        serde_json::from_slice::<Value>(bytes)
            .map_err(|_| "response is not valid JSON".to_owned())
            .and_then(unwrap_envelope)
    };
    if status.as_u16() < 400 {
        return parsed.map(Outcome::Done).map_err(|detail| Error::Response {
            path: path.to_owned(),
            detail,
        });
    }
    let value = parsed.unwrap_or(Value::Null);
    let errors: &[Value] = value
        .get("errors")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice);
    let code_of = |e: &Value| e.get("code").and_then(Value::as_str).map(str::to_owned);
    if errors
        .iter()
        .any(|e| code_of(e).as_deref() == Some("accessTokenExpired"))
    {
        return Ok(Outcome::Expired);
    }
    let code = errors.iter().find_map(code_of);
    let mut messages: Vec<String> = errors
        .iter()
        .filter_map(|e| {
            let message = e
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| code_of(e))?;
            match e.get("field").and_then(Value::as_str) {
                Some(field) if !field.is_empty() => Some(format!("{field} => {message}")),
                _ => Some(message),
            }
        })
        .collect();
    if messages.is_empty() {
        if let Some(m) = value.get("message").and_then(Value::as_str) {
            messages.push(m.to_owned());
        } else {
            messages.push(
                status
                    .canonical_reason()
                    .unwrap_or("request failed")
                    .to_owned(),
            );
        }
    }
    Err(Error::Api {
        method: method.to_string(),
        path: path.to_owned(),
        status: status.as_u16(),
        code,
        message: messages.join("; "),
    })
}

/// Extracts a list: a bare array or `{"items": [...]}`.
pub(crate) fn list_values(v: Value, path: &str) -> Result<Vec<Value>> {
    match v {
        Value::Array(a) => Ok(a),
        Value::Object(mut o) => match o.remove("items") {
            Some(Value::Array(a)) => Ok(a),
            Some(Value::Null) => Ok(Vec::new()),
            _ => Err(Error::Response {
                path: path.to_owned(),
                detail: "expected a list".into(),
            }),
        },
        Value::Null => Ok(Vec::new()),
        _ => Err(Error::Response {
            path: path.to_owned(),
            detail: "expected a list".into(),
        }),
    }
}

/// Deserializes `v` into `T`, mapping failures to [`Error::Response`].
pub(crate) fn from_value<T: serde::de::DeserializeOwned>(v: Value, path: &str) -> Result<T> {
    serde_json::from_value(v).map_err(|e| Error::Response {
        path: path.to_owned(),
        detail: e.to_string(),
    })
}

/// Extracts `{"id": "…"}` from a create response.
pub(crate) fn id_from(v: &Value, path: &str) -> Result<String> {
    match v.get("id") {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Number(n)) => Ok(n.to_string()),
        _ => Err(Error::Response {
            path: path.to_owned(),
            detail: "missing id in response".into(),
        }),
    }
}

/// An empty JSON object.
pub(crate) fn object() -> Map<String, Value> {
    Map::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_normalisation() {
        assert_eq!(
            normalize_host("https://pw.example.com/").unwrap(),
            "https://pw.example.com"
        );
        assert_eq!(
            normalize_host(" http://pw.example.com/sub// ").unwrap(),
            "http://pw.example.com/sub"
        );
        assert!(normalize_host("ftp://pw.example.com").is_err());
        assert!(normalize_host("pw.example.com").is_err());
    }

    #[test]
    fn envelope() {
        let content = base64::engine::general_purpose::STANDARD.encode(br#"{"a":1}"#);
        let v = unwrap_envelope(json!({"format": "base64", "content": content})).unwrap();
        assert_eq!(v, json!({"a": 1}));
        let v = unwrap_envelope(json!({"format": "raw", "x": 1})).unwrap();
        assert_eq!(v, json!({"format": "raw", "x": 1}));
    }
}
