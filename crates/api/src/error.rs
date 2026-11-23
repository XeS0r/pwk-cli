//! Errors of the API client.

/// Errors of the API client. Messages never contain tokens, keys or decrypted values.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The server answered with an error status.
    #[error("{method} {path}: HTTP {status}: {message}")]
    Api {
        /// HTTP method.
        method: String,
        /// Request path (without host and query).
        path: String,
        /// HTTP status code.
        status: u16,
        /// First error `code` from the response, if any.
        code: Option<String>,
        /// Joined error messages (`field => message`).
        message: String,
    },
    /// Network or TLS failure.
    #[error("request failed: {0}")]
    Http(String),
    /// Response is not the JSON we expected.
    #[error("unexpected response from {path}: {detail}")]
    Response {
        /// Request path.
        path: String,
        /// What was wrong.
        detail: String,
    },
    /// Access token expired and could not be refreshed.
    #[error("session expired: {0}")]
    SessionExpired(String),
    /// An operation needs the master key, but none is set.
    #[error("the vault is locked: a master key is required")]
    Locked,
    /// Wrong master password or master key.
    #[error("wrong master password or master key")]
    WrongMasterKey,
    /// Cryptographic failure.
    #[error(transparent)]
    Crypto(#[from] pwk_crypto::Error),
    /// A lookup found nothing.
    #[error("{0}")]
    NotFound(String),
    /// Invalid input from the caller.
    #[error("{0}")]
    Invalid(String),
    /// Failure of a [`crate::TokenStore`] implementation (file I/O and the like).
    #[error("token store: {0}")]
    TokenStore(String),
}

/// Result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;
