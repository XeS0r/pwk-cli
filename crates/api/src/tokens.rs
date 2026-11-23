//! Access/refresh token pair and where it is kept.

use std::sync::Mutex;

use crate::Result;

/// An access/refresh token pair. `Debug` hides the values.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Tokens {
    /// Access token (`Authorization: Bearer …`).
    pub access_token: String,
    /// Refresh token; without it an expired access token is final.
    pub refresh_token: Option<String>,
    /// Expiry of the access token, Unix seconds, if known.
    pub access_expires_at: Option<u64>,
    /// Expiry of the refresh token, Unix seconds, if known.
    pub refresh_expires_at: Option<u64>,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens")
            .field("access_token", &"..")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| ".."))
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}

/// Where the client gets its tokens from and puts refreshed ones.
pub trait TokenStore: Send + Sync {
    /// The current token pair.
    fn current(&self) -> Result<Tokens>;

    /// Called after the server rejected `stale` with `accessTokenExpired`.
    ///
    /// Implementations that share tokens between processes take an exclusive lock and
    /// re-read their storage. If the stored pair differs from `stale`, another process
    /// has refreshed already and that pair is returned. Otherwise `refresh(stale)`
    /// performs the refresh request; the result is stored and returned.
    fn refresh(
        &self,
        stale: &Tokens,
        refresh: &mut dyn FnMut(&Tokens) -> Result<Tokens>,
    ) -> Result<Tokens>;
}

/// Tokens kept in memory only (stateless mode, tests).
#[derive(Debug)]
pub struct MemoryTokenStore {
    tokens: Mutex<Tokens>,
}

impl MemoryTokenStore {
    /// A store holding `tokens`.
    #[must_use]
    pub fn new(tokens: Tokens) -> Self {
        Self {
            tokens: Mutex::new(tokens),
        }
    }
}

impl TokenStore for MemoryTokenStore {
    fn current(&self) -> Result<Tokens> {
        Ok(self
            .tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }

    fn refresh(
        &self,
        stale: &Tokens,
        refresh: &mut dyn FnMut(&Tokens) -> Result<Tokens>,
    ) -> Result<Tokens> {
        let mut guard = self.tokens.lock().unwrap_or_else(|e| e.into_inner());
        if *guard != *stale {
            return Ok(guard.clone());
        }
        let fresh = refresh(stale)?;
        *guard = fresh.clone();
        Ok(fresh)
    }
}
