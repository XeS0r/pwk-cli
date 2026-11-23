//! Passwork 7 API client (blocking).
//!
//! See `docs/protocol.md` for the protocol and `docs/design.md` for how the crates fit
//! together.
//!
//! ```no_run
//! use std::sync::Arc;
//! use pwk_api::{Client, ClientConfig, ItemFilter, MemoryTokenStore, Tokens};
//!
//! # fn main() -> pwk_api::Result<()> {
//! let tokens = Tokens {
//!     access_token: "…".into(),
//!     refresh_token: Some("…".into()),
//!     access_expires_at: None,
//!     refresh_expires_at: None,
//! };
//! let client = Client::new(
//!     ClientConfig::new("https://passwork.example.com"),
//!     Arc::new(MemoryTokenStore::new(tokens)),
//! )?;
//! client.unlock_with_password("master password")?;
//! for row in client.search_items(&ItemFilter { query: Some("db".into()), ..Default::default() })? {
//!     let item = client.get_item(&row.id)?;
//!     println!("{} {:?}", item.name, item.login);
//! }
//! # Ok(())
//! # }
//! ```

mod client;
pub mod endpoints;
mod error;
mod items;
mod models;
pub mod tokens;
mod vaults;

pub use crate::client::{Client, ClientConfig, DEFAULT_MAX_RESPONSE_BYTES};
pub use crate::error::{Error, Result};
pub use crate::items::MAX_ATTACHMENT_SIZE;
pub use crate::models::{
    AttachmentRef, BatchRequest, BatchResponse, CustomField, CustomKind, Feature, Folder, Item,
    ItemFilter, ItemSummary, ItemUpdate, NewAttachment, NewItem, SessionInfo, Shortcut,
    ShortcutSummary, ShortcutWithItem, UserInfo, Vault, VaultType,
};
pub use crate::tokens::{MemoryTokenStore, TokenStore, Tokens};
pub use pwk_crypto::{MasterKeyOptions, SecretBytes, SecretString};
