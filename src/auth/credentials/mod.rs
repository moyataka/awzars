//! Credential loading and persistence pipeline.
//!
//! Reads from the in-process cache, falling back to the OS keyring. When
//! both are stale, returns `None` so the caller can drive the (slow)
//! browser-based login flow.

pub mod pipeline;
pub(crate) mod refresh_lock;

pub use pipeline::{credential_identity, try_load_credentials};
pub use refresh_lock::{refresh_under_lock, CredentialRefreshGuard};
