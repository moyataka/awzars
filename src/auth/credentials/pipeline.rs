//! Cache → keyring → login fallback chain.
//!
//! Three CLI commands need the same lookup: `login`, `credential-process`,
//! and any future caller that wants to reuse cached or persisted creds
//! before doing a browser login. This module is the single place that
//! knows the priority order and the cache-promotion side effect.

use crate::credential_process::protocol::CredentialProcessOutput;
use crate::error::Result;
use crate::storage::cache::CacheHandle;
use crate::storage::keyring::KeyringStorage;

/// Try to load credentials without driving a browser login.
///
/// Returns `Some(creds)` when the in-process cache or the OS keyring has
/// a still-valid set of credentials for `profile`. Returns `None` when
/// the caller must perform a fresh login.
///
/// Side effect: a keyring hit is promoted into the in-process cache, so
/// subsequent calls in the same process skip the keyring round trip (and
/// on macOS, skip the Keychain authorization dialog).
///
/// `force_refresh = true` short-circuits to `Ok(None)` regardless of
/// what's stored. Use it for `--force-refresh` style flags.
pub fn try_load_credentials(
    profile: &str,
    force_refresh: bool,
) -> Result<Option<CredentialProcessOutput>> {
    if force_refresh {
        return Ok(None);
    }

    let cache = CacheHandle::new(profile)?;
    if let Some(creds) = cache.get_valid_credentials()? {
        return Ok(Some(creds));
    }

    let keyring = KeyringStorage::new(profile)?;
    if let Some(creds) = keyring.get_credentials()? {
        if creds.is_valid() {
            let output = CredentialProcessOutput::from(creds);
            cache.store(&output)?;
            return Ok(Some(output));
        }
        tracing::info!(
            "Keyring credentials expired for profile '{}', re-authenticating",
            profile
        );
    }

    Ok(None)
}
