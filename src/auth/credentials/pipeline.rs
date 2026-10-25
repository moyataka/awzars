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

/// Domain-separation prefix for `credential_identity`.
const IDENTITY_FP_DOMAIN: &[u8] = b"awzars-credential-identity-v1\0";

/// Fingerprint of the identity a set of credentials is issued for: the Azure
/// tenant, the app ID URI and the AWS role. Stored credentials are reused
/// only for the identity they were issued for, so a profile whose identity
/// changed by any route re-authenticates. Truncated SHA-256 (128 bits) in
/// hex: an equality tag, not a secret.
pub fn credential_identity(tenant_id: &str, app_id_uri: &str, role_arn: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_FP_DOMAIN);
    // Length-prefix each field so no two different tuples hash the same input.
    for field in [Some(tenant_id), Some(app_id_uri), role_arn] {
        match field {
            Some(value) => {
                hasher.update([1]);
                hasher.update((value.len() as u64).to_le_bytes());
                hasher.update(value.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    hasher
        .finalize()
        .iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Try to load credentials without driving a browser login.
///
/// Returns `Some(creds)` when the in-process cache or the OS keyring has
/// a still-valid set of credentials for `profile` issued for `identity`
/// (see [`credential_identity`]). Returns `None` when the caller must
/// perform a fresh login.
///
/// Side effect: a keyring hit is promoted into the in-process cache, so
/// subsequent calls in the same process skip the keyring round trip (and
/// on macOS, skip the Keychain authorization dialog).
///
/// `session_duration` is the profile's configured session length in seconds;
/// it sets the refresh window (see `protocol::is_fresh`).
///
/// `force_refresh = true` short-circuits to `Ok(None)` regardless of
/// what's stored. Use it for `--force-refresh` style flags.
pub fn try_load_credentials(
    profile: &str,
    identity: &str,
    session_duration: i32,
    force_refresh: bool,
) -> Result<Option<CredentialProcessOutput>> {
    let lifetime_secs = i64::from(session_duration);
    if force_refresh {
        return Ok(None);
    }

    let cache = CacheHandle::new(profile)?;
    if let Some(creds) = cache.get_valid_credentials(lifetime_secs, identity)? {
        return Ok(Some(creds));
    }

    let keyring = KeyringStorage::new(profile)?;
    if let Some(creds) = keyring.get_credentials(identity)? {
        if creds.is_valid(lifetime_secs) {
            let output = CredentialProcessOutput::from(creds);
            cache.store(&output, identity)?;
            return Ok(Some(output));
        }
        tracing::info!(
            "Keyring credentials expired for profile '{}', re-authenticating",
            profile
        );
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::credential_identity;

    #[test]
    fn identity_changes_with_each_field() {
        let base = credential_identity("tenant", "app", Some("role"));
        assert_eq!(base, credential_identity("tenant", "app", Some("role")));
        for other in [
            credential_identity("tenant-2", "app", Some("role")),
            credential_identity("tenant", "app-2", Some("role")),
            credential_identity("tenant", "app", Some("role-2")),
            credential_identity("tenant", "app", None),
            credential_identity("tenantapp", "", Some("role")),
        ] {
            assert_ne!(base, other);
        }
        assert_ne!(
            credential_identity("tenant", "app", None),
            credential_identity("tenant", "app", Some(""))
        );
    }
}
