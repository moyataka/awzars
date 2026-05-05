//! Profile deletion: remove an awzars profile and all of its owned state.
//!
//! Cleans up the config entry, keyring credentials (including the cookie
//! encryption key), in-memory cache, and the per-profile chromium data
//! directory. Does **not** modify `~/.aws/config`; AWS profiles whose
//! `credential_process` still references the deleted profile are returned
//! in `orphaned_aws_profiles` so the caller can warn the user.
//!
//! Used by both the CLI `delete-profile` command and the TUI delete handler.

use super::Profile;
use crate::error::{AwzarsError, Result};
use crate::tui::aws_config;

/// Outcome of a profile deletion. The deletion itself succeeded if this is
/// returned (the config entry is gone); fields describe non-fatal issues
/// the caller should surface to the user.
pub struct ProfileDeletionReport {
    /// Names of `~/.aws/config` profiles whose `credential_process` still
    /// references the deleted awzars profile. Read-only — never modified.
    pub orphaned_aws_profiles: Vec<String>,
    /// Non-fatal cleanup failures (chromium dir removal, keyring delete).
    pub warnings: Vec<String>,
}

/// Delete an awzars profile and clean up all owned state.
///
/// Errors only when the profile does not exist or the config file cannot be
/// rewritten. Filesystem and keyring failures during cleanup are recorded as
/// warnings — the config entry is the source of truth for "does this profile
/// exist", and once that is gone the rest is best-effort cleanup.
pub fn delete_awzars_profile(name: &str) -> Result<ProfileDeletionReport> {
    let mut config = super::Config::load()?;
    if config.remove_profile(name).is_none() {
        return Err(AwzarsError::ProfileNotFound(name.to_string()));
    }
    config.save()?;

    let mut warnings = Vec::new();

    match super::chromium_data_dir(name) {
        Ok(dir) if dir.exists() => {
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                warnings.push(format!("chromium dir: {}", e));
            }
        }
        Ok(_) => {}
        Err(e) => warnings.push(format!("chromium dir: {}", e)),
    }

    // Full keyring wipe (includes `cookie_key`), unlike the edit-time
    // invalidation which preserves the cookie key.
    match crate::storage::keyring::KeyringStorage::new(name) {
        Ok(keyring) => {
            if let Err(e) = keyring.delete_credentials() {
                warnings.push(format!("keyring: {}", e));
            }
        }
        Err(e) => warnings.push(format!("keyring: {}", e)),
    }

    if let Err(e) = crate::storage::cache::clear_profile_cache(name) {
        warnings.push(format!("cache: {}", e));
    }

    // Drop any session unlock/consent token for this profile. Best-effort:
    // the verifier is already gone (with the profile entry), so an orphaned
    // token would be inert — but we clean it up so `lock::gc_stale_unlocks`
    // does not have to.
    if let Err(e) = crate::auth::lock::remove_unlock(name) {
        warnings.push(format!("session unlock token: {}", e));
    }

    let orphaned_aws_profiles = aws_config::load_aws_integration(None)
        .for_awzars_profile(name)
        .iter()
        .map(|p| p.name.clone())
        .collect();

    Ok(ProfileDeletionReport {
        orphaned_aws_profiles,
        warnings,
    })
}

/// Wipe cached and persisted STS credentials for a profile while leaving the
/// browser cookie key intact.
///
/// Used by edit paths (TUI form save, CLI `configure`) when the profile's
/// identity-defining fields (tenant, app id URI, role ARN) change. The cached
/// session was minted for the previous identity and would be misleading if
/// returned by `try_load_credentials`.
///
/// Best-effort: returns a list of human-readable warnings rather than `Err`,
/// so a flaky keyring backend cannot block the user from saving config.
pub fn invalidate_cached_credentials(name: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    match crate::storage::keyring::KeyringStorage::new(name) {
        Ok(keyring) => {
            if let Err(e) = keyring.delete_session_credentials() {
                warnings.push(format!("keyring: {}", e));
            }
        }
        Err(e) => warnings.push(format!("keyring: {}", e)),
    }
    if let Err(e) = crate::storage::cache::clear_profile_cache(name) {
        warnings.push(format!("cache: {}", e));
    }
    warnings
}

/// Whether a profile edit changed any field that the cached STS session was
/// minted against. A `true` answer means existing credentials are no longer
/// valid for the configured identity and must be invalidated.
pub fn credential_identity_changed(prev: &Profile, next: &Profile) -> bool {
    prev.azure.tenant_id != next.azure.tenant_id
        || prev.azure.app_id_uri != next.azure.app_id_uri
        || prev.role_arn != next.role_arn
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AzureConfig;

    fn profile_with(tenant: &str, app: &str, role: Option<&str>) -> Profile {
        Profile {
            azure: AzureConfig {
                tenant_id: tenant.to_string(),
                app_id_uri: app.to_string(),
                ..AzureConfig::default()
            },
            role_arn: role.map(|s| s.to_string()),
            ..Profile::default()
        }
    }

    #[test]
    fn identity_change_detected_for_role_arn() {
        let a = profile_with("t", "a", Some("arn:aws:iam::1:role/A"));
        let b = profile_with("t", "a", Some("arn:aws:iam::1:role/B"));
        assert!(credential_identity_changed(&a, &b));
    }

    #[test]
    fn identity_change_detected_when_role_cleared() {
        let a = profile_with("t", "a", Some("arn:aws:iam::1:role/A"));
        let b = profile_with("t", "a", None);
        assert!(credential_identity_changed(&a, &b));
    }

    #[test]
    fn identity_change_detected_for_tenant() {
        let a = profile_with("tenant-1", "a", Some("arn"));
        let b = profile_with("tenant-2", "a", Some("arn"));
        assert!(credential_identity_changed(&a, &b));
    }

    #[test]
    fn identity_change_detected_for_app_id_uri() {
        let a = profile_with("t", "app-1", Some("arn"));
        let b = profile_with("t", "app-2", Some("arn"));
        assert!(credential_identity_changed(&a, &b));
    }

    #[test]
    fn identity_unchanged_for_non_identity_fields() {
        let mut a = profile_with("t", "a", Some("arn"));
        let mut b = profile_with("t", "a", Some("arn"));
        a.region = Some("us-east-1".into());
        b.region = Some("eu-west-1".into());
        a.headless = Some(false);
        b.headless = Some(true);
        a.lock_verifier = Some("$argon2id$old".into());
        b.lock_verifier = Some("$argon2id$new".into());
        assert!(!credential_identity_changed(&a, &b));
    }

    #[test]
    fn invalidate_clears_in_memory_cache() {
        use crate::credential_process::protocol::CredentialProcessOutput;
        use crate::storage::cache::CacheHandle;
        use chrono::{Duration, Utc};

        let profile = "test-invalidate-cache";
        let creds = CredentialProcessOutput::new("AKIA", "secret")
            .with_session_token("token")
            .with_expiration(
                (Utc::now() + Duration::hours(1))
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            );
        let handle = CacheHandle::new(profile).expect("cache handle");
        handle.store(&creds).expect("cache store");
        assert!(handle.get_valid_credentials().expect("cache get").is_some());

        let _warnings = invalidate_cached_credentials(profile);

        assert!(handle
            .get_valid_credentials()
            .expect("cache get after invalidate")
            .is_none());
    }
}
