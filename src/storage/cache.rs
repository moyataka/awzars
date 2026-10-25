//! In-memory credential cache

use crate::credential_process::protocol::CredentialProcessOutput;
use crate::error::{AwzarsError, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Global credential cache
static CACHE: once_cell::sync::Lazy<Arc<Mutex<CredentialCache>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(CredentialCache::new())));

/// In-memory credential cache
struct CredentialCache {
    credentials: HashMap<String, CachedCredential>,
}

/// A cached credential
#[derive(Debug, Clone)]
struct CachedCredential {
    credentials: CredentialProcessOutput,
    /// Fingerprint of the identity the credentials were issued for
    /// (see `auth::credentials::credential_identity`).
    identity: String,
}

impl CredentialCache {
    /// Create a new cache
    fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    /// Store credentials
    fn store(&mut self, profile: &str, credentials: CredentialProcessOutput, identity: &str) {
        self.credentials.insert(
            profile.to_string(),
            CachedCredential {
                credentials,
                identity: identity.to_string(),
            },
        );
    }

    /// Get valid credentials (outside the refresh window for `lifetime_secs`)
    /// issued for `identity`
    fn get(
        &self,
        profile: &str,
        lifetime_secs: i64,
        identity: &str,
    ) -> Option<CredentialProcessOutput> {
        let cached = self.credentials.get(profile)?;

        if cached.identity != identity {
            tracing::debug!(
                "Cached credentials for profile {} were issued for another identity",
                profile
            );
            return None;
        }

        // Check expiration
        if !cached.credentials.is_valid(lifetime_secs) {
            tracing::debug!("Cached credentials expired for profile: {}", profile);
            return None;
        }

        Some(cached.credentials.clone())
    }

    /// Clear cached credentials for a profile
    fn clear(&mut self, profile: &str) {
        self.credentials.remove(profile);
    }

    /// Clear all cached credentials
    fn clear_all(&mut self) {
        self.credentials.clear();
    }
}

/// Handle to the credential cache for a specific profile
pub struct CacheHandle {
    profile: String,
    cache: Arc<Mutex<CredentialCache>>,
}

impl CacheHandle {
    /// Create a new cache handle for a profile
    pub fn new(profile: &str) -> Result<Self> {
        Ok(Self {
            profile: profile.to_string(),
            cache: CACHE.clone(),
        })
    }

    /// Store credentials in cache, tagged with the fingerprint of the
    /// identity they were issued for
    pub fn store(&self, credentials: &CredentialProcessOutput, identity: &str) -> Result<()> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| AwzarsError::Cache("Failed to lock cache".to_string()))?;
        cache.store(&self.profile, credentials.clone(), identity);
        Ok(())
    }

    /// Get valid credentials from cache for a session configured to last
    /// `lifetime_secs`. Credentials issued for another identity are a miss.
    pub fn get_valid_credentials(
        &self,
        lifetime_secs: i64,
        identity: &str,
    ) -> Result<Option<CredentialProcessOutput>> {
        let cache = self
            .cache
            .lock()
            .map_err(|_| AwzarsError::Cache("Failed to lock cache".to_string()))?;
        Ok(cache.get(&self.profile, lifetime_secs, identity))
    }

    /// Clear cached credentials
    pub fn clear(&self) -> Result<()> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| AwzarsError::Cache("Failed to lock cache".to_string()))?;
        cache.clear(&self.profile);
        Ok(())
    }
}

/// Clear cache for a specific profile
pub fn clear_profile_cache(profile: &str) -> Result<()> {
    let handle = CacheHandle::new(profile)?;
    handle.clear()
}

/// Clear all cached credentials
pub fn clear_all_caches() -> Result<()> {
    let mut cache = CACHE
        .lock()
        .map_err(|_| AwzarsError::Cache("Failed to lock cache".to_string()))?;
    cache.clear_all();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials() -> CredentialProcessOutput {
        CredentialProcessOutput::new("cached-key", "test-secret")
            .with_session_token("test-token")
            .with_expiration((chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339())
    }

    #[test]
    fn credentials_are_returned_only_for_the_identity_they_were_issued_for() {
        let role_a = crate::auth::credentials::credential_identity(
            "tenant",
            "app",
            Some("arn:aws:iam::123456789012:role/A"),
        );
        let role_b = crate::auth::credentials::credential_identity(
            "tenant",
            "app",
            Some("arn:aws:iam::123456789012:role/B"),
        );
        let profile = format!("identity_{}", uuid::Uuid::new_v4());
        let cache = CacheHandle::new(&profile).unwrap();
        cache.store(&credentials(), &role_a).unwrap();

        assert!(cache
            .get_valid_credentials(3600, &role_b)
            .unwrap()
            .is_none());
        assert!(cache
            .get_valid_credentials(3600, &role_a)
            .unwrap()
            .is_some());
        cache.clear().unwrap();
    }
}
