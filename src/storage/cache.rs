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
}

impl CredentialCache {
    /// Create a new cache
    fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    /// Store credentials
    fn store(&mut self, profile: &str, credentials: CredentialProcessOutput) {
        self.credentials
            .insert(profile.to_string(), CachedCredential { credentials });
    }

    /// Get valid credentials (not expired)
    fn get(&self, profile: &str) -> Option<CredentialProcessOutput> {
        let cached = self.credentials.get(profile)?;

        // Check expiration
        if !cached.credentials.is_valid() {
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

    /// Store credentials in cache
    pub fn store(&self, credentials: &CredentialProcessOutput) -> Result<()> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| AwzarsError::Cache("Failed to lock cache".to_string()))?;
        cache.store(&self.profile, credentials.clone());
        Ok(())
    }

    /// Get valid credentials from cache
    pub fn get_valid_credentials(&self) -> Result<Option<CredentialProcessOutput>> {
        let cache = self
            .cache
            .lock()
            .map_err(|_| AwzarsError::Cache("Failed to lock cache".to_string()))?;
        Ok(cache.get(&self.profile))
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
