//! OS keychain integration using keyring-rs

use crate::credential_process::protocol::CredentialProcessOutput;
use crate::credential_process::protocol::Credentials;
use crate::error::{AwzarsError, Result};
use keyring::Entry;
use zeroize::Zeroizing;

/// Keychain storage for credentials
pub struct KeyringStorage {
    service_name: String,
    profile: String,
}

impl KeyringStorage {
    /// Create a new keyring storage for a profile
    pub fn new(profile: &str) -> Result<Self> {
        Ok(Self {
            service_name: "awzars".to_string(),
            profile: profile.to_string(),
        })
    }

    /// Store credentials in keychain as a single JSON entry.
    ///
    /// Writes only the consolidated entry. Legacy per-field entries (if any)
    /// are left in place — touching them here would trigger extra macOS
    /// Keychain authorization dialogs on every login. They are cleaned up
    /// only by `delete_credentials`.
    pub fn store_credentials(&self, credentials: &CredentialProcessOutput) -> Result<()> {
        // Hold the serialized JSON in a Zeroizing wrapper so the heap buffer
        // containing the secret access key + session token is wiped after we
        // hand it to the OS keychain backend.
        let json: Zeroizing<String> = Zeroizing::new(credentials.to_json().map_err(|e| {
            AwzarsError::Keyring(format!("Failed to serialize credentials: {}", e))
        })?);
        let entry = self.entry_for_field("credentials")?;
        entry
            .set_password(&json)
            .map_err(|e| AwzarsError::Keyring(format!("Failed to store credentials: {}", e)))?;

        tracing::info!(
            "Credentials stored in keychain for profile: {}",
            self.profile
        );
        Ok(())
    }

    /// Retrieve credentials from keychain.
    ///
    /// Reads the consolidated entry only. Legacy per-field entries from
    /// pre-consolidation versions are ignored — the next `store_credentials`
    /// after a re-login will write the new format. Reading the legacy layout
    /// here would cost up to 4 macOS Keychain dialogs per call.
    pub fn get_credentials(&self) -> Result<Option<Credentials>> {
        let entry = match self.entry_for_field("credentials") {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };
        // Wrap the keychain payload so the JSON-encoded secret is wiped from
        // heap after we deserialize.
        let json: Zeroizing<String> = match entry.get_password() {
            Ok(j) => Zeroizing::new(j),
            Err(_) => return Ok(None),
        };
        let output: CredentialProcessOutput = serde_json::from_str(&json).map_err(|e| {
            AwzarsError::Keyring(format!("Failed to deserialize credentials: {}", e))
        })?;
        Ok(Some(Credentials::from(output)))
    }

    /// Delete credentials from keychain
    pub fn delete_credentials(&self) -> Result<()> {
        let keys = [
            "credentials",
            "access_key_id",
            "secret_access_key",
            "session_token",
            "expiration",
            "cookie_key",
        ];

        for key in keys {
            if let Ok(entry) = self.entry_for_field(key) {
                let _ = entry.delete_credential();
            }
        }

        tracing::info!(
            "Credentials deleted from keychain for profile: {}",
            self.profile
        );
        Ok(())
    }

    /// Delete only the STS session credential entries, preserving `cookie_key`.
    ///
    /// Used when a profile is *edited* (role_arn changed, etc.) — the cached
    /// STS session is now stale, but the saved browser cookie store should
    /// survive so the user does not have to re-do an interactive
    /// `--remember-me` login.
    pub fn delete_session_credentials(&self) -> Result<()> {
        let keys = [
            "credentials",
            "access_key_id",
            "secret_access_key",
            "session_token",
            "expiration",
        ];

        for key in keys {
            if let Ok(entry) = self.entry_for_field(key) {
                let _ = entry.delete_credential();
            }
        }
        Ok(())
    }

    /// Create a keyring entry for a key
    pub fn entry_for_field(&self, key: &str) -> Result<Entry> {
        let username = format!("{}:{}", self.profile, key);
        Entry::new(&self.service_name, &username)
            .map_err(|e| AwzarsError::Keyring(format!("Failed to create keyring entry: {}", e)))
    }
}
