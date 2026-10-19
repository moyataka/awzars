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
    ///
    /// Returns `Ok(None)` only when no entry exists. Any other keychain error
    /// is returned so the caller does not treat an unreadable entry as empty.
    pub fn get_credentials(&self) -> Result<Option<Credentials>> {
        let entry = self.entry_for_field("credentials")?;
        credentials_from_entry(&entry)
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

/// Read a secret from a keychain entry.
///
/// Returns `Ok(None)` only when the entry does not exist
/// (`keyring::Error::NoEntry`). Every other keychain error — locked keychain,
/// denied access, platform failure, undecodable value — is returned as an
/// error, so callers never mistake an unreadable item for a missing one and
/// overwrite it. `item` is a human-readable name used in the error message.
///
/// The returned value is wrapped in `Zeroizing` so the secret is wiped from
/// heap memory when dropped.
pub fn read_secret(entry: &Entry, item: &str) -> Result<Option<Zeroizing<String>>> {
    match entry.get_password() {
        Ok(value) => Ok(Some(Zeroizing::new(value))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(AwzarsError::Keyring(format!(
            "cannot read {} from the OS keychain ({}); not regenerating it — \
             unlock the keychain or allow access, then retry",
            item, e
        ))),
    }
}

/// Deserialize the consolidated credentials JSON held in `entry`.
fn credentials_from_entry(entry: &Entry) -> Result<Option<Credentials>> {
    let json = match read_secret(entry, "the stored AWS credentials")? {
        Some(j) => j,
        None => return Ok(None),
    };
    let output: CredentialProcessOutput = serde_json::from_str(&json)
        .map_err(|e| AwzarsError::Keyring(format!("Failed to deserialize credentials: {}", e)))?;
    Ok(Some(Credentials::from(output)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyring::mock::MockCredential;

    fn mock_entry() -> Entry {
        Entry::new_with_credential(Box::new(MockCredential::default()))
    }

    fn mock_of(entry: &Entry) -> &MockCredential {
        entry
            .get_credential()
            .downcast_ref::<MockCredential>()
            .expect("mock credential")
    }

    fn read_errors() -> Vec<keyring::Error> {
        vec![
            keyring::Error::NoStorageAccess("keychain locked".into()),
            keyring::Error::PlatformFailure("platform failure".into()),
            keyring::Error::BadEncoding(vec![0xff, 0xfe]),
        ]
    }

    #[test]
    fn read_secret_missing_entry_is_none() {
        let entry = mock_entry();
        assert!(read_secret(&entry, "item").unwrap().is_none());
    }

    #[test]
    fn read_secret_returns_stored_value() {
        let entry = mock_entry();
        entry.set_password("value").unwrap();
        let v = read_secret(&entry, "item").unwrap().expect("value");
        assert_eq!(v.as_str(), "value");
    }

    #[test]
    fn read_secret_propagates_other_errors() {
        for err in read_errors() {
            let entry = mock_entry();
            mock_of(&entry).set_error(err);
            let res = read_secret(&entry, "the test item");
            match res {
                Err(AwzarsError::Keyring(msg)) => {
                    assert!(msg.contains("the test item"), "message: {}", msg)
                }
                other => panic!("expected Keyring error, got {:?}", other.map(|_| ())),
            }
        }
    }

    #[test]
    fn credentials_missing_entry_is_none() {
        let entry = mock_entry();
        assert!(credentials_from_entry(&entry).unwrap().is_none());
    }

    #[test]
    fn credentials_read_error_is_reported() {
        for err in read_errors() {
            let entry = mock_entry();
            mock_of(&entry).set_error(err);
            assert!(credentials_from_entry(&entry).is_err());
        }
    }
}
