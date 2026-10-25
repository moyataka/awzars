//! OS keychain integration using keyring-rs

use crate::credential_process::protocol::CredentialProcessOutput;
use crate::credential_process::protocol::Credentials;
use crate::error::{AwzarsError, Result};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The keychain JSON: the credential_process fields plus the fingerprint of
/// the identity they were issued for (see
/// `auth::credentials::credential_identity`). Kept apart from
/// `CredentialProcessOutput` so `credential-process` output stays
/// protocol-clean.
#[derive(Serialize)]
struct StoredCredentials<'a> {
    #[serde(flatten)]
    credentials: &'a CredentialProcessOutput,
    #[serde(rename = "AwzarsIdentity")]
    identity: &'a str,
}

/// The identity fingerprint of a stored entry; `None` for entries written
/// before the fingerprint existed.
#[derive(Deserialize)]
struct StoredIdentity {
    #[serde(rename = "AwzarsIdentity", default)]
    identity: Option<String>,
}

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
    ///
    /// `identity` is the fingerprint of the identity the credentials were
    /// issued for; `get_credentials` returns them only for that identity.
    pub fn store_credentials(
        &self,
        credentials: &CredentialProcessOutput,
        identity: &str,
    ) -> Result<()> {
        let entry = self.entry_for_field("credentials")?;
        credentials_to_entry(&entry, credentials, identity)?;

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
    /// Returns `Ok(None)` when no entry exists, or when the entry was issued
    /// for another identity than `identity` or carries no identity (written
    /// by an earlier version). Any other keychain error is returned so the
    /// caller does not treat an unreadable entry as empty.
    pub fn get_credentials(&self, identity: &str) -> Result<Option<Credentials>> {
        let entry = self.entry_for_field("credentials")?;
        credentials_from_entry(&entry, identity)
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

/// Serialize `credentials` tagged with `identity` into `entry`.
fn credentials_to_entry(
    entry: &Entry,
    credentials: &CredentialProcessOutput,
    identity: &str,
) -> Result<()> {
    // Hold the serialized JSON in a Zeroizing wrapper so the heap buffer
    // containing the secret access key + session token is wiped after we
    // hand it to the OS keychain backend.
    let stored = StoredCredentials {
        credentials,
        identity,
    };
    let json: Zeroizing<String> =
        Zeroizing::new(serde_json::to_string(&stored).map_err(|e| {
            AwzarsError::Keyring(format!("Failed to serialize credentials: {}", e))
        })?);
    entry
        .set_password(&json)
        .map_err(|e| AwzarsError::Keyring(format!("Failed to store credentials: {}", e)))
}

/// Deserialize the consolidated credentials JSON held in `entry`, if it was
/// issued for `identity`.
fn credentials_from_entry(entry: &Entry, identity: &str) -> Result<Option<Credentials>> {
    let json = match read_secret(entry, "the stored AWS credentials")? {
        Some(j) => j,
        None => return Ok(None),
    };
    let stored: StoredIdentity = serde_json::from_str(&json)
        .map_err(|e| AwzarsError::Keyring(format!("Failed to deserialize credentials: {}", e)))?;
    if stored.identity.as_deref() != Some(identity) {
        tracing::info!(
            "Stored credentials were issued for another identity, or by an earlier \
             version; re-authenticating"
        );
        return Ok(None);
    }
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
        assert!(credentials_from_entry(&entry, "identity")
            .unwrap()
            .is_none());
    }

    #[test]
    fn credentials_read_error_is_reported() {
        for err in read_errors() {
            let entry = mock_entry();
            mock_of(&entry).set_error(err);
            assert!(credentials_from_entry(&entry, "identity").is_err());
        }
    }

    fn credentials() -> CredentialProcessOutput {
        CredentialProcessOutput::new("stored-key", "test-secret")
            .with_session_token("test-token")
            .with_expiration("2099-01-01T00:00:00Z")
    }

    #[test]
    fn credentials_are_returned_only_for_the_identity_they_were_issued_for() {
        let entry = mock_entry();
        credentials_to_entry(&entry, &credentials(), "identity-a").unwrap();

        assert!(credentials_from_entry(&entry, "identity-b")
            .unwrap()
            .is_none());
        let stored = credentials_from_entry(&entry, "identity-a")
            .unwrap()
            .expect("credentials for the identity they were issued for");
        assert_eq!(stored.access_key_id, "stored-key");
    }

    #[test]
    fn entry_without_an_identity_is_a_miss() {
        // The layout written before identities were recorded.
        let entry = mock_entry();
        entry
            .set_password(&credentials().to_json().unwrap())
            .unwrap();
        assert!(credentials_from_entry(&entry, "identity-a")
            .unwrap()
            .is_none());
    }

    #[test]
    fn stored_entry_keeps_the_credential_process_fields() {
        let entry = mock_entry();
        credentials_to_entry(&entry, &credentials(), "identity-a").unwrap();
        let json = entry.get_password().unwrap();
        let output: CredentialProcessOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(output.access_key_id, "stored-key");
        assert!(json.contains("\"AwzarsIdentity\":\"identity-a\""), "{json}");
    }
}
