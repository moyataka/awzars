//! AWS credential_process protocol implementation
//!
//! The credential_process protocol allows external tools to provide credentials
//! to the AWS CLI and SDKs. The output must be a JSON object written to stdout.
//!
//! Reference: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Result;

// SECURITY: `CredentialProcessOutput` and `Credentials` hold AWS secrets in
// plain `String` fields because the credential_process protocol mandates
// `Serialize`/`Deserialize` to/from JSON, and `zeroize::Zeroizing<String>` is
// not (de)serializable. Instead, both types implement `Drop` so that secret
// memory is wiped when the value is dropped.
//
// Caveats accepted by this design:
//   * `clone()` and serde deserialization create transient copies whose
//     buffers are not directly tracked. They will still be wiped when the
//     clone is dropped, but intermediate stack/parser buffers may persist.
//   * `String` reallocation (e.g. `push_str` causing growth) leaves the
//     previous heap allocation un-zeroed. We do not mutate these fields
//     after construction, so this is not exercised in practice.

/// Output format for credential_process protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProcessOutput {
    /// Version (must be 1)
    #[serde(rename = "Version")]
    pub version: i32,

    /// AWS Access Key ID
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,

    /// AWS Secret Access Key
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,

    /// Session Token (for temporary credentials)
    #[serde(rename = "SessionToken", skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,

    /// Expiration timestamp (ISO 8601 format)
    #[serde(rename = "Expiration", skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
}

impl CredentialProcessOutput {
    /// Create a new credential output
    pub fn new(access_key_id: impl Into<String>, secret_access_key: impl Into<String>) -> Self {
        Self {
            version: 1,
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            session_token: None,
            expiration: None,
        }
    }

    /// Add session token
    pub fn with_session_token(mut self, token: impl Into<String>) -> Self {
        self.session_token = Some(token.into());
        self
    }

    /// Add expiration
    pub fn with_expiration(mut self, expiration: impl Into<String>) -> Self {
        self.expiration = Some(expiration.into());
        self
    }

    /// Check if credentials are still valid (with 5 minute buffer)
    pub fn is_valid(&self) -> bool {
        if let Some(ref expiration) = self.expiration {
            if let Ok(exp_time) = DateTime::parse_from_rfc3339(expiration) {
                let now = Utc::now();
                let buffer = chrono::Duration::minutes(5);
                return now + buffer < exp_time.with_timezone(&Utc);
            }
        }
        false
    }

    /// Convert to JSON string for credential_process output
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// Convert to pretty JSON string for display
    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Get access key ID
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// Get secret access key
    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }

    /// Get session token
    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }

    /// Get expiration
    pub fn expiration(&self) -> Option<&str> {
        self.expiration.as_deref()
    }
}

impl Drop for CredentialProcessOutput {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        if let Some(token) = self.session_token.as_mut() {
            token.zeroize();
        }
    }
}

/// Serialize credentials and write to stdout as a single JSON line, then a
/// newline. The intermediate `String` produced by `serde_json` is held in a
/// `Zeroizing<String>` so its heap buffer is wiped on drop instead of leaking
/// the secret to the next allocator user (or to swap / a core dump).
///
/// Use this instead of `println!("{}", serde_json::to_string(&creds)?)` for
/// any path that emits live (unmasked) credentials.
pub fn write_credentials_json(creds: &CredentialProcessOutput) -> Result<()> {
    use std::io::Write;
    let json: Zeroizing<String> = Zeroizing::new(serde_json::to_string(creds)?);
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(json.as_bytes())?;
    handle.write_all(b"\n")?;
    handle.flush()?;
    Ok(())
}

/// Pretty-printed variant for human-facing JSON output (`-o json`). Same
/// zeroization guarantee on the intermediate buffer.
pub fn write_credentials_json_pretty(creds: &CredentialProcessOutput) -> Result<()> {
    use std::io::Write;
    let json: Zeroizing<String> = Zeroizing::new(serde_json::to_string_pretty(creds)?);
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(json.as_bytes())?;
    handle.write_all(b"\n")?;
    handle.flush()?;
    Ok(())
}

/// AWS credentials for internal use
#[derive(Debug, Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub expiration: Option<DateTime<Utc>>,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        if let Some(token) = self.session_token.as_mut() {
            token.zeroize();
        }
    }
}

impl Credentials {
    /// Check if credentials are still valid (with 5 minute buffer)
    pub fn is_valid(&self) -> bool {
        if let Some(exp_time) = self.expiration {
            let now = Utc::now();
            let buffer = chrono::Duration::minutes(5);
            return now + buffer < exp_time;
        }
        false
    }
}

impl From<Credentials> for CredentialProcessOutput {
    fn from(mut creds: Credentials) -> Self {
        // `Credentials` implements `Drop` to zeroize, so we cannot move
        // fields out of it. Take ownership of the strings via mem::take,
        // leaving empty strings behind for the destructor to wipe harmlessly.
        Self {
            version: 1,
            access_key_id: std::mem::take(&mut creds.access_key_id),
            secret_access_key: std::mem::take(&mut creds.secret_access_key),
            session_token: creds.session_token.take(),
            expiration: creds.expiration.map(|t| t.to_rfc3339()),
        }
    }
}

impl From<&Credentials> for CredentialProcessOutput {
    fn from(creds: &Credentials) -> Self {
        Self {
            version: 1,
            access_key_id: creds.access_key_id.clone(),
            secret_access_key: creds.secret_access_key.clone(),
            session_token: creds.session_token.clone(),
            expiration: creds.expiration.map(|t| t.to_rfc3339()),
        }
    }
}

impl From<CredentialProcessOutput> for Credentials {
    fn from(mut output: CredentialProcessOutput) -> Self {
        // Same `Drop` constraint as From<Credentials>: take fields out by ref.
        Self {
            access_key_id: std::mem::take(&mut output.access_key_id),
            secret_access_key: std::mem::take(&mut output.secret_access_key),
            session_token: output.session_token.take(),
            expiration: output.expiration.as_deref().and_then(|s| {
                DateTime::parse_from_rfc3339(s)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_output_json() {
        let output = CredentialProcessOutput::new("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG")
            .with_session_token("AQoDYXdzEJr...<truncated>")
            .with_expiration("2024-01-01T00:00:00Z");

        let json = output.to_json().unwrap();
        assert!(json.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(json.contains("AccessKeyId"));
        assert!(json.contains("SessionToken"));
    }

    #[test]
    fn test_credential_output_minimal() {
        let output = CredentialProcessOutput::new("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG");

        let json = output.to_json().unwrap();
        assert!(json.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!json.contains("SessionToken"));
        assert!(!json.contains("Expiration"));
    }

    #[test]
    fn test_is_valid() {
        let future = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let output =
            CredentialProcessOutput::new("AKIAIOSFODNN7EXAMPLE", "secret").with_expiration(future);
        assert!(output.is_valid());

        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let output =
            CredentialProcessOutput::new("AKIAIOSFODNN7EXAMPLE", "secret").with_expiration(past);
        assert!(!output.is_valid());
    }
}
