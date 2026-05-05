//! AWS STS AssumeRoleWithSAML integration

use crate::credential_process::protocol::CredentialProcessOutput;
use crate::error::{AwzarsError, Result};
use aws_config::BehaviorVersion;

/// Filter an AWS error code string down to a printable, terminal-safe subset
/// before surfacing it to the user. The SDK echoes whatever the service
/// returned, which on TLS-handshake / parse-error paths has historically been
/// arbitrary bytes; an unfiltered code could carry ANSI escape sequences and
/// rewrite the user's terminal. Restrict to ASCII alphanumerics, `_`, `-`,
/// and `.`, cap the length, and substitute a placeholder if the cleaned
/// value is empty.
fn sanitize_aws_error_code(code: &str) -> String {
    let cleaned: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "Unknown".to_string()
    } else {
        cleaned
    }
}

/// Exchange a SAML assertion for AWS credentials
pub async fn exchange_saml_for_credentials(
    saml_assertion: &str,
    role_arn: &str,
    principal_arn: &str,
    session_duration: i32,
) -> Result<CredentialProcessOutput> {
    // Load AWS config (uses environment variables and ~/.aws/config)
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let sts_client = aws_sdk_sts::Client::new(&config);

    // Call AssumeRoleWithSAML
    // The saml_assertion should be base64-encoded
    let response = sts_client
        .assume_role_with_saml()
        .role_arn(role_arn)
        .principal_arn(principal_arn)
        .saml_assertion(saml_assertion)
        .duration_seconds(session_duration)
        .send()
        .await
        .map_err(|e| {
            // Detailed AWS error metadata (request IDs, account numbers,
            // service messages) is logged at debug level only; the user-facing
            // error message contains just the AWS error code.
            use aws_sdk_sts::error::ProvideErrorMetadata;
            let code = sanitize_aws_error_code(e.code().unwrap_or("Unknown"));
            tracing::debug!("AssumeRoleWithSAML detailed error: {:?}", e);
            AwzarsError::AwsSts(format!("AssumeRoleWithSAML failed: {}", code))
        })?;

    // Extract credentials
    let credentials = response
        .credentials
        .ok_or_else(|| AwzarsError::AwsSts("No credentials in response".to_string()))?;

    // Extract fields - these are already Strings
    let access_key_id = credentials.access_key_id;
    let secret_access_key = credentials.secret_access_key;
    let session_token = credentials.session_token;

    // Handle expiration - convert AWS SDK DateTime to RFC3339 string
    let expiration = Some(credentials.expiration.to_string());

    Ok(CredentialProcessOutput {
        version: 1,
        access_key_id,
        secret_access_key,
        session_token: Some(session_token),
        expiration,
    })
}

#[cfg(test)]
mod tests {
    use super::sanitize_aws_error_code;

    #[test]
    fn passes_typical_codes_unchanged() {
        for code in [
            "InvalidIdentityToken",
            "ExpiredTokenException",
            "AccessDenied",
            "Unknown",
            "RegionDisabledException",
        ] {
            assert_eq!(sanitize_aws_error_code(code), code);
        }
    }

    #[test]
    fn strips_ansi_escape_sequences() {
        let evil = "\x1b[31mEvil\x1b[0m";
        let cleaned = sanitize_aws_error_code(evil);
        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('['));
    }

    #[test]
    fn strips_control_and_non_ascii() {
        assert_eq!(
            sanitize_aws_error_code("foo\nbar\rbaz\tqux"),
            "foobarbazqux"
        );
        assert_eq!(sanitize_aws_error_code("café"), "caf");
    }

    #[test]
    fn empty_or_all_stripped_becomes_unknown() {
        assert_eq!(sanitize_aws_error_code(""), "Unknown");
        assert_eq!(sanitize_aws_error_code("\x1b[0m"), "0m"); // square brackets stripped
        assert_eq!(sanitize_aws_error_code("!!!"), "Unknown");
    }

    #[test]
    fn caps_length_to_64_chars() {
        let huge = "A".repeat(1000);
        assert_eq!(sanitize_aws_error_code(&huge).len(), 64);
    }
}
