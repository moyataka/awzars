//! AWS STS AssumeRoleWithSAML integration

use crate::credential_process::protocol::CredentialProcessOutput;
use crate::error::{AwzarsError, Result};
use aws_config::meta::region::RegionProviderChain;
use aws_config::BehaviorVersion;
use aws_sdk_sts::config::Region;

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

/// Normalize a user-supplied region: trim surrounding whitespace and treat a
/// blank value as "unset" so a hand-edited `region = ""` in
/// `~/.awzars/config.toml` never becomes an empty, invalid region.
fn sanitize_region(region: Option<String>) -> Option<Region> {
    region
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .map(Region::new)
}

/// Region provider for the STS endpoint, in precedence order:
///
/// 1. the awzars profile's `region` (so a region set only in
///    `~/.awzars/config.toml` is honoured — it was previously ignored),
/// 2. the standard AWS default chain (`AWS_REGION` / `AWS_DEFAULT_REGION`,
///    `~/.aws/config`, IMDS),
/// 3. a `us-east-1` fallback so `AssumeRoleWithSAML` never fails purely for
///    lack of a configured region anywhere.
fn build_region_provider(profile_region: Option<String>) -> RegionProviderChain {
    RegionProviderChain::first_try(sanitize_region(profile_region))
        .or_default_provider()
        .or_else(Region::new("us-east-1"))
}

/// Exchange a SAML assertion for AWS credentials
pub async fn exchange_saml_for_credentials(
    saml_assertion: &str,
    role_arn: &str,
    principal_arn: &str,
    session_duration: i32,
    profile_region: Option<String>,
) -> Result<CredentialProcessOutput> {
    // Region honours the awzars profile first, then the AWS default chain,
    // then a us-east-1 fallback (see `build_region_provider`). Previously this
    // used `load_defaults`, which ignored the awzars profile region entirely.
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(build_region_provider(profile_region))
        .load()
        .await;
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

    #[test]
    fn sanitize_region_trims_and_drops_blank() {
        use super::sanitize_region;
        use aws_sdk_sts::config::Region;
        assert_eq!(
            sanitize_region(Some("eu-west-1".into())),
            Some(Region::new("eu-west-1"))
        );
        // Surrounding whitespace from a hand-edited config is trimmed.
        assert_eq!(
            sanitize_region(Some("  us-east-2 ".into())),
            Some(Region::new("us-east-2"))
        );
        // Blank / whitespace-only values are treated as unset, not an empty
        // (invalid) region.
        assert_eq!(sanitize_region(Some(String::new())), None);
        assert_eq!(sanitize_region(Some("   ".into())), None);
        assert_eq!(sanitize_region(None), None);
    }
}
