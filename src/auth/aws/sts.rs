//! AWS STS AssumeRoleWithSAML integration

use crate::credential_process::protocol::CredentialProcessOutput;
use crate::error::{AwzarsError, Result};
use aws_config::meta::region::RegionProviderChain;
use aws_config::BehaviorVersion;
use aws_sdk_sts::config::http::HttpResponse;
use aws_sdk_sts::config::Region;
use aws_sdk_sts::error::SdkError;
use aws_sdk_sts::operation::assume_role_with_saml::AssumeRoleWithSAMLError;

/// Longest error detail shown for a request that got no answer from STS.
const ERROR_DETAIL_LIMIT: usize = 300;

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

/// User-facing reason for a failed `AssumeRoleWithSAML` call.
///
/// A service error shows only its sanitized code: the service message can
/// name accounts or roles. A request that got no answer (DNS, TLS, proxy,
/// timeout, invalid input) shows its cause chain, built from `Display` only,
/// because the `Debug` form (and so `DisplayErrorContext`) includes the raw
/// response. A response that could not be read gets a fixed text: its body
/// may hold credentials.
fn sts_error_message(error: &SdkError<AssumeRoleWithSAMLError, HttpResponse>) -> String {
    use aws_sdk_sts::error::ProvideErrorMetadata;
    match error {
        SdkError::ServiceError(_) => sanitize_aws_error_code(error.code().unwrap_or("Unknown")),
        SdkError::ResponseError(_) => "the STS response could not be read".to_string(),
        SdkError::ConstructionFailure(_)
        | SdkError::TimeoutError(_)
        | SdkError::DispatchFailure(_) => sanitize_error_detail(&error_chain(error)),
        _ => sanitize_error_detail(&error.to_string()),
    }
}

/// `error` and its sources, joined with `": "`, using `Display` only.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// Make an error detail safe to print: printable ASCII only (no terminal
/// escapes), URL userinfo (`://user:pass@`) removed, and at most
/// `ERROR_DETAIL_LIMIT` characters.
fn sanitize_error_detail(detail: &str) -> String {
    let printable: String = detail.chars().filter(|c| matches!(c, ' '..='~')).collect();
    let mut cleaned = String::with_capacity(printable.len());
    let mut rest = printable.as_str();
    while let Some(index) = rest.find("://") {
        let (before, after) = rest.split_at(index + 3);
        cleaned.push_str(before);
        // Characters that cannot appear unencoded in userinfo end the authority.
        let authority_end = after
            .find(|c: char| c.is_whitespace() || "/?#\"'<>`".contains(c))
            .unwrap_or(after.len());
        rest = match after[..authority_end].rfind('@') {
            Some(at) => &after[at + 1..],
            None => after,
        };
    }
    cleaned.push_str(rest);
    if cleaned.len() > ERROR_DETAIL_LIMIT {
        cleaned.truncate(ERROR_DETAIL_LIMIT);
        cleaned.push_str("...");
    }
    cleaned
}

/// Normalize a user-supplied region: trim surrounding whitespace and treat a
/// blank value as "unset" so a hand-edited `region = ""` in
/// the configured `config.toml` never becomes an empty, invalid region.
fn sanitize_region(region: Option<String>) -> Option<Region> {
    region
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .map(Region::new)
}

/// Region provider for the STS endpoint, in precedence order:
///
/// 1. the awzars profile's `region` (so a region set only in
///    the configured `config.toml` is honoured — it was previously ignored),
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
            // error message is limited by `sts_error_message`.
            tracing::debug!("AssumeRoleWithSAML detailed error: {:?}", e);
            AwzarsError::AwsSts(format!(
                "AssumeRoleWithSAML failed: {}",
                sts_error_message(&e)
            ))
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

    mod error_message {
        use super::super::{sanitize_error_detail, sts_error_message};
        use aws_sdk_sts::config::http::HttpResponse;
        use aws_sdk_sts::error::{ConnectorError, ErrorMetadata, SdkError};
        use aws_sdk_sts::operation::assume_role_with_saml::AssumeRoleWithSAMLError;

        type StsError = SdkError<AssumeRoleWithSAMLError, HttpResponse>;

        fn dispatch_failure(detail: &str) -> StsError {
            SdkError::dispatch_failure(ConnectorError::io(Box::new(std::io::Error::other(
                detail.to_string(),
            ))))
        }

        #[test]
        fn dispatch_failure_shows_its_cause() {
            let message = sts_error_message(&dispatch_failure(
                "dns error: failed to lookup address information",
            ));
            assert!(!message.contains("Unknown"), "{message}");
            assert!(message.contains("dispatch failure"), "{message}");
            assert!(
                message.contains("dns error: failed to lookup address information"),
                "{message}"
            );
        }

        #[test]
        fn timeout_shows_its_cause() {
            let error: StsError =
                SdkError::timeout_error(std::io::Error::other("operation timed out"));
            let message = sts_error_message(&error);
            assert!(message.contains("operation timed out"), "{message}");
        }

        #[test]
        fn cause_is_printable_capped_and_without_url_userinfo() {
            let message = sts_error_message(&dispatch_failure(
                "proxy http://someone:hunter2@proxy.example:8080/ refused \x1b[31m",
            ));
            assert!(!message.contains("someone"), "{message}");
            assert!(!message.contains("hunter2"), "{message}");
            assert!(message.contains("http://proxy.example:8080/"), "{message}");
            assert!(!message.contains('\x1b'), "{message}");

            let message = sts_error_message(&dispatch_failure(&"x".repeat(1000)));
            assert!(message.len() <= 303, "{}", message.len());
        }

        #[test]
        fn unreadable_response_hides_its_body() {
            let body = "<Credentials><SessionToken>FAKE-SESSION-TOKEN</SessionToken>";
            let error: StsError = SdkError::response_error(
                std::io::Error::other(format!("unexpected element in {body}")),
                HttpResponse::new(200u16.try_into().unwrap(), body.into()),
            );
            let message = sts_error_message(&error);
            assert!(!message.contains("FAKE-SESSION-TOKEN"), "{message}");
            assert!(!message.contains("SessionToken"), "{message}");
            assert!(!message.contains("Unknown"), "{message}");
        }

        #[test]
        fn unreadable_response_has_a_fixed_message() {
            let error: StsError = SdkError::response_error(
                std::io::Error::other("unexpected element"),
                HttpResponse::new(200u16.try_into().unwrap(), "".into()),
            );
            assert_eq!(
                sts_error_message(&error),
                "the STS response could not be read"
            );
        }

        #[test]
        fn unhandled_service_error_hides_the_body() {
            // A 200 that fails to parse surfaces as ServiceError(Unhandled).
            let error: StsError = SdkError::service_error(
                AssumeRoleWithSAMLError::unhandled(std::io::Error::other("invalid XML")),
                HttpResponse::new(
                    200u16.try_into().unwrap(),
                    "<SecretAccessKey>MARKER</SecretAccessKey>".into(),
                ),
            );
            assert_eq!(sts_error_message(&error), "Unknown");
        }

        #[test]
        fn userinfo_is_removed_only_inside_the_url_authority() {
            for (detail, expected) in [
                ("http://u:p@h/ then a@b", "http://h/ then a@b"),
                ("http://h then a@b", "http://h then a@b"),
                ("http://u:p@h then a@b", "http://h then a@b"),
                ("http://h?q then a@b", "http://h?q then a@b"),
            ] {
                assert_eq!(sanitize_error_detail(detail), expected, "{detail}");
            }
        }

        #[test]
        fn detail_is_cut_only_beyond_the_limit() {
            let exact = "x".repeat(300);
            assert_eq!(sanitize_error_detail(&exact), exact);
            let over = "x".repeat(301);
            assert_eq!(sanitize_error_detail(&over), format!("{exact}..."));
        }

        #[test]
        fn service_error_shows_only_its_code() {
            let error: StsError = SdkError::service_error(
                AssumeRoleWithSAMLError::generic(
                    ErrorMetadata::builder()
                        .code("AccessDenied")
                        .message("Not authorized for role example-role")
                        .build(),
                ),
                HttpResponse::new(403u16.try_into().unwrap(), "".into()),
            );
            let message = sts_error_message(&error);
            assert_eq!(message, "AccessDenied");
        }
    }
}
