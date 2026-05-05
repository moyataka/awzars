//! Pure Azure AD ↔ AWS SAML protocol helpers.
//!
//! These functions are about building and extracting SAML/AWS-redirect
//! data — they have no dependency on the browser stack and can be
//! unit-tested without launching chromiumoxide.

use crate::error::{AwzarsError, Result};

/// Build the Azure AD login URL that initiates the SAML AuthnRequest.
///
/// `tenant_id` is validated as a UUID before being interpolated into the
/// URL to prevent path injection or arbitrary host redirection.
pub fn build_azure_login_url(tenant_id: &str, app_id_uri: &str) -> Result<String> {
    uuid::Uuid::parse_str(tenant_id)
        .map_err(|_| AwzarsError::Browser("tenant_id must be a valid UUID".to_string()))?;

    Ok(format!(
        "https://login.microsoftonline.com/{}/saml2?SAMLRequest={}",
        tenant_id,
        urlencoding::encode(&build_saml_request(app_id_uri)?)
    ))
}

/// Build a SAML AuthnRequest (DEFLATE compressed + base64 encoded).
///
/// `app_id_uri` is XML-escaped before interpolation so a malicious profile
/// value cannot inject SAML attributes into the request.
pub fn build_saml_request(app_id_uri: &str) -> Result<String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    let id = format!("id{}", uuid::Uuid::new_v4().simple());
    let issue_instant = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let escaped_uri = xml_escape(app_id_uri);

    let authn_request = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{}" Version="2.0" IssueInstant="{}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://signin.aws.amazon.com/saml"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{}</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/></samlp:AuthnRequest>"#,
        id, issue_instant, escaped_uri
    );

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(authn_request.as_bytes())
        .map_err(|e| AwzarsError::Browser(format!("Failed to compress SAML request: {}", e)))?;
    let compressed = encoder
        .finish()
        .map_err(|e| AwzarsError::Browser(format!("Failed to finish compression: {}", e)))?;

    Ok(BASE64.encode(&compressed))
}

/// Extract the SAMLResponse from an AWS sign-in HTML form.
///
/// Returns `None` if the form field is missing — caller should treat that
/// as "page is not the AWS landing page yet" and keep waiting.
///
/// Accepts attributes in either order (`name=… value=…` or `value=… name=…`)
/// and either single- or double-quoted attribute values, so a small change
/// in AWS's emitted HTML does not silently break the fallback path. (The
/// primary path is a CSS selector on the form input element; this regex is
/// only used when the selector misses.)
pub fn extract_saml_from_html(html: &str) -> Option<String> {
    static RE_NAME_FIRST: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r#"(?is)name\s*=\s*["']SAMLResponse["'][^>]*?value\s*=\s*["']([^"']+)["']"#,
        )
        .expect("SAMLResponse regex must compile — programmer error")
    });
    static RE_VALUE_FIRST: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r#"(?is)value\s*=\s*["']([^"']+)["'][^>]*?name\s*=\s*["']SAMLResponse["']"#,
        )
        .expect("SAMLResponse regex must compile — programmer error")
    });

    if let Some(caps) = RE_NAME_FIRST.captures(html) {
        return Some(caps[1].to_string());
    }
    if let Some(caps) = RE_VALUE_FIRST.captures(html) {
        return Some(caps[1].to_string());
    }
    None
}

/// Whether a URL is the AWS sign-in / console redirect we expect after a
/// successful Azure AD authentication.
///
/// Uses strict host comparison (with subdomain suffix on a dot boundary)
/// so a look-alike host like `signin.aws.amazon.com.attacker.com` is
/// rejected.
pub fn is_aws_redirect_url(url_str: &str) -> bool {
    let Ok(u) = url::Url::parse(url_str) else {
        return false;
    };
    let Some(host) = u.host_str() else {
        return false;
    };
    host == "signin.aws.amazon.com"
        || host == "console.aws.amazon.com"
        || host.ends_with(".signin.aws.amazon.com")
        || host.ends_with(".console.aws.amazon.com")
}

/// XML-escape a string for safe interpolation into XML templates.
pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TENANT: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn build_azure_login_url_accepts_uuid() {
        let url = build_azure_login_url(VALID_TENANT, "https://signin.aws.amazon.com/saml")
            .expect("valid uuid should succeed");
        assert!(url.starts_with(&format!(
            "https://login.microsoftonline.com/{}/saml2?SAMLRequest=",
            VALID_TENANT
        )));
    }

    #[test]
    fn build_azure_login_url_rejects_non_uuid() {
        let err =
            build_azure_login_url("../evil", "https://signin.aws.amazon.com/saml").unwrap_err();
        assert!(matches!(err, AwzarsError::Browser(ref m) if m.contains("UUID")));
    }

    #[test]
    fn is_aws_redirect_url_accepts_canonical_hosts() {
        assert!(is_aws_redirect_url("https://signin.aws.amazon.com/saml"));
        assert!(is_aws_redirect_url(
            "https://console.aws.amazon.com/console/home"
        ));
        assert!(is_aws_redirect_url(
            "https://us-east-1.signin.aws.amazon.com/saml"
        ));
    }

    #[test]
    fn is_aws_redirect_url_rejects_lookalike() {
        assert!(!is_aws_redirect_url(
            "https://signin.aws.amazon.com.attacker.com/"
        ));
        assert!(!is_aws_redirect_url(
            "https://attacker.com/?signin.aws.amazon.com"
        ));
        assert!(!is_aws_redirect_url("not a url at all"));
    }

    #[test]
    fn xml_escape_handles_all_metacharacters() {
        assert_eq!(xml_escape("hello"), "hello");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape("a&b"), "a&amp;b");
        assert_eq!(xml_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(xml_escape("it's"), "it&apos;s");
    }

    #[test]
    fn extract_saml_from_html_finds_response_in_form() {
        let html = r#"<html><body><form action="/saml">
            <input name="SAMLResponse" value="PHNhbWxwOlJlc3BvbnNlPg==" />
            </form></body></html>"#;
        assert_eq!(
            extract_saml_from_html(html).as_deref(),
            Some("PHNhbWxwOlJlc3BvbnNlPg==")
        );
    }

    #[test]
    fn extract_saml_from_html_returns_none_when_missing() {
        assert_eq!(extract_saml_from_html("<html></html>"), None);
    }

    #[test]
    fn extract_saml_from_html_handles_value_first_attribute_order() {
        let html = r#"<form><input value="PHNhbWxwOlJlc3BvbnNlPg==" name="SAMLResponse" /></form>"#;
        assert_eq!(
            extract_saml_from_html(html).as_deref(),
            Some("PHNhbWxwOlJlc3BvbnNlPg==")
        );
    }

    #[test]
    fn extract_saml_from_html_handles_single_quotes() {
        let html = r#"<form><input name='SAMLResponse' value='PHNhbWxwOlJlc3BvbnNlPg==' /></form>"#;
        assert_eq!(
            extract_saml_from_html(html).as_deref(),
            Some("PHNhbWxwOlJlc3BvbnNlPg==")
        );
    }

    #[test]
    fn extract_saml_from_html_handles_whitespace_around_equals() {
        let html = r#"<input name = "SAMLResponse"  value = "PHNhbWxwOlJlc3BvbnNlPg==" />"#;
        assert_eq!(
            extract_saml_from_html(html).as_deref(),
            Some("PHNhbWxwOlJlc3BvbnNlPg==")
        );
    }
}
