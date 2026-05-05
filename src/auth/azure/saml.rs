//! SAML assertion parsing and validation
//
// SECURITY: This module does NOT verify XML Digital Signatures (XML DSIG) on
// the SAML assertion. There is currently no mature, well-audited Rust crate
// that implements XML DSIG verification (the `xmlsec` C bindings are an option
// for future work).
//
// Integrity of the assertion is therefore relied upon at two layers:
//   1. Transport: the assertion is fetched over TLS from
//      `login.microsoftonline.com` (rustls, no native-tls), so a network
//      attacker cannot tamper with it in flight.
//   2. Server-side: AWS STS verifies the XML signature against the registered
//      SAML provider during `AssumeRoleWithSAML`, so a tampered assertion
//      cannot be exchanged for credentials.
//
// In addition, this module performs the following client-side semantic
// validations on every parse:
//   * Issuer matches `https://sts.windows.net/{tenant_id}/`
//   * `<AudienceRestriction>/<Audience>` contains the expected app ID URI
//   * Current time is within `[NotBefore, NotOnOrAfter)` (30s clock skew)

use crate::error::{AwzarsError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use roxmltree::Node;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Allowed clock skew when validating SAML time conditions.
const CLOCK_SKEW_SECONDS: i64 = 30;

/// Maximum allowed decoded size for a SAML assertion (256 KB).
///
/// Prevents memory exhaustion from maliciously oversized assertions.
/// Real Azure AD SAML assertions are typically 5–20 KB.
const MAX_SAML_SIZE: usize = 256 * 1024;

/// SAML 2.0 assertion namespace. All assertion-scoped elements
/// (`Assertion`, `Issuer`, `Conditions`, `AudienceRestriction`, `Audience`,
/// `AttributeStatement`, `Attribute`, `AttributeValue`,
/// `SubjectConfirmationData`) must carry this namespace. Matching on the
/// namespace as well as the local name prevents a crafted assertion that
/// reuses these local names under an attacker-chosen namespace from
/// influencing parse results.
const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// Whether a node is a SAML-assertion-namespaced element with the given local name.
fn is_saml_tag(node: &Node, local: &str) -> bool {
    let name = node.tag_name();
    name.name() == local && name.namespace() == Some(SAML_ASSERTION_NS)
}

/// Represents a parsed and validated SAML assertion
#[derive(Debug, Clone)]
pub struct SamlAssertion {
    /// Raw base64-encoded assertion (zeroized on drop)
    raw_xml: Zeroizing<String>,

    /// Decoded XML body (zeroized on drop)
    #[allow(dead_code)]
    decoded: Zeroizing<String>,

    /// Available roles (Role ARN -> Principal ARN)
    roles: HashMap<String, String>,

    /// Assertion expiration (NotOnOrAfter)
    expiration: Option<DateTime<Utc>>,
}

#[derive(Debug, Default)]
struct SamlConditions {
    not_before: Option<DateTime<Utc>>,
    not_on_or_after: Option<DateTime<Utc>>,
    audiences: Vec<String>,
}

impl SamlAssertion {
    /// Parse and validate a base64-encoded SAML assertion.
    ///
    /// Validation performed:
    /// * Issuer matches `https://sts.windows.net/{expected_tenant_id}/`
    /// * `expected_audience` is present in the assertion's audience restriction
    /// * Current time is within the assertion's `[NotBefore, NotOnOrAfter)` window
    pub fn parse(encoded: &str, expected_tenant_id: &str, expected_audience: &str) -> Result<Self> {
        // Reject oversized assertions before decoding to prevent memory exhaustion.
        // Base64 encodes 3 bytes as 4 characters, so upper bound is (len * 3) / 4.
        let estimated_size = encoded.len().div_ceil(4) * 3;
        if estimated_size > MAX_SAML_SIZE {
            return Err(AwzarsError::Saml(
                "SAML assertion exceeds maximum allowed size".to_string(),
            ));
        }

        // Decode base64. Wrap the decoded XML in `Zeroizing` immediately so
        // that any of the validation steps below that early-return still wipe
        // the heap holding the assertion body. (Pre-fix, an early-return on a
        // validation failure dropped `decoded_str: String` un-scrubbed.)
        let decoded = BASE64
            .decode(encoded)
            .map_err(|e| AwzarsError::Saml(format!("Failed to decode base64: {}", e)))?;
        let decoded_str: Zeroizing<String> = Zeroizing::new(
            String::from_utf8(decoded)
                .map_err(|e| AwzarsError::Saml(format!("Invalid UTF-8 in SAML: {}", e)))?,
        );

        // Parse XML
        let doc = roxmltree::Document::parse(&decoded_str)
            .map_err(|e| AwzarsError::Saml(format!("Failed to parse SAML XML: {}", e)))?;

        // Locate the single `<saml:Assertion>` element once; all semantic
        // fields are extracted from its subtree so crafted elements placed
        // outside the assertion envelope cannot influence parse results.
        let assertion_node = find_assertion_node(&doc).ok_or_else(|| {
            AwzarsError::Saml("SAML document does not contain an <Assertion> element".to_string())
        })?;

        // Extract semantic fields
        let roles = extract_roles(assertion_node)?;
        let issuer = extract_assertion_issuer_node(assertion_node);
        let conditions = extract_conditions(assertion_node)?;

        // Validate issuer (URL-normalized comparison)
        let expected_issuer = format!("https://sts.windows.net/{}/", expected_tenant_id);
        let issuer_matches = match issuer.as_deref() {
            Some(i) => {
                // Normalize both sides as URLs for comparison
                match (url::Url::parse(i), url::Url::parse(&expected_issuer)) {
                    (Ok(parsed_issuer), Ok(parsed_expected)) => {
                        parsed_issuer.scheme() == parsed_expected.scheme()
                            && parsed_issuer.host_str() == parsed_expected.host_str()
                            && parsed_issuer.path().trim_end_matches('/')
                                == parsed_expected.path().trim_end_matches('/')
                    }
                    // Fallback to exact string match if URL parsing fails
                    _ => i == expected_issuer,
                }
            }
            None => false,
        };
        if !issuer_matches {
            return Err(AwzarsError::Saml("SAML issuer mismatch".to_string()));
        }

        // Validate audience
        if !conditions.audiences.iter().any(|a| a == expected_audience) {
            return Err(AwzarsError::Saml(
                "SAML audience restriction does not match expected app ID URI".to_string(),
            ));
        }

        // Validate time window: temporal sanity check first
        if let (Some(nb), Some(na)) = (conditions.not_before, conditions.not_on_or_after) {
            if nb >= na {
                return Err(AwzarsError::Saml(
                    "SAML assertion has inverted time window (NotBefore >= NotOnOrAfter)"
                        .to_string(),
                ));
            }
        }
        let now = Utc::now();
        let skew = chrono::Duration::seconds(CLOCK_SKEW_SECONDS);
        if let Some(nb) = conditions.not_before {
            if now + skew < nb {
                return Err(AwzarsError::Saml(
                    "SAML assertion is not yet valid (NotBefore in the future)".to_string(),
                ));
            }
        }
        if let Some(na) = conditions.not_on_or_after {
            if now >= na {
                return Err(AwzarsError::Saml(
                    "SAML assertion has expired (NotOnOrAfter in the past)".to_string(),
                ));
            }
        }

        // Validate SubjectConfirmation Recipient (if present)
        if let Some(recipient) = extract_recipient(assertion_node) {
            const EXPECTED_RECIPIENT: &str = "https://signin.aws.amazon.com/saml";
            if recipient != EXPECTED_RECIPIENT {
                return Err(AwzarsError::Saml("SAML Recipient mismatch".to_string()));
            }
        }

        Ok(Self {
            raw_xml: Zeroizing::new(encoded.to_string()),
            decoded: decoded_str,
            roles,
            expiration: conditions.not_on_or_after,
        })
    }

    /// Get available roles
    pub fn roles(&self) -> Vec<(String, String)> {
        self.roles
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Get principal ARN for a role
    pub fn principal_for_role(&self, role_arn: &str) -> Option<String> {
        self.roles.get(role_arn).cloned()
    }

    /// Get expiration time
    pub fn expiration(&self) -> Option<DateTime<Utc>> {
        self.expiration
    }

    /// Get the raw base64-encoded assertion
    pub fn raw(&self) -> &str {
        &self.raw_xml
    }
}

/// Locate the `<saml:Assertion>` element. Scoped by namespace so that a
/// crafted element named `Assertion` under an attacker-chosen namespace
/// cannot be picked up in place of the real one.
fn find_assertion_node<'a, 'input>(
    doc: &'a roxmltree::Document<'input>,
) -> Option<Node<'a, 'input>> {
    doc.descendants().find(|n| is_saml_tag(n, "Assertion"))
}

/// Extract roles from the scoped SAML `<Assertion>` subtree.
fn extract_roles(assertion: Node) -> Result<HashMap<String, String>> {
    let mut roles = HashMap::new();

    for node in assertion.descendants() {
        if !is_saml_tag(&node, "AttributeStatement") {
            continue;
        }
        for attr in node.descendants() {
            if !is_role_attribute(&attr) {
                continue;
            }
            for value in attr.descendants() {
                if is_saml_tag(&value, "AttributeValue") {
                    if let Some(text) = value.text() {
                        if let Some((role, principal)) = parse_role_value(text) {
                            roles.insert(role, principal);
                        }
                    }
                }
            }
        }
    }

    if roles.is_empty() {
        tracing::warn!("No AWS roles found in SAML assertion");
    }

    Ok(roles)
}

/// Check if an attribute is the AWS Role attribute
fn is_role_attribute(node: &Node) -> bool {
    if !is_saml_tag(node, "Attribute") {
        return false;
    }

    if let Some(name) = node.attribute("Name") {
        name == "https://aws.amazon.com/SAML/Attributes/Role"
    } else {
        false
    }
}

/// Parse a role value (format: "role_arn,principal_arn")
fn parse_role_value(value: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = value.split(',').collect();
    if parts.len() != 2 {
        return None;
    }

    let role = parts[0].trim();
    let principal = parts[1].trim();

    // Validate ARNs
    if role.starts_with("arn:aws:iam::") && principal.starts_with("arn:aws:iam::") {
        Some((role.to_string(), principal.to_string()))
    } else if role.starts_with("arn:aws:sts::") && principal.starts_with("arn:aws:iam::") {
        // Handle STS roles
        Some((role.to_string(), principal.to_string()))
    } else {
        None
    }
}

/// Extract the assertion-level `<Issuer>` element.
///
/// The `<Issuer>` is always a direct child of `<Assertion>` per the SAML 2.0
/// schema. Scoping to direct children avoids picking up nested / attacker-
/// placed `Issuer` elements deeper in the tree.
fn extract_assertion_issuer_node(assertion: Node) -> Option<String> {
    assertion
        .children()
        .find(|c| is_saml_tag(c, "Issuer"))
        .and_then(|c| c.text())
        .map(|t| t.trim().to_string())
}

/// Extract `<Conditions>`: NotBefore, NotOnOrAfter, and audience restrictions.
///
/// Scoped to the `<Assertion>` subtree with namespace-checked tag matches.
fn extract_conditions(assertion: Node) -> Result<SamlConditions> {
    let mut out = SamlConditions::default();

    // `<Conditions>` is a direct child of `<Assertion>`; iterate children
    // rather than descendants so a nested decoy `Conditions` is ignored.
    for node in assertion.children() {
        if !is_saml_tag(&node, "Conditions") {
            continue;
        }

        if let Some(nb) = node.attribute("NotBefore") {
            out.not_before = DateTime::parse_from_rfc3339(nb)
                .map(|dt| dt.with_timezone(&Utc))
                .ok();
        }
        if let Some(na) = node.attribute("NotOnOrAfter") {
            out.not_on_or_after = DateTime::parse_from_rfc3339(na)
                .map(|dt| dt.with_timezone(&Utc))
                .ok();
        }

        for restriction in node.children() {
            if !is_saml_tag(&restriction, "AudienceRestriction") {
                continue;
            }
            for aud in restriction.children() {
                if is_saml_tag(&aud, "Audience") {
                    if let Some(text) = aud.text() {
                        out.audiences.push(text.trim().to_string());
                    }
                }
            }
        }
    }

    Ok(out)
}

/// Extract the `SubjectConfirmationData Recipient` URL from the assertion.
///
/// Scoped to the assertion subtree. `<SubjectConfirmationData>` lives at
/// `Assertion/Subject/SubjectConfirmation/SubjectConfirmationData`, so
/// descendants() within the assertion subtree is safe (and matches the
/// conventional structure). The namespace check guards against decoy
/// elements under an attacker-chosen namespace.
fn extract_recipient(assertion: Node) -> Option<String> {
    for node in assertion.descendants() {
        if is_saml_tag(&node, "SubjectConfirmationData") {
            if let Some(recipient) = node.attribute("Recipient") {
                return Some(recipient.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT_ID: &str = "11111111-2222-3333-4444-555555555555";
    const AUDIENCE: &str = "https://signin.aws.amazon.com/saml";

    fn build_assertion_xml(
        issuer: &str,
        audience: &str,
        not_before: &str,
        not_on_or_after: &str,
    ) -> String {
        format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
      <saml:AudienceRestriction>
        <saml:Audience>{audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
        <saml:AttributeValue>arn:aws:iam::123456789012:role/MyRole,arn:aws:iam::123456789012:saml-provider/MyProvider</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#,
        )
    }

    fn encode(xml: &str) -> String {
        BASE64.encode(xml.as_bytes())
    }

    fn valid_xml() -> String {
        let nb = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let na = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        build_assertion_xml(
            &format!("https://sts.windows.net/{}/", TENANT_ID),
            AUDIENCE,
            &nb,
            &na,
        )
    }

    #[test]
    fn test_parse_role_value() {
        let value = "arn:aws:iam::123456789012:role/MyRole,arn:aws:iam::123456789012:saml-provider/MyProvider";
        let result = parse_role_value(value);
        assert!(result.is_some());

        let (role, principal) = result.unwrap();
        assert_eq!(role, "arn:aws:iam::123456789012:role/MyRole");
        assert_eq!(
            principal,
            "arn:aws:iam::123456789012:saml-provider/MyProvider"
        );
    }

    #[test]
    fn test_parse_role_value_invalid() {
        assert!(parse_role_value("not-a-valid-arn").is_none());
    }

    #[test]
    fn test_parse_accepts_valid_assertion() {
        let xml = valid_xml();
        let assertion = SamlAssertion::parse(&encode(&xml), TENANT_ID, AUDIENCE)
            .expect("valid assertion should parse");
        assert_eq!(assertion.roles().len(), 1);
        assert!(assertion.expiration().is_some());
    }

    #[test]
    fn test_parse_rejects_wrong_issuer() {
        let nb = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let na = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let xml = build_assertion_xml(
            "https://sts.windows.net/00000000-0000-0000-0000-000000000000/",
            AUDIENCE,
            &nb,
            &na,
        );
        let err = SamlAssertion::parse(&encode(&xml), TENANT_ID, AUDIENCE).unwrap_err();
        assert!(matches!(err, AwzarsError::Saml(ref m) if m.contains("issuer")));
    }

    #[test]
    fn test_parse_rejects_wrong_audience() {
        let nb = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let na = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let xml = build_assertion_xml(
            &format!("https://sts.windows.net/{}/", TENANT_ID),
            "https://attacker.example/saml",
            &nb,
            &na,
        );
        let err = SamlAssertion::parse(&encode(&xml), TENANT_ID, AUDIENCE).unwrap_err();
        assert!(matches!(err, AwzarsError::Saml(ref m) if m.contains("audience")));
    }

    #[test]
    fn test_parse_rejects_expired_assertion() {
        let nb = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        let na = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let xml = build_assertion_xml(
            &format!("https://sts.windows.net/{}/", TENANT_ID),
            AUDIENCE,
            &nb,
            &na,
        );
        let err = SamlAssertion::parse(&encode(&xml), TENANT_ID, AUDIENCE).unwrap_err();
        assert!(matches!(err, AwzarsError::Saml(ref m) if m.contains("expired")));
    }

    #[test]
    fn test_parse_rejects_future_not_before() {
        let nb = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let na = (Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
        let xml = build_assertion_xml(
            &format!("https://sts.windows.net/{}/", TENANT_ID),
            AUDIENCE,
            &nb,
            &na,
        );
        let err = SamlAssertion::parse(&encode(&xml), TENANT_ID, AUDIENCE).unwrap_err();
        assert!(matches!(err, AwzarsError::Saml(ref m) if m.contains("not yet valid")));
    }

    #[test]
    fn test_extract_conditions_parses_audiences() {
        let xml = valid_xml();
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let assertion = find_assertion_node(&doc).expect("assertion present");
        let conditions = extract_conditions(assertion).unwrap();
        assert_eq!(conditions.audiences, vec![AUDIENCE.to_string()]);
        assert!(conditions.not_before.is_some());
        assert!(conditions.not_on_or_after.is_some());
    }

    #[test]
    fn test_extract_ignores_foreign_namespace_decoys() {
        // A crafted document with `Conditions`, `Audience`, and
        // `SubjectConfirmationData` elements under an attacker-chosen namespace
        // must be ignored. The real SAML assertion inside should still parse.
        let nb = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let na = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:evil="urn:attacker">
  <evil:Conditions NotBefore="2099-01-01T00:00:00Z" NotOnOrAfter="2099-01-02T00:00:00Z">
    <evil:AudienceRestriction><evil:Audience>urn:evil</evil:Audience></evil:AudienceRestriction>
  </evil:Conditions>
  <evil:SubjectConfirmationData Recipient="https://evil.example.com/" />
  <saml:Assertion>
    <saml:Issuer>https://sts.windows.net/{tenant}/</saml:Issuer>
    <saml:Conditions NotBefore="{nb}" NotOnOrAfter="{na}">
      <saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:Subject>
      <saml:SubjectConfirmation>
        <saml:SubjectConfirmationData Recipient="https://signin.aws.amazon.com/saml" />
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
        <saml:AttributeValue>arn:aws:iam::123456789012:role/MyRole,arn:aws:iam::123456789012:saml-provider/MyProvider</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#,
            tenant = TENANT_ID,
            nb = nb,
            na = na,
            aud = AUDIENCE,
        );
        let result = SamlAssertion::parse(&encode(&xml), TENANT_ID, AUDIENCE);
        assert!(
            result.is_ok(),
            "foreign-namespace decoys should not influence parse: {:?}",
            result
        );
    }

    #[test]
    fn test_parse_rejects_inverted_time_window() {
        let nb = (Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
        let na = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let xml = build_assertion_xml(
            &format!("https://sts.windows.net/{}/", TENANT_ID),
            AUDIENCE,
            &nb,
            &na,
        );
        let err = SamlAssertion::parse(&encode(&xml), TENANT_ID, AUDIENCE).unwrap_err();
        assert!(matches!(err, AwzarsError::Saml(ref m) if m.contains("inverted time window")));
    }

    #[test]
    fn test_parse_accepts_issuer_without_trailing_slash() {
        let nb = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let na = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        // Issuer without trailing slash — URL normalization should still match
        let xml = build_assertion_xml(
            &format!("https://sts.windows.net/{}", TENANT_ID),
            AUDIENCE,
            &nb,
            &na,
        );
        let result = SamlAssertion::parse(&encode(&xml), TENANT_ID, AUDIENCE);
        assert!(
            result.is_ok(),
            "expected URL-normalized issuer to match, got {:?}",
            result
        );
    }

    #[test]
    fn test_parse_rejects_wrong_recipient() {
        let nb = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let na = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:Issuer>https://sts.windows.net/{}/</saml:Issuer>
    <saml:Conditions NotBefore="{}" NotOnOrAfter="{}">
      <saml:AudienceRestriction>
        <saml:Audience>{}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:Subject>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="https://evil.example.com/saml" NotOnOrAfter="{}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
        <saml:AttributeValue>arn:aws:iam::123456789012:role/MyRole,arn:aws:iam::123456789012:saml-provider/MyProvider</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#,
            TENANT_ID, nb, na, AUDIENCE, na
        );
        let err = SamlAssertion::parse(&encode(&xml), TENANT_ID, AUDIENCE).unwrap_err();
        assert!(matches!(err, AwzarsError::Saml(ref m) if m.contains("Recipient")));
    }

    #[test]
    fn test_parse_accepts_correct_recipient() {
        let nb = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let na = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:Issuer>https://sts.windows.net/{}/</saml:Issuer>
    <saml:Conditions NotBefore="{}" NotOnOrAfter="{}">
      <saml:AudienceRestriction>
        <saml:Audience>{}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:Subject>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="https://signin.aws.amazon.com/saml" NotOnOrAfter="{}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
        <saml:AttributeValue>arn:aws:iam::123456789012:role/MyRole,arn:aws:iam::123456789012:saml-provider/MyProvider</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#,
            TENANT_ID, nb, na, AUDIENCE, na
        );
        let result = SamlAssertion::parse(&encode(&xml), TENANT_ID, AUDIENCE);
        assert!(
            result.is_ok(),
            "expected correct recipient to pass, got {:?}",
            result
        );
    }

    #[test]
    fn test_parse_accepts_missing_recipient() {
        // Missing recipient should not cause rejection
        let xml = valid_xml();
        let result = SamlAssertion::parse(&encode(&xml), TENANT_ID, AUDIENCE);
        assert!(
            result.is_ok(),
            "expected missing recipient to pass, got {:?}",
            result
        );
    }

    #[test]
    fn test_parse_rejects_oversized_assertion() {
        // Generate a base64 string whose decoded size would exceed MAX_SAML_SIZE.
        // MAX_SAML_SIZE is 256 KB, so we need ~342 KB of base64 (342 KB * 3/4 ≈ 256 KB).
        let oversized = "A".repeat(350_000);
        let err = SamlAssertion::parse(&oversized, TENANT_ID, AUDIENCE).unwrap_err();
        assert!(matches!(err, AwzarsError::Saml(ref m) if m.contains("maximum allowed size")));
    }
}
