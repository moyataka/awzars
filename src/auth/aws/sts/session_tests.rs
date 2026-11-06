use super::*;
use crate::auth::aws::test_support::serve_once;

const POLICY: &str =
    include_str!("../../../../examples/session-policies/ec2-describe-instances.json");
const SUCCESS: &str = r#"<AssumeRoleWithSAMLResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithSAMLResult>
    <Credentials>
      <AccessKeyId>TEST-RESTRICTED-KEY</AccessKeyId>
      <SecretAccessKey>test-secret</SecretAccessKey>
      <SessionToken>test-token</SessionToken>
      <Expiration>2030-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithSAMLResult>
  <ResponseMetadata><RequestId>test-request</RequestId></ResponseMetadata>
</AssumeRoleWithSAMLResponse>"#;
const REJECTED: &str = r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>MalformedPolicyDocument</Code>
    <Message>PRIVATE-POLICY-MARKER</Message></Error>
  <RequestId>test-request</RequestId>
</ErrorResponse>"#;

async fn exchange_against_mock(
    policy: Option<&SessionPolicy>,
    response_body: &'static str,
    status: &str,
) -> (
    Result<CredentialProcessOutput>,
    std::collections::HashMap<String, String>,
) {
    let (endpoint, server) = serve_once(response_body, status).await;
    let configuration = aws_sdk_sts::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .retry_config(aws_sdk_sts::config::retry::RetryConfig::disabled())
        .build();
    let client = aws_sdk_sts::Client::from_conf(configuration);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        exchange_with_client(
            &client,
            "test-saml-assertion",
            "arn:aws:iam::123456789012:role/Test",
            "arn:aws:iam::123456789012:saml-provider/Test",
            900,
            policy,
        ),
    )
    .await
    .expect("mock STS exchange timed out");
    let request = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    (result, request.parameters)
}

#[tokio::test]
async fn saml_exchange_sends_policy_and_preserves_ordinary_requests() {
    let policy = SessionPolicy::parse(POLICY.into()).unwrap();
    for requested_policy in [None, Some(&policy)] {
        let (result, request) = exchange_against_mock(requested_policy, SUCCESS, "200 OK").await;
        let credentials = result.unwrap();
        assert_eq!(credentials.access_key_id, "TEST-RESTRICTED-KEY");
        assert_eq!(credentials.session_token.as_deref(), Some("test-token"));
        assert_eq!(request["Action"], "AssumeRoleWithSAML");
        assert_eq!(request["DurationSeconds"], "900");
        assert_eq!(request["SAMLAssertion"], "test-saml-assertion");
        assert_eq!(
            request.get("Policy").map(String::as_str),
            requested_policy.map(SessionPolicy::as_str)
        );
    }
}

#[tokio::test]
async fn rejected_policy_returns_an_error_without_credentials() {
    let policy = SessionPolicy::parse(POLICY.into()).unwrap();
    let (result, request) = exchange_against_mock(Some(&policy), REJECTED, "400 Bad Request").await;
    let error = result.unwrap_err().to_string();
    assert_eq!(request["Policy"], POLICY);
    assert!(error.contains("MalformedPolicyDocument"), "{error}");
    assert!(!error.contains("PRIVATE-POLICY-MARKER"), "{error}");
}
