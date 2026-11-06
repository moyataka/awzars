use super::*;
use crate::auth::aws::read_only::ReadOnlyCapability;
use crate::auth::aws::test_support::{serve_once, Request};
use crate::config::ReadOnlyAccess;

const SUCCESS: &str = r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult><Credentials>
    <AccessKeyId>FINAL-RESTRICTED-KEY</AccessKeyId>
    <SecretAccessKey>final-secret</SecretAccessKey>
    <SessionToken>final-token</SessionToken>
    <Expiration>2030-01-01T00:00:00Z</Expiration>
  </Credentials></AssumeRoleResult>
  <ResponseMetadata><RequestId>test-request</RequestId></ResponseMetadata>
</AssumeRoleResponse>"#;

fn authorized_request() -> AuthorizedReadOnlyRequest {
    toml::from_str::<ReadOnlyAccess>(
        r#"
        [targets.workload]
        role_arn = "arn:aws:iam::123456789012:role/Workload"
        region = "ap-southeast-1"
        capabilities = ["s3-list-buckets"]
    "#,
    )
    .unwrap()
    .authorize(
        &"workload".parse().unwrap(),
        ReadOnlyCapability::S3ListBuckets,
    )
    .unwrap()
}

fn source_credentials() -> CredentialProcessOutput {
    CredentialProcessOutput::new("SOURCE-KEY", "source-secret")
        .with_session_token("source-token")
        .with_expiration("2030-01-01T00:00:00Z")
}

async fn exchange(body: &str, status: &str) -> (Result<ReadOnlyCredentials>, Request) {
    let request = authorized_request();
    let (endpoint, server) = serve_once(body, status).await;
    let config = client_configuration(&request, &source_credentials())
        .unwrap()
        .endpoint_url(endpoint)
        .retry_config(aws_sdk_sts::config::retry::RetryConfig::disabled())
        .build();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        issue_with_client(&aws_sdk_sts::Client::from_conf(config), &request),
    )
    .await
    .expect("mock STS exchange timed out");
    (result, server.await.unwrap())
}

#[tokio::test]
async fn final_role_receives_mandatory_policy_and_only_final_credentials_are_returned() {
    let (result, request) = exchange(SUCCESS, "200 OK").await;
    let credentials = result.expect("restricted session");
    let json = credentials.0.to_json().unwrap();
    assert!(json.contains("FINAL-RESTRICTED-KEY"));
    assert!(json.contains("final-token"));
    assert!(!json.contains("SOURCE"));
    assert!(!json.contains("source-"));
    assert!(request.headers.contains("Credential=SOURCE-KEY/"));
    assert!(request.headers.contains("source-token"));
    let parameters = request.parameters;
    assert_eq!(parameters["Action"], "AssumeRole");
    assert_eq!(
        parameters["RoleArn"],
        "arn:aws:iam::123456789012:role/Workload"
    );
    assert_eq!(parameters["DurationSeconds"], "900");
    assert_eq!(parameters["RoleSessionName"], "awzars-read-only");
    assert_eq!(parameters["Policy"], authorized_request().policy().as_str());
}

#[tokio::test]
async fn rejected_or_invalid_responses_never_return_credentials_or_private_error_bodies() {
    let denied = r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
        <Error><Type>Sender</Type><Code>AccessDenied</Code><Message>PRIVATE-MARKER</Message></Error>
        <RequestId>test</RequestId></ErrorResponse>"#;
    let responses = [
        (denied.to_owned(), "403 Forbidden"),
        ("PRIVATE-MARKER".into(), "200 OK"),
        (SUCCESS.replace("final-token", ""), "200 OK"),
        (SUCCESS.replace("2030-01-01", "2020-01-01"), "200 OK"),
        (
            SUCCESS
                .replace("<Credentials>", "<Other>")
                .replace("</Credentials>", "</Other>"),
            "200 OK",
        ),
    ];
    for (body, status) in responses {
        let (result, request) = exchange(&body, status).await;
        let error = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("accepted invalid response"),
        };
        assert!(!error.contains("PRIVATE-MARKER"));
        assert!(!error.contains("final-secret"));
        assert!(!error.contains("source-secret"));
        assert_eq!(
            request.parameters["Policy"],
            authorized_request().policy().as_str()
        );
    }
}

#[test]
fn invalid_source_sessions_fail_before_building_a_client() {
    for source in [
        CredentialProcessOutput::new("key", "secret"),
        source_credentials().with_session_token(""),
        source_credentials().with_expiration("2020-01-01T00:00:00Z"),
        source_credentials().with_expiration("invalid"),
    ] {
        assert!(client_configuration(&authorized_request(), &source).is_err());
    }
}
