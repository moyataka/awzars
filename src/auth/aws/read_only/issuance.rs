use super::SESSION_DURATION_SECONDS;
use crate::config::AuthorizedReadOnlyRequest;
use crate::credential_process::protocol::{write_credentials_json, CredentialProcessOutput};
use crate::error::{AwzarsError, Result};
use aws_sdk_sts::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_sts::error::ProvideErrorMetadata;
use std::time::Duration;

/// Constructed only after STS accepts the approved policy for the final role.
pub struct ReadOnlyCredentials(CredentialProcessOutput);

impl ReadOnlyCredentials {
    pub fn write_json(&self) -> Result<()> {
        write_credentials_json(&self.0)
    }
}

pub async fn issue_credentials(
    request: &AuthorizedReadOnlyRequest,
    source: CredentialProcessOutput,
) -> Result<ReadOnlyCredentials> {
    let configuration = client_configuration(request, &source)?.build();
    let client = aws_sdk_sts::Client::from_conf(configuration);
    issue_with_client(&client, request).await
}

fn client_configuration(
    request: &AuthorizedReadOnlyRequest,
    source: &CredentialProcessOutput,
) -> Result<aws_sdk_sts::config::Builder> {
    validate_temporary_credentials(source)?;
    // Do not load AWS profiles, endpoint overrides or ambient credentials.
    Ok(aws_sdk_sts::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(request.scope().region().as_str().to_owned()))
        .credentials_provider(Credentials::new(
            source.access_key_id.clone(),
            source.secret_access_key.clone(),
            source.session_token.clone(),
            None,
            "awzars-source-session",
        ))
        .timeout_config(
            aws_sdk_sts::config::timeout::TimeoutConfig::builder()
                .operation_timeout(Duration::from_secs(30))
                .build(),
        ))
}

async fn issue_with_client(
    client: &aws_sdk_sts::Client,
    request: &AuthorizedReadOnlyRequest,
) -> Result<ReadOnlyCredentials> {
    let response = client
        .assume_role()
        .role_arn(request.scope().role().as_str())
        .role_session_name("awzars-read-only")
        .duration_seconds(SESSION_DURATION_SECONDS)
        .policy(request.policy().as_str())
        .send()
        .await
        .map_err(|error| {
            let code = error.code().map(super::super::sts::sanitize_aws_error_code);
            AwzarsError::AwsSts(format!(
                "Restricted AssumeRole failed: {}",
                code.as_deref()
                    .unwrap_or("STS request failed or returned an unreadable response")
            ))
        })?;
    let credentials = response.credentials.ok_or_else(|| {
        AwzarsError::AwsSts("Restricted AssumeRole returned no credentials".into())
    })?;
    let output =
        CredentialProcessOutput::new(credentials.access_key_id, credentials.secret_access_key)
            .with_session_token(credentials.session_token)
            .with_expiration(credentials.expiration.to_string());
    validate_temporary_credentials(&output)?;
    Ok(ReadOnlyCredentials(output))
}

fn validate_temporary_credentials(credentials: &CredentialProcessOutput) -> Result<()> {
    if credentials.version != 1
        || credentials.access_key_id.is_empty()
        || credentials.secret_access_key.is_empty()
        || credentials
            .session_token
            .as_deref()
            .is_none_or(str::is_empty)
        || !credentials.is_valid(0)
    {
        return Err(AwzarsError::AwsSts(
            "Missing, invalid or expired temporary credentials".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
