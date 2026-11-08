use crate::auth::aws::read_only::issue_credentials;
use crate::cli::args::{Args, Command};
use crate::config::Config;
use crate::error::{AwzarsError, Result};
use std::io::IsTerminal;

pub async fn execute(args: &Args) -> Result<()> {
    let Command::ReadOnly {
        target,
        capability,
        client,
        aws_operation,
    } = &args.command
    else {
        return Err(AwzarsError::Config("Invalid command".into()));
    };
    let config = Config::load()?;
    let profile = config.get_profile(&args.profile)?;
    if let Some(client) = client {
        if std::io::stdout().is_terminal() {
            return Err(AwzarsError::Config(
                "MCP credentials require captured stdout, never a terminal".into(),
            ));
        }
        if std::io::stdin().is_terminal() {
            return Err(AwzarsError::Config(
                "Send the MCP secret through a private stdin pipe, then close the pipe".into(),
            ));
        }
        let secret = crate::auth::mcp::McpSecret::from_reader(std::io::stdin().lock())?;
        let request = profile.authenticate_mcp_operation(
            &args.profile,
            client,
            target,
            *capability,
            &secret,
            aws_operation.as_ref(),
        )?;
        drop(secret);
        let credentials = super::credential_process::issue_mcp_credentials(&request).await?;
        return deliver_mcp_credentials(&request, &credentials, std::io::stdout().lock());
    }
    let access = profile.read_only.as_ref().ok_or_else(|| {
        AwzarsError::Config("No approved read-only targets are configured for this profile".into())
    })?;
    let request = match (*capability, aws_operation.as_ref()) {
        (crate::auth::aws::read_only::ReadOnlyCapability::AwsRead, Some(operation)) => {
            access.authorize_operation(target, operation)?
        }
        (crate::auth::aws::read_only::ReadOnlyCapability::AwsRead, None) | (_, Some(_)) => {
            return Err(AwzarsError::Config(
                "Only aws-read accepts and requires --aws-operation".into(),
            ))
        }
        (_, None) => access.authorize(target, *capability)?,
    };

    let (source_credentials, refresh_guard) =
        super::credential_process::load_credentials(args, profile, false, false, false, false)
            .await?;
    drop(refresh_guard);
    let credentials = issue_credentials(&request, source_credentials).await?;
    credentials.write_json()
}

pub(super) fn deliver_mcp_credentials(
    request: &crate::config::AuthenticatedMcpRequest<'_>,
    credentials: &crate::auth::aws::read_only::ReadOnlyCredentials,
    output: impl std::io::Write,
) -> Result<()> {
    credentials.write_json_after(output, || {
        let latest = Config::load().map_err(|_| AwzarsError::McpAuthentication)?;
        let current = latest
            .get_profile(request.profile_name())
            .map_err(|_| AwzarsError::McpAuthentication)?;
        request.revalidate(current)
    })
}
