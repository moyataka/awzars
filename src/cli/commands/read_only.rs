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
    } = &args.command
    else {
        return Err(AwzarsError::Config("Invalid command".into()));
    };
    let config = Config::load()?;
    let profile = config.get_profile(&args.profile)?;
    if let Some(client) = client {
        if std::io::stdin().is_terminal() {
            return Err(AwzarsError::Config(
                "Send the MCP secret through a private stdin pipe, then close the pipe".into(),
            ));
        }
        let secret = crate::auth::mcp::McpSecret::from_reader(std::io::stdin().lock())?;
        let request =
            profile.authenticate_mcp(&args.profile, client, target, *capability, &secret)?;
        drop(secret);
        return super::credential_process::issue_mcp_credentials(&request)
            .await?
            .write_json();
    }
    let request = profile
        .read_only
        .as_ref()
        .ok_or_else(|| {
            AwzarsError::Config(
                "No approved read-only targets are configured for this profile".into(),
            )
        })?
        .authorize(target, *capability)?;

    let (source_credentials, refresh_guard) =
        super::credential_process::load_credentials(args, profile, false, false, false, false)
            .await?;
    drop(refresh_guard);
    let credentials = issue_credentials(&request, source_credentials).await?;
    credentials.write_json()
}
