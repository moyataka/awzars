use crate::auth::{lock, mcp::McpSecret};
use crate::cli::args::{Args, Command};
use crate::config::{Config, McpClientGrant, Profile};
use crate::error::{AwzarsError, Result};
use std::{
    io::{IsTerminal, Write},
    path::Path,
};

pub fn execute(args: &Args) -> Result<()> {
    let config = Config::load()?;
    let profile = config.get_profile(&args.profile)?;
    match &args.command {
        Command::EnrollMcp {
            client,
            target,
            capability,
            secret_file,
        } => {
            validate_secret_path(secret_file)?;
            authorize_management(&args.profile, profile)?;
            let (grant, secret) = McpClientGrant::enroll(
                &args.profile,
                profile,
                target.clone(),
                capability.iter().copied().collect(),
            )?;
            // Re-read after the password prompt; refuse a changed authorization context.
            let mut latest = Config::load()?;
            let current = latest.get_profile_mut(&args.profile)?;
            if !grant.matches_profile(&args.profile, current)? {
                return Err(AwzarsError::Config(
                    "Profile or target changed during enrollment; retry".into(),
                ));
            }
            current
                .read_only
                .as_mut()
                .ok_or(AwzarsError::McpAuthentication)?
                .insert_client(client.clone(), grant)?;
            write_new_secret(secret_file, &secret)?;
            latest.save().map_err(|error| AwzarsError::Config(format!(
                "Could not save MCP enrollment: {error}. The new secret file remains at {}; check enrollment before using it.", secret_file.display()
            )))?;
            if !args.quiet {
                println!("Enrolled MCP client '{client}' for target '{target}'. Secret saved to {}. Normal access remains locked unless already unlocked.", secret_file.display());
            }
        }
        Command::RevokeMcp { client } => {
            authorize_management(&args.profile, profile)?;
            let mut latest = Config::load()?;
            let current = latest.get_profile_mut(&args.profile)?;
            if current.lock_verifier != profile.lock_verifier {
                return Err(AwzarsError::Config(
                    "Profile lock changed during revocation; retry".into(),
                ));
            }
            if let Some(access) = current.read_only.as_mut() {
                access.remove_client(client);
            }
            latest.save()?;
            if !args.quiet {
                println!("Revoked MCP client '{client}'. Previously issued AWS sessions remain valid until expiry; remove the MCP's stored enrollment secret.");
            }
        }
        _ => return Err(AwzarsError::Config("Invalid command".into())),
    }
    Ok(())
}

fn authorize_management(profile_name: &str, profile: &Profile) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err(AwzarsError::LockRequiresTty);
    }
    if let Some(marker) = lock::is_ai_context(&lock::effective_markers(profile)) {
        return Err(AwzarsError::AiContextBlocked {
            profile: profile_name.into(),
            marker,
            hint: "Manage MCP enrollment from your own terminal.".into(),
        });
    }
    if let Some(verifier) = &profile.lock_verifier {
        let password = lock::read_password_via_tty(&format!(
            "Password for awzars profile '{profile_name}' (manage MCP access)"
        ))?;
        lock::verify_password_or_fail(&password, verifier, profile_name)?;
    } else if !dialoguer::Confirm::new()
        .with_prompt(format!(
            "Authorize this MCP enrollment change for profile '{profile_name}'?"
        ))
        .default(false)
        .interact()
        .map_err(|error| AwzarsError::Dialog(error.to_string()))?
    {
        return Err(AwzarsError::Config(
            "MCP enrollment change cancelled".into(),
        ));
    }
    Ok(())
}

fn validate_secret_path(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(AwzarsError::Config(
            "--secret-file must be an absolute path to a new file".into(),
        ));
    }
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(AwzarsError::Config(
            "--secret-file already exists; choose a new file".into(),
        ));
    }
    Ok(())
}

fn write_new_secret(path: &Path, secret: &McpSecret) -> Result<()> {
    validate_secret_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| AwzarsError::Config("Missing secret file directory".into()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    writeln!(temporary, "{}", secret.expose())?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| AwzarsError::Io(error.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_file_is_private_and_existing_paths_are_never_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.secret");
        let secret = McpSecret::generate().unwrap();
        write_new_secret(&path, &secret).unwrap();
        assert!(secret
            .verifier()
            .unwrap()
            .verifies(&McpSecret::from_reader(std::fs::File::open(&path).unwrap()).unwrap()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let link = directory.path().join("link.secret");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(write_new_secret(&link, &secret).is_err());
        }
        let original = std::fs::read(&path).unwrap();
        assert!(write_new_secret(&path, &McpSecret::generate().unwrap()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(validate_secret_path(Path::new("relative.secret")).is_err());
    }
}
