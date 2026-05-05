//! Configure command implementation

use crate::cli::args::{parse_app_id_uri, parse_role_arn, parse_tenant_uuid, Args, ConfigureArgs};
use crate::config::{AzureConfig, Config, Profile};
use crate::error::{AwzarsError, Result};
use dialoguer::{Confirm, Input};
use std::io::IsTerminal;

/// Execute the configure command
pub async fn execute(args: &Args) -> Result<()> {
    let config_args = ConfigureArgs::from_command(&args.command);

    let mut config = match Config::load() {
        Ok(c) => c,
        Err(AwzarsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            // Config file doesn't exist yet — start fresh
            Config::default()
        }
        Err(AwzarsError::Toml(msg)) => {
            eprintln!("Warning: Existing config file is corrupted: {}", msg);
            eprintln!("Fix the file manually, or remove it to start fresh.");
            return Err(AwzarsError::Config(format!(
                "Corrupted config file: {}",
                msg
            )));
        }
        Err(e) => return Err(e),
    };

    let (tenant_id, app_id_uri, role_arn, session_duration, remember_me) =
        if let Some(ref cfg) = config_args {
            if cfg.non_interactive {
                // Use provided values
                (
                    cfg.azure_tenant.clone().unwrap_or_default(),
                    cfg.azure_app.clone().unwrap_or_default(),
                    cfg.role_arn.clone(),
                    cfg.session_duration,
                    None,
                )
            } else {
                // Interactive mode with defaults from args
                interactive_configure(&config, &args.profile, Some(cfg))?
            }
        } else {
            // Fully interactive mode
            interactive_configure(&config, &args.profile, None)?
        };

    // Create Azure config
    let azure_config = AzureConfig {
        tenant_id,
        app_id_uri,
        default_role_arn: role_arn.clone(),
        session_duration,
    };

    // Create or update profile
    let profile = Profile {
        azure: azure_config,
        role_arn,
        remember_me,
        ..Default::default()
    };

    let prev_profile = config.profiles.get(&args.profile).cloned();
    let identity_changed = prev_profile
        .as_ref()
        .map(|prev| crate::config::cleanup::credential_identity_changed(prev, &profile))
        .unwrap_or(false);

    config.set_profile(&args.profile, profile);
    config.save()?;

    if identity_changed {
        for warning in crate::config::cleanup::invalidate_cached_credentials(&args.profile) {
            eprintln!("warning: credential cache cleanup: {}", warning);
        }
    }

    println!("Profile '{}' configured successfully", args.profile);

    // Add-time only, and only when a real terminal is attached so non-interactive
    // callers (CI, scripts) are never blocked on a prompt.
    let is_new_profile = prev_profile.is_none();
    if is_new_profile && std::io::stdin().is_terminal() {
        let want_lock = Confirm::new()
            .with_prompt(format!(
                "Set a password lock for profile '{}'? (recommended for shared hosts)",
                args.profile
            ))
            .default(false)
            .interact()
            .map_err(|e| AwzarsError::Dialog(e.to_string()))?;
        if want_lock {
            crate::cli::commands::set_password::run(&args.profile, false)?;
        }
    }

    Ok(())
}

/// (tenant_id, app_id_uri, role_arn, session_duration, remember_me)
type InteractiveConfigureResult = (String, String, Option<String>, i32, Option<bool>);

fn interactive_configure(
    config: &Config,
    profile_name: &str,
    args: Option<&ConfigureArgs>,
) -> Result<InteractiveConfigureResult> {
    let existing = config.get_profile(profile_name).ok();

    let default_tenant = args
        .and_then(|a| a.azure_tenant.clone())
        .or_else(|| existing.map(|p| p.azure.tenant_id.clone()))
        .unwrap_or_default();

    let default_app = args
        .and_then(|a| a.azure_app.clone())
        .or_else(|| existing.map(|p| p.azure.app_id_uri.clone()))
        .unwrap_or_else(|| "https://signin.aws.amazon.com/saml".to_string());

    let default_role = args
        .and_then(|a| a.role_arn.clone())
        .or_else(|| existing.and_then(|p| p.role_arn.clone()))
        .unwrap_or_default();

    let default_duration = args
        .map(|a| a.session_duration)
        .or_else(|| existing.map(|p| p.azure.session_duration))
        .unwrap_or(3600);

    let default_remember = existing.and_then(|p| p.remember_me).unwrap_or(false);

    let tenant_id: String = Input::new()
        .with_prompt("Azure AD Tenant ID")
        .default(default_tenant)
        .validate_with(|s: &String| parse_tenant_uuid(s).map(|_| ()))
        .interact_text()
        .map_err(|e| crate::error::AwzarsError::Dialog(e.to_string()))?;

    let app_id_uri: String = Input::new()
        .with_prompt("Azure AD App ID URI")
        .default(default_app)
        .validate_with(|s: &String| parse_app_id_uri(s).map(|_| ()))
        .interact_text()
        .map_err(|e| crate::error::AwzarsError::Dialog(e.to_string()))?;

    let role_arn_input: String = Input::new()
        .with_prompt("Default AWS Role ARN (optional)")
        .default(default_role)
        .allow_empty(true)
        .validate_with(|s: &String| {
            if s.is_empty() {
                Ok(())
            } else {
                parse_role_arn(s).map(|_| ())
            }
        })
        .interact_text()
        .map_err(|e| crate::error::AwzarsError::Dialog(e.to_string()))?;

    let session_duration: i32 = Input::new()
        .with_prompt("Session duration (seconds)")
        .default(default_duration)
        .validate_with(|v: &i32| {
            if (900..=43200).contains(v) {
                Ok(())
            } else {
                Err("must be between 900 and 43200 seconds")
            }
        })
        .interact_text()
        .map_err(|e| crate::error::AwzarsError::Dialog(e.to_string()))?;

    let remember_me = Confirm::new()
        .with_prompt("Stay logged in? (skip re-authentication while refreshing)")
        .default(default_remember)
        .interact()
        .map_err(|e| crate::error::AwzarsError::Dialog(e.to_string()))?;

    let role_arn = if role_arn_input.is_empty() {
        None
    } else {
        Some(role_arn_input)
    };

    Ok((
        tenant_id,
        app_id_uri,
        role_arn,
        session_duration,
        Some(remember_me),
    ))
}
