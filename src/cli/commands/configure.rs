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
                non_interactive_values(config.get_profile(&args.profile).ok(), cfg)
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

    let prev_profile = config.profiles.get(&args.profile).cloned();

    // Create or update profile
    let profile = build_profile(prev_profile.as_ref(), azure_config, role_arn, remember_me);

    let identity_changed = prev_profile
        .as_ref()
        .map(|prev| crate::config::cleanup::credential_identity_changed(prev, &profile))
        .unwrap_or(false);

    config.set_profile(&args.profile, profile);
    config.save()?;

    if identity_changed {
        for warning in crate::config::cleanup::invalidate_cached_credentials(&args.profile) {
            tracing::warn!("credential cache cleanup: {}", warning);
        }
    }

    if !args.quiet {
        println!("Profile '{}' configured successfully", args.profile);
    }

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
            crate::cli::commands::set_password::run(&args.profile, false, args.quiet)?;
        }
    }

    Ok(())
}

/// Build the profile to save from the values `configure` collected.
/// An existing profile keeps every setting `configure` does not ask for.
fn build_profile(
    existing: Option<&Profile>,
    azure: AzureConfig,
    role_arn: Option<String>,
    remember_me: Option<bool>,
) -> Profile {
    Profile {
        azure,
        role_arn,
        remember_me,
        ..existing.cloned().unwrap_or_default()
    }
}

/// (tenant_id, app_id_uri, role_arn, session_duration, remember_me)
type InteractiveConfigureResult = (String, String, Option<String>, i32, Option<bool>);

/// Values for `--non-interactive`. A flag that is not given keeps the existing
/// profile's value, except `--role-arn`: without it the role is cleared.
fn non_interactive_values(
    existing: Option<&Profile>,
    args: &ConfigureArgs,
) -> InteractiveConfigureResult {
    (
        args.azure_tenant
            .clone()
            .or_else(|| existing.map(|p| p.azure.tenant_id.clone()))
            .unwrap_or_default(),
        args.azure_app
            .clone()
            .or_else(|| existing.map(|p| p.azure.app_id_uri.clone()))
            .unwrap_or_default(),
        args.role_arn.clone(),
        args.session_duration
            .or_else(|| existing.map(|p| p.azure.session_duration))
            .unwrap_or(3600),
        existing.and_then(|p| p.remember_me),
    )
}

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
        .and_then(|a| a.session_duration)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_profile_keeps_existing_settings_on_update() {
        let existing = Profile {
            azure: AzureConfig {
                tenant_id: "old-tenant".into(),
                app_id_uri: "https://old.example/app".into(),
                default_role_arn: Some("arn:aws:iam::1:role/Old".into()),
                session_duration: 7200,
            },
            region: Some("eu-west-1".into()),
            role_arn: Some("arn:aws:iam::1:role/Old".into()),
            principal_arn: Some("arn:aws:iam::1:saml-provider/Test".into()),
            remember_me: Some(false),
            headless: Some(true),
            no_sandbox: Some(true),
            allow_insecure_remote_chrome: Some(true),
            lock_verifier: Some("$argon2id$test".into()),
            lock_ttl_hours: Some(12),
            lock_ai_markers: Some(vec!["TEST_MARKER".into()]),
        };
        let azure = AzureConfig {
            tenant_id: "new-tenant".into(),
            app_id_uri: "https://new.example/app".into(),
            default_role_arn: Some("arn:aws:iam::1:role/New".into()),
            session_duration: 3600,
        };

        let updated = build_profile(
            Some(&existing),
            azure,
            Some("arn:aws:iam::1:role/New".into()),
            Some(true),
        );

        // Fields configure collects are replaced.
        assert_eq!(updated.azure.tenant_id, "new-tenant");
        assert_eq!(updated.azure.app_id_uri, "https://new.example/app");
        assert_eq!(
            updated.azure.default_role_arn.as_deref(),
            Some("arn:aws:iam::1:role/New")
        );
        assert_eq!(updated.azure.session_duration, 3600);
        assert_eq!(updated.role_arn.as_deref(), Some("arn:aws:iam::1:role/New"));
        assert_eq!(updated.remember_me, Some(true));

        // Everything else is kept.
        assert_eq!(updated.region.as_deref(), Some("eu-west-1"));
        assert_eq!(
            updated.principal_arn.as_deref(),
            Some("arn:aws:iam::1:saml-provider/Test")
        );
        assert_eq!(updated.headless, Some(true));
        assert_eq!(updated.no_sandbox, Some(true));
        assert_eq!(updated.allow_insecure_remote_chrome, Some(true));
        assert_eq!(updated.lock_verifier.as_deref(), Some("$argon2id$test"));
        assert_eq!(updated.lock_ttl_hours, Some(12));
        assert_eq!(
            updated.lock_ai_markers.as_deref(),
            Some(&["TEST_MARKER".to_string()][..])
        );

        // The identity comparison still sees the change.
        assert!(crate::config::cleanup::credential_identity_changed(
            &existing, &updated
        ));
    }

    fn configure_args(command: &[&str]) -> ConfigureArgs {
        use clap::Parser;
        let args = Args::try_parse_from(command).unwrap();
        ConfigureArgs::from_command(&args.command).unwrap()
    }

    fn stored_profile() -> Profile {
        Profile {
            azure: AzureConfig {
                tenant_id: "11111111-2222-3333-4444-aaaaaaaaaaaa".into(),
                app_id_uri: "https://stored.example/app".into(),
                default_role_arn: Some("arn:aws:iam::123456789012:role/Stored".into()),
                session_duration: 43200,
            },
            role_arn: Some("arn:aws:iam::123456789012:role/Stored".into()),
            remember_me: Some(true),
            ..Profile::default()
        }
    }

    #[test]
    fn configure_session_duration_is_unset_without_the_flag() {
        let args = configure_args(&["awzars", "configure"]);
        assert_eq!(args.session_duration, None);

        let args = configure_args(&["awzars", "configure", "--session-duration", "7200"]);
        assert_eq!(args.session_duration, Some(7200));
    }

    #[test]
    fn non_interactive_keeps_stored_values_for_absent_flags() {
        let existing = stored_profile();
        let args = ConfigureArgs {
            azure_tenant: None,
            azure_app: None,
            role_arn: None,
            session_duration: None,
            non_interactive: true,
        };

        let (tenant, app, role, duration, remember) =
            non_interactive_values(Some(&existing), &args);

        assert_eq!(tenant, "11111111-2222-3333-4444-aaaaaaaaaaaa");
        assert_eq!(app, "https://stored.example/app");
        assert_eq!(duration, 43200);
        assert_eq!(remember, Some(true));
        // An absent --role-arn still clears the role.
        assert_eq!(role, None);
    }

    #[test]
    fn non_interactive_rerun_with_same_role_keeps_credential_identity() {
        let existing = stored_profile();
        let args = ConfigureArgs {
            azure_tenant: None,
            azure_app: None,
            role_arn: existing.role_arn.clone(),
            session_duration: None,
            non_interactive: true,
        };

        let (tenant_id, app_id_uri, role_arn, session_duration, remember_me) =
            non_interactive_values(Some(&existing), &args);
        let azure = AzureConfig {
            tenant_id,
            app_id_uri,
            default_role_arn: role_arn.clone(),
            session_duration,
        };
        let updated = build_profile(Some(&existing), azure, role_arn, remember_me);

        assert_eq!(updated.azure.session_duration, 43200);
        assert_eq!(updated.remember_me, Some(true));
        assert!(!crate::config::cleanup::credential_identity_changed(
            &existing, &updated
        ));
    }

    #[test]
    fn non_interactive_flags_override_stored_values() {
        let existing = stored_profile();
        let args = ConfigureArgs {
            azure_tenant: Some("11111111-2222-3333-4444-bbbbbbbbbbbb".into()),
            azure_app: Some("https://new.example/app".into()),
            role_arn: Some("arn:aws:iam::123456789012:role/New".into()),
            session_duration: Some(900),
            non_interactive: true,
        };

        let (tenant, app, role, duration, remember) =
            non_interactive_values(Some(&existing), &args);

        assert_eq!(tenant, "11111111-2222-3333-4444-bbbbbbbbbbbb");
        assert_eq!(app, "https://new.example/app");
        assert_eq!(role.as_deref(), Some("arn:aws:iam::123456789012:role/New"));
        assert_eq!(duration, 900);
        assert_eq!(remember, Some(true));
    }

    #[test]
    fn non_interactive_new_profile_uses_defaults() {
        let args = ConfigureArgs {
            azure_tenant: None,
            azure_app: None,
            role_arn: None,
            session_duration: None,
            non_interactive: true,
        };

        let (tenant, app, role, duration, remember) = non_interactive_values(None, &args);

        assert_eq!(tenant, "");
        assert_eq!(app, "");
        assert_eq!(role, None);
        assert_eq!(duration, 3600);
        assert_eq!(remember, None);
    }

    #[test]
    fn build_profile_new_profile_uses_defaults() {
        let azure = AzureConfig {
            tenant_id: "tenant".into(),
            app_id_uri: "https://example/app".into(),
            default_role_arn: None,
            session_duration: 3600,
        };

        let created = build_profile(None, azure, None, Some(true));

        assert_eq!(created.azure.tenant_id, "tenant");
        assert_eq!(created.remember_me, Some(true));
        assert_eq!(created.role_arn, None);
        assert_eq!(created.region, None);
        assert_eq!(created.principal_arn, None);
        assert_eq!(created.headless, None);
        assert_eq!(created.no_sandbox, None);
        assert_eq!(created.allow_insecure_remote_chrome, None);
        assert_eq!(created.lock_verifier, None);
        assert_eq!(created.lock_ttl_hours, None);
        assert_eq!(created.lock_ai_markers, None);
    }
}
