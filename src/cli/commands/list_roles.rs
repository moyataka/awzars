//! List roles command implementation

use crate::auth::azure::saml::SamlAssertion;
use crate::browser::chromium::AzureLoginBrowser;
use crate::cli::args::{Args, OutputFormat};
use crate::config::Config;
use crate::error::Result;

/// Execute the list-roles command
pub async fn execute(args: &Args) -> Result<()> {
    let (output_format, session_remember) = match &args.command {
        crate::cli::args::Command::ListRoles {
            output,
            session_remember,
        } => (*output, *session_remember),
        _ => {
            return Err(crate::error::AwzarsError::Config(
                "Invalid command".to_string(),
            ))
        }
    };

    // Load configuration
    let config = Config::load()?;
    let profile = config.get_profile(&args.profile)?;

    // Gate: password lock and/or AI consent. list-roles drives a browser
    // login, so we treat it the same as `login` and allow inline prompts.
    // `--session-remember` opts into persisting AI consent.
    crate::auth::lock::enforce(&args.profile, profile, true, session_remember)?;
    profile.validate_app_id_uri(&args.profile)?;

    // Start browser automation.
    // Pre-flight: pick headless only when a session exists (cookie store or
    // persistent Chrome user-data-dir), otherwise launch a visible browser so
    // the user can actually authenticate. Skip the check if CHROME_REMOTE_URL
    // is set — the remote Chrome may already have a live session.
    tracing::info!("Fetching SAML assertion to list roles");
    let remember_me = profile.remember_me.unwrap_or(false);
    let has_remote = std::env::var("CHROME_REMOTE_URL").is_ok();
    let has_cookie_store = AzureLoginBrowser::has_cookie_store(&args.profile);
    let chromium_dir_exists = crate::config::chromium_data_dir(&args.profile)
        .map(|p| p.exists())
        .unwrap_or(false);
    let headless = has_remote || has_cookie_store || (remember_me && chromium_dir_exists);
    let mut browser =
        AzureLoginBrowser::new(headless, false, remember_me, &args.profile, false).await?;
    browser.set_quiet(args.quiet);

    // Perform login and get SAML assertion, then close the browser before
    // parsing — avoids spurious CDP warnings while processing the assertion.
    let saml_result = browser
        .login_and_get_saml(&profile.azure.tenant_id, &profile.azure.app_id_uri)
        .await;
    browser.shutdown().await;
    let saml_response = saml_result?;

    // Parse and validate SAML assertion
    let assertion = SamlAssertion::parse(
        &saml_response,
        &profile.azure.tenant_id,
        &profile.azure.app_id_uri,
    )?;

    // Get roles
    let roles = assertion.roles();
    if args.quiet && !matches!(output_format, OutputFormat::Json) {
        return Ok(());
    }

    // Output
    match output_format {
        OutputFormat::Json => {
            let roles_json: Vec<serde_json::Value> = roles
                .iter()
                .map(|(role, principal)| {
                    serde_json::json!({
                        "role_arn": role,
                        "principal_arn": principal
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&roles_json)?);
        }
        OutputFormat::Table | OutputFormat::Text => {
            println!("Available AWS Roles:");
            println!("{:-<80}", "");
            println!("{:<50} Principal ARN", "Role ARN");
            println!("{:-<80}", "");
            for (role, principal) in &roles {
                println!("{:<50} {}", role, principal);
            }
            println!();
            println!("Total: {} role(s)", roles.len());
            if let Some(configured) = profile
                .role_arn
                .as_deref()
                .filter(|role| assertion.principal_for_role(role).is_none())
            {
                eprintln!(
                    "Note: role {configured} configured for profile '{p}' is not in this \
                     SAML assertion. Run `awzars login --profile {p}` to pick another \
                     role and save it.",
                    p = args.profile
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_stored_app_id_uri_is_a_config_error() {
        use clap::Parser;
        if let Ok(directory) = std::env::var("AWZARS_LIST_ROLES_APP_ID_URI_DIRECTORY") {
            crate::config::set_config_dir_override(&directory).unwrap();
            let mut profile = crate::config::Profile::new(crate::config::AzureConfig::new(
                "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "http://example.com/saml",
            ));
            profile.lock_ai_markers = Some(vec![]);
            let mut config = Config::default();
            config.set_profile("default", profile);
            config.save().unwrap();
            let error = execute(&Args::try_parse_from(["awzars", "list-roles"]).unwrap())
                .await
                .unwrap_err();
            let crate::error::AwzarsError::Config(message) = &error else {
                panic!("expected a config error, got {error:?}");
            };
            assert!(message.contains("app_id_uri"), "{message}");
            return;
        }
        // The child runs `execute`. A `ws://` remote URL without
        // `--allow-insecure-remote-chrome` is refused before connecting, so a
        // missing check fails with a browser error instead of opening Chrome.
        let directory = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cli::commands::list_roles::tests::invalid_stored_app_id_uri_is_a_config_error",
                "--nocapture",
            ])
            .env("AWZARS_LIST_ROLES_APP_ID_URI_DIRECTORY", directory.path())
            .env(
                "CHROME_REMOTE_URL",
                "ws://127.0.0.1:9/devtools/browser/test",
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
