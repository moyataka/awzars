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
        }
    }

    Ok(())
}
