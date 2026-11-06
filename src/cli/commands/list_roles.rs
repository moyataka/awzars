//! List roles command implementation

use crate::auth::azure::saml::SamlAssertion;
use crate::browser::chromium::AzureLoginBrowser;
use crate::cli::args::{Args, OutputFormat};
use crate::config::Config;
use crate::error::{AwzarsError, Result};

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
    tracing::info!("Fetching SAML assertion to list roles");
    let has_remote = std::env::var("CHROME_REMOTE_URL").is_ok();
    let (headless, no_sandbox, persistent_profile) =
        browser_options(&args.profile, profile, has_remote);
    use std::io::IsTerminal;
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let saml_response =
        sign_in_with_fallback(headless, has_remote, interactive, |headless| async move {
            let mut browser = AzureLoginBrowser::new(
                headless,
                no_sandbox,
                persistent_profile,
                &args.profile,
                false,
            )
            .await?;
            browser.set_quiet(args.quiet);
            let result = crate::util::interrupt::until_interrupted(async {
                let response = browser
                    .login_and_get_saml(&profile.azure.tenant_id, &profile.azure.app_id_uri)
                    .await?;
                if profile.remember_me.unwrap_or(false) {
                    if let Err(error) = browser.save_cookies().await {
                        tracing::warn!("Failed to save the renewed browser session: {error}");
                    }
                }
                Ok(response)
            })
            .await;
            browser.shutdown().await;
            result
        })
        .await
        .map_err(|error| explain_headless_timeout(error, headless, has_remote, &args.profile))?;

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

async fn sign_in_with_fallback<T, Operation: std::future::Future<Output = Result<T>>>(
    headless: bool,
    remote: bool,
    interactive: bool,
    mut sign_in: impl FnMut(bool) -> Operation,
) -> Result<T> {
    match sign_in(headless).await {
        Err(AwzarsError::Browser(message))
            if headless && !remote && interactive && message == "Authentication timed out" =>
        {
            tracing::warn!("The saved session expired; opening a browser to sign in again");
            sign_in(false).await
        }
        result => result,
    }
}

/// Headless, no-sandbox and persistent-profile settings for the list-roles
/// browser.
///
/// Headless only when a session can be reused: a remote Chrome, a saved
/// cookie store, or a persistent Chrome profile with `remember_me`.
/// Otherwise a visible browser opens so the user can sign in. `no_sandbox`
/// comes from the profile. The user-data-dir follows `login`: a saved
/// cookie store goes into a temporary profile, not the persistent one.
fn browser_options(
    profile_name: &str,
    profile: &crate::config::Profile,
    has_remote: bool,
) -> (bool, bool, bool) {
    let remember_me = profile.remember_me.unwrap_or(false);
    let has_cookie_store = AzureLoginBrowser::has_cookie_store(profile_name);
    let chromium_dir_exists = crate::config::chromium_data_dir(profile_name)
        .map(|p| p.exists())
        .unwrap_or(false);
    let headless = has_remote || has_cookie_store || (remember_me && chromium_dir_exists);
    (
        headless,
        profile.no_sandbox.unwrap_or(false),
        crate::cli::commands::login::use_persistent_profile(has_cookie_store, remember_me),
    )
}

/// A local headless sign-in (not a remote Chrome) that times out usually
/// means the saved browser session has expired. Say how to sign in again.
fn explain_headless_timeout(
    error: AwzarsError,
    headless: bool,
    has_remote: bool,
    profile: &str,
) -> AwzarsError {
    match error {
        AwzarsError::Browser(message)
            if headless && !has_remote && message == "Authentication timed out" =>
        {
            AwzarsError::Browser(format!(
                "Authentication timed out. The saved browser session for profile '{p}' \
                 may have expired: run `awzars login --profile {p}` to sign in again, \
                 then run list-roles again.",
                p = profile
            ))
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_interactive_session_retries_once_in_a_visible_browser() {
        let mut modes = Vec::new();
        let result = sign_in_with_fallback(true, false, true, |headless| {
            modes.push(headless);
            std::future::ready(if headless {
                Err(AwzarsError::Browser("Authentication timed out".into()))
            } else {
                Ok("renewed assertion")
            })
        })
        .await
        .unwrap();
        assert_eq!(result, "renewed assertion");
        assert_eq!(modes, [true, false]);
    }

    #[tokio::test]
    async fn fallback_preserves_remote_noninteractive_and_other_failures() {
        for (headless, remote, interactive, message) in [
            (true, true, true, "Authentication timed out"),
            (true, false, false, "Authentication timed out"),
            (false, false, true, "Authentication timed out"),
            (true, false, true, "Invalid SAML"),
        ] {
            let mut attempts = 0;
            let result: Result<()> = sign_in_with_fallback(headless, remote, interactive, |_| {
                attempts += 1;
                std::future::ready(Err(AwzarsError::Browser(message.into())))
            })
            .await;
            assert!(result.is_err());
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn browser_options_keep_the_headless_rule_and_use_profile_no_sandbox() {
        const DIRECTORY: &str = "AWZARS_LIST_ROLES_BROWSER_OPTIONS_DIRECTORY";
        let Ok(directory) = std::env::var(DIRECTORY) else {
            // Runs in a child so the config directory override stays out of
            // this process.
            let directory = tempfile::tempdir().unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cli::commands::list_roles::tests::browser_options_keep_the_headless_rule_and_use_profile_no_sandbox",
                ])
                .env(DIRECTORY, directory.path())
                .output()
                .unwrap();
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        };
        crate::config::set_config_dir_override(&directory).unwrap();
        let mut profile = crate::config::Profile::new(crate::config::AzureConfig::new(
            "11111111-2222-3333-4444-aaaaaaaaaaaa",
            "https://signin.aws.amazon.com/saml",
        ));
        profile.no_sandbox = Some(true);

        // No saved session: a visible browser, so the user can sign in.
        assert_eq!(
            browser_options("default", &profile, false),
            (false, true, false)
        );
        // A remote Chrome stays headless.
        assert_eq!(
            browser_options("default", &profile, true),
            (true, true, false)
        );

        // A persistent Chrome profile is reused headless only with
        // remember_me, and remember_me alone needs that profile to exist.
        profile.remember_me = Some(true);
        assert_eq!(
            browser_options("default", &profile, false),
            (false, true, true)
        );
        let store = crate::config::chromium_data_dir("default")
            .unwrap()
            .join("cookies.enc");
        std::fs::create_dir_all(store.parent().unwrap()).unwrap();
        assert_eq!(
            browser_options("default", &profile, false),
            (true, true, true)
        );
        profile.remember_me = None;
        assert_eq!(
            browser_options("default", &profile, false),
            (false, true, false)
        );

        // A cookie store from an earlier remembered sign-in: headless.
        std::fs::write(&store, b"").unwrap();
        assert_eq!(
            browser_options("default", &profile, false),
            (true, true, false)
        );

        profile.no_sandbox = None;
        assert_eq!(
            browser_options("default", &profile, false),
            (true, false, false)
        );
    }

    #[test]
    fn browser_options_use_a_temporary_profile_when_a_cookie_store_exists() {
        const DIRECTORY: &str = "AWZARS_LIST_ROLES_PERSISTENT_PROFILE_DIRECTORY";
        let Ok(directory) = std::env::var(DIRECTORY) else {
            // Runs in a child so the config directory override stays out of
            // this process.
            let directory = tempfile::tempdir().unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cli::commands::list_roles::tests::browser_options_use_a_temporary_profile_when_a_cookie_store_exists",
                ])
                .env(DIRECTORY, directory.path())
                .output()
                .unwrap();
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        };
        crate::config::set_config_dir_override(&directory).unwrap();
        let mut profile = crate::config::Profile::new(crate::config::AzureConfig::new(
            "11111111-2222-3333-4444-aaaaaaaaaaaa",
            "https://signin.aws.amazon.com/saml",
        ));
        profile.remember_me = Some(true);

        // remember_me without a cookie store: the persistent profile.
        assert!(browser_options("default", &profile, false).2);

        // With a cookie store, as in `login`: a temporary profile, so another
        // Chrome holding the persistent one can't block the launch.
        let store = crate::config::chromium_data_dir("default")
            .unwrap()
            .join("cookies.enc");
        std::fs::create_dir_all(store.parent().unwrap()).unwrap();
        std::fs::write(&store, b"").unwrap();
        assert!(!browser_options("default", &profile, false).2);
    }

    #[test]
    fn local_headless_timeout_points_to_login() {
        let timeout = || AwzarsError::Browser("Authentication timed out".to_string());
        let AwzarsError::Browser(message) =
            explain_headless_timeout(timeout(), true, false, "work")
        else {
            panic!("expected a browser error");
        };
        assert!(
            message.contains("`awzars login --profile work`"),
            "{message}"
        );

        // A visible or remote browser, and other errors, are left as they are.
        for error in [
            explain_headless_timeout(timeout(), false, false, "work"),
            explain_headless_timeout(timeout(), true, true, "work"),
            explain_headless_timeout(
                AwzarsError::Browser("other".to_string()),
                true,
                false,
                "work",
            ),
        ] {
            let AwzarsError::Browser(message) = error else {
                panic!("expected a browser error");
            };
            assert!(!message.contains("awzars login"), "{message}");
        }
    }

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
