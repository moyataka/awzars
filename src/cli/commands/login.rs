//! Login command implementation

use crate::auth::aws::sts::exchange_saml_for_credentials;
use crate::auth::azure::saml::SamlAssertion;
use crate::browser::chromium::AzureLoginBrowser;
use crate::cli::args::{Args, LoginArgs, OutputFormat};
use crate::config::{self, Config};
use crate::credential_process::protocol::{
    write_credentials_json, write_credentials_json_pretty, CredentialProcessOutput,
};
use crate::error::{AwzarsError, Result};
use crate::storage::cache::CacheHandle;
use crate::storage::keyring::KeyringStorage;
use crate::tui::app::RoleSelector;
use dialoguer::Confirm;

/// Parameters for the shared login/authentication flow.
pub struct LoginParams {
    pub profile_name: String,
    pub tenant_id: String,
    pub app_id_uri: String,
    /// If None and multiple roles are available, opens TUI selector.
    pub role_arn: Option<String>,
    pub session_duration: i32,
    pub headless: bool,
    pub no_sandbox: bool,
    pub remember_me: bool,
    pub allow_insecure_remote_chrome: bool,
}

/// Result of a successful login: credentials plus the role ARN that was
/// actually used for STS (which may have come from `params.role_arn` or
/// from the interactive selector).
pub struct LoginOutcome {
    pub credentials: CredentialProcessOutput,
    pub role_arn: String,
}

/// Perform the full login flow: browser → SAML → role selection → STS → cache → return credentials.
pub async fn perform_login(params: &LoginParams) -> Result<LoginOutcome> {
    let mut browser = launch_browser_for_login(params).await?;

    // Extract SAML then close the browser immediately — avoids spurious CDP
    // warnings and prevents the AWS role-selection page from appearing live
    // alongside the terminal TUI selector.
    let saml_result = authenticate(&mut browser, params).await;
    browser.shutdown().await;
    let saml_response = saml_result?;

    let assertion =
        SamlAssertion::parse(&saml_response, &params.tenant_id, &params.app_id_uri)?;
    let (role_arn, principal_arn) = select_role(&assertion, params.role_arn.as_deref())?;

    tracing::info!("Exchanging SAML assertion for AWS credentials");
    let credentials = exchange_saml_for_credentials(
        &saml_response,
        &role_arn,
        &principal_arn,
        params.session_duration,
    )
    .await?;

    persist_credentials(&credentials, &params.profile_name)?;
    Ok(LoginOutcome {
        credentials,
        role_arn,
    })
}

/// Set up an `AzureLoginBrowser` for `perform_login`. Picks between
/// persistent user-data-dir and cookie-store-injection-into-temp-dir to
/// avoid SingletonLock conflicts when another Chrome holds the profile.
async fn launch_browser_for_login(params: &LoginParams) -> Result<AzureLoginBrowser> {
    if params.headless && params.remember_me {
        let chromium_dir = config::chromium_data_dir(&params.profile_name)?;
        if !chromium_dir.exists() {
            tracing::warn!(
                "Headless mode requested, but no persistent browser session found at {}",
                chromium_dir.display()
            );
            tracing::warn!("Run `awzars login --remember-me` first to establish a session.");
        }
    }

    // Use a cookie store (from a prior remote-Chrome login) if one exists,
    // even if --remember-me was passed: a persistent user-data-dir would
    // race with any other Chrome holding the profile via SingletonLock.
    let use_cookie_store = AzureLoginBrowser::has_cookie_store(&params.profile_name);
    let remember_me_for_launch = if use_cookie_store {
        false
    } else {
        params.remember_me
    };

    // SECURITY: tenant IDs are PII-adjacent (aid targeted phishing). Only the
    // first 8 chars appear in logs at any verbosity, so -vvv output is safe
    // to paste into bug reports.
    tracing::info!(
        "Starting Azure AD login for tenant: {}…",
        params.tenant_id.get(..8).unwrap_or("????????")
    );

    AzureLoginBrowser::new(
        params.headless,
        params.no_sandbox,
        remember_me_for_launch,
        &params.profile_name,
        params.allow_insecure_remote_chrome,
    )
    .await
}

/// Drive the browser through Azure AD login and return the SAML response.
/// Persists session cookies for future local re-auth when running against
/// a remote Chrome with --remember-me.
///
/// The SAML response is returned in `Zeroizing<String>` so the heap copy is
/// wiped on drop. `SamlAssertion::parse` accepts `&str` and deref-coerces
/// from the wrapper, so the call site syntax is unchanged.
async fn authenticate(
    browser: &mut AzureLoginBrowser,
    params: &LoginParams,
) -> Result<zeroize::Zeroizing<String>> {
    let saml_response = browser
        .login_and_get_saml(&params.tenant_id, &params.app_id_uri)
        .await?;

    if browser.is_remote() && params.remember_me {
        if let Err(e) = browser.save_cookies().await {
            tracing::warn!("Failed to save cookies for local re-auth: {}", e);
        }
    }

    Ok(saml_response)
}

/// Resolve `(role_arn, principal_arn)` from the SAML assertion.
///
/// If the caller supplied an explicit role override, validate that the
/// assertion has a matching principal for it. Otherwise fall back to the
/// interactive TUI role selector (auto-selects when only one role is
/// available).
fn select_role(assertion: &SamlAssertion, role_override: Option<&str>) -> Result<(String, String)> {
    let role_arn = match role_override {
        Some(r) => r.to_string(),
        None => {
            let roles = assertion.roles();
            if roles.is_empty() {
                return Err(AwzarsError::NoRolesAvailable);
            }
            RoleSelector::new(roles)
                .select()?
                .ok_or(AwzarsError::NoRolesAvailable)?
        }
    };

    let principal_arn = assertion
        .principal_for_role(&role_arn)
        .ok_or_else(|| AwzarsError::Saml(format!("Principal not found for role: {}", role_arn)))?;

    Ok((role_arn, principal_arn))
}

/// Write fresh credentials to both the in-process cache and the OS
/// keyring so subsequent calls (and subsequent processes) skip the
/// browser flow.
fn persist_credentials(credentials: &CredentialProcessOutput, profile: &str) -> Result<()> {
    CacheHandle::new(profile)?.store(credentials)?;
    KeyringStorage::new(profile)?.store_credentials(credentials)?;
    Ok(())
}

/// Execute the login command
pub async fn execute(args: &Args) -> Result<()> {
    let login_args = LoginArgs::from_command(&args.command)
        .ok_or_else(|| AwzarsError::Config("Invalid command".to_string()))?;

    // Load configuration
    let config = Config::load()?;
    let profile = config.get_profile(&args.profile)?;

    // Gate: password lock and/or AI consent. Runs before cache lookup so
    // even cached credentials cannot be returned to an AI context that has
    // not been explicitly approved. `--session-remember` persists the AI
    // consent answer for the rest of the terminal session; default is to
    // ask every invocation.
    crate::auth::lock::enforce(&args.profile, profile, true, login_args.session_remember)?;

    // Check cache then keyring before driving a browser login.
    if let Some(creds) =
        crate::auth::credentials::try_load_credentials(&args.profile, login_args.force_refresh)?
    {
        if login_args.credential_process {
            write_credentials_json(&creds)?;
            return Ok(());
        }
        print_credentials(&creds, login_args.output, login_args.show_secrets)?;
        return Ok(());
    }

    // Build Azure configuration (allow CLI overrides)
    let tenant_id = login_args
        .azure_tenant
        .as_ref()
        .unwrap_or(&profile.azure.tenant_id);
    let app_id_uri = login_args
        .azure_app
        .as_ref()
        .unwrap_or(&profile.azure.app_id_uri);

    // Resolve remember_me: CLI flag > profile config > prompt
    let remember_me = if login_args.remember_me {
        true
    } else if let Some(rm) = profile.remember_me {
        rm
    } else {
        let answer = Confirm::new()
            .with_prompt("Stay logged in? (skip re-authentication while refreshing)")
            .default(false)
            .interact()
            .map_err(|e| AwzarsError::Dialog(e.to_string()))?;

        // Save preference to profile config
        let mut config = Config::load()?;
        if let Ok(p) = config.get_profile_mut(&args.profile) {
            p.remember_me = Some(answer);
            config.save()?;
        }
        answer
    };

    // Resolve role_arn: CLI arg > profile config
    let role_arn = login_args.role_arn.clone().or(profile.role_arn.clone());
    let role_was_supplied = role_arn.is_some();

    let params = LoginParams {
        profile_name: args.profile.clone(),
        tenant_id: tenant_id.clone(),
        app_id_uri: app_id_uri.clone(),
        role_arn,
        session_duration: login_args.session_duration,
        headless: login_args.headless,
        no_sandbox: login_args.no_sandbox,
        remember_me,
        allow_insecure_remote_chrome: login_args.allow_insecure_remote_chrome,
    };

    let outcome = perform_login(&params).await?;

    // Save the interactively-picked role so subsequent non-interactive
    // credential-process calls don't fail with "role_arn not set".
    if !role_was_supplied {
        if let Err(e) = persist_picked_role(&args.profile, &outcome.role_arn) {
            tracing::warn!("Could not save picked role to profile config: {}", e);
        }
    }

    // Output
    if login_args.credential_process {
        write_credentials_json(&outcome.credentials)?;
    } else {
        print_credentials(
            &outcome.credentials,
            login_args.output,
            login_args.show_secrets,
        )?;
    }

    Ok(())
}

/// Save `role_arn` into the named profile in `~/.awzars/config.toml`.
///
/// Best-effort: callers log and continue on failure rather than fail the
/// whole login (credentials are already cached at this point).
fn persist_picked_role(profile_name: &str, role_arn: &str) -> Result<()> {
    let mut config = Config::load()?;
    let profile = config.get_profile_mut(profile_name)?;
    profile.role_arn = Some(role_arn.to_string());
    config.save()
}

fn print_credentials(
    creds: &CredentialProcessOutput,
    format: OutputFormat,
    show_secrets: bool,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            if show_secrets {
                write_credentials_json_pretty(creds)?;
            } else {
                // Build the masked struct directly from the source instead
                // of `creds.clone()` + overwrite. The clone-then-overwrite
                // pattern leaves the cloned secret on the heap un-zeroed:
                // assigning a new String into the field drops the old one
                // via `String::drop`, which does not scrub.
                let masked = CredentialProcessOutput {
                    version: creds.version,
                    access_key_id: creds.access_key_id.clone(),
                    secret_access_key: mask_secret(&creds.secret_access_key),
                    session_token: creds.session_token.as_deref().map(mask_secret),
                    expiration: creds.expiration.clone(),
                };
                write_credentials_json_pretty(&masked)?;
            }
        }
        OutputFormat::Text | OutputFormat::Table => {
            println!("AWS Credentials:");
            println!("  Access Key ID:     {}", creds.access_key_id);
            if show_secrets {
                println!("  Secret Access Key: {}", creds.secret_access_key);
                if let Some(ref token) = creds.session_token {
                    println!("  Session Token:     {}", token);
                }
            } else {
                println!(
                    "  Secret Access Key: {}",
                    mask_secret(&creds.secret_access_key)
                );
                if let Some(ref token) = creds.session_token {
                    println!("  Session Token:     {}", mask_secret(token));
                }
                println!("  (pass --show-secrets to reveal full values)");
            }
            if let Some(ref expiration) = creds.expiration {
                println!("  Expiration:        {}", expiration);
            }
        }
    }
    Ok(())
}

/// Mask a secret string. Shows the first 4 characters as a "which key is
/// this" hint and replaces the rest with `...`.
///
/// The previous implementation also revealed the trailing 4 characters,
/// which is unnecessary — the Access Key ID (printed in full) already
/// disambiguates between cached profiles, and the trailing tail is a
/// gratuitous information leak in pasted output. Multi-byte boundary safe
/// via `char_indices` so non-ASCII inputs cannot panic.
fn mask_secret(s: &str) -> String {
    if s.len() <= 8 {
        return "****".to_string();
    }
    let prefix_end = s.char_indices().nth(4).map(|(i, _)| i).unwrap_or(s.len());
    format!("{}...", &s[..prefix_end])
}

#[cfg(test)]
mod tests {
    use super::mask_secret;

    #[test]
    fn test_mask_secret_short() {
        assert_eq!(mask_secret(""), "****");
        assert_eq!(mask_secret("abc"), "****");
        assert_eq!(mask_secret("12345678"), "****");
    }

    #[test]
    fn test_mask_secret_long() {
        assert_eq!(mask_secret("abcdefghij"), "abcd...");
        let s = "AKIAIOSFODNN7EXAMPLEKEY1234567890ABCDEF12";
        let masked = mask_secret(s);
        assert!(masked.starts_with("AKIA"));
        assert!(masked.ends_with("..."));
        assert!(!masked.contains("OSFODNN"));
        assert!(!masked.contains("EF12"));
    }

    #[test]
    fn test_mask_secret_multibyte_safe() {
        // Non-ASCII input must not panic. Length is "long enough" by byte
        // count so we exercise the prefix path.
        let s = "αβγδεζηθικλμνξ";
        let masked = mask_secret(s);
        assert!(masked.ends_with("..."));
    }
}
