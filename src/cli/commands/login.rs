//! Login command implementation

use crate::auth::aws::sts::exchange_saml_for_credentials;
use crate::auth::azure::saml::SamlAssertion;
use crate::auth::credentials::CredentialRefreshGuard;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialScope {
    Profile,
    Request,
}

impl CredentialScope {
    fn for_login(arguments: &LoginArgs) -> Self {
        if arguments.role_arn.is_some()
            || arguments.azure_tenant.is_some()
            || arguments.azure_app.is_some()
        {
            Self::Request
        } else {
            Self::Profile
        }
    }

    fn load(
        self,
        profile: &str,
        session_duration: i32,
        force_refresh: bool,
    ) -> Result<Option<CredentialProcessOutput>> {
        crate::auth::credentials::try_load_credentials(
            profile,
            session_duration,
            force_refresh || self == Self::Request,
        )
    }

    fn persist(self, credentials: &CredentialProcessOutput, profile: &str) -> Result<()> {
        match self {
            Self::Profile => persist_credentials(credentials, profile),
            Self::Request => Ok(()),
        }
    }
}

/// Parameters for the shared login/authentication flow.
pub struct LoginParams {
    pub quiet: bool,
    pub profile_name: String,
    pub tenant_id: String,
    pub app_id_uri: String,
    /// If None and multiple roles are available, opens TUI selector.
    pub role_arn: Option<String>,
    /// AWS region for the STS endpoint. Sourced from the awzars profile's
    /// `region`; `None` defers to the AWS default chain, then `us-east-1`.
    pub region: Option<String>,
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

/// Perform the login flow: browser → SAML → role selection → STS → return credentials.
pub async fn perform_login(params: &LoginParams) -> Result<LoginOutcome> {
    let sign_in = sign_in(params).await?;
    let role_arn = pick_role(&sign_in.assertion, params.role_arn.as_deref())?;
    exchange_for_credentials(params, &sign_in, role_arn).await
}

/// A completed browser sign-in: the raw SAML response and its parsed form.
struct SamlSignIn {
    response: zeroize::Zeroizing<String>,
    assertion: SamlAssertion,
}

/// Drive the browser through Azure AD and parse the resulting SAML assertion.
async fn sign_in(params: &LoginParams) -> Result<SamlSignIn> {
    let mut browser = launch_browser_for_login(params).await?;

    // Extract SAML then close the browser immediately — avoids spurious CDP
    // warnings and prevents the AWS role-selection page from appearing live
    // alongside the terminal TUI selector.
    let saml_result = authenticate(&mut browser, params).await;
    browser.shutdown().await;
    let response = saml_result?;

    let assertion = SamlAssertion::parse(&response, &params.tenant_id, &params.app_id_uri)?;
    Ok(SamlSignIn {
        response,
        assertion,
    })
}

/// Exchange the SAML assertion for credentials of `role_arn` via STS.
async fn exchange_for_credentials(
    params: &LoginParams,
    sign_in: &SamlSignIn,
    role_arn: String,
) -> Result<LoginOutcome> {
    let principal_arn = sign_in
        .assertion
        .principal_for_role(&role_arn)
        .ok_or_else(|| AwzarsError::Saml(format!("Principal not found for role: {}", role_arn)))?;

    tracing::info!("Exchanging SAML assertion for AWS credentials");
    let credentials = exchange_saml_for_credentials(
        &sign_in.response,
        &role_arn,
        &principal_arn,
        params.session_duration,
        params.region.clone(),
    )
    .await?;

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

    // Use a cookie store from a prior remembered login if one exists,
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

    let mut browser = AzureLoginBrowser::new(
        params.headless,
        params.no_sandbox,
        remember_me_for_launch,
        &params.profile_name,
        params.allow_insecure_remote_chrome,
    )
    .await?;
    browser.set_quiet(params.quiet);
    Ok(browser)
}

/// Drive the browser through Azure AD login and return the SAML response.
/// Persists session cookies for future local re-auth with --remember-me.
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

    if params.remember_me {
        if let Err(e) = browser.save_cookies().await {
            tracing::warn!("Failed to save cookies for local re-auth: {}", e);
        }
    }

    Ok(saml_response)
}

/// Resolve the role ARN to use from the SAML assertion.
///
/// An explicit role override wins (its principal is checked during the STS
/// exchange). Otherwise fall back to the interactive TUI role selector
/// (auto-selects when only one role is available).
fn pick_role(assertion: &SamlAssertion, role_override: Option<&str>) -> Result<String> {
    if let Some(role) = role_override {
        return Ok(role.to_string());
    }
    let roles = assertion.roles();
    if roles.is_empty() {
        return Err(AwzarsError::NoRolesAvailable);
    }
    RoleSelector::new(roles)
        .select()?
        .ok_or(AwzarsError::NoRolesAvailable)
}

/// Whether `pick_role` will wait for a human in the TUI selector.
fn role_pick_is_interactive(assertion: &SamlAssertion, role_override: Option<&str>) -> bool {
    role_override.is_none() && assertion.roles().len() > 1
}

/// Write fresh credentials to both the in-process cache and the OS
/// keyring so subsequent calls (and subsequent processes) skip the
/// browser flow.
pub(super) fn persist_credentials(
    credentials: &CredentialProcessOutput,
    profile: &str,
) -> Result<()> {
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

    // A cache hit needs neither the refresh lock nor any prompt, so it never
    // waits behind another process's browser sign-in (#23).
    let credential_scope = CredentialScope::for_login(&login_args);
    let session_duration = profile.azure.session_duration;
    let force_refresh = login_args.refresh_requested();
    if let Some(creds) = credential_scope.load(&args.profile, session_duration, force_refresh)? {
        return output_credentials(&creds, &login_args, args.quiet);
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

    // Resolve remember_me: CLI flag > profile config > prompt. The prompt runs
    // before the refresh lock is taken so it never blocks other refreshes.
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
        quiet: args.quiet,
        profile_name: args.profile.clone(),
        tenant_id: tenant_id.clone(),
        app_id_uri: app_id_uri.clone(),
        role_arn,
        region: profile.region.clone(),
        session_duration: login_args.resolved_session_duration(&profile.azure),
        headless: login_args.headless,
        no_sandbox: login_args.no_sandbox,
        remember_me,
        allow_insecure_remote_chrome: login_args.allow_insecure_remote_chrome,
    };

    // Identity overrides (request scope) neither read nor write the profile's
    // stored credentials, so they do not take the profile's refresh lock.
    let mut refresh_guard = None;
    if credential_scope == CredentialScope::Profile {
        let (guard, refreshed) =
            lock_and_recheck(&args.profile, session_duration, force_refresh).await?;
        if let Some(creds) = refreshed {
            return output_credentials(&creds, &login_args, args.quiet);
        }
        refresh_guard = Some(guard);
    }

    let sign_in = sign_in(&params).await?;
    let role_arn = if role_pick_is_interactive(&sign_in.assertion, params.role_arn.as_deref()) {
        // Never hold the lock while a human picks a role: every other refresh
        // of this profile would wait on the selector (#23).
        drop(refresh_guard.take());
        let role_arn = pick_role(&sign_in.assertion, None)?;
        if credential_scope == CredentialScope::Profile {
            let (guard, refreshed) =
                lock_and_recheck(&args.profile, session_duration, force_refresh).await?;
            if let Some(creds) = refreshed {
                // Another login stored credentials while the role was being
                // chosen. Reuse them when they are for the same role; otherwise
                // the explicit choice made here replaces them, visibly.
                if configured_role(&args.profile)?.as_deref() == Some(role_arn.as_str()) {
                    return output_credentials(&creds, &login_args, args.quiet);
                }
                tracing::warn!(
                    "Another awzars login stored credentials for profile '{}' while the \
                     role was being chosen; replacing them with the chosen role",
                    args.profile
                );
            }
            refresh_guard = Some(guard);
        }
        role_arn
    } else {
        pick_role(&sign_in.assertion, params.role_arn.as_deref())?
    };

    let outcome = exchange_for_credentials(&params, &sign_in, role_arn).await?;
    credential_scope.persist(&outcome.credentials, &args.profile)?;

    // Save the interactively-picked role so subsequent non-interactive
    // credential-process calls don't fail with "role_arn not set".
    if credential_scope == CredentialScope::Profile && !role_was_supplied {
        if let Err(e) = persist_picked_role(&args.profile, &outcome.role_arn) {
            tracing::warn!("Could not save picked role to profile config: {}", e);
        }
    }

    output_credentials(&outcome.credentials, &login_args, args.quiet)?;
    drop(refresh_guard);
    Ok(())
}

/// Take the profile's refresh lock, then re-check stored credentials: another
/// process may have refreshed them while this one prompted or waited.
async fn lock_and_recheck(
    profile: &str,
    session_duration: i32,
    force_refresh: bool,
) -> Result<(CredentialRefreshGuard, Option<CredentialProcessOutput>)> {
    let guard = CredentialRefreshGuard::acquire(profile).await?;
    let stored = CredentialScope::Profile.load(profile, session_duration, force_refresh)?;
    Ok((guard, stored))
}

/// The role ARN currently saved in the profile's configuration.
fn configured_role(profile_name: &str) -> Result<Option<String>> {
    Ok(Config::load()?.get_profile(profile_name)?.role_arn.clone())
}

fn output_credentials(
    creds: &CredentialProcessOutput,
    login_args: &LoginArgs,
    quiet: bool,
) -> Result<()> {
    if login_args.credential_process {
        write_credentials_json(creds)?;
        return Ok(());
    }
    print_credentials(creds, login_args.output, login_args.show_secrets, quiet)
}

/// Save `role_arn` into the named profile in the configured `config.toml`.
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
    quiet: bool,
) -> Result<()> {
    if quiet && !matches!(format, OutputFormat::Json) {
        return Ok(());
    }
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
    use super::*;

    #[tokio::test]
    async fn quiet_login_suppresses_human_output_but_keeps_json() {
        use clap::Parser;
        if let Ok(case) = std::env::var("AWZARS_QUIET_LOGIN_TEST") {
            let directory = std::env::var("AWZARS_QUIET_LOGIN_DIRECTORY").unwrap();
            config::set_config_dir_override(&directory).unwrap();
            let mut config = Config::default();
            config.set_profile(
                "default",
                crate::config::Profile {
                    lock_ai_markers: Some(vec![]),
                    ..Default::default()
                },
            );
            config.save().unwrap();
            CacheHandle::new("default")
                .unwrap()
                .store(&credentials("cached-output"))
                .unwrap();
            let mut arguments = vec!["awzars", "login"];
            if case != "normal" {
                arguments.push("--quiet");
            }
            match case.as_str() {
                "json" => arguments.extend(["--output", "json"]),
                "protocol" => arguments.push("--credential-process"),
                _ => {}
            }
            execute(&Args::try_parse_from(arguments).unwrap())
                .await
                .unwrap();
            return;
        }
        for case in ["normal", "quiet", "json", "protocol"] {
            let directory = tempfile::tempdir().unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cli::commands::login::tests::quiet_login_suppresses_human_output_but_keeps_json", "--nocapture"])
                .env("AWZARS_QUIET_LOGIN_TEST", case)
                .env("AWZARS_QUIET_LOGIN_DIRECTORY", directory.path())
                .env_remove("AWZARS_AZURE_TENANT_ID")
                .env_remove("AWZARS_AZURE_APP_ID_URI")
                .output().unwrap();
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(stdout.contains("AWS Credentials:"), case == "normal");
            assert_eq!(
                stdout.contains("\"Version\""),
                matches!(case, "json" | "protocol")
            );
            if case == "quiet" {
                assert!(!stdout.contains("cached-output"));
            }
        }
    }

    #[tokio::test]
    async fn cached_login_does_not_wait_for_the_refresh_lock() {
        use clap::Parser;
        if let Ok(directory) = std::env::var("AWZARS_LOCKED_LOGIN_DIRECTORY") {
            config::set_config_dir_override(&directory).unwrap();
            let mut config = Config::default();
            config.set_profile(
                "default",
                crate::config::Profile {
                    lock_ai_markers: Some(vec![]),
                    ..Default::default()
                },
            );
            config.save().unwrap();
            CacheHandle::new("default")
                .unwrap()
                .store(&credentials("cached-output"))
                .unwrap();
            let arguments = ["awzars", "login", "--credential-process"];
            execute(&Args::try_parse_from(arguments).unwrap())
                .await
                .unwrap();
            return;
        }

        // Hold the profile's refresh lock the way a login waiting for browser
        // sign-in would, then run a login that has valid cached credentials.
        let directory = tempfile::tempdir().unwrap();
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.path().join("refresh-default.lock"))
            .unwrap();
        lock.lock().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cli::commands::login::tests::cached_login_does_not_wait_for_the_refresh_lock",
                "--nocapture",
            ])
            .env("AWZARS_LOCKED_LOGIN_DIRECTORY", directory.path())
            .env("AWZARS_REFRESH_LOCK_TIMEOUT_SECS", "600")
            .env_remove("AWZARS_AZURE_TENANT_ID")
            .env_remove("AWZARS_AZURE_APP_ID_URI")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() > deadline {
                child.kill().unwrap();
                panic!("a login with cached credentials waited on the refresh lock");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("\"Version\""));
        drop(lock);
    }

    fn login_arguments() -> LoginArgs {
        LoginArgs {
            azure_tenant: None,
            azure_app: None,
            role_arn: None,
            session_duration: None,
            headless: false,
            no_sandbox: false,
            force_refresh: false,
            output: OutputFormat::Text,
            credential_process: false,
            show_secrets: false,
            remember_me: false,
            allow_insecure_remote_chrome: false,
            session_remember: false,
        }
    }

    fn credentials(access_key_id: &str) -> CredentialProcessOutput {
        CredentialProcessOutput {
            version: 1,
            access_key_id: access_key_id.to_string(),
            secret_access_key: "test-secret".to_string(),
            session_token: Some("test-token".to_string()),
            expiration: Some((chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339()),
        }
    }

    #[test]
    fn identity_overrides_neither_reuse_nor_replace_profile_credentials() {
        for override_index in 0..3 {
            let mut arguments = login_arguments();
            match override_index {
                0 => arguments.role_arn = Some("arn:aws:iam::123456789012:role/Other".into()),
                1 => arguments.azure_tenant = Some("11111111-2222-3333-4444-555555555555".into()),
                _ => arguments.azure_app = Some("https://example.com/other-app".into()),
            }
            let profile = format!("override_{}", uuid::Uuid::new_v4());
            let cache = CacheHandle::new(&profile).unwrap();
            cache.store(&credentials("original-role")).unwrap();

            let scope = CredentialScope::for_login(&arguments);
            assert_eq!(scope, CredentialScope::Request);
            assert!(scope.load(&profile, 3600, false).unwrap().is_none());
            scope
                .persist(&credentials("override-role"), &profile)
                .unwrap();
            assert_eq!(
                cache
                    .get_valid_credentials(3600)
                    .unwrap()
                    .unwrap()
                    .access_key_id,
                "original-role"
            );
            cache.clear().unwrap();
        }
    }

    #[test]
    fn ordinary_login_reuses_profile_credentials_unless_refreshing() {
        let profile = format!("ordinary_{}", uuid::Uuid::new_v4());
        let cache = CacheHandle::new(&profile).unwrap();
        cache.store(&credentials("original-role")).unwrap();
        let scope = CredentialScope::for_login(&login_arguments());
        assert_eq!(scope, CredentialScope::Profile);
        assert_eq!(
            scope
                .load(&profile, 3600, false)
                .unwrap()
                .unwrap()
                .access_key_id,
            "original-role"
        );
        assert!(scope.load(&profile, 3600, true).unwrap().is_none());
        cache.clear().unwrap();
    }

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
