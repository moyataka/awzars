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
use std::io::IsTerminal;

/// How many of the closest roles a missing-role error lists.
const ROLE_SUGGESTION_LIMIT: usize = 5;

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
        identity: &str,
        session_duration: i32,
        force_refresh: bool,
    ) -> Result<Option<CredentialProcessOutput>> {
        crate::auth::credentials::try_load_credentials(
            profile,
            identity,
            session_duration,
            force_refresh || self == Self::Request,
        )
    }

    fn persist(
        self,
        credentials: &CredentialProcessOutput,
        profile: &str,
        identity: &str,
    ) -> Result<()> {
        match self {
            Self::Profile => persist_credentials(credentials, profile, identity),
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
    /// If None, `perform_login` uses the only available role and fails when
    /// there are several (it never prompts).
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
    let role_arn = pick_role(
        &sign_in.assertion,
        params.role_arn.as_deref(),
        &params.profile_name,
    )?;
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
        .ok_or_else(|| {
            role_not_in_assertion(&params.profile_name, &role_arn, &sign_in.assertion.roles())
        })?;

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

/// Where a requested role ARN came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoleSource {
    /// `--role-arn` on the command line: an explicit request, never replaced.
    Override,
    /// The profile's configured `role_arn`.
    Profile,
}

/// How the role for this login is chosen from the assertion's roles.
#[derive(Debug, PartialEq, Eq)]
enum RoleDecision {
    /// The requested role is available.
    Use(String),
    /// Choose from the available roles. `missing` names the configured role
    /// the assertion no longer offers, when that is why a choice is needed.
    Pick { missing: Option<String> },
    /// The requested role is not available and nobody can choose another.
    Fail(String),
    /// No role is requested and nobody can choose one of several.
    Unset,
}

/// Decide how to choose the role. A configured role that the assertion no
/// longer offers falls back to a choice only when someone can make it; an
/// explicit `--role-arn` never does. With no role requested, a single role
/// is used as is and several need someone to choose.
fn resolve_role(
    roles: &[(String, String)],
    requested: Option<&str>,
    source: RoleSource,
    interactive: bool,
) -> RoleDecision {
    let Some(requested) = requested else {
        return if interactive || roles.len() <= 1 {
            RoleDecision::Pick { missing: None }
        } else {
            RoleDecision::Unset
        };
    };
    if roles.iter().any(|(role, _)| role == requested) {
        return RoleDecision::Use(requested.to_string());
    }
    if source == RoleSource::Profile && interactive && !roles.is_empty() {
        RoleDecision::Pick {
            missing: Some(requested.to_string()),
        }
    } else {
        RoleDecision::Fail(requested.to_string())
    }
}

/// Whether a person can answer a role prompt: stdin and stdout are terminals
/// (the selector draws on stdout) and stdout is not reserved for the
/// credential-process protocol.
fn role_pick_can_prompt(credential_process: bool, stdin_tty: bool, stdout_tty: bool) -> bool {
    !credential_process && stdin_tty && stdout_tty
}

/// Whether choosing the role will wait for a human: the selector for more
/// than one role, and always when replacing a missing configured role (a
/// single remaining role is confirmed, never picked silently).
fn role_pick_is_interactive(decision: &RoleDecision, available: usize) -> bool {
    match decision {
        RoleDecision::Pick { missing: Some(_) } => true,
        RoleDecision::Pick { missing: None } => available > 1,
        RoleDecision::Use(_) | RoleDecision::Fail(_) | RoleDecision::Unset => false,
    }
}

/// Resolve the role ARN to use from the SAML assertion without prompting
/// (credential-process). With no role requested, a single available role is
/// used and several are an error.
fn pick_role(assertion: &SamlAssertion, requested: Option<&str>, profile: &str) -> Result<String> {
    let roles = assertion.roles();
    match resolve_role(&roles, requested, RoleSource::Profile, false) {
        RoleDecision::Use(role) => Ok(role),
        RoleDecision::Fail(missing) => Err(role_not_in_assertion(profile, &missing, &roles)),
        RoleDecision::Unset => Err(role_not_set(profile)),
        RoleDecision::Pick { missing } => choose_role(roles, missing.as_deref(), profile),
    }
}

/// The error for a login that needs a role chosen from several but cannot
/// prompt (stdout carries the credential-process protocol, or there is no
/// terminal).
fn role_not_set(profile: &str) -> AwzarsError {
    AwzarsError::Config(format!(
        "role_arn is not set for profile '{p}' and the SAML assertion offers several \
         roles. This login cannot prompt for one (--credential-process, or no terminal).\n\
         \n\
         Fix it one of two ways:\n  \
         1. Pass the role: `awzars login --profile {p} --role-arn \
         arn:aws:iam::<account>:role/<name>`.\n  \
         2. Save it in the profile: `awzars configure --profile {p} \
         --role-arn arn:aws:iam::<account>:role/<name>`, or run \
         `awzars login --profile {p}` in a terminal and pick a role.",
        p = profile,
    ))
}

/// Let the user choose a role. When `missing` names the configured role the
/// assertion no longer offers, say so first, and confirm a single remaining
/// role instead of switching to it silently. Cancelling that choice reports
/// the missing role.
fn choose_role(
    roles: Vec<(String, String)>,
    missing: Option<&str>,
    profile: &str,
) -> Result<String> {
    let Some(missing) = missing else {
        if roles.is_empty() {
            return Err(AwzarsError::NoRolesAvailable);
        }
        return RoleSelector::new(roles)
            .select()?
            .ok_or(AwzarsError::NoRolesAvailable);
    };
    tracing::warn!(
        "Role {} configured for profile '{}' is not in the SAML assertion (it may have been \
         renamed or removed); choose another role",
        missing,
        profile
    );
    let missing_error = || role_not_in_assertion(profile, missing, &roles);
    if let [(only, _)] = roles.as_slice() {
        let confirmed = Confirm::new()
            .with_prompt(format!(
                "Role {missing} is no longer available. Use the only available role {only}?"
            ))
            .default(false)
            .interact()
            .map_err(|e| AwzarsError::Dialog(e.to_string()))?;
        return if confirmed {
            Ok(only.clone())
        } else {
            Err(missing_error())
        };
    }
    let missing_name = missing.rsplit('/').next().unwrap_or(missing);
    RoleSelector::new(roles.clone())
        .with_notice(format!("configured role {missing_name} not found"))
        .select()?
        .ok_or_else(missing_error)
}

/// The error for a role the assertion does not offer, listing the closest
/// available roles.
fn role_not_in_assertion(profile: &str, missing: &str, roles: &[(String, String)]) -> AwzarsError {
    AwzarsError::RoleNotInAssertion {
        profile: profile.to_string(),
        role_arn: missing.to_string(),
        suggestions: suggest_roles(missing, roles, ROLE_SUGGESTION_LIMIT),
        available: roles.len(),
    }
}

/// Up to `limit` available roles closest to `missing`, best first: a
/// case-only difference, then the same account, then the smallest edit
/// distance and longest common prefix between normalized role names.
fn suggest_roles(missing: &str, roles: &[(String, String)], limit: usize) -> Vec<String> {
    let (missing_account, missing_name) = role_account_and_name(missing);
    let target = normalized_role_name(missing_name);
    let mut ranked: Vec<_> = roles
        .iter()
        .map(|(role, _)| {
            let (account, name) = role_account_and_name(role);
            let candidate = normalized_role_name(name);
            (
                !role.eq_ignore_ascii_case(missing),
                account != missing_account,
                edit_distance(&target, &candidate),
                std::cmp::Reverse(common_prefix_len(&target, &candidate)),
                role.as_str(),
            )
        })
        .collect();
    ranked.sort_unstable();
    ranked
        .into_iter()
        .take(limit)
        .map(|(.., role)| role.to_string())
        .collect()
}

/// The account ID and role name (last path segment) of a role ARN.
fn role_account_and_name(role: &str) -> (&str, &str) {
    let mut components = role.splitn(6, ':');
    let account = components.nth(4).unwrap_or_default();
    let resource = components.next().unwrap_or_default();
    (account, resource.rsplit('/').next().unwrap_or(resource))
}

/// Lowercase alphanumerics only, so `Foo-Bar_Role` and `foobarrole` match.
fn normalized_role_name(name: &str) -> Vec<char> {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

/// Levenshtein distance.
fn edit_distance(left: &[char], right: &[char]) -> usize {
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];
    for (i, left_char) in left.iter().enumerate() {
        current[0] = i + 1;
        for (j, right_char) in right.iter().enumerate() {
            let substitution = previous[j] + usize::from(left_char != right_char);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

fn common_prefix_len(left: &[char], right: &[char]) -> usize {
    left.iter().zip(right).take_while(|(a, b)| a == b).count()
}

/// Whether to save the role used by this login as the profile's `role_arn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SavePicked {
    Yes,
    Ask,
    No,
}

/// Profile-scope logins save a role picked when none was configured, ask
/// before replacing a configured role that went missing, and otherwise leave
/// the configuration alone.
fn should_save_picked(
    scope: CredentialScope,
    role_was_supplied: bool,
    fell_back: bool,
) -> SavePicked {
    match (scope, role_was_supplied, fell_back) {
        (CredentialScope::Request, ..) => SavePicked::No,
        (CredentialScope::Profile, false, _) => SavePicked::Yes,
        (CredentialScope::Profile, true, true) => SavePicked::Ask,
        (CredentialScope::Profile, true, false) => SavePicked::No,
    }
}

/// What a login stores once its role is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PickPersistence {
    /// Where the fresh credentials go (`Request` stores nothing).
    credentials: CredentialScope,
    /// Whether the role is saved as the profile's `role_arn`.
    save_role: bool,
}

impl PickPersistence {
    /// Whether stored credentials must be re-checked (under the refresh
    /// lock) after the role is chosen: only when this login stores them.
    fn rechecks_stored_credentials(self) -> bool {
        self.credentials == CredentialScope::Profile
    }
}

/// Declining to save a role that replaced a missing configured one keeps
/// the profile untouched: neither the role nor the credentials are stored,
/// so the credentials serve only this invocation and credential-process
/// keeps failing visibly until the profile is fixed.
fn persistence_after_pick(
    scope: CredentialScope,
    policy: SavePicked,
    answered_yes: bool,
) -> PickPersistence {
    let (credentials, save_role) = match policy {
        SavePicked::Yes => (scope, true),
        SavePicked::No => (scope, false),
        SavePicked::Ask if answered_yes => (scope, true),
        SavePicked::Ask => (CredentialScope::Request, false),
    };
    PickPersistence {
        credentials,
        save_role,
    }
}

/// Write fresh credentials to both the in-process cache and the OS
/// keyring so subsequent calls (and subsequent processes) skip the
/// browser flow. `identity` is the fingerprint of the identity the
/// credentials were issued for (the role actually used).
pub(super) fn persist_credentials(
    credentials: &CredentialProcessOutput,
    profile: &str,
    identity: &str,
) -> Result<()> {
    CacheHandle::new(profile)?.store(credentials, identity)?;
    KeyringStorage::new(profile)?.store_credentials(credentials, identity)?;
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
    let configured_identity = crate::auth::credentials::credential_identity(
        &profile.azure.tenant_id,
        &profile.azure.app_id_uri,
        profile.role_arn.as_deref(),
    );
    if let Some(creds) = credential_scope.load(
        &args.profile,
        &configured_identity,
        session_duration,
        force_refresh,
    )? {
        return output_credentials(&creds, &login_args, args.quiet);
    }

    // Build Azure configuration (allow CLI overrides). `--azure-app` is
    // already checked by clap; a stored value is checked here, before any
    // prompt or browser.
    if login_args.azure_app.is_none() {
        profile.validate_app_id_uri(&args.profile)?;
    }
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

    // Profile scope re-checks stored credentials once it holds the lock.
    // Identity overrides (request scope) never read or write them, but still
    // hold the lock through the browser phase: it reads and may rotate the
    // profile's cookie keystore, a read-modify-write that must not interleave.
    let mut refresh_guard = Some(match credential_scope {
        CredentialScope::Profile => {
            let (guard, refreshed) = lock_and_recheck(
                &args.profile,
                &configured_identity,
                session_duration,
                force_refresh,
            )
            .await?;
            if let Some(creds) = refreshed {
                return output_credentials(&creds, &login_args, args.quiet);
            }
            guard
        }
        CredentialScope::Request => CredentialRefreshGuard::acquire(&args.profile).await?,
    });

    let sign_in = sign_in(&params).await?;
    if credential_scope == CredentialScope::Request {
        drop(refresh_guard.take());
    }
    let roles = sign_in.assertion.roles();
    let role_source = if login_args.role_arn.is_some() {
        RoleSource::Override
    } else {
        RoleSource::Profile
    };
    let can_prompt = role_pick_can_prompt(
        login_args.credential_process,
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    );
    let decision = resolve_role(&roles, params.role_arn.as_deref(), role_source, can_prompt);
    let fell_back = matches!(decision, RoleDecision::Pick { missing: Some(_) });
    let save_policy = should_save_picked(credential_scope, role_was_supplied, fell_back);
    let waits_for_human = role_pick_is_interactive(&decision, roles.len());
    let mut persistence = persistence_after_pick(credential_scope, save_policy, false);
    let role_arn = match decision {
        RoleDecision::Use(role_arn) => role_arn,
        RoleDecision::Fail(missing) => {
            return Err(role_not_in_assertion(&args.profile, &missing, &roles));
        }
        RoleDecision::Unset => return Err(role_not_set(&args.profile)),
        RoleDecision::Pick { missing } if !waits_for_human => {
            choose_role(roles, missing.as_deref(), &args.profile)?
        }
        RoleDecision::Pick { missing } => {
            // Never hold the lock while a human picks a role: every other
            // refresh of this profile would wait on the selector (#23).
            drop(refresh_guard.take());
            let role_arn = choose_role(roles, missing.as_deref(), &args.profile)?;
            if save_policy == SavePicked::Ask {
                let answered_yes = Confirm::new()
                    .with_prompt(format!(
                        "Save {role_arn} as the role for profile '{}'? \
                         (credential-process uses it)",
                        args.profile
                    ))
                    .default(false)
                    .interact()
                    .map_err(|e| AwzarsError::Dialog(e.to_string()))?;
                persistence = persistence_after_pick(credential_scope, save_policy, answered_yes);
                if !answered_yes {
                    tracing::warn!(
                        "Not saved: these credentials are for this login only and profile \
                         '{}' is unchanged, so credential-process keeps failing until its \
                         role_arn is fixed",
                        args.profile
                    );
                }
            }
            // Nothing is stored when the user declined to save the role, so
            // there is no stored state to re-check or protect: the browser
            // phase (cookie keystore) is over and STS needs no lock.
            if persistence.rechecks_stored_credentials() {
                let picked_identity = crate::auth::credentials::credential_identity(
                    tenant_id,
                    app_id_uri,
                    Some(&role_arn),
                );
                let (guard, refreshed) = lock_and_recheck(
                    &args.profile,
                    &picked_identity,
                    session_duration,
                    force_refresh,
                )
                .await?;
                if let Some(creds) = refreshed {
                    // Another login stored credentials while the role was being
                    // chosen. Reuse them when they are for the same role; otherwise
                    // the explicit choice made here replaces them, visibly.
                    let configured = configured_role(&args.profile)?;
                    if reuse_after_role_pick(configured.as_deref(), &role_arn) {
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
        }
    };

    let outcome = exchange_for_credentials(&params, &sign_in, role_arn).await?;
    let used_identity = crate::auth::credentials::credential_identity(
        &params.tenant_id,
        &params.app_id_uri,
        Some(&outcome.role_arn),
    );
    persistence
        .credentials
        .persist(&outcome.credentials, &args.profile, &used_identity)?;

    // Save the interactively-picked role so subsequent non-interactive
    // credential-process calls don't fail with "role_arn not set" (or keep
    // failing on a configured role that went missing, if the user agreed).
    if persistence.save_role {
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
    identity: &str,
    session_duration: i32,
    force_refresh: bool,
) -> Result<(CredentialRefreshGuard, Option<CredentialProcessOutput>)> {
    let guard = CredentialRefreshGuard::acquire(profile).await?;
    let stored =
        CredentialScope::Profile.load(profile, identity, session_duration, force_refresh)?;
    Ok((guard, stored))
}

/// Whether credentials another login stored while this one's role was being
/// picked can be reused: only when the profile is now configured for the
/// same role. Otherwise the role picked here replaces them.
fn reuse_after_role_pick(configured_role: Option<&str>, picked_role: &str) -> bool {
    configured_role == Some(picked_role)
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
            let profile = crate::config::Profile {
                lock_ai_markers: Some(vec![]),
                ..Default::default()
            };
            let identity = crate::auth::credentials::credential_identity(
                &profile.azure.tenant_id,
                &profile.azure.app_id_uri,
                profile.role_arn.as_deref(),
            );
            let mut config = Config::default();
            config.set_profile("default", profile);
            config.save().unwrap();
            CacheHandle::new("default")
                .unwrap()
                .store(&credentials("cached-output"), &identity)
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
        use crate::auth::credentials::refresh_lock::test_support;
        use clap::Parser;
        if let Ok(directory) = std::env::var(test_support::CHILD_DIRECTORY_ENV) {
            test_support::prepare_cached_default_profile(&directory);
            let arguments = ["awzars", "login", "--credential-process"];
            execute(&Args::try_parse_from(arguments).unwrap())
                .await
                .unwrap();
            return;
        }
        let output = test_support::run_child_while_lock_held(
            "cli::commands::login::tests::cached_login_does_not_wait_for_the_refresh_lock",
        );
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("\"Version\""));
    }

    #[tokio::test]
    async fn invalid_stored_app_id_uri_is_checked_unless_overridden() {
        use clap::Parser;
        if let Ok(directory) = std::env::var("AWZARS_LOGIN_APP_ID_URI_DIRECTORY") {
            config::set_config_dir_override(&directory).unwrap();
            let mut profile = crate::config::Profile::new(crate::config::AzureConfig::new(
                "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "http://example.com/saml",
            ));
            profile.lock_ai_markers = Some(vec![]);
            profile.remember_me = Some(false);
            let mut config = Config::default();
            config.set_profile("default", profile);
            config.save().unwrap();
            let mut arguments = vec!["awzars", "login"];
            let overridden = std::env::var("AWZARS_LOGIN_APP_ID_URI_OVERRIDE").is_ok();
            if overridden {
                arguments.extend(["--azure-app", "https://signin.aws.amazon.com/saml"]);
            }
            let error = execute(&Args::try_parse_from(arguments).unwrap())
                .await
                .unwrap_err();
            // With the override, sign-in goes on to the browser, which
            // refuses the `ws://` remote URL.
            match (&error, overridden) {
                (AwzarsError::Config(message), false) => {
                    assert!(message.contains("app_id_uri"), "{message}")
                }
                (AwzarsError::Browser(_), true) => {}
                _ => panic!("unexpected error (override: {overridden}): {error:?}"),
            }
            return;
        }
        // The child runs `execute`. A `ws://` remote URL without
        // `--allow-insecure-remote-chrome` is refused before connecting, so
        // no case can open Chrome.
        for overridden in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "cli::commands::login::tests::invalid_stored_app_id_uri_is_checked_unless_overridden",
                    "--nocapture",
                ])
                .env("AWZARS_LOGIN_APP_ID_URI_DIRECTORY", directory.path())
                .env("CHROME_REMOTE_URL", "ws://127.0.0.1:9/devtools/browser/test")
                .env_remove("AWZARS_AZURE_TENANT_ID")
                .env_remove("AWZARS_AZURE_APP_ID_URI");
            if overridden {
                command.env("AWZARS_LOGIN_APP_ID_URI_OVERRIDE", "1");
            } else {
                command.env_remove("AWZARS_LOGIN_APP_ID_URI_OVERRIDE");
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "override: {overridden}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
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
            cache
                .store(&credentials("original-role"), "identity")
                .unwrap();

            let scope = CredentialScope::for_login(&arguments);
            assert_eq!(scope, CredentialScope::Request);
            assert!(scope
                .load(&profile, "identity", 3600, false)
                .unwrap()
                .is_none());
            scope
                .persist(&credentials("override-role"), &profile, "identity")
                .unwrap();
            assert_eq!(
                cache
                    .get_valid_credentials(3600, "identity")
                    .unwrap()
                    .unwrap()
                    .access_key_id,
                "original-role"
            );
            cache.clear().unwrap();
        }
    }

    #[test]
    fn persisted_credentials_load_back_only_for_their_identity() {
        crate::storage::keyring::test_keychain::install();
        let identity = |role: &str| {
            crate::auth::credentials::credential_identity(
                "tenant",
                "app",
                Some(&format!("arn:aws:iam::123456789012:role/{role}")),
            )
        };
        let load = |profile: &str, role: &str| {
            crate::auth::credentials::try_load_credentials(profile, &identity(role), 3600, false)
                .unwrap()
                .map(|creds| creds.access_key_id.clone())
        };
        for through_scope in [false, true] {
            let profile = format!("roundtrip_{}", uuid::Uuid::new_v4());
            if through_scope {
                CredentialScope::Profile
                    .persist(&credentials("persisted"), &profile, &identity("A"))
                    .unwrap();
            } else {
                persist_credentials(&credentials("persisted"), &profile, &identity("A")).unwrap();
            }
            // In-memory cache.
            assert_eq!(load(&profile, "B"), None);
            assert_eq!(load(&profile, "A").as_deref(), Some("persisted"));
            // Keyring alone.
            CacheHandle::new(&profile).unwrap().clear().unwrap();
            assert_eq!(load(&profile, "B"), None);
            assert_eq!(load(&profile, "A").as_deref(), Some("persisted"));
            CacheHandle::new(&profile).unwrap().clear().unwrap();
        }
    }

    #[test]
    fn role_pick_rechecks_only_credentials_this_login_stores() {
        use CredentialScope::{Profile, Request};
        for (scope, policy, answered_yes, rechecks) in [
            (Profile, SavePicked::Yes, false, true),
            (Profile, SavePicked::No, false, true),
            (Profile, SavePicked::Ask, true, true),
            (Profile, SavePicked::Ask, false, false),
            (Request, SavePicked::No, false, false),
        ] {
            assert_eq!(
                persistence_after_pick(scope, policy, answered_yes).rechecks_stored_credentials(),
                rechecks,
                "{scope:?} {policy:?} {answered_yes}"
            );
        }
    }

    #[test]
    fn ordinary_login_reuses_profile_credentials_unless_refreshing() {
        let profile = format!("ordinary_{}", uuid::Uuid::new_v4());
        let cache = CacheHandle::new(&profile).unwrap();
        cache
            .store(&credentials("original-role"), "identity")
            .unwrap();
        let scope = CredentialScope::for_login(&login_arguments());
        assert_eq!(scope, CredentialScope::Profile);
        assert_eq!(
            scope
                .load(&profile, "identity", 3600, false)
                .unwrap()
                .unwrap()
                .access_key_id,
            "original-role"
        );
        assert!(scope
            .load(&profile, "identity", 3600, true)
            .unwrap()
            .is_none());
        cache.clear().unwrap();
    }

    #[test]
    fn role_pick_recheck_reuses_only_credentials_for_the_picked_role() {
        let picked = "arn:aws:iam::123456789012:role/Picked";
        assert!(reuse_after_role_pick(Some(picked), picked));
        assert!(!reuse_after_role_pick(
            Some("arn:aws:iam::123456789012:role/Other"),
            picked
        ));
        assert!(!reuse_after_role_pick(None, picked));
    }

    /// A valid SAML assertion offering `roles`.
    fn assertion_with_roles(roles: &[&str]) -> SamlAssertion {
        use base64::{engine::general_purpose::STANDARD, Engine};
        const TENANT: &str = "11111111-2222-3333-4444-aaaaaaaaaaaa";
        const AUDIENCE: &str = "https://signin.aws.amazon.com/saml";
        let values: String = role_list(roles)
            .iter()
            .map(|(role, principal)| {
                format!("<saml:AttributeValue>{role},{principal}</saml:AttributeValue>")
            })
            .collect();
        let not_before = (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let not_on_or_after = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:Issuer>https://sts.windows.net/{TENANT}/</saml:Issuer>
    <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
      <saml:AudienceRestriction><saml:Audience>{AUDIENCE}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">{values}</saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#
        );
        SamlAssertion::parse(&STANDARD.encode(xml), TENANT, AUDIENCE).unwrap()
    }

    #[test]
    fn pick_role_without_a_request_never_prompts() {
        let several = assertion_with_roles(&[CONFIGURED, "arn:aws:iam::123456789012:role/Other"]);
        let error = pick_role(&several, None, "work").unwrap_err();
        assert_eq!(error.to_string(), role_not_set("work").to_string());
        // A single role is used without a prompt; a requested role is used as is.
        let single = assertion_with_roles(&[CONFIGURED]);
        assert_eq!(pick_role(&single, None, "work").unwrap(), CONFIGURED);
        assert_eq!(
            pick_role(&several, Some(CONFIGURED), "work").unwrap(),
            CONFIGURED
        );
    }

    fn role_list(roles: &[&str]) -> Vec<(String, String)> {
        roles
            .iter()
            .map(|role| {
                let account = role.split(':').nth(4).unwrap();
                (
                    role.to_string(),
                    format!("arn:aws:iam::{account}:saml-provider/AzureAD"),
                )
            })
            .collect()
    }

    const CONFIGURED: &str = "arn:aws:iam::123456789012:role/Old-Admin";

    #[test]
    fn resolve_role_uses_an_available_role_from_either_source() {
        let roles = role_list(&[CONFIGURED, "arn:aws:iam::123456789012:role/Other"]);
        for source in [RoleSource::Override, RoleSource::Profile] {
            for interactive in [false, true] {
                assert_eq!(
                    resolve_role(&roles, Some(CONFIGURED), source, interactive),
                    RoleDecision::Use(CONFIGURED.into())
                );
            }
        }
    }

    #[test]
    fn resolve_role_falls_back_to_a_pick_only_for_a_missing_profile_role_on_a_terminal() {
        let roles = role_list(&["arn:aws:iam::123456789012:role/New-Admin"]);
        assert_eq!(
            resolve_role(&roles, Some(CONFIGURED), RoleSource::Profile, true),
            RoleDecision::Pick {
                missing: Some(CONFIGURED.into())
            }
        );
        assert_eq!(
            resolve_role(&roles, Some(CONFIGURED), RoleSource::Profile, false),
            RoleDecision::Fail(CONFIGURED.into())
        );
        for interactive in [false, true] {
            assert_eq!(
                resolve_role(&roles, Some(CONFIGURED), RoleSource::Override, interactive),
                RoleDecision::Fail(CONFIGURED.into())
            );
        }
        assert_eq!(
            resolve_role(&[], Some(CONFIGURED), RoleSource::Profile, true),
            RoleDecision::Fail(CONFIGURED.into())
        );
    }

    #[test]
    fn resolve_role_without_a_request_picks_only_when_someone_can_choose() {
        let roles = role_list(&[CONFIGURED, "arn:aws:iam::123456789012:role/Other"]);
        assert_eq!(
            resolve_role(&roles, None, RoleSource::Profile, true),
            RoleDecision::Pick { missing: None }
        );
        // credential-process output or no terminal: never open the selector.
        assert_eq!(
            resolve_role(&roles, None, RoleSource::Profile, false),
            RoleDecision::Unset
        );
        assert!(!role_pick_is_interactive(&RoleDecision::Unset, roles.len()));
        // A single role is still selected without a prompt.
        let single = role_list(&[CONFIGURED]);
        for interactive in [false, true] {
            let decision = resolve_role(&single, None, RoleSource::Profile, interactive);
            assert_eq!(decision, RoleDecision::Pick { missing: None });
            assert!(!role_pick_is_interactive(&decision, single.len()));
        }
    }

    #[test]
    fn role_not_set_points_to_role_arn_and_configure() {
        let message = role_not_set("work").to_string();
        assert!(message.contains("--role-arn"), "{message}");
        assert!(
            message.contains("awzars configure --profile work"),
            "{message}"
        );
    }

    #[test]
    fn role_prompts_need_both_terminals_and_no_credential_process_output() {
        assert!(role_pick_can_prompt(false, true, true));
        assert!(!role_pick_can_prompt(true, true, true));
        assert!(!role_pick_can_prompt(false, false, true));
        assert!(!role_pick_can_prompt(false, true, false));
    }

    #[test]
    fn replacing_a_missing_role_always_waits_for_a_human() {
        let fallback = RoleDecision::Pick {
            missing: Some(CONFIGURED.into()),
        };
        // Even one remaining role is confirmed, so the lock must be released.
        assert!(role_pick_is_interactive(&fallback, 1));
        assert!(role_pick_is_interactive(&fallback, 3));
        let pick = RoleDecision::Pick { missing: None };
        assert!(!role_pick_is_interactive(&pick, 1));
        assert!(role_pick_is_interactive(&pick, 2));
        assert!(!role_pick_is_interactive(
            &RoleDecision::Use(CONFIGURED.into()),
            2
        ));
        assert!(!role_pick_is_interactive(
            &RoleDecision::Fail(CONFIGURED.into()),
            2
        ));
    }

    #[test]
    fn suggestions_rank_case_only_then_same_account_then_similar_names() {
        let roles = role_list(&[
            "arn:aws:iam::999999999999:role/Old-Admin-Role",
            "arn:aws:iam::123456789012:role/ReadOnly",
            "arn:aws:iam::123456789012:role/OldAdmin-v2",
            "arn:aws:iam::123456789012:role/old-admin",
        ]);
        assert_eq!(
            suggest_roles(CONFIGURED, &roles, 5),
            [
                "arn:aws:iam::123456789012:role/old-admin",
                "arn:aws:iam::123456789012:role/OldAdmin-v2",
                "arn:aws:iam::123456789012:role/ReadOnly",
                "arn:aws:iam::999999999999:role/Old-Admin-Role",
            ]
        );
    }

    #[test]
    fn suggestions_match_on_the_role_name_not_its_path() {
        let roles = role_list(&[
            "arn:aws:iam::123456789012:role/Zebra",
            "arn:aws:iam::123456789012:role/team/platform/Old_Admin_2",
        ]);
        assert_eq!(
            suggest_roles(CONFIGURED, &roles, 1),
            ["arn:aws:iam::123456789012:role/team/platform/Old_Admin_2"]
        );
    }

    #[test]
    fn suggestions_are_capped_and_empty_without_roles() {
        let many: Vec<String> = (0..12)
            .map(|index| format!("arn:aws:iam::123456789012:role/Role{index}"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(
            suggest_roles(CONFIGURED, &role_list(&many), ROLE_SUGGESTION_LIMIT).len(),
            ROLE_SUGGESTION_LIMIT
        );
        assert!(suggest_roles(CONFIGURED, &[], ROLE_SUGGESTION_LIMIT).is_empty());
    }

    #[test]
    fn edit_distance_counts_single_character_edits() {
        let chars = |text: &str| text.chars().collect::<Vec<_>>();
        assert_eq!(edit_distance(&chars("kitten"), &chars("sitting")), 3);
        assert_eq!(edit_distance(&chars(""), &chars("abc")), 3);
        assert_eq!(edit_distance(&chars("same"), &chars("same")), 0);
    }

    #[test]
    fn missing_role_error_names_the_role_suggestions_and_fixes() {
        let roles = role_list(&[
            "arn:aws:iam::123456789012:role/New-Admin",
            "arn:aws:iam::123456789012:role/ReadOnly",
        ]);
        let error = role_not_in_assertion("work", CONFIGURED, &roles);
        assert!(matches!(
            error,
            AwzarsError::RoleNotInAssertion { available: 2, .. }
        ));
        let message = error.to_string();
        assert!(message.contains(CONFIGURED), "{message}");
        assert!(message.contains("not in the SAML assertion"), "{message}");
        assert!(
            message.contains("Closest of 2 available role(s)"),
            "{message}"
        );
        assert!(
            message.contains("arn:aws:iam::123456789012:role/New-Admin"),
            "{message}"
        );
        assert!(
            message.contains("arn:aws:iam::123456789012:role/ReadOnly"),
            "{message}"
        );
        assert!(
            message.contains("`awzars login --profile work`"),
            "{message}"
        );
        assert!(
            message.contains("`awzars configure --profile work --role-arn "),
            "{message}"
        );
        assert!(
            message.contains("`awzars list-roles --profile work`"),
            "{message}"
        );
        assert!(!message.contains("Principal"), "{message}");
    }

    #[test]
    fn missing_role_error_without_roles_skips_the_suggestion_list() {
        let message = role_not_in_assertion("work", CONFIGURED, &[]).to_string();
        assert!(!message.contains("Closest"), "{message}");
        assert!(
            message.contains("`awzars login --profile work`"),
            "{message}"
        );
    }

    #[test]
    fn picked_roles_are_saved_asked_about_or_left_alone() {
        use CredentialScope::{Profile, Request};
        // No configured role: keep saving the picked one.
        assert_eq!(should_save_picked(Profile, false, false), SavePicked::Yes);
        // Configured role went missing: ask before replacing it.
        assert_eq!(should_save_picked(Profile, true, true), SavePicked::Ask);
        // Configured role used as is: nothing to save.
        assert_eq!(should_save_picked(Profile, true, false), SavePicked::No);
        // Identity overrides never touch the profile.
        for (supplied, fell_back) in [(false, false), (true, true), (true, false)] {
            assert_eq!(
                should_save_picked(Request, supplied, fell_back),
                SavePicked::No
            );
        }
    }

    #[test]
    fn declining_to_save_a_replacement_role_stores_nothing() {
        use CredentialScope::{Profile, Request};
        let stored = |credentials, save_role| PickPersistence {
            credentials,
            save_role,
        };
        // Missing configured role, user declines: neither role nor credentials.
        assert_eq!(
            persistence_after_pick(Profile, SavePicked::Ask, false),
            stored(Request, false)
        );
        // Missing configured role, user accepts: both, as before.
        assert_eq!(
            persistence_after_pick(Profile, SavePicked::Ask, true),
            stored(Profile, true)
        );
        // No configured role: the picked role and credentials are saved.
        assert_eq!(
            persistence_after_pick(Profile, SavePicked::Yes, false),
            stored(Profile, true)
        );
        // Configured role used as is: credentials only.
        assert_eq!(
            persistence_after_pick(Profile, SavePicked::No, false),
            stored(Profile, false)
        );
        // Identity overrides store nothing.
        assert_eq!(
            persistence_after_pick(Request, SavePicked::No, false),
            stored(Request, false)
        );
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
