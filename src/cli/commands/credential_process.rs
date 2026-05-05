//! Credential process command implementation

use crate::browser::chromium::AzureLoginBrowser;
use crate::cli::args::Args;
use crate::cli::args::Command;
use crate::cli::commands::login::{perform_login, LoginParams};
use crate::config::{self, Config};
use crate::credential_process::protocol::write_credentials_json;
use crate::error::{AwzarsError, Result};

/// Execute the credential-process command
pub async fn execute(args: &Args) -> Result<()> {
    let (refresh, cli_headless, cli_no_sandbox, cli_allow_insecure) = match &args.command {
        Command::CredentialProcess {
            refresh,
            headless,
            no_sandbox,
            allow_insecure_remote_chrome,
        } => (
            *refresh,
            *headless,
            *no_sandbox,
            *allow_insecure_remote_chrome,
        ),
        _ => return Err(AwzarsError::Config("Invalid command".to_string())),
    };

    // Load configuration to verify profile exists
    let config = Config::load()?;
    let profile = config.get_profile(&args.profile)?;

    // Gate: password lock and/or AI consent. AWS CLI typically inherits the
    // parent shell's stdin when invoking us as a credential_process subprocess,
    // so when stdin is a TTY we let `enforce` inline-prompt for the password
    // (`allow_inline_prompt = true`) — the unlock token is then written for the
    // session and subsequent calls in the same TTY skip the prompt. AI markers
    // still refuse the inline prompt (security: never read a password under AI
    // gaze; user must run `awzars unlock --allow-ai` explicitly).
    // `persist_consent` stays false: the AI-consent inline path is unreachable
    // here because credential-process never sees an unlocked profile that needs
    // consent without already having a token.
    crate::auth::lock::enforce(&args.profile, profile, true, false)?;

    // Cache + keyring lookup before falling through to browser login.
    if let Some(creds) = crate::auth::credentials::try_load_credentials(&args.profile, refresh)? {
        write_credentials_json(&creds)?;
        return Ok(());
    }

    // Credentials expired or missing — auto-login
    tracing::info!("Credentials expired, attempting automatic re-authentication");

    let role_arn = profile.role_arn.clone().ok_or_else(|| {
        AwzarsError::Config(format!(
            "role_arn is not set for profile '{p}'. credential-process is \
             non-interactive and cannot prompt for one.\n\
             \n\
             Fix it one of two ways:\n  \
             1. Run an interactive login once: `awzars login --profile {p}` \
             — pick a role from the list and it will be saved to the profile.\n  \
             2. Set it manually: `awzars configure --profile {p} \
             --role-arn arn:aws:iam::<account>:role/<name>`.",
            p = args.profile,
        ))
    })?;

    // Resolve browser flags: CLI > profile config > credential-process defaults
    // Credential-process is always non-interactive, so headless and remember_me
    // default to true (unless the CLI flag or profile config explicitly overrides).
    let headless = cli_headless || profile.headless.unwrap_or(true);
    let no_sandbox = cli_no_sandbox || profile.no_sandbox.unwrap_or(false);
    let allow_insecure =
        cli_allow_insecure || profile.allow_insecure_remote_chrome.unwrap_or(false);
    let remember_me = profile.remember_me.unwrap_or(true);

    // Pre-flight: when using local Chrome for re-auth, verify a session exists.
    // Skip this check when CHROME_REMOTE_URL is set (remote Chrome manages its own sessions).
    let using_remote = std::env::var("CHROME_REMOTE_URL").is_ok();
    if headless && remember_me && !using_remote {
        let has_cookies = AzureLoginBrowser::has_cookie_store(&args.profile);
        let has_session = config::chromium_data_dir(&args.profile)
            .map(|d| d.exists())
            .unwrap_or(false);
        if !has_cookies && !has_session {
            return Err(AwzarsError::Browser(format!(
                "No persistent browser session found for profile '{}'. \
                 Credential-process requires a prior interactive login to establish \
                 a browser session.\n\
                 \n\
                 Fix: Run `awzars login --profile {} --remember-me` first (opens a \
                 browser window for interactive authentication), then \
                 credential-process will automatically reuse the session for \
                 headless re-authentication.",
                args.profile, args.profile
            )));
        }
    }

    let params = LoginParams {
        profile_name: args.profile.clone(),
        tenant_id: profile.azure.tenant_id.clone(),
        app_id_uri: profile.azure.app_id_uri.clone(),
        role_arn: Some(role_arn),
        session_duration: profile.azure.session_duration,
        headless,
        no_sandbox,
        remember_me,
        allow_insecure_remote_chrome: allow_insecure,
    };

    let outcome = perform_login(&params).await?;
    write_credentials_json(&outcome.credentials)?;
    Ok(())
}
