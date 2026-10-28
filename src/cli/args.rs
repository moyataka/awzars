//! CLI argument definitions using clap

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "awzars",
    author,
    version,
    about = "Modern Rust-based Azure AD to AWS credential federation",
    long_about = "A modern replacement for aws-azure-login using Rust and chromiumoxide.\n\
                  Automates Azure AD authentication and exchanges SAML assertions for AWS credentials."
)]
pub struct Args {
    /// Profile name to use
    #[arg(
        short,
        long,
        global = true,
        default_value = "default",
        value_parser = parse_profile_name
    )]
    pub profile: String,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress informational output and logs below error (preserves JSON and prompts)
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Configuration directory
    #[arg(long, global = true, env = "AWZARS_CONFIG_DIR")]
    pub config_dir: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Login to Azure AD and obtain AWS credentials
    Login {
        /// Azure AD tenant ID (overrides profile config)
        #[arg(long, env = "AWZARS_AZURE_TENANT_ID", value_parser = parse_tenant_uuid)]
        azure_tenant: Option<String>,

        /// Azure AD app ID URI (overrides profile config)
        #[arg(long, env = "AWZARS_AZURE_APP_ID_URI", value_parser = parse_app_id_uri)]
        azure_app: Option<String>,

        /// AWS role ARN to assume (overrides profile config)
        #[arg(long, value_parser = parse_role_arn)]
        role_arn: Option<String>,

        /// Session duration in seconds (900..=43200; defaults to profile setting)
        #[arg(long, value_parser = parse_session_duration)]
        session_duration: Option<i32>,

        /// Run browser in headless mode
        #[arg(long)]
        headless: bool,

        /// Disable Chrome sandbox (required when running as root, reduces security)
        #[arg(long)]
        no_sandbox: bool,

        /// Force re-authentication (ignore cached credentials)
        #[arg(long)]
        force_refresh: bool,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        output: OutputFormat,

        /// Output in credential_process format (for AWS CLI)
        #[arg(long)]
        credential_process: bool,

        /// Show full secret values in text/table output (default: masked)
        #[arg(long)]
        show_secrets: bool,

        /// Persist browser session to skip re-authentication on future logins
        #[arg(long)]
        remember_me: bool,

        /// Allow unencrypted ws:// connections to remote Chrome (insecure, use wss:// instead)
        #[arg(long)]
        allow_insecure_remote_chrome: bool,

        /// When the AI-consent prompt fires for an unlocked profile, persist
        /// the answer for the rest of this terminal session. Default is to
        /// ask every invocation.
        #[arg(long)]
        session_remember: bool,
    },

    /// Configure a new profile
    Configure {
        /// Azure AD tenant ID
        #[arg(long, env = "AWZARS_AZURE_TENANT_ID", value_parser = parse_tenant_uuid)]
        azure_tenant: Option<String>,

        /// Azure AD app ID URI
        #[arg(long, env = "AWZARS_AZURE_APP_ID_URI", value_parser = parse_app_id_uri)]
        azure_app: Option<String>,

        /// Default AWS role ARN
        #[arg(long, value_parser = parse_role_arn)]
        role_arn: Option<String>,

        /// Default session duration (900..=43200)
        #[arg(long, default_value = "3600", value_parser = parse_session_duration)]
        session_duration: i32,

        /// Non-interactive mode (use provided values)
        #[arg(long)]
        non_interactive: bool,
    },

    /// List available AWS roles from SAML assertion
    ListRoles {
        /// Output format
        #[arg(short, long, value_enum, default_value = "table")]
        output: OutputFormat,

        /// When the AI-consent prompt fires for an unlocked profile, persist
        /// the answer for the rest of this terminal session. Default is to
        /// ask every invocation.
        #[arg(long)]
        session_remember: bool,
    },

    /// Run in credential_process mode (for AWS CLI integration)
    CredentialProcess {
        /// Force credential refresh
        #[arg(long)]
        refresh: bool,

        /// Run browser in headless mode for auto-login (overrides profile config)
        #[arg(long)]
        headless: bool,

        /// Disable Chrome sandbox (overrides profile config)
        #[arg(long)]
        no_sandbox: bool,

        /// Allow unencrypted ws:// connections to remote Chrome (insecure, use wss:// instead)
        #[arg(long)]
        allow_insecure_remote_chrome: bool,
    },

    /// Clear cached credentials for the current profile
    ClearCache {
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Delete an awzars profile and all its credentials, cookies, and cached data.
    /// Does not modify ~/.aws/config; orphaned entries there are listed as a warning.
    DeleteProfile {
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Open interactive TUI config manager
    Tui,

    /// Set, change, or remove the password lock on a profile.
    SetPassword {
        /// Remove the password lock entirely (still requires the old password).
        #[arg(long)]
        remove: bool,
    },

    /// Unlock a password-locked profile for this terminal session, or grant
    /// AI consent on an unlocked profile under an AI agent.
    Unlock {
        /// Permit AI agents (CLAUDECODE, AI_AGENT) to use the profile in this
        /// session. For unlocked profiles, this is the only way to grant
        /// session consent.
        #[arg(long)]
        allow_ai: bool,

        /// Override the unlock token TTL in hours. Range 1..=24 by default;
        /// pass `--allow-long-ttl` to extend up to 720 (30 days). Values
        /// much larger than the typical 12 h AWS STS session approach
        /// "always unlocked" semantics — pick the smallest workable window.
        /// Default is 8 or the profile's `lock_ttl_hours`.
        #[arg(long, value_parser = parse_lock_ttl_hours)]
        ttl_hours: Option<u64>,

        /// Permit `--ttl-hours` values above the 24 h default cap (up to the
        /// 720 h / 30-day hard ceiling). Required because long-lived unlock
        /// tokens approach "always unlocked" semantics on shared hosts.
        #[arg(long)]
        allow_long_ttl: bool,

        /// Skip the time-based expiration entirely. The unlock token lasts as
        /// long as the terminal session does (auto-reaped on logout via tmpfs
        /// and SID liveness check). No time fallback — a forgotten unlock on
        /// a long-lived session has no safety net. Mutually exclusive with
        /// `--ttl-hours` and `--allow-long-ttl`.
        #[arg(long, conflicts_with_all = ["ttl_hours", "allow_long_ttl"])]
        no_expire: bool,
    },

    /// Lock the profile in this terminal session (drops the unlock token).
    Lock,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Table,
}

/// Login command arguments extracted from Command enum
pub struct LoginArgs {
    pub azure_tenant: Option<String>,
    pub azure_app: Option<String>,
    pub role_arn: Option<String>,
    pub session_duration: Option<i32>,
    pub headless: bool,
    pub no_sandbox: bool,
    pub force_refresh: bool,
    pub output: OutputFormat,
    pub credential_process: bool,
    pub show_secrets: bool,
    pub remember_me: bool,
    pub allow_insecure_remote_chrome: bool,
    pub session_remember: bool,
}

impl LoginArgs {
    pub fn resolved_session_duration(&self, azure: &crate::config::AzureConfig) -> i32 {
        self.session_duration.unwrap_or(azure.session_duration)
    }

    pub fn refresh_requested(&self) -> bool {
        self.force_refresh || self.session_duration.is_some()
    }

    pub fn from_command(cmd: &Command) -> Option<Self> {
        match cmd {
            Command::Login {
                azure_tenant,
                azure_app,
                role_arn,
                session_duration,
                headless,
                no_sandbox,
                force_refresh,
                output,
                credential_process,
                show_secrets,
                remember_me,
                allow_insecure_remote_chrome,
                session_remember,
            } => Some(Self {
                azure_tenant: azure_tenant.clone(),
                azure_app: azure_app.clone(),
                role_arn: role_arn.clone(),
                session_duration: *session_duration,
                headless: *headless,
                no_sandbox: *no_sandbox,
                force_refresh: *force_refresh,
                output: *output,
                credential_process: *credential_process,
                show_secrets: *show_secrets,
                remember_me: *remember_me,
                allow_insecure_remote_chrome: *allow_insecure_remote_chrome,
                session_remember: *session_remember,
            }),
            _ => None,
        }
    }
}

/// Configure command arguments extracted from Command enum
pub struct ConfigureArgs {
    pub azure_tenant: Option<String>,
    pub azure_app: Option<String>,
    pub role_arn: Option<String>,
    pub session_duration: i32,
    pub non_interactive: bool,
}

impl ConfigureArgs {
    pub fn from_command(cmd: &Command) -> Option<Self> {
        match cmd {
            Command::Configure {
                azure_tenant,
                azure_app,
                role_arn,
                session_duration,
                non_interactive,
            } => Some(Self {
                azure_tenant: azure_tenant.clone(),
                azure_app: azure_app.clone(),
                role_arn: role_arn.clone(),
                session_duration: *session_duration,
                non_interactive: *non_interactive,
            }),
            _ => None,
        }
    }
}

// ----- value parsers / validators -----

/// Session duration must be within AWS STS limits (15 min .. 12 h).
pub fn parse_session_duration(s: &str) -> Result<i32, String> {
    let v: i32 = s.parse().map_err(|_| "must be an integer".to_string())?;
    if !(900..=43200).contains(&v) {
        return Err("must be between 900 and 43200 seconds".to_string());
    }
    Ok(v)
}

/// Validate an IAM role ARN in the AWS, China, or GovCloud partition.
pub fn parse_role_arn(s: &str) -> Result<String, String> {
    use crate::auth::aws::arn::{IamArn, IamResource};
    IamArn::parse(s)
        .filter(|arn| arn.resource() == IamResource::Role)
        .map(|arn| arn.as_str().to_string())
        .ok_or_else(|| {
            "invalid IAM role ARN (expected arn:<partition>:iam::<12-digit-account>:role/<name>)"
                .to_string()
        })
}

/// AWS profile names are restricted to a safe alphanumeric subset.
pub fn parse_profile_name(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("profile name must not be empty".to_string());
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        Ok(s.to_string())
    } else {
        Err("profile name must match [a-zA-Z0-9_-]+".to_string())
    }
}

/// Azure AD tenant IDs are GUIDs.
pub fn parse_tenant_uuid(s: &str) -> Result<String, String> {
    uuid::Uuid::parse_str(s)
        .map(|_| s.to_string())
        .map_err(|_| "tenant ID must be a valid UUID".to_string())
}

/// Soft cap on `--ttl-hours`. Values above this require `--allow-long-ttl`
/// (enforced at command time, not in this parser, because cross-arg
/// validation is awkward in clap value parsers).
pub const LOCK_TTL_SOFT_CAP_HOURS: u64 = 24;

/// Hard cap on `--ttl-hours` even with `--allow-long-ttl`.
pub const LOCK_TTL_HARD_CAP_HOURS: u64 = 720;

/// Unlock TTL in hours, capped at 30 days so that "infinite" tokens cannot
/// be created by mistake. Values above `LOCK_TTL_SOFT_CAP_HOURS` parse here
/// but are rejected at command time unless `--allow-long-ttl` is also set.
pub fn parse_lock_ttl_hours(s: &str) -> Result<u64, String> {
    let v: u64 = s.parse().map_err(|_| "must be an integer".to_string())?;
    if !(1..=LOCK_TTL_HARD_CAP_HOURS).contains(&v) {
        return Err(format!(
            "must be between 1 and {} hours (30 days)",
            LOCK_TTL_HARD_CAP_HOURS
        ));
    }
    Ok(v)
}

/// Azure AD app ID URI must be an https:// URI or a `urn:` URN.
///
/// For https:// URIs, also reject empty hosts, loopback names
/// (`localhost`), and IP-literal hosts. Azure would refuse to issue a SAML
/// AuthnRequest against any of those, so the user gets a clear error up
/// front instead of an opaque 4xx from `login.microsoftonline.com`.
///
/// A URN must have the RFC 8141 shape `urn:<NID>:<NSS>`, as in
/// `urn:amazon:webservices`. Whitespace, control characters and `<`, `>`,
/// `"` (none of which may appear in a URI) are rejected for both forms.
/// `&` and `'` are valid URI characters and are allowed: the AuthnRequest
/// builder XML-escapes the value.
pub fn parse_app_id_uri(s: &str) -> Result<String, String> {
    // Checked before `Url::parse`, which silently strips tabs, newlines and
    // leading or trailing spaces instead of failing.
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("app ID URI must not contain whitespace or control characters".to_string());
    }
    if s.contains(['<', '>', '"']) {
        return Err("app ID URI must not contain <, > or \"".to_string());
    }
    let url = url::Url::parse(s).map_err(|e| format!("invalid app ID URI: {}", e))?;
    match url.scheme() {
        "https" => {}
        "urn" if is_urn(s) => return Ok(s.to_string()),
        "urn" => return Err("app ID URI must have the form urn:<namespace>:<name>".to_string()),
        other => {
            return Err(format!(
                "app ID URI must use the https:// or urn: scheme (got {})",
                other
            ));
        }
    }
    let host = url
        .host()
        .ok_or_else(|| "app ID URI must include a host".to_string())?;
    match host {
        url::Host::Domain(d) => {
            if d.is_empty() {
                return Err("app ID URI must include a host".to_string());
            }
            if d.eq_ignore_ascii_case("localhost") {
                return Err("app ID URI must not point at localhost".to_string());
            }
        }
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => {
            return Err("app ID URI must use a hostname, not an IP literal".to_string());
        }
    }
    Ok(s.to_string())
}

/// RFC 8141 shape check: `urn:<NID>:<NSS>`, where NID is 2 to 32 ASCII
/// letters, digits or hyphens that starts and ends with a letter or digit,
/// and NSS is not empty.
fn is_urn(s: &str) -> bool {
    let Some((nid, nss)) = s.split_once(':').and_then(|(_, rest)| rest.split_once(':')) else {
        return false;
    };
    (2..=32).contains(&nid.len())
        && nid.starts_with(|c: char| c.is_ascii_alphanumeric())
        && nid.ends_with(|c: char| c.is_ascii_alphanumeric())
        && nid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !nss.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_environment_is_namespaced() {
        const TENANT: &str = "11111111-2222-3333-4444-555555555555";
        const APPLICATION: &str = "https://signin.aws.amazon.com/saml";
        if let Ok(case) = std::env::var("AWZARS_ENVIRONMENT_TEST") {
            for command in ["login", "configure"] {
                let arguments = Args::try_parse_from(["awzars", command]).unwrap();
                let (tenant, application) = match arguments.command {
                    Command::Login {
                        azure_tenant,
                        azure_app,
                        ..
                    }
                    | Command::Configure {
                        azure_tenant,
                        azure_app,
                        ..
                    } => (azure_tenant, azure_app),
                    _ => unreachable!(),
                };
                if case == "namespaced" {
                    assert_eq!(tenant.as_deref(), Some(TENANT));
                    assert_eq!(application.as_deref(), Some(APPLICATION));
                } else {
                    assert!(tenant.is_none());
                    assert!(application.is_none());
                }
            }
            return;
        }
        for case in ["common", "namespaced"] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "cli::args::tests::azure_environment_is_namespaced",
                ])
                .env("AWZARS_ENVIRONMENT_TEST", case)
                .env("AZURE_TENANT_ID", "unrelated-azure-sdk-value")
                .env("AZURE_APP_ID_URI", "unrelated-azure-sdk-value")
                .env_remove("AWZARS_AZURE_TENANT_ID")
                .env_remove("AWZARS_AZURE_APP_ID_URI");
            if case == "namespaced" {
                child
                    .env("AWZARS_AZURE_TENANT_ID", TENANT)
                    .env("AWZARS_AZURE_APP_ID_URI", APPLICATION);
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }

    #[test]
    fn login_duration_uses_cli_then_profile_then_default() {
        let mut azure = crate::config::AzureConfig::default();
        let arguments = Args::try_parse_from(["awzars", "login"]).unwrap();
        let login = LoginArgs::from_command(&arguments.command).unwrap();
        assert_eq!(login.session_duration, None);
        assert_eq!(login.resolved_session_duration(&azure), 3600);
        assert!(!login.refresh_requested());
        azure.session_duration = 43200;
        assert_eq!(login.resolved_session_duration(&azure), 43200);

        let arguments =
            Args::try_parse_from(["awzars", "login", "--session-duration", "7200"]).unwrap();
        let login = LoginArgs::from_command(&arguments.command).unwrap();
        assert_eq!(login.resolved_session_duration(&azure), 7200);
        assert!(login.refresh_requested());
    }

    #[test]
    fn test_parse_session_duration_valid() {
        assert_eq!(parse_session_duration("3600"), Ok(3600));
        assert_eq!(parse_session_duration("900"), Ok(900));
        assert_eq!(parse_session_duration("43200"), Ok(43200));
    }

    #[test]
    fn test_parse_session_duration_invalid() {
        assert!(parse_session_duration("0").is_err());
        assert!(parse_session_duration("899").is_err());
        assert!(parse_session_duration("43201").is_err());
        assert!(parse_session_duration("notanumber").is_err());
    }

    #[test]
    fn test_parse_role_arn_valid() {
        assert!(parse_role_arn("arn:aws:iam::123456789012:role/MyRole").is_ok());
    }

    #[test]
    fn test_parse_role_arn_invalid() {
        assert!(parse_role_arn("not-an-arn").is_err());
        assert!(parse_role_arn("arn:aws:iam::12345:role/Foo").is_err()); // wrong digits
        assert!(parse_role_arn("arn:aws:s3:::bucket/key").is_err());
    }

    #[test]
    fn test_parse_profile_name() {
        assert!(parse_profile_name("default").is_ok());
        assert!(parse_profile_name("my-profile_1").is_ok());
        assert!(parse_profile_name("").is_err());
        assert!(parse_profile_name("bad name").is_err());
        assert!(parse_profile_name("../etc").is_err());
    }

    #[test]
    fn test_parse_tenant_uuid() {
        assert!(parse_tenant_uuid("11111111-2222-3333-4444-555555555555").is_ok());
        assert!(parse_tenant_uuid("not-a-uuid").is_err());
    }

    #[test]
    fn test_parse_app_id_uri() {
        assert!(parse_app_id_uri("https://signin.aws.amazon.com/saml").is_ok());
        assert!(parse_app_id_uri("http://example.com/saml").is_err()); // http rejected
        assert!(parse_app_id_uri("ftp://example.com/saml").is_err());
        assert!(parse_app_id_uri("mailto:someone").is_err());
        assert!(parse_app_id_uri("not a uri at all").is_err());
    }

    #[test]
    fn test_parse_app_id_uri_accepts_urn() {
        for uri in [
            "urn:amazon:webservices",
            "URN:amazon:webservices",
            "urn:example:app",
            "urn:x-example-1:a:b/c",
        ] {
            assert_eq!(parse_app_id_uri(uri).as_deref(), Ok(uri), "{uri}");
        }
    }

    #[test]
    fn test_parse_app_id_uri_rejects_malformed_urn() {
        let long_nid = format!("urn:{}:x", "a".repeat(33));
        for uri in [
            "urn:",
            "urn:amazon",
            "urn:amazon:",
            "urn::webservices",
            "urn:a:webservices",
            "urn:-amazon:webservices",
            "urn:amazon-:webservices",
            "urn:ama_zon:webservices",
            long_nid.as_str(),
        ] {
            assert!(parse_app_id_uri(uri).is_err(), "{uri}");
        }
        assert!(parse_app_id_uri(&format!("urn:{}:x", "a".repeat(32))).is_ok());
    }

    #[test]
    fn test_parse_app_id_uri_allows_ampersand_and_apostrophe() {
        for uri in [
            "https://example.com/saml?a=1&b=2",
            "https://example.com/it's",
            "urn:example:a&b",
        ] {
            assert_eq!(parse_app_id_uri(uri).as_deref(), Ok(uri), "{uri}");
        }
    }

    #[test]
    fn test_parse_app_id_uri_rejects_xml_unsafe() {
        assert!(parse_app_id_uri("https://example.com/<script>").is_err());
        assert!(parse_app_id_uri("https://example.com/a>b").is_err());
        assert!(parse_app_id_uri("https://example.com/a\"b").is_err());
        assert!(parse_app_id_uri("urn:example:<script>").is_err());
    }

    #[test]
    fn test_parse_app_id_uri_rejects_whitespace_and_control() {
        for uri in [
            "https://example.com/a b",
            "https://example.com/saml\n",
            "https://example.com/sa\tml",
            " https://example.com/saml",
            "https://example.com/saml\u{7}",
            "urn:amazon:web services",
            "urn:amazon:webservices\r\n",
        ] {
            assert!(parse_app_id_uri(uri).is_err(), "{uri:?}");
        }
    }

    #[test]
    fn test_parse_app_id_uri_rejects_loopback_and_ip() {
        // Loopback name.
        assert!(parse_app_id_uri("https://localhost/").is_err());
        assert!(parse_app_id_uri("https://LOCALHOST/").is_err());
        // IPv4 / IPv6 literals.
        assert!(parse_app_id_uri("https://127.0.0.1/").is_err());
        assert!(parse_app_id_uri("https://10.0.0.1/").is_err());
        assert!(parse_app_id_uri("https://[::1]/").is_err());
    }
}
