//! Error types for awzars

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AwzarsError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Azure AD authentication failed: {0}")]
    AzureAuth(String),

    #[error("SAML assertion error: {0}")]
    Saml(String),

    #[error("AWS STS error: {0}")]
    AwsSts(String),

    #[error("Browser automation error: {0}")]
    Browser(String),

    #[error("Credential storage error: {0}")]
    Storage(String),

    #[error("TUI error: {0}")]
    Tui(String),

    /// User pressed q/Esc to quit a TUI loop. Carries no message — the
    /// containing command should treat this as a normal exit.
    #[error("user quit")]
    UserQuit,

    #[error("Network error: {0}")]
    Network(String),

    #[error("Profile '{0}' not found. Run `awzars configure` to create it.")]
    ProfileNotFound(String),

    #[error("No roles available in SAML assertion")]
    NoRolesAvailable,

    /// The requested role is absent from the SAML assertion, typically
    /// because it was renamed or removed on the identity-provider side.
    #[error("{}", role_not_in_assertion_message(.profile, .role_arn, .suggestions, .available))]
    RoleNotInAssertion {
        profile: String,
        role_arn: String,
        /// The closest available roles, best first.
        suggestions: Vec<String>,
        /// How many roles the assertion offers in total.
        available: usize,
    },

    #[error("Credential expired")]
    CredentialExpired,

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML error: {0}")]
    Toml(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Keyring error: {0}")]
    Keyring(String),

    #[error("Dialog error: {0}")]
    Dialog(String),

    /// `hint` says how to unlock in the session scope that was checked.
    #[error("Profile '{profile}' is password-locked. {hint}")]
    LockedProfile { profile: String, hint: String },

    /// `hint` says how to unlock in the session scope that was checked.
    #[error("AI context detected ({marker}) for profile '{profile}'. {hint}")]
    AiContextBlocked {
        profile: String,
        marker: String,
        hint: String,
    },

    #[error("Incorrect password.")]
    LockVerificationFailed,

    #[error("Lock and unlock require an interactive terminal (TTY).")]
    LockRequiresTty,

    #[error(
        "Another awzars login or credential refresh for profile '{profile}' is in \
         progress (for example a login waiting for browser sign-in); waited \
         {waited_secs}s. Retry once it finishes, or raise \
         AWZARS_REFRESH_LOCK_TIMEOUT_SECS."
    )]
    RefreshLockTimeout { profile: String, waited_secs: u128 },

    #[error(
        "Cannot determine the current boot session; session unlock is \
         unavailable in this environment."
    )]
    SessionUnlockUnavailable,
}

impl From<toml::de::Error> for AwzarsError {
    fn from(e: toml::de::Error) -> Self {
        AwzarsError::Toml(e.to_string())
    }
}

impl From<toml::ser::Error> for AwzarsError {
    fn from(e: toml::ser::Error) -> Self {
        AwzarsError::Toml(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AwzarsError>;

fn role_not_in_assertion_message(
    profile: &str,
    role_arn: &str,
    suggestions: &[String],
    available: &usize,
) -> String {
    let mut message = format!(
        "Role {role_arn} is not in the SAML assertion for profile '{profile}' \
         (it may have been renamed or removed)."
    );
    if !suggestions.is_empty() {
        message.push_str(&format!("\nClosest of {available} available role(s):"));
        for suggestion in suggestions {
            message.push_str(&format!("\n  {suggestion}"));
        }
    }
    message.push_str(&format!(
        "\n\nFix it one of two ways:\n  \
         1. Run an interactive login: `awzars login --profile {profile}` \
         — pick a role from the list and save it to the profile.\n  \
         2. Set it manually: `awzars configure --profile {profile} \
         --role-arn arn:aws:iam::<account>:role/<name>`.\n\
         List every available role with `awzars list-roles --profile {profile}`."
    ));
    message
}
