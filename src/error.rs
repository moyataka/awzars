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

    #[error(
        "Profile '{profile}' is password-locked. Run `awzars unlock {profile}` \
         interactively to unlock for this terminal session."
    )]
    LockedProfile { profile: String },

    #[error(
        "AI context detected ({marker}) for profile '{profile}'. Run \
         `awzars unlock {profile} --allow-ai` interactively to grant AI access \
         for this terminal session."
    )]
    AiContextBlocked { profile: String, marker: String },

    #[error("Incorrect password.")]
    LockVerificationFailed,

    #[error("Lock and unlock require an interactive terminal (TTY).")]
    LockRequiresTty,
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
