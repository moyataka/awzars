//! Profile configuration management

use super::{config_file, enforce_config_dir_perms, ensure_config_dir, AzureConfig};
use crate::error::{AwzarsError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main configuration file structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Override the default ~/.aws/config path used by the TUI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_config_path: Option<String>,

    /// Named profiles
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,
}

/// A single profile configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Profile {
    /// Azure AD configuration
    pub azure: AzureConfig,

    /// Optional: Default AWS region
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Optional: Default AWS role ARN
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,

    /// Optional: Principal ARN (from SAML)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_arn: Option<String>,

    /// Persist browser session cookies to skip re-authentication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remember_me: Option<bool>,

    /// Run browser in headless mode for credential-process auto-login
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headless: Option<bool>,

    /// Disable Chrome sandbox (required when running as root)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_sandbox: Option<bool>,

    /// Allow insecure remote Chrome connections
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_insecure_remote_chrome: Option<bool>,

    /// Argon2id PHC string. `Some(_)` means the profile is password-locked;
    /// credential operations require a prior `awzars unlock <profile>` in the
    /// same terminal session. `None` means no password — but AI agents in the
    /// session still need a one-time consent (see `auth::lock`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_verifier: Option<String>,

    /// Override the default 8h unlock-token TTL for this profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_ttl_hours: Option<u64>,

    /// Override the built-in AI marker list (`CLAUDECODE`, `AI_AGENT`).
    /// `Some(vec![])` disables AI detection for this profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_ai_markers: Option<Vec<String>>,
}

impl Profile {
    /// Create a new profile with Azure configuration
    pub fn new(azure: AzureConfig) -> Self {
        Self {
            azure,
            region: None,
            role_arn: None,
            principal_arn: None,
            remember_me: None,
            headless: None,
            no_sandbox: None,
            allow_insecure_remote_chrome: None,
            lock_verifier: None,
            lock_ttl_hours: None,
            lock_ai_markers: None,
        }
    }
}

/// Maximum size of `config.toml` in bytes. A genuine config holding many
/// profiles is well under 100 KB; anything larger is treated as malformed
/// rather than parsed (prevents OOM from a hostile or corrupted file).
const MAX_CONFIG_SIZE: u64 = 1 << 20; // 1 MiB

impl Config {
    /// Load configuration from file
    pub fn load() -> Result<Self> {
        use std::io::Read;

        // Tighten ~/.awzars/ to 0o700 before reading anything out of it.
        // Save also does this; doing it on load too closes the window where
        // a fresh install's first operation is a load (e.g. credential-process)
        // and the directory was pre-created with loose perms by another tool
        // or a same-UID adversary.
        enforce_config_dir_perms()?;

        let path = config_file()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        let file = std::fs::File::open(&path)?;

        // Auto-tighten the file mode if the bits are looser than 0o600.
        // Catches operator error (e.g. `cp config.toml` from a backup that
        // dropped the original mode). We warn and tighten rather than fail
        // so a one-off permissions slip doesn't render the tool unusable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = file.metadata() {
                let mode = meta.mode() & 0o777;
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        "config file {} has loose permissions {:o}; tightening to 0600",
                        path.display(),
                        mode
                    );
                    // Symlink-safe: refuse to chmod through a planted symlink
                    // (the file we just opened is the real one, but the path
                    // could in principle have been swapped between open and
                    // chmod). Errors are non-fatal — the tighten is
                    // best-effort hardening.
                    let _ = crate::util::enforce_perms_no_symlink(&path, 0o600);
                }
            }
        }

        let mut contents = String::new();
        (&file)
            .take(MAX_CONFIG_SIZE)
            .read_to_string(&mut contents)?;

        // Detect the truncation case: if we hit the cap, the file is bigger
        // than allowed. Reject explicitly rather than parsing a half-file.
        let actual_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if actual_size > MAX_CONFIG_SIZE {
            return Err(AwzarsError::Config(format!(
                "config file exceeds {} bytes maximum",
                MAX_CONFIG_SIZE
            )));
        }

        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Save configuration to file with restricted permissions.
    ///
    /// On Unix, the file is written with mode 0o600 so that only the owner
    /// can read the configuration (which contains tenant IDs, app ID URIs,
    /// and role ARNs).
    ///
    /// Writes are atomic: contents go to a sibling `<path>.tmp` first, then
    /// are renamed over the target. A crash mid-write leaves the previous
    /// config intact rather than truncating it.
    pub fn save(&self) -> Result<()> {
        ensure_config_dir()?;
        let path = config_file()?;
        let contents = toml::to_string_pretty(self)?;
        crate::util::atomic_write(&path, contents.as_bytes(), 0o600)?;
        Ok(())
    }

    /// Get a profile by name
    pub fn get_profile(&self, name: &str) -> Result<&Profile> {
        self.profiles
            .get(name)
            .ok_or_else(|| AwzarsError::ProfileNotFound(name.to_string()))
    }

    /// Get a mutable profile by name
    pub fn get_profile_mut(&mut self, name: &str) -> Result<&mut Profile> {
        self.profiles
            .get_mut(name)
            .ok_or_else(|| AwzarsError::ProfileNotFound(name.to_string()))
    }

    /// Set or update a profile
    pub fn set_profile(&mut self, name: impl Into<String>, profile: Profile) {
        self.profiles.insert(name.into(), profile);
    }

    /// Remove a profile
    pub fn remove_profile(&mut self, name: &str) -> Option<Profile> {
        self.profiles.remove(name)
    }

    /// List all profile names
    pub fn list_profiles(&self) -> Vec<&String> {
        self.profiles.keys().collect()
    }
}
