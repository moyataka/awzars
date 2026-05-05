//! Configuration management module

mod azure_config;
pub mod cleanup;
mod profile;

pub use azure_config::AzureConfig;
pub use profile::{Config, Profile};

use crate::error::{AwzarsError, Result};
use directories::ProjectDirs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Process-wide override for the configuration directory, populated at startup
/// from `--config-dir` / `AWZARS_CONFIG_DIR`. Set once; subsequent attempts to
/// change it are silently ignored (OnceLock semantics).
static CONFIG_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Install a user-supplied configuration directory override.
///
/// Call this once during startup, before any call to `config_dir()`.
/// Rejects empty strings and non-absolute paths (to avoid surprising
/// cwd-relative behavior across different invocation contexts).
pub fn set_config_dir_override(dir: &str) -> Result<()> {
    let path = Path::new(dir);
    if dir.is_empty() {
        return Err(AwzarsError::Config(
            "--config-dir / AWZARS_CONFIG_DIR must not be empty".to_string(),
        ));
    }
    if !path.is_absolute() {
        return Err(AwzarsError::Config(format!(
            "--config-dir must be an absolute path (got {})",
            dir
        )));
    }
    // OnceLock::set returns Err if already set; ignore (first call wins).
    let _ = CONFIG_DIR_OVERRIDE.set(path.to_path_buf());
    Ok(())
}

/// Get the configuration directory path.
///
/// Honors `--config-dir` / `AWZARS_CONFIG_DIR` if it was installed via
/// `set_config_dir_override` at startup; otherwise defaults to the
/// platform XDG config directory (`~/.config/awzars/` on Linux).
pub fn config_dir() -> Result<PathBuf> {
    if let Some(override_path) = CONFIG_DIR_OVERRIDE.get() {
        return Ok(override_path.clone());
    }
    let project_dirs = ProjectDirs::from("com", "awzars", "awzars").ok_or_else(|| {
        AwzarsError::Config("Could not determine configuration directory".to_string())
    })?;
    Ok(project_dirs.config_dir().to_path_buf())
}

/// Get the configuration file path
pub fn config_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

/// Ensure the configuration directory exists with restricted permissions.
///
/// On Unix, the directory is created with mode 0o700 so that only the owner
/// can read tenant IDs, app ID URIs, and role ARNs stored inside.
///
/// SECURITY: Permissions are always enforced, even if the directory already
/// existed. This prevents an attacker from pre-creating the directory with
/// world-readable permissions (0o777) to expose config contents. The chmod
/// is symlink-safe: a planted symlink at the leaf is rejected rather than
/// silently traversed.
pub fn ensure_config_dir() -> Result<()> {
    let dir = config_dir()?;
    if !dir.exists() {
        // Create parent chain with default permissions, then create the leaf
        // directory explicitly so we can restrict its mode.
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir(&dir)?;
    }
    crate::util::enforce_perms_no_symlink(&dir, 0o700)?;
    Ok(())
}

/// Tighten permissions on the config directory if it exists, without creating it.
///
/// Use this on read paths (`Config::load`) so a pre-existing 0o777 dir gets
/// cinched down before we read sensitive files out of it. Read paths must
/// not create the directory as a side effect — that was the job of an
/// explicit `awzars configure` / save.
pub fn enforce_config_dir_perms() -> Result<()> {
    let dir = config_dir()?;
    if !dir.exists() {
        return Ok(());
    }
    crate::util::enforce_perms_no_symlink(&dir, 0o700)?;
    Ok(())
}

/// Get the Chromium user data directory for a profile (for persistent sessions).
///
/// SECURITY: The profile name is validated to prevent path traversal (e.g. `../../etc`).
/// This defense is applied at the function level so it cannot be bypassed by callers
/// that skip CLI-level validation.
pub fn chromium_data_dir(profile: &str) -> Result<PathBuf> {
    if profile.is_empty()
        || !profile
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AwzarsError::Config(
            "Invalid profile name: must match [a-zA-Z0-9_-]+".to_string(),
        ));
    }
    Ok(config_dir()?.join("chromium").join(profile))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    #[cfg(unix)]
    fn test_ensure_config_dir_has_restricted_permissions() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("awzars");

        // Create directory with restricted permissions
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mode = dir.metadata().unwrap().permissions().mode();
        // Mode bits: 0o700 = 0o40700 (0o40000 is directory bit)
        assert_eq!(
            mode & 0o777,
            0o700,
            "config dir should be 0700, got {:o}",
            mode & 0o777
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_config_save_has_restricted_permissions() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("config.toml");

        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&file_path)
            .unwrap()
            .write_all(b"test")
            .unwrap();

        let mode = file_path.metadata().unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "config file should be 0600, got {:o}",
            mode & 0o777
        );
    }
}
