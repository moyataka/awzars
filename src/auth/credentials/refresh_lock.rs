use crate::error::{AwzarsError, Result};
use std::fs::{File, OpenOptions};
use std::path::Path;

/// Held through the cache check, authentication, and credential persistence.
#[must_use]
pub struct CredentialRefreshGuard {
    _file: File,
}

impl CredentialRefreshGuard {
    pub async fn acquire(profile: &str) -> Result<Self> {
        let profile = crate::cli::args::parse_profile_name(profile).map_err(AwzarsError::Config)?;
        crate::config::ensure_config_dir()?;
        let path = crate::config::config_dir()?.join(format!("refresh-{profile}.lock"));
        tokio::task::spawn_blocking(move || Self::acquire_path(&path))
            .await
            .map_err(|_| AwzarsError::Cache("Credential refresh lock task failed".into()))?
            .map_err(AwzarsError::Io)
    }

    fn acquire_path(path: &Path) -> std::io::Result<Self> {
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other("Refresh lock is not a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.lock()?;
        // The OS releases this on close or process exit. Never unlink the lock
        // path: waiters must continue to refer to the same inode.
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_lock_excludes_other_processes_and_releases_on_drop() {
        if let Some(path) = std::env::var_os("AWZARS_REFRESH_LOCK_TEST") {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap();
            if std::env::var_os("AWZARS_REFRESH_LOCK_HELD").is_some() {
                assert!(matches!(
                    file.try_lock(),
                    Err(std::fs::TryLockError::WouldBlock)
                ));
            } else {
                file.try_lock().unwrap();
            }
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.lock");
        let guard = CredentialRefreshGuard::acquire_path(&path).unwrap();
        let run_child = |held| {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child.args(["--exact", "auth::credentials::refresh_lock::tests::refresh_lock_excludes_other_processes_and_releases_on_drop"])
                .env("AWZARS_REFRESH_LOCK_TEST", &path)
                .env_remove("AWZARS_REFRESH_LOCK_HELD");
            if held {
                child.env("AWZARS_REFRESH_LOCK_HELD", "1");
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        };
        run_child(true);
        drop(guard);
        run_child(false);
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_lock_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.lock");
        let target = directory.path().join("target");
        std::fs::write(&target, b"untouched").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(CredentialRefreshGuard::acquire_path(&path).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"untouched");
    }
}
