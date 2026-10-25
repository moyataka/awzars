use crate::error::{AwzarsError, Result};
use std::fs::{File, OpenOptions, TryLockError};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Environment variable that overrides how long a waiter blocks on the lock.
pub const REFRESH_LOCK_TIMEOUT_ENV: &str = "AWZARS_REFRESH_LOCK_TIMEOUT_SECS";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const NOTICE_AFTER: Duration = Duration::from_secs(1);

/// Held through the cache re-check, authentication, and credential persistence.
#[must_use]
pub struct CredentialRefreshGuard {
    _file: File,
}

impl CredentialRefreshGuard {
    /// Take the refresh lock for `profile`, giving up after the configured
    /// timeout (`AWZARS_REFRESH_LOCK_TIMEOUT_SECS`, default 60 s).
    pub async fn acquire(profile: &str) -> Result<Self> {
        let path = lock_path(profile)?;
        Self::acquire_path(&path, profile, refresh_lock_timeout()).await
    }

    async fn acquire_path(path: &Path, profile: &str, timeout: Duration) -> Result<Self> {
        let owned = path.to_path_buf();
        let file = tokio::task::spawn_blocking(move || open_lock_file(&owned))
            .await
            .map_err(|_| AwzarsError::Cache("Credential refresh lock task failed".into()))??;
        let started = Instant::now();
        let mut notified = false;
        loop {
            // `try_lock` never blocks, so polling it from the async task is sound.
            match file.try_lock() {
                Ok(()) => {
                    // The OS releases this on close or process exit. Never unlink
                    // the lock path: waiters must keep referring to the same inode.
                    return Ok(Self { _file: file });
                }
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Error(error)) => return Err(AwzarsError::Io(error)),
            }
            let waited = started.elapsed();
            if waited >= timeout {
                return Err(AwzarsError::RefreshLockTimeout {
                    profile: profile.to_string(),
                    waited_secs: (waited.as_millis() + 500) / 1000,
                });
            }
            if !notified && waited >= NOTICE_AFTER {
                notified = true;
                tracing::warn!(
                    "Waiting for another awzars login or credential refresh for profile '{}' \
                     to finish (giving up after {}s)",
                    profile,
                    timeout.as_secs()
                );
            }
            tokio::time::sleep(POLL_INTERVAL.min(timeout - waited)).await;
        }
    }
}

/// Take the refresh lock, re-check with `load`, and call `refresh` only on a
/// miss. Another process may have refreshed while this one waited, so the
/// re-check is what keeps concurrent callers from running a second login.
///
/// The guard is returned so the caller can keep holding the lock until it has
/// finished with the credentials.
pub async fn refresh_under_lock<T, F>(
    profile: &str,
    load: impl FnOnce() -> Result<Option<T>>,
    refresh: impl FnOnce() -> F,
) -> Result<(T, CredentialRefreshGuard)>
where
    F: Future<Output = Result<T>>,
{
    let path = lock_path(profile)?;
    refresh_under_lock_at(&path, profile, refresh_lock_timeout(), load, refresh).await
}

async fn refresh_under_lock_at<T, F>(
    path: &Path,
    profile: &str,
    timeout: Duration,
    load: impl FnOnce() -> Result<Option<T>>,
    refresh: impl FnOnce() -> F,
) -> Result<(T, CredentialRefreshGuard)>
where
    F: Future<Output = Result<T>>,
{
    let guard = CredentialRefreshGuard::acquire_path(path, profile, timeout).await?;
    if let Some(value) = load()? {
        return Ok((value, guard));
    }
    let value = refresh().await?;
    Ok((value, guard))
}

fn lock_path(profile: &str) -> Result<PathBuf> {
    let profile = crate::cli::args::parse_profile_name(profile).map_err(AwzarsError::Config)?;
    crate::config::ensure_config_dir()?;
    Ok(crate::config::config_dir()?.join(format!("refresh-{profile}.lock")))
}

fn refresh_lock_timeout() -> Duration {
    match std::env::var(REFRESH_LOCK_TIMEOUT_ENV) {
        Ok(value) => parse_timeout(Some(&value)),
        Err(std::env::VarError::NotPresent) => parse_timeout(None),
        Err(std::env::VarError::NotUnicode(_)) => parse_timeout(Some("")),
    }
}

/// A positive whole number of seconds; anything else falls back to the default.
fn parse_timeout(value: Option<&str>) -> Duration {
    let Some(value) = value else {
        return DEFAULT_TIMEOUT;
    };
    match value.trim().parse::<u64>() {
        Ok(seconds) if seconds > 0 => Duration::from_secs(seconds),
        _ => {
            tracing::warn!(
                "Ignoring {}: expected a positive whole number of seconds; using {}s",
                REFRESH_LOCK_TIMEOUT_ENV,
                DEFAULT_TIMEOUT.as_secs()
            );
            DEFAULT_TIMEOUT
        }
    }
}

fn open_lock_file(path: &Path) -> std::io::Result<File> {
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
    Ok(file)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Runs a test's child process while this process holds a profile's
    //! refresh lock, failing if the child is still blocked after a deadline.

    use crate::config::{self, Config, Profile};
    use crate::credential_process::protocol::CredentialProcessOutput;
    use crate::storage::cache::CacheHandle;
    use std::time::{Duration, Instant};

    /// Env var naming the config directory a child should use.
    pub(crate) const CHILD_DIRECTORY_ENV: &str = "AWZARS_LOCKED_REFRESH_DIRECTORY";

    /// Child side: point the config at `directory` and give the `default`
    /// profile valid credentials in the in-process cache.
    pub(crate) fn prepare_cached_default_profile(directory: &str) {
        config::set_config_dir_override(directory).unwrap();
        let profile = Profile {
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
            .store(
                &CredentialProcessOutput {
                    version: 1,
                    access_key_id: "cached-output".to_string(),
                    secret_access_key: "test-secret".to_string(),
                    session_token: Some("test-token".to_string()),
                    expiration: Some(
                        (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339(),
                    ),
                },
                &identity,
            )
            .unwrap();
    }

    /// Parent side: hold `refresh-default.lock` the way a login waiting for
    /// browser sign-in would, run the test `test_path` as a child, and return
    /// its output. Panics if the child has not finished within 20 seconds.
    pub(crate) fn run_child_while_lock_held(test_path: &str) -> std::process::Output {
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
            .args(["--exact", test_path, "--nocapture"])
            .env(CHILD_DIRECTORY_ENV, directory.path())
            .env("AWZARS_REFRESH_LOCK_TIMEOUT_SECS", "600")
            .env_remove("AWZARS_AZURE_TENANT_ID")
            .env_remove("AWZARS_AZURE_APP_ID_URI")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                child.kill().unwrap();
                panic!("{test_path}: a call with cached credentials waited on the refresh lock");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let output = child.wait_with_output().unwrap();
        drop(lock);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    async fn acquire(path: &Path, timeout: Duration) -> Result<CredentialRefreshGuard> {
        CredentialRefreshGuard::acquire_path(path, "work", timeout).await
    }

    fn release_after(
        guard: CredentialRefreshGuard,
        delay: Duration,
        before: impl FnOnce() + Send + 'static,
    ) {
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            before();
            drop(guard);
        });
    }

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
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let guard = runtime
            .block_on(acquire(&path, Duration::from_secs(5)))
            .unwrap();
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
    #[tokio::test]
    async fn refuses_symlink_lock_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.lock");
        let target = directory.path().join("target");
        std::fs::write(&target, b"untouched").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(acquire(&path, Duration::from_secs(1)).await.is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"untouched");
    }

    #[tokio::test]
    async fn waiter_gives_up_with_a_message_naming_the_profile() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.lock");
        let _holder = acquire(&path, Duration::from_secs(1)).await.unwrap();

        let started = Instant::now();
        let error = acquire(&path, Duration::from_millis(1200))
            .await
            .err()
            .expect("waiter must time out while the lock is held");
        let elapsed = started.elapsed();

        assert!(elapsed >= Duration::from_millis(1200), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
        assert!(matches!(
            error,
            AwzarsError::RefreshLockTimeout { ref profile, waited_secs: 1 } if profile == "work"
        ));
        let message = error.to_string();
        assert!(message.contains("profile 'work'"), "{message}");
        assert!(message.contains("waited 1s"), "{message}");
        assert!(message.contains("in progress"), "{message}");
        assert!(
            message.contains("AWZARS_REFRESH_LOCK_TIMEOUT_SECS"),
            "{message}"
        );
        assert!(!message.contains("prompt"), "{message}");
        assert!(path.exists());
    }

    #[tokio::test]
    async fn waiter_acquires_once_the_holder_releases() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.lock");
        let holder = acquire(&path, Duration::from_secs(1)).await.unwrap();
        release_after(holder, Duration::from_millis(100), || {});

        let started = Instant::now();
        let _waiter = acquire(&path, Duration::from_secs(5)).await.unwrap();
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(100), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }

    #[tokio::test]
    async fn waiter_reuses_what_the_holder_stored_instead_of_refreshing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.lock");
        let store = Arc::new(Mutex::new(None::<String>));
        let refreshes = AtomicUsize::new(0);
        let counter = &refreshes;

        let holder = acquire(&path, Duration::from_secs(1)).await.unwrap();
        let writer = Arc::clone(&store);
        release_after(holder, Duration::from_millis(100), move || {
            *writer.lock().unwrap() = Some("from-holder".to_string());
        });

        let (value, _guard) = refresh_under_lock_at(
            &path,
            "work",
            Duration::from_secs(5),
            || Ok(store.lock().unwrap().clone()),
            move || async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok("from-waiter".to_string())
            },
        )
        .await
        .unwrap();

        assert_eq!(value, "from-holder");
        assert_eq!(refreshes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn refresh_runs_on_a_miss_and_the_guard_keeps_the_lock() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.lock");
        let refreshes = AtomicUsize::new(0);
        let counter = &refreshes;

        let (value, guard) = refresh_under_lock_at(
            &path,
            "work",
            Duration::from_secs(5),
            || Ok(None),
            move || async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok("fresh")
            },
        )
        .await
        .unwrap();

        assert_eq!(value, "fresh");
        assert_eq!(refreshes.load(Ordering::SeqCst), 1);
        assert!(matches!(
            acquire(&path, Duration::from_millis(300)).await,
            Err(AwzarsError::RefreshLockTimeout { .. })
        ));
        drop(guard);
        assert!(acquire(&path, Duration::from_millis(300)).await.is_ok());
    }

    #[test]
    fn timeout_override_accepts_only_positive_whole_seconds() {
        assert_eq!(parse_timeout(None), DEFAULT_TIMEOUT);
        assert_eq!(parse_timeout(Some("5")), Duration::from_secs(5));
        assert_eq!(parse_timeout(Some(" 120 ")), Duration::from_secs(120));
        for invalid in ["0", "", "-3", "1.5", "abc", "60s"] {
            assert_eq!(parse_timeout(Some(invalid)), DEFAULT_TIMEOUT, "{invalid:?}");
        }
    }
}
