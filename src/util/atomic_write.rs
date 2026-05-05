//! Atomic file write helper.
//!
//! Writes are durable against crash mid-write: contents go to a sibling
//! temp file with the requested mode, then are renamed over the target.
//! A crash between open and rename leaves the target's previous contents
//! intact.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Append `.tmp` to a path. Used so the temp file is in the same directory
/// as the target — `fs::rename` is only atomic on the same filesystem.
fn tmp_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Atomically write `contents` to `path`, applying `unix_mode` on Unix.
///
/// On Unix the temp file is created with `O_CREAT | O_EXCL | O_NOFOLLOW`
/// after first unlinking any stale `<path>.tmp`. The combination defeats a
/// same-UID adversary who tries to plant the temp path as a symlink, a
/// pre-existing file with looser mode bits, or a hardlink: the create
/// refuses any of those, and `fchmod` on the open fd applies `unix_mode`
/// over whatever the umask masked off at create time.
///
/// If the rename fails, the temp file is left in place; the next call to
/// `atomic_write` for the same target will unlink and recreate it before
/// renaming again, so there is no leak across normal recovery.
pub fn atomic_write(path: &Path, contents: &[u8], unix_mode: u32) -> std::io::Result<()> {
    let tmp = tmp_for(path);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        // Drop any stale temp file. A previous run may have crashed mid-write,
        // or — more interestingly — a same-UID adversary may have pre-created
        // <path>.tmp as a symlink to a file outside our control. Unlinking
        // first guarantees the create below makes a fresh inode of our own.
        // ENOENT is the expected case; other errors are reported by the
        // create that follows.
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => { /* fall through; OpenOptions will surface a real error */ }
        }

        let mut file = std::fs::OpenOptions::new()
            // O_CREAT | O_EXCL: refuse to open if the temp file reappeared
            // between the unlink and now (race with another caller, or an
            // adversarial create).
            .create_new(true)
            .write(true)
            .mode(unix_mode)
            // O_NOFOLLOW: belt-and-braces — O_EXCL alone already refuses
            // existing symlinks, but keeping NOFOLLOW makes the intent
            // explicit and survives any future relaxation of create_new.
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&tmp)?;

        // fchmod the open fd. The mode argument to OpenOptions is masked by
        // the process umask at create time, so a 0o022 umask would leave a
        // 0o600-requested file at 0o600 anyway — but a more permissive umask
        // (or a custom create-mode handler) would silently widen the mode.
        // Operating on the fd cannot be redirected by a symlink race.
        file.set_permissions(std::fs::Permissions::from_mode(unix_mode))?;
        file.write_all(contents)?;
    }
    #[cfg(not(unix))]
    {
        let _ = unix_mode;
        std::fs::write(&tmp, contents)?;
    }

    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_contents_and_removes_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        atomic_write(&path, b"hello", 0o600).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        assert!(
            !tmp_for(&path).exists(),
            "temp file should be gone after rename"
        );
    }

    #[test]
    fn overwrites_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        std::fs::write(&path, b"old").unwrap();

        atomic_write(&path, b"new", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn applies_unix_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        atomic_write(&path, b"x", 0o600).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_temp_file_that_is_a_symlink() {
        // Plant <path>.tmp as a symlink to a sentinel file. atomic_write
        // must unlink the symlink and create a fresh file rather than
        // writing through it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        let sentinel = dir.path().join("sentinel");
        std::fs::write(&sentinel, b"original").unwrap();

        std::os::unix::fs::symlink(&sentinel, tmp_for(&path)).unwrap();

        atomic_write(&path, b"new", 0o600).unwrap();

        // The sentinel must NOT have been overwritten through the symlink.
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"original");
        // The real target must hold the new contents.
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn applies_mode_even_when_temp_existed_with_loose_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        let tmp = tmp_for(&path);

        // Pre-plant a stale temp file with a loose mode. atomic_write must
        // unlink it and create a fresh one whose mode matches the request.
        std::fs::write(&tmp, b"stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();

        atomic_write(&path, b"new", 0o600).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
