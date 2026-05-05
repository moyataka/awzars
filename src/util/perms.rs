//! Symlink-safe `set_permissions`.
//!
//! `std::fs::set_permissions` calls `chmod()`, which follows symlinks. A
//! same-UID actor (or an existing user-made symlink) at a path we are about
//! to tighten would have us silently chmod the symlink target. This helper
//! refuses to operate on a symlink and otherwise behaves exactly like
//! `set_permissions`.

use std::io;
use std::path::Path;

/// Apply `mode` to `path`, refusing to follow a symlink at the leaf.
///
/// On non-Unix this is a no-op (the underlying mode bits are not meaningful).
#[cfg_attr(not(unix), allow(unused_variables))]
pub fn enforce_perms_no_symlink(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // symlink_metadata does not follow symlinks; metadata does. We need
        // the former to detect a planted symlink, then defer the actual
        // chmod to set_permissions only after we have proven the leaf is
        // not a symlink. There is still a TOCTOU window between this check
        // and the chmod, but a same-UID adversary that wins it must replace
        // the path with a symlink in microseconds — at which point they
        // already have write access to the parent directory.
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is a symlink; refusing to chmod through it",
                    path.display()
                ),
            ));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn applies_mode_to_regular_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        enforce_perms_no_symlink(&path, 0o600).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_when_path_is_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = enforce_perms_no_symlink(&link, 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
