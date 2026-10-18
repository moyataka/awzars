//! Atomic file write helper.
//!
//! Writes are durable against crash mid-write: contents go to a sibling
//! temp file with the requested mode, then are renamed over the target.
//! A crash between open and rename leaves the target's previous contents
//! intact.

use std::io::Write;
use std::path::Path;

/// Write a unique sibling file, sync it, then atomically replace the target.
/// Concurrent writers never share a temporary path. Failed writes clean up
/// their own temporary file; the previous target remains intact.
pub fn atomic_write(path: &Path, contents: &[u8], unix_mode: u32) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".awzars-")
        .tempfile_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(unix_mode))?;
    }
    #[cfg(not(unix))]
    let _ = unix_mode;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_writes_produce_one_complete_file_without_leftovers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("target");
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for byte in 0..8 {
                let path = &path;
                let barrier = &barrier;
                scope.spawn(move || {
                    let contents = vec![byte; 128 * 1024];
                    barrier.wait();
                    atomic_write(path, &contents, 0o600).unwrap();
                });
            }
        });
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents.len(), 128 * 1024);
        assert!(contents.iter().all(|byte| *byte == contents[0]));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn failed_rename_cleans_up_its_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("directory");
        std::fs::create_dir(&target).unwrap();
        assert!(atomic_write(&target, b"contents", 0o600).is_err());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn writes_contents_and_removes_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        atomic_write(&path, b"hello", 0o600).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        assert!(
            !dir.path().join("target.tmp").exists(),
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
        // A planted legacy temporary path must never be used by a new write.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        let sentinel = dir.path().join("sentinel");
        std::fs::write(&sentinel, b"original").unwrap();

        std::os::unix::fs::symlink(&sentinel, dir.path().join("target.tmp")).unwrap();

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
        let tmp = dir.path().join("target.tmp");

        // A stale temporary file must not affect the new file permissions.
        std::fs::write(&tmp, b"stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();

        atomic_write(&path, b"new", 0o600).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
