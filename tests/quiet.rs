use std::process::Command;

#[test]
fn quiet_configure_suppresses_status_and_overrides_verbose_logging() {
    for quiet in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "[profiles]\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_awzars"));
        command
            .arg("--config-dir")
            .arg(directory.path())
            .args([
                "-vvv",
                "configure",
                "--non-interactive",
                "--azure-tenant",
                "11111111-2222-3333-4444-555555555555",
                "--azure-app",
                "https://signin.aws.amazon.com/saml",
            ])
            .env("RUST_LOG", "trace");
        if quiet {
            command.arg("--quiet");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if quiet {
            assert!(output.stdout.is_empty());
            assert!(output.stderr.is_empty());
        } else {
            assert!(String::from_utf8_lossy(&output.stdout).contains("configured successfully"));
            #[cfg(unix)]
            assert!(String::from_utf8_lossy(&output.stderr).contains("loose permissions"));
        }
        assert!(std::fs::read_to_string(path)
            .unwrap()
            .contains("11111111-2222-3333-4444-555555555555"));
    }
}

#[test]
fn quiet_preserves_errors_and_exit_status() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_awzars"))
        .arg("--config-dir")
        .arg(directory.path())
        .args(["--quiet", "--profile", "missing", "login"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Error:"));
}
