#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};

#[test]
fn inaccessible_keyring_reports_recovery_without_attempting_browser_login() {
    let directory = tempfile::tempdir().unwrap();
    let profile = awzars::config::Profile {
        azure: awzars::config::AzureConfig::new(
            "11111111-2222-3333-4444-555555555555",
            "https://signin.aws.amazon.com/saml",
        ),
        role_arn: Some("arn:aws:iam::123456789012:role/Test".into()),
        lock_ai_markers: Some(vec![]),
        ..Default::default()
    };
    let mut configuration = awzars::config::Config::default();
    configuration.set_profile("default", profile);
    let configuration_path = directory.path().join("config.toml");
    let configuration_contents = toml::to_string(&configuration).unwrap();
    std::fs::write(&configuration_path, &configuration_contents).unwrap();

    for quiet in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_awzars"));
        command
            .arg("--config-dir")
            .arg(directory.path())
            .args(["--profile", "default", "credential-process"])
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/missing-dbus.sock", directory.path().display()),
            )
            .env("CHROME_REMOTE_URL", "http://invalid-browser-endpoint")
            .env("RUST_LOG", "info")
            .stdin(Stdio::null());
        if quiet {
            command.arg("--quiet");
        }
        let output = command.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(output.status.code(), Some(5), "{stderr}");
        assert!(output.stdout.is_empty());
        assert!(stderr.contains("OS keyring access failed"), "{stderr}");
        assert!(
            stderr.contains("Credential expiration could not be checked"),
            "{stderr}"
        );
        assert!(stderr.contains("locked after a reboot"), "{stderr}");
        assert!(stderr.contains("Unlock the OS keyring"), "{stderr}");
        assert!(stderr.contains("original AWS CLI command"), "{stderr}");
        assert!(stderr.contains("Details:"), "{stderr}");
        assert!(
            !stderr.contains("attempting automatic re-authentication"),
            "{stderr}"
        );
        assert!(!stderr.contains("Browser automation error"), "{stderr}");
        assert_eq!(
            std::fs::read_to_string(&configuration_path).unwrap(),
            configuration_contents
        );
    }
}
