use std::process::{Command, Stdio};

const POLICY: &str = include_str!("../examples/session-policies/ec2-describe-instances.json");

#[test]
fn session_policy_keeps_the_password_and_ai_gate() {
    let directory = tempfile::tempdir().unwrap();
    let policy_path = directory.path().join("policy.json");
    std::fs::write(&policy_path, POLICY).unwrap();
    let profile = awzars::config::Profile {
        lock_verifier: Some(awzars::auth::lock::hash_password("test-password").unwrap()),
        lock_ai_markers: Some(vec!["AWZARS_SESSION_POLICY_TEST_AI".into()]),
        ..Default::default()
    };
    let mut configuration = awzars::config::Config::default();
    configuration.set_profile("restricted-test", profile);
    let configuration_path = directory.path().join("config.toml");
    let contents = toml::to_string(&configuration).unwrap();
    std::fs::write(&configuration_path, &contents).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_awzars"))
        .arg("--config-dir")
        .arg(directory.path())
        .args([
            "--profile",
            "restricted-test",
            "login",
            "--credential-process",
            "--session-policy",
        ])
        .arg(&policy_path)
        .env("AWZARS_SESSION_POLICY_TEST_AI", "1")
        .env("AWZARS_SESSION_ID", "restricted_policy_test")
        .env("XDG_RUNTIME_DIR", directory.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(8), "{stderr}");
    assert!(stderr.contains("AI context detected"), "{stderr}");
    assert!(output.stdout.is_empty());
    assert_eq!(
        std::fs::read_to_string(configuration_path).unwrap(),
        contents
    );
    assert!(!directory
        .path()
        .join("refresh-restricted-test.lock")
        .exists());
    assert!(!directory.path().join("chromium").exists());
}

#[test]
fn invalid_session_policy_fails_before_configuration_or_authentication() {
    let directory = tempfile::tempdir().unwrap();
    let policy_path = directory.path().join("policy.json");
    let configuration_directory = directory.path().join("absent-config");
    for document in [None, Some("PRIVATE-POLICY-MARKER"), Some("{}"), Some("")] {
        if let Some(document) = document {
            std::fs::write(&policy_path, document).unwrap();
        }
        let output = Command::new(env!("CARGO_BIN_EXE_awzars"))
            .arg("--config-dir")
            .arg(&configuration_directory)
            .args(["login", "--session-policy"])
            .arg(&policy_path)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(stderr.to_lowercase().contains("session policy"), "{stderr}");
        assert!(!stderr.contains("PRIVATE-POLICY-MARKER"), "{stderr}");
        assert!(output.stdout.is_empty());
        assert!(!configuration_directory.exists());
    }
}
