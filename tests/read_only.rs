use awzars::cli::Args;
use clap::Parser;
use std::process::{Command, Output, Stdio};

const CONFIG: &str = r#"
    [profiles.work]
    mcp_readonly_accessible = true
    lock_verifier = "locked-test-profile"
    lock_ai_markers = ["AWZARS_READ_ONLY_TEST_AI"]
    [profiles.work.azure]
    tenant_id = "11111111-2222-3333-4444-aaaaaaaaaaaa"
    app_id_uri = "https://signin.aws.amazon.com/saml"
    [profiles.work.read_only.targets.workload]
    role_arn = "arn:aws:iam::123456789012:role/Workload"
    region = "ap-southeast-1"
    capabilities = ["s3-list-buckets"]
"#;

fn execute(config: &str, target: &str, capability: &str) -> Output {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, config).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_awzars"))
        .arg("--config-dir")
        .arg(directory.path())
        .args([
            "--profile",
            "work",
            "read-only",
            "--target",
            target,
            "--capability",
            capability,
        ])
        .env("AWZARS_READ_ONLY_TEST_AI", "1")
        .env("AWZARS_SESSION_ID", "read_only_test")
        .env("XDG_RUNTIME_DIR", directory.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.stdout.is_empty());
    assert_eq!(std::fs::read_to_string(path).unwrap(), config);
    assert!(!directory.path().join("refresh-work.lock").exists());
    assert!(!directory.path().join("chromium").exists());
    output
}

#[test]
fn approved_capability_does_not_bypass_the_profile_lock() {
    let output = execute(CONFIG, "workload", "s3-list-buckets");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(8), "{stderr}");
    assert!(stderr.contains("AI context detected"), "{stderr}");
}

#[test]
fn unknown_targets_and_unapproved_capabilities_fail_before_authentication() {
    for (target, capability, message) in [
        ("other", "s3-list-buckets", "not configured"),
        ("workload", "ec2-describe-instances", "not enabled"),
    ] {
        let output = execute(CONFIG, target, capability);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(stderr.contains(message), "{stderr}");
    }
    let output = execute(
        CONFIG.split("[profiles.work.read_only").next().unwrap(),
        "workload",
        "s3-list-buckets",
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("No approved read-only targets"));
}

#[test]
fn arbitrary_policies_actions_and_scope_overrides_are_not_cli_inputs() {
    for capability in ["s3:DeleteObject", "s3:*", "read-only", "{\"Statement\":[]}"] {
        assert!(Args::try_parse_from([
            "awzars",
            "read-only",
            "--target",
            "workload",
            "--capability",
            capability
        ])
        .is_err());
    }
    for option in [
        "--role-arn",
        "--region",
        "--session-policy",
        "--endpoint-url",
        "--duration-seconds",
    ] {
        assert!(Args::try_parse_from([
            "awzars",
            "read-only",
            "--target",
            "workload",
            "--capability",
            "s3-list-buckets",
            option,
            "override"
        ])
        .is_err());
    }
}

#[test]
fn public_catalog_discovery_requires_no_profile_or_credentials_and_rejects_writes() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_awzars"))
        .arg("--config-dir")
        .arg(directory.path())
        .args(["read-catalog", "--aws-operation", "dynamodb/Query"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    let entry: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(entry["command"], "query");
    assert_eq!(entry["actions"], serde_json::json!(["dynamodb:Query"]));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    for operation in [
        "dynamodb/DeleteTable",
        "secretsmanager/GetSecretValue",
        "unknown/GetAnything",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_awzars"))
            .args(["read-catalog", "--aws-operation", operation])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn registration_requires_exactly_one_secret_destination_and_an_explicit_switch_value() {
    let arguments = [
        "awzars",
        "enroll-mcp",
        "--client",
        "incident-agent",
        "--target",
        "workload",
        "--capability",
        "s3-list-buckets",
    ];
    for (extra, accepted) in [
        (vec![], false),
        (vec!["--secret-stdout"], true),
        (vec!["--secret-file", "/tmp/example.secret"], true),
        (
            vec!["--secret-stdout", "--secret-file", "/tmp/example.secret"],
            false,
        ),
    ] {
        assert_eq!(
            Args::try_parse_from(arguments.into_iter().chain(extra)).is_ok(),
            accepted
        );
    }
    assert!(Args::try_parse_from(["awzars", "set-mcp-access"]).is_err());
    for enabled in ["true", "false"] {
        assert!(Args::try_parse_from(["awzars", "set-mcp-access", "--enabled", enabled]).is_ok());
    }
}

#[test]
fn unknown_mcp_client_is_rejected_without_credentials_or_unlocking() {
    use std::io::Write;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, CONFIG).unwrap();
    for secret in ["A".repeat(43), "PRIVATE-SECRET".into(), "A".repeat(4096)] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_awzars"))
            .arg("--config-dir")
            .arg(directory.path())
            .args([
                "--profile",
                "work",
                "read-only",
                "--target",
                "workload",
                "--capability",
                "s3-list-buckets",
                "--client",
                "unknown",
            ])
            .env("AWZARS_READ_ONLY_TEST_AI", "1")
            .env("AWZARS_SESSION_ID", "mcp_rejection_test")
            .env("XDG_RUNTIME_DIR", directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(secret.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(12), "{stderr}");
        assert!(output.stdout.is_empty());
        assert!(!stderr.contains(&secret));
        assert!(!directory.path().join("refresh-work.lock").exists());
        assert!(!directory.path().join("awzars/sessions").exists());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), CONFIG);
    }
}

#[test]
fn enrollment_management_requires_a_human_terminal_and_writes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let configuration = directory.path().join("config.toml");
    let secret = directory.path().join("mcp.secret");
    std::fs::write(&configuration, CONFIG).unwrap();
    let enrolled = Command::new(env!("CARGO_BIN_EXE_awzars"))
        .arg("--config-dir")
        .arg(directory.path())
        .args([
            "--profile",
            "work",
            "enroll-mcp",
            "--client",
            "incident-agent",
            "--target",
            "workload",
            "--capability",
            "s3-list-buckets",
            "--secret-file",
        ])
        .arg(&secret)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let revoked = Command::new(env!("CARGO_BIN_EXE_awzars"))
        .arg("--config-dir")
        .arg(directory.path())
        .args([
            "--profile",
            "work",
            "revoke-mcp",
            "--client",
            "incident-agent",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let enabled = Command::new(env!("CARGO_BIN_EXE_awzars"))
        .arg("--config-dir")
        .arg(directory.path())
        .args(["--profile", "work", "set-mcp-access", "--enabled", "true"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    for output in [enrolled, revoked, enabled] {
        assert_eq!(
            output.status.code(),
            Some(10),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
    }
    assert!(!secret.exists());
    assert_eq!(std::fs::read_to_string(configuration).unwrap(), CONFIG);
}
