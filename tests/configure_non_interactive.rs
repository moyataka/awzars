//! `configure --non-interactive` refuses to create a profile without a
//! tenant ID and app ID URI, and writes nothing.
#![cfg(unix)]

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

#[test]
fn configure_preserves_unknown_settings_at_every_level() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("config.toml");
    std::fs::write(
        &file,
        r#"
future_global = { enabled = true, values = [1, 2] }
[profiles.work]
future_profile = "keep me"
[profiles.work.azure]
tenant_id = "11111111-2222-3333-4444-aaaaaaaaaaaa"
app_id_uri = "https://signin.aws.amazon.com/saml"
future_azure = { nested = "retained" }
"#,
    )
    .unwrap();
    let before: toml::Value = toml::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_awzars"))
        .arg("--config-dir")
        .arg(directory.path())
        .args([
            "--profile",
            "work",
            "configure",
            "--non-interactive",
            "--session-duration",
            "7200",
        ])
        .env_remove("AWZARS_AZURE_TENANT_ID")
        .env_remove("AWZARS_AZURE_APP_ID_URI")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let after: toml::Value = toml::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(after["future_global"], before["future_global"]);
    assert_eq!(
        after["profiles"]["work"]["future_profile"],
        before["profiles"]["work"]["future_profile"]
    );
    assert_eq!(
        after["profiles"]["work"]["azure"]["future_azure"],
        before["profiles"]["work"]["azure"]["future_azure"]
    );
    assert_eq!(
        after["profiles"]["work"]["azure"]["session_duration"].as_integer(),
        Some(7200)
    );
}

#[test]
fn new_profile_without_tenant_and_app_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let aws_config = home.path().join("aws-config");
    std::fs::write(&aws_config, "").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_awzars"))
        .arg("--config-dir")
        .arg(directory.path())
        .args(["--profile", "fresh", "configure", "--non-interactive"])
        .env("HOME", home.path())
        .env("AWS_CONFIG_FILE", &aws_config)
        .env_remove("AWZARS_AZURE_TENANT_ID")
        .env_remove("AWZARS_AZURE_APP_ID_URI")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A background process group: a prompt that opens `/dev/tty` is
        // stopped instead of reading from the terminal the tests run in.
        .process_group(0)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("needs --azure-tenant and --azure-app"),
        "{stderr}"
    );
    assert!(
        !directory.path().join("config.toml").exists(),
        "nothing may be written"
    );
}
