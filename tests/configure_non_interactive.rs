//! `configure --non-interactive` refuses to create a profile without a
//! tenant ID and app ID URI, and writes nothing.
#![cfg(unix)]

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

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
