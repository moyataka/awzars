//! `clear-cache` and `delete-profile` refuse to prompt without a terminal and
//! point to `--yes`, and refuse a profile that doesn't exist before asking.
//! Every case here stops before any keychain access.
#![cfg(unix)]

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const CONFIG: &str = "[profiles.dev.azure]\n\
    tenant_id = \"11111111-2222-3333-4444-aaaaaaaaaaaa\"\n\
    app_id_uri = \"https://signin.aws.amazon.com/saml\"\n";

/// Run awzars with stdin from /dev/null, failing instead of hanging.
fn awzars(config_dir: &Path, args: &[&str]) -> Output {
    let home = tempfile::tempdir().unwrap();
    let aws_config = home.path().join("aws-config");
    std::fs::write(&aws_config, "").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_awzars"))
        .arg("--config-dir")
        .arg(config_dir)
        .args(args)
        .env("HOME", home.path())
        .env("AWS_CONFIG_FILE", &aws_config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A background process group: a prompt that opens `/dev/tty` is
        // stopped instead of reading from the terminal the tests run in.
        .process_group(0)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("awzars {:?} did not exit", args);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

fn config_dir_with_dev_profile() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("config.toml"), CONFIG).unwrap();
    directory
}

#[test]
fn clear_cache_reports_a_missing_profile() {
    let directory = tempfile::tempdir().unwrap();
    let output = awzars(directory.path(), &["--profile", "absent", "clear-cache"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("Profile 'absent' not found"), "{stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn clear_cache_without_a_terminal_points_to_yes() {
    let directory = config_dir_with_dev_profile();
    let output = awzars(directory.path(), &["--profile", "dev", "clear-cache"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(6), "{stderr}");
    assert!(stderr.contains("pass --yes"), "{stderr}");
}

#[test]
fn delete_profile_reports_a_missing_profile_before_asking() {
    let directory = config_dir_with_dev_profile();
    let output = awzars(directory.path(), &["--profile", "absent", "delete-profile"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("Profile 'absent' not found"), "{stderr}");
    assert!(output.stdout.is_empty());
    let config = std::fs::read_to_string(directory.path().join("config.toml")).unwrap();
    assert_eq!(config, CONFIG, "the config must not change");
}

#[test]
fn delete_profile_without_a_terminal_points_to_yes() {
    let directory = config_dir_with_dev_profile();
    let output = awzars(directory.path(), &["--profile", "dev", "delete-profile"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(6), "{stderr}");
    assert!(stderr.contains("pass --yes"), "{stderr}");
    let config = std::fs::read_to_string(directory.path().join("config.toml")).unwrap();
    assert!(config.contains("[profiles.dev"), "the profile must be kept");
}
