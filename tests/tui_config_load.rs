#![cfg(unix)]

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn tui_exits_with_load_error_and_keeps_unloadable_config() {
    let directory = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let aws_config = home.path().join("aws-config");
    std::fs::write(&aws_config, "").unwrap();
    let path = directory.path().join("config.toml");
    let broken = "[profiles.dev]\nrole_arn = \"unterminated\n";
    std::fs::write(&path, broken).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_awzars"));
    command
        .arg("--config-dir")
        .arg(directory.path())
        .arg("tui")
        .env("HOME", home.path())
        .env("AWS_CONFIG_FILE", &aws_config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A background process group: if the TUI ever opens `/dev/tty` and
        // tries to enter raw mode, it is stopped by SIGTTOU instead of
        // changing the terminal the tests run in.
        .process_group(0);
    let mut child = command.spawn().unwrap();

    // Fail instead of blocking if the TUI ever starts.
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("awzars tui did not exit");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "{}", stderr);
    assert!(stderr.contains("TOML error"), "{}", stderr);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), broken);
}
