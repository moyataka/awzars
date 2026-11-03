use std::process::Command;

#[test]
fn malformed_config_toml_exits_with_config_error_code() {
    let directory = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let aws_config = home.path().join("aws-config");
    std::fs::write(&aws_config, "").unwrap();
    let path = directory.path().join("config.toml");
    let broken = "[profiles.dev]\nrole_arn = \"unterminated\n";
    std::fs::write(&path, broken).unwrap();

    for command in [
        &["login"][..],
        &["list-roles"][..],
        &["credential-process"][..],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_awzars"))
            .arg("--config-dir")
            .arg(directory.path())
            .args(["--profile", "dev"])
            .args(command)
            .env("HOME", home.path())
            .env("AWS_CONFIG_FILE", &aws_config)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{:?}: {}", command, stderr);
        assert!(stderr.contains("TOML error"), "{:?}: {}", command, stderr);
    }
    assert_eq!(std::fs::read_to_string(&path).unwrap(), broken);
}
