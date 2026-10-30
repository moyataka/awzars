use std::process::Command;

#[test]
fn completions_print_a_script_and_touch_nothing() {
    const TENANT: &str = "11111111-2222-3333-4444-aaaaaaaaaaaa";
    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join("config");
    let output = Command::new(env!("CARGO_BIN_EXE_awzars"))
        .args(["completions", "fish"])
        .env("HOME", home.path())
        .env("AWZARS_CONFIG_DIR", &config_dir)
        .env("AWZARS_AZURE_TENANT_ID", TENANT)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let script = String::from_utf8(output.stdout).unwrap();
    assert!(script.contains("complete -c awzars"));
    assert!(output.stderr.is_empty());
    // Values from the environment are never written into the script.
    assert!(!script.contains(TENANT));
    // No configuration, cache or session files were created.
    assert!(!config_dir.exists());
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}
