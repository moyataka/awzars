use super::*;
use crate::config::{AzureConfig, Config, Profile};

#[test]
fn profile_saves_reject_collisions_and_preserve_existing_state() {
    const TEST_DIRECTORY: &str = "AWZARS_PROFILE_SAVE_TEST";
    let Ok(directory) = std::env::var(TEST_DIRECTORY) else {
        let directory = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tui::manager::handlers::tests::profile_saves_reject_collisions_and_preserve_existing_state"])
            .env(TEST_DIRECTORY, directory.path())
            .output().unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    };
    crate::config::set_config_dir_override(&directory).unwrap();
    let aws_path = std::path::Path::new(&directory).join("aws-config");
    let aws_original = "[profile dev]\nregion = us-east-1\n[profile prod]\nregion = us-west-2\n";
    std::fs::write(&aws_path, aws_original).unwrap();
    let profile = Profile {
        azure: AzureConfig::new(
            "11111111-2222-3333-4444-555555555555",
            "https://signin.aws.amazon.com/saml",
        ),
        ..Default::default()
    };
    let protected = Profile {
        lock_verifier: Some("protected-verifier".into()),
        ..profile.clone()
    };
    let mut config = Config {
        aws_config_path: Some(aws_path.to_string_lossy().into()),
        ..Default::default()
    };
    config.set_profile("dev", profile.clone());
    config.set_profile("prod", protected.clone());
    config.save().unwrap();
    let original_config = std::fs::read(crate::config::config_file().unwrap()).unwrap();
    let mut manager = ConfigManager::new(config).unwrap();

    // Add/clone to an existing name, rename to an existing name, and rename
    // to a fresh name all leave the existing awzars identities intact.
    for (editing, name) in [(false, "prod"), (true, "prod"), (true, "new-name")] {
        let mut form = if editing {
            ProfileForm::from_profile("dev", &profile)
        } else {
            ProfileForm::clone_from("dev", &profile)
        };
        form.fields[0].value = name.into();
        manager.form = Some(form);
        manager.save_awzars_form();
        assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Error);
        assert_eq!(manager.config.profiles.len(), 2);
        assert_eq!(
            manager.config.profiles["prod"].lock_verifier,
            protected.lock_verifier
        );
        assert_eq!(
            std::fs::read(crate::config::config_file().unwrap()).unwrap(),
            original_config
        );
        assert!(manager.form.is_some());
    }

    let mut form = ProfileForm::from_profile("prod", &protected);
    form.focused = 0;
    assert!(form.focused_field_mut().is_none());
    form.fields[5].value = "eu-west-1".into();
    manager.form = Some(form);
    manager.save_awzars_form();
    assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Success);
    assert_eq!(
        Config::load().unwrap().profiles["prod"].lock_verifier,
        protected.lock_verifier
    );

    for editing in [false, true] {
        let mut form = if editing {
            AwsProfileForm::from_entry(&manager.aws_profiles[0], vec![], vec![])
        } else {
            AwsProfileForm::new_empty(vec![], vec![])
        };
        form.fields[0].value = "prod".into();
        manager.aws_form = Some(form);
        manager.save_aws_form();
        assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Error);
        assert_eq!(std::fs::read_to_string(&aws_path).unwrap(), aws_original);
        assert_eq!(manager.aws_profiles.len(), 2);
        assert!(manager.aws_form.is_some());
    }

    let mut form = AwsProfileForm::from_entry(&manager.aws_profiles[0], vec![], vec![]);
    form.fields[1].value = "eu-central-1".into();
    manager.aws_form = Some(form);
    manager.save_aws_form();
    assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Success);
    assert_eq!(
        manager.aws_profiles[0].region.as_deref(),
        Some("eu-central-1")
    );
    assert_eq!(manager.aws_profiles[1].region.as_deref(), Some("us-west-2"));
}

const AWS_BASE: &str =
    "[profile target]\nregion = us-east-1\noutput = json\n\n[profile other]\nregion = us-west-2\n";

/// Edits made by another tool while the TUI is open: a new profile, another
/// profile's region, a setting the TUI never loaded on the target, and an
/// sso-session.
fn edit_outside(contents: &str) -> String {
    format!(
        "{}\n[profile outside]\nregion = sa-east-1\n\n[sso-session x]\nsso_start_url = https://example.invalid/start\n",
        contents
            .replacen("output = json\n", "output = json\nsso_region = eu-west-1\n", 1)
            .replacen("region = us-west-2", "region = ap-south-1", 1)
    )
}

fn aws_manager(contents: &str) -> (tempfile::TempDir, std::path::PathBuf, ConfigManager) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config");
    std::fs::write(&path, contents).unwrap();
    let mut config = Config {
        aws_config_path: Some(path.to_string_lossy().into()),
        ..Default::default()
    };
    config.set_profile("team", Profile::default());
    let manager = ConfigManager::new(config).unwrap();
    (directory, path, manager)
}

/// Opens the edit form on `target` from the startup snapshot, lets another
/// tool rewrite the file, then saves `value` into `field`.
fn save_target_after_outside_edit(
    manager: &mut ConfigManager,
    path: &std::path::Path,
    outside: &str,
    field: usize,
    value: &str,
) {
    let mut form = AwsProfileForm::from_entry(&manager.aws_profiles[0], vec![], vec![]);
    std::fs::write(path, outside).unwrap();
    form.fields[field].value = value.into();
    manager.aws_form = Some(form);
    manager.save_aws_form();
}

#[test]
fn aws_edit_and_rename_keep_changes_made_outside_the_tui() {
    for (field, value, expected) in [
        (
            1,
            "eu-central-1",
            ("region = us-east-1", "region = eu-central-1"),
        ),
        (0, "renamed", ("[profile target]", "[profile renamed]")),
    ] {
        let (_directory, path, mut manager) = aws_manager(AWS_BASE);
        let outside = edit_outside(AWS_BASE);
        save_target_after_outside_edit(&mut manager, &path, &outside, field, value);

        assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Success);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            outside.replacen(expected.0, expected.1, 1)
        );
        assert!(manager.aws_form.is_none());
        assert!(manager.aws_profiles.iter().any(|p| p.name == "outside"));
    }
}

#[test]
fn aws_edit_overriding_an_outside_change_saves_and_warns() {
    let (_directory, path, mut manager) = aws_manager(AWS_BASE);
    let outside =
        edit_outside(AWS_BASE).replacen("region = us-east-1", "region = ap-northeast-1", 1);
    save_target_after_outside_edit(&mut manager, &path, &outside, 1, "eu-central-1");

    let (level, message) = manager.status.clone().unwrap();
    assert_eq!(level, StatusLevel::Warning);
    assert!(
        message.contains("overrode outside change to region"),
        "{message}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        outside.replacen("region = ap-northeast-1", "region = eu-central-1", 1)
    );
}

#[test]
fn aws_delete_keeps_changes_made_outside_the_tui() {
    let (_directory, path, mut manager) = aws_manager(AWS_BASE);
    let outside = edit_outside(AWS_BASE);
    std::fs::write(&path, &outside).unwrap();
    manager.aws_selected = 0;
    manager.mode = Mode::DeleteConfirm {
        target: "target".into(),
        is_awzars: false,
    };
    manager.handle_delete_confirm(KeyCode::Char('y')).unwrap();

    assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Success);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        &outside[outside.find("[profile other]").unwrap()..]
    );
    assert!(manager.aws_profiles.iter().any(|p| p.name == "outside"));
}

#[test]
fn aws_link_and_unlink_keep_changes_made_outside_the_tui() {
    let (_directory, path, mut manager) = aws_manager(AWS_BASE);
    let outside = edit_outside(AWS_BASE);
    std::fs::write(&path, &outside).unwrap();
    manager.aws_selected = 0;
    manager.link_picker_selected = 0;
    manager.apply_link();

    let credential_process = "credential_process = awzars credential-process --profile team\n";
    let linked = outside.replacen(
        "[profile other]",
        &format!("{credential_process}[profile other]"),
        1,
    );
    assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Success);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), linked);

    let outside = linked.replacen("region = ap-south-1", "region = ca-central-1", 1);
    std::fs::write(&path, &outside).unwrap();
    manager.link_picker_selected = 1; // "Unlink"
    manager.apply_link();

    assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Success);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        outside.replacen(credential_process, "", 1)
    );
}

#[test]
fn aws_save_onto_a_name_added_outside_is_rejected_without_writing() {
    for rename in [false, true] {
        let (_directory, path, mut manager) = aws_manager(AWS_BASE);
        let mut form = if rename {
            AwsProfileForm::from_entry(&manager.aws_profiles[0], vec![], vec![])
        } else {
            AwsProfileForm::new_empty(vec![], vec![])
        };
        let outside = edit_outside(AWS_BASE);
        std::fs::write(&path, &outside).unwrap();
        form.fields[0].value = "outside".into();
        manager.aws_form = Some(form);
        manager.save_aws_form();

        assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Error);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), outside);
        assert!(manager.aws_form.is_some());
        assert!(manager.aws_profiles.iter().any(|p| p.name == "outside"));
    }
}

#[test]
fn aws_edit_of_a_profile_removed_outside_is_rejected_and_reloaded() {
    let (_directory, path, mut manager) = aws_manager(AWS_BASE);
    let outside = "[profile other]\nregion = us-west-2\n";
    save_target_after_outside_edit(&mut manager, &path, outside, 1, "eu-central-1");

    let (level, message) = manager.status.clone().unwrap();
    assert_eq!(level, StatusLevel::Error);
    assert!(message.contains("changed outside the TUI"), "{message}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), outside);
    assert!(manager.aws_profiles.iter().all(|p| p.name != "target"));
}

#[test]
fn aws_edit_keeps_duplicate_and_default_sections_byte_identical() {
    let contents = "[default]\nregion = us-east-1\n\n[profile default]\nregion = us-east-2\n\n\
                    [profile dup]\nregion = eu-west-1\n\n[profile target]\nregion = us-west-2\n\n\
                    [profile dup]\noutput = json\n";
    let (_directory, path, mut manager) = aws_manager(contents);
    let target = manager
        .aws_profiles
        .iter()
        .position(|p| p.name == "target")
        .unwrap();
    let mut form = AwsProfileForm::from_entry(&manager.aws_profiles[target], vec![], vec![]);
    form.fields[1].value = "ap-southeast-2".into();
    manager.aws_form = Some(form);
    manager.save_aws_form();

    assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Success);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        contents.replacen("us-west-2", "ap-southeast-2", 1)
    );
}

/// Runs `name` in a child test process with `directory` as the config
/// directory, HOME and cache, so the process-wide config directory override
/// and any session-token cleanup stay in a temporary directory.
fn run_in_child(name: &str, variable: &str) {
    let directory = tempfile::tempdir().unwrap();
    // Re-runs this test binary itself, not an external program.
    let test_binary = std::env::current_exe().unwrap(); // nosemgrep: rust.lang.security.current-exe.current-exe
    let output = std::process::Command::new(test_binary)
        .args(["--exact", &format!("tui::manager::handlers::tests::{name}")])
        .env(variable, directory.path())
        .env("HOME", directory.path())
        .env("XDG_CACHE_HOME", directory.path())
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn tui_profile() -> Profile {
    Profile {
        azure: AzureConfig::new(
            "11111111-2222-3333-4444-aaaaaaaaaaaa",
            "https://signin.aws.amazon.com/saml",
        ),
        ..Default::default()
    }
}

/// A config with an empty AWS config file in `directory`, so the manager
/// never reads the user's AWS config.
fn tui_config(directory: &str) -> Config {
    let aws_path = std::path::Path::new(directory).join("aws-config");
    std::fs::write(&aws_path, "").unwrap();
    Config {
        aws_config_path: Some(aws_path.to_string_lossy().into()),
        ..Default::default()
    }
}

#[test]
fn profile_save_keeps_changes_made_outside_the_tui() {
    const TEST_DIRECTORY: &str = "AWZARS_TUI_OUTSIDE_CHANGE_TEST";
    let Ok(directory) = std::env::var(TEST_DIRECTORY) else {
        return run_in_child(
            "profile_save_keeps_changes_made_outside_the_tui",
            TEST_DIRECTORY,
        );
    };
    crate::config::set_config_dir_override(&directory).unwrap();
    let mut config = tui_config(&directory);
    config.set_profile("dev", tui_profile());
    config.set_profile("prod", tui_profile());
    config.save().unwrap();
    let mut manager = ConfigManager::new(Config::load().unwrap()).unwrap();

    // While the TUI is open, another program adds a profile, changes
    // another profile and sets a password lock on the profile being edited.
    let mut outside = Config::load().unwrap();
    outside.set_profile("outside", tui_profile());
    outside.get_profile_mut("prod").unwrap().region = Some("ap-south-1".into());
    outside.get_profile_mut("dev").unwrap().lock_verifier = Some("outside-verifier".into());
    outside.save().unwrap();

    let mut form = ProfileForm::from_profile("dev", &tui_profile());
    form.fields[5].value = "eu-west-1".into();
    manager.form = Some(form);
    manager.save_awzars_form();
    assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Success);

    let saved = Config::load().unwrap();
    assert!(saved.profiles.contains_key("outside"));
    assert_eq!(saved.profiles["prod"].region.as_deref(), Some("ap-south-1"));
    assert_eq!(saved.profiles["dev"].region.as_deref(), Some("eu-west-1"));
    assert_eq!(
        saved.profiles["dev"].lock_verifier.as_deref(),
        Some("outside-verifier")
    );
    // The view now shows what was written, outside changes included.
    assert!(manager.config.profiles.contains_key("outside"));

    // Adding a profile under a name that now exists on disk is refused.
    let mut outside = Config::load().unwrap();
    outside.set_profile("outside-2", tui_profile());
    outside.save().unwrap();
    let before_add = std::fs::read(crate::config::config_file().unwrap()).unwrap();
    let mut form = ProfileForm::clone_from("dev", &tui_profile());
    form.fields[0].value = "outside-2".into();
    manager.form = Some(form);
    manager.save_awzars_form();
    let (level, message) = manager.status.clone().unwrap();
    assert_eq!(level, StatusLevel::Error);
    assert!(message.contains("already exists"), "{message}");
    assert_eq!(
        std::fs::read(crate::config::config_file().unwrap()).unwrap(),
        before_add
    );
}

#[test]
fn profile_save_writes_nothing_when_config_does_not_load() {
    const TEST_DIRECTORY: &str = "AWZARS_TUI_FRESH_LOAD_FAILURE_TEST";
    let Ok(directory) = std::env::var(TEST_DIRECTORY) else {
        return run_in_child(
            "profile_save_writes_nothing_when_config_does_not_load",
            TEST_DIRECTORY,
        );
    };
    crate::config::set_config_dir_override(&directory).unwrap();
    let mut config = tui_config(&directory);
    config.set_profile("dev", tui_profile());
    config.save().unwrap();
    let mut manager = ConfigManager::new(Config::load().unwrap()).unwrap();

    let path = crate::config::config_file().unwrap();
    let broken = "[profiles.dev]\nrole_arn = \"unterminated\n";
    std::fs::write(&path, broken).unwrap();

    let mut form = ProfileForm::from_profile("dev", &tui_profile());
    form.fields[5].value = "eu-west-1".into();
    manager.form = Some(form);
    manager.save_awzars_form();
    let (level, message) = manager.status.clone().unwrap();
    assert_eq!(level, StatusLevel::Error);
    assert!(message.contains("could not be loaded"), "{message}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), broken);
    assert!(manager.form.is_some());
}

#[test]
fn failed_reload_after_delete_does_not_bring_the_profile_back() {
    const TEST_DIRECTORY: &str = "AWZARS_TUI_RELOAD_FAILURE_TEST";
    let Ok(directory) = std::env::var(TEST_DIRECTORY) else {
        return run_in_child(
            "failed_reload_after_delete_does_not_bring_the_profile_back",
            TEST_DIRECTORY,
        );
    };
    crate::config::set_config_dir_override(&directory).unwrap();
    let path = crate::config::config_file().unwrap();
    // `kept` has a long marker list. Written compactly it loads, but a save
    // puts one item per line, which takes config.toml past the 1 MiB load
    // limit, so the reload after the delete fails.
    let kept = Profile {
        lock_ai_markers: Some(vec!["A".to_string(); 180_000]),
        ..tui_profile()
    };
    let mut config = tui_config(&directory);
    config.set_profile("kept", kept);
    config.set_profile("deleted-profile", tui_profile());
    let compact = toml::to_string(&config).unwrap();
    assert!(compact.len() < 1 << 20);
    std::fs::write(&path, compact).unwrap();
    let mut manager = ConfigManager::new(Config::load().unwrap()).unwrap();

    manager.mode = Mode::DeleteConfirm {
        target: "deleted-profile".into(),
        is_awzars: true,
    };
    manager.handle_delete_confirm(KeyCode::Char('y')).unwrap();
    assert!(Config::load().is_err());
    let (level, message) = manager.status.clone().unwrap();
    assert_eq!(level, StatusLevel::Warning);
    assert!(message.contains("could not be reloaded"), "{message}");
    assert!(!manager
        .profile_names
        .contains(&"deleted-profile".to_string()));

    // While config.toml doesn't load, a save is refused and writes nothing.
    let before = std::fs::read(&path).unwrap();
    let mut form = ProfileForm::from_profile("kept", &tui_profile());
    form.fields[5].value = "eu-west-1".into();
    manager.form = Some(form);
    manager.save_awzars_form();
    assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Error);
    assert_eq!(std::fs::read(&path).unwrap(), before);

    // Once it loads again, the same save goes through and the deleted
    // profile stays deleted.
    let mut fixed = tui_config(&directory);
    fixed.set_profile("kept", tui_profile());
    fixed.save().unwrap();
    manager.save_awzars_form();
    assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Success);
    let saved = Config::load().unwrap();
    assert!(!saved.profiles.contains_key("deleted-profile"));
    assert_eq!(saved.profiles["kept"].region.as_deref(), Some("eu-west-1"));
}

#[test]
fn delete_keeps_the_profile_when_keychain_items_cannot_be_removed() {
    use crate::storage::keyring::{test_keychain, KeyringStorage};
    const TEST_DIRECTORY: &str = "AWZARS_TUI_DELETE_KEYRING_FAILURE_TEST";
    let Ok(directory) = std::env::var(TEST_DIRECTORY) else {
        return run_in_child(
            "delete_keeps_the_profile_when_keychain_items_cannot_be_removed",
            TEST_DIRECTORY,
        );
    };
    crate::config::set_config_dir_override(&directory).unwrap();
    test_keychain::install();
    let mut config = tui_config(&directory);
    config.set_profile("kept", tui_profile());
    config.save().unwrap();
    let path = crate::config::config_file().unwrap();
    let before = std::fs::read(&path).unwrap();
    let entry = KeyringStorage::new("kept")
        .unwrap()
        .entry_for_field("cookie_key")
        .unwrap();
    entry.set_password("stored").unwrap();
    let mut manager = ConfigManager::new(Config::load().unwrap()).unwrap();

    test_keychain::fail_deletes(true);
    manager.mode = Mode::DeleteConfirm {
        target: "kept".into(),
        is_awzars: true,
    };
    manager.handle_delete_confirm(KeyCode::Char('y')).unwrap();
    test_keychain::fail_deletes(false);

    let (level, message) = manager.status.clone().unwrap();
    assert_eq!(level, StatusLevel::Error);
    assert!(message.contains("profile 'kept' was kept"), "{message}");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(manager.config.profiles.contains_key("kept"));
    assert!(manager.profile_names.contains(&"kept".to_string()));
    assert!(entry.get_password().is_ok());

    // Deleting again retries and now succeeds.
    manager.mode = Mode::DeleteConfirm {
        target: "kept".into(),
        is_awzars: true,
    };
    manager.handle_delete_confirm(KeyCode::Char('y')).unwrap();
    assert_eq!(manager.status.as_ref().unwrap().0, StatusLevel::Success);
    assert!(!Config::load().unwrap().profiles.contains_key("kept"));
    assert!(!manager.profile_names.contains(&"kept".to_string()));
}
