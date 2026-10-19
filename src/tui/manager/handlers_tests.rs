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
