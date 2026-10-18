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
