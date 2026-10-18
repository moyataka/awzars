use super::{load_aws_integration, save_aws_config};
use crate::tui::form::{AwsProfileForm, AWS_IDX_REGION};
use std::path::PathBuf;

const SHARED_CONFIG: &str = include_str!("fixtures/shared-config.ini");

fn config_file(contents: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config");
    std::fs::write(&path, contents).unwrap();
    (directory, path)
}

#[test]
fn commented_headers_keep_profiles_separate_when_saved() {
    for comment in ["# note", "; note"] {
        let contents = format!(
            "[profile a]\nregion = us-east-1\n[profile b] {comment}\n\
             region = us-west-2\nrole_arn = arn:aws:iam::123456789012:role/B\n"
        );
        let (_directory, path) = config_file(&contents);
        let profiles = load_aws_integration(path.to_str()).all_profiles;

        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].name, "a");
        assert_eq!(profiles[0].region.as_deref(), Some("us-east-1"));
        assert!(profiles[0].role_arn.is_none());
        assert_eq!(profiles[1].name, "b");
        assert_eq!(profiles[1].region.as_deref(), Some("us-west-2"));

        save_aws_config(&profiles, path.to_str()).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), contents);
    }
}

#[test]
fn save_preserves_sections_comments_and_nested_settings() {
    let (_directory, path) = config_file(SHARED_CONFIG);
    let profiles = load_aws_integration(path.to_str()).all_profiles;

    assert_eq!(
        profiles
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["default", "engineering", "audit"]
    );
    assert!(!profiles[1].extra.contains_key("max_concurrent_requests"));
    assert!(profiles[1].extra["s3"].contains("max_concurrent_requests = 20"));

    save_aws_config(&profiles, path.to_str()).unwrap();
    assert_eq!(std::fs::read_to_string(path).unwrap(), SHARED_CONFIG);
}

#[test]
fn renaming_preserves_the_section_body_and_header_comment() {
    let contents = SHARED_CONFIG.replace(
        "[profile engineering]",
        "[profile engineering] # team settings",
    );
    let (_directory, path) = config_file(&contents);
    let mut profiles = load_aws_integration(path.to_str()).all_profiles;
    profiles[1].name = "development".to_string();

    save_aws_config(&profiles, path.to_str()).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        contents.replace("[profile engineering]", "[profile development]")
    );
    let reloaded = load_aws_integration(path.to_str()).all_profiles;
    assert_eq!(reloaded[1].name, "development");
    save_aws_config(&reloaded, path.to_str()).unwrap();
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        contents.replace("[profile engineering]", "[profile development]")
    );
}

#[test]
fn removing_a_profile_preserves_every_other_section() {
    let (_directory, path) = config_file(SHARED_CONFIG);
    let mut profiles = load_aws_integration(path.to_str()).all_profiles;
    profiles.retain(|entry| entry.name != "engineering");

    save_aws_config(&profiles, path.to_str()).unwrap();
    let start = SHARED_CONFIG.find("[profile engineering]").unwrap();
    let end = SHARED_CONFIG.find("[sso-session corp]").unwrap();
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        format!("{}{}", &SHARED_CONFIG[..start], &SHARED_CONFIG[end..])
    );
}

#[test]
fn adding_a_profile_keeps_existing_text_intact() {
    let (_directory, path) = config_file(SHARED_CONFIG);
    let mut profiles = load_aws_integration(path.to_str()).all_profiles;
    let mut form = AwsProfileForm::new_empty(Vec::new(), Vec::new());
    form.fields
        .iter_mut()
        .find(|field| field.label == "Profile Name")
        .unwrap()
        .value = "new-profile".to_string();
    form.fields[AWS_IDX_REGION].value = "ap-southeast-1".to_string();
    profiles.push(form.to_entry().unwrap());

    save_aws_config(&profiles, path.to_str()).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("{SHARED_CONFIG}\n[profile new-profile]\nregion = ap-southeast-1\n")
    );
    let reloaded = load_aws_integration(path.to_str()).all_profiles;
    assert_eq!(reloaded.len(), 4);
    assert_eq!(reloaded[3].region.as_deref(), Some("ap-southeast-1"));
}

#[test]
fn linking_and_unlinking_change_only_the_credential_process() {
    let (_directory, path) = config_file(SHARED_CONFIG);
    let mut profiles = load_aws_integration(path.to_str()).all_profiles;
    profiles[1].credential_process = None;

    save_aws_config(&profiles, path.to_str()).unwrap();
    let unlinked = SHARED_CONFIG.replace(
        "credential_process = awzars credential-process --profile engineering\n",
        "",
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), unlinked);

    let mut profiles = load_aws_integration(path.to_str()).all_profiles;
    profiles[1].credential_process =
        Some("awzars credential-process --profile updated".to_string());
    save_aws_config(&profiles, path.to_str()).unwrap();
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        unlinked.replace(
            "[sso-session corp]",
            "credential_process = awzars credential-process --profile updated\n[sso-session corp]"
        )
    );
}

#[test]
fn edits_preserve_line_endings_spacing_and_missing_final_newline() {
    for newline in ["\n", "\r\n"] {
        for ending in ["", newline] {
            let contents = format!("# Configuration — keep formatting{newline}[profile work] # note{newline}  Region:\tus-east-1  {ending}");
            let (_directory, path) = config_file(&contents);
            let mut profiles = load_aws_integration(path.to_str()).all_profiles;
            assert_eq!(profiles[0].region.as_deref(), Some("us-east-1"));

            save_aws_config(&profiles, path.to_str()).unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
            profiles[0].region = Some("eu-west-1".to_string());
            save_aws_config(&profiles, path.to_str()).unwrap();
            assert_eq!(
                std::fs::read_to_string(path).unwrap(),
                contents.replace("us-east-1", "eu-west-1")
            );
        }
    }
}

#[test]
fn appending_a_setting_after_an_unterminated_nested_value_is_valid() {
    let contents = "[profile work]\ns3 =\n    addressing_style = path";
    let (_directory, path) = config_file(contents);
    let mut profiles = load_aws_integration(path.to_str()).all_profiles;
    profiles[0].region = Some("us-east-1".to_string());

    save_aws_config(&profiles, path.to_str()).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("{contents}\nregion = us-east-1\n")
    );
    let reloaded = load_aws_integration(path.to_str()).all_profiles;
    assert_eq!(reloaded[0].region.as_deref(), Some("us-east-1"));
    assert_eq!(reloaded[0].extra, profiles[0].extra);
}

#[test]
fn unreadable_existing_content_is_never_overwritten() {
    let (_directory, path) = config_file("");
    std::fs::write(&path, [0xff, 0xfe]).unwrap();

    assert!(save_aws_config(&[], path.to_str()).is_err());
    assert_eq!(std::fs::read(path).unwrap(), [0xff, 0xfe]);
}
