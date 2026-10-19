use super::{load_aws_integration, save_aws_config, AwsProfileEntry, AwsProfileOp, SaveError};
use crate::tui::form::{AwsProfileForm, AWS_IDX_REGION};
use std::path::{Path, PathBuf};

const SHARED_CONFIG: &str = include_str!("fixtures/shared-config.ini");

fn config_file(contents: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config");
    std::fs::write(&path, contents).unwrap();
    (directory, path)
}

/// Save `before` -> `after` and return the overridden settings.
fn save(path: &Path, before: &AwsProfileEntry, after: AwsProfileEntry) -> Vec<String> {
    let op = AwsProfileOp::Upsert {
        before: Some(before.clone()),
        after,
    };
    save_aws_config(&op, path.to_str()).unwrap()
}

/// Save every profile unchanged.
fn save_unchanged(path: &Path, profiles: &[AwsProfileEntry]) {
    for profile in profiles {
        assert!(save(path, profile, profile.clone()).is_empty());
    }
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

        save_unchanged(&path, &profiles);
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

    save_unchanged(&path, &profiles);
    assert_eq!(std::fs::read_to_string(path).unwrap(), SHARED_CONFIG);
}

#[test]
fn editing_region_preserves_unexposed_settings_and_original_text() {
    let (_directory, path) = config_file(SHARED_CONFIG);
    let profiles = load_aws_integration(path.to_str()).all_profiles;
    let mut form = AwsProfileForm::from_entry(&profiles[1], Vec::new(), Vec::new());
    form.fields[AWS_IDX_REGION].value = "eu-west-1".to_string();
    let edited = form.to_entry().unwrap();

    assert_eq!(edited.extra, profiles[1].extra);
    save(&path, &profiles[1], edited);
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        SHARED_CONFIG.replacen("region  = us-west-2", "region  = eu-west-1", 1)
    );
}

#[test]
fn changing_or_clearing_output_preserves_other_settings() {
    for output in ["text", ""] {
        let (_directory, path) = config_file(SHARED_CONFIG);
        let profiles = load_aws_integration(path.to_str()).all_profiles;
        let mut form = AwsProfileForm::from_entry(&profiles[1], Vec::new(), Vec::new());
        form.fields
            .iter_mut()
            .find(|field| field.label == "Output")
            .unwrap()
            .value = output.to_string();
        let edited = form.to_entry().unwrap();

        let expected_setting = if output.is_empty() {
            String::new()
        } else {
            format!("output = {output}\n")
        };
        let original_setting =
            "credential_process = awzars credential-process --profile engineering\noutput = json\n";
        let replacement = format!("credential_process = awzars credential-process --profile engineering\n{expected_setting}");
        save(&path, &profiles[1], edited.clone());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            SHARED_CONFIG.replace(original_setting, &replacement)
        );
        assert_eq!(
            load_aws_integration(path.to_str()).all_profiles[1].extra,
            edited.extra
        );
    }
}

#[test]
fn renaming_preserves_the_section_body_and_header_comment() {
    let contents = SHARED_CONFIG.replace(
        "[profile engineering]",
        "[profile engineering] # team settings",
    );
    let (_directory, path) = config_file(&contents);
    let profiles = load_aws_integration(path.to_str()).all_profiles;
    let mut form = AwsProfileForm::from_entry(&profiles[1], Vec::new(), Vec::new());
    form.fields
        .iter_mut()
        .find(|field| field.label == "Profile Name")
        .unwrap()
        .value = "development".to_string();

    save(&path, &profiles[1], form.to_entry().unwrap());
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        contents.replace("[profile engineering]", "[profile development]")
    );
    let reloaded = load_aws_integration(path.to_str()).all_profiles;
    assert_eq!(reloaded[1].name, "development");
    save_unchanged(&path, &reloaded);
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        contents.replace("[profile engineering]", "[profile development]")
    );
}

#[test]
fn removing_a_profile_preserves_every_other_section() {
    let (_directory, path) = config_file(SHARED_CONFIG);
    let op = AwsProfileOp::Delete {
        name: "engineering".to_string(),
    };

    assert!(save_aws_config(&op, path.to_str()).unwrap().is_empty());
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
    let mut form = AwsProfileForm::new_empty(Vec::new(), Vec::new());
    form.fields
        .iter_mut()
        .find(|field| field.label == "Profile Name")
        .unwrap()
        .value = "new-profile".to_string();
    form.fields[AWS_IDX_REGION].value = "ap-southeast-1".to_string();
    let op = AwsProfileOp::Upsert {
        before: None,
        after: form.to_entry().unwrap(),
    };

    assert!(save_aws_config(&op, path.to_str()).unwrap().is_empty());
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
    let profiles = load_aws_integration(path.to_str()).all_profiles;
    let mut unlinked_entry = profiles[1].clone();
    unlinked_entry.credential_process = None;

    save(&path, &profiles[1], unlinked_entry);
    let unlinked = SHARED_CONFIG.replace(
        "credential_process = awzars credential-process --profile engineering\n",
        "",
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), unlinked);

    let profiles = load_aws_integration(path.to_str()).all_profiles;
    let mut linked = profiles[1].clone();
    linked.credential_process = Some("awzars credential-process --profile updated".to_string());
    save(&path, &profiles[1], linked);
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
            let profiles = load_aws_integration(path.to_str()).all_profiles;
            assert_eq!(profiles[0].region.as_deref(), Some("us-east-1"));

            save_unchanged(&path, &profiles);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
            let mut edited = profiles[0].clone();
            edited.region = Some("eu-west-1".to_string());
            save(&path, &profiles[0], edited);
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
    let profiles = load_aws_integration(path.to_str()).all_profiles;
    let mut edited = profiles[0].clone();
    edited.region = Some("us-east-1".to_string());

    save(&path, &profiles[0], edited);
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

    let op = AwsProfileOp::Delete {
        name: "work".to_string(),
    };
    assert!(matches!(
        save_aws_config(&op, path.to_str()),
        Err(SaveError::Io(_))
    ));
    assert_eq!(std::fs::read(path).unwrap(), [0xff, 0xfe]);
}

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

const BASE: &str =
    "[profile target]\nregion = us-east-1\noutput = json\n\n[profile other]\nregion = us-west-2\n";

/// Initial file, the TUI's change to the target, and the expected result.
type Case<'a> = (&'a str, fn(&mut AwsProfileEntry), String);

#[test]
fn saving_a_stale_entry_keeps_changes_made_outside() {
    let credential_process = "credential_process = awzars credential-process --profile team\n";
    let linked = BASE.replacen(
        "output = json\n",
        &format!("output = json\n{credential_process}"),
        1,
    );
    let outside = edit_outside(BASE);
    let cases: [Case; 4] = [
        (
            BASE,
            |entry| entry.region = Some("eu-central-1".to_string()),
            outside.replacen("region = us-east-1", "region = eu-central-1", 1),
        ),
        (
            BASE,
            |entry| entry.name = "renamed".to_string(),
            outside.replacen("[profile target]", "[profile renamed]", 1),
        ),
        (
            BASE,
            |entry| {
                entry.credential_process =
                    Some("awzars credential-process --profile team".to_string())
            },
            outside.replacen(
                "[profile other]",
                &format!("{credential_process}[profile other]"),
                1,
            ),
        ),
        (
            &linked,
            |entry| entry.credential_process = None,
            edit_outside(&linked).replacen(credential_process, "", 1),
        ),
    ];
    for (initial, change, expected) in cases {
        let (_directory, path) = config_file(initial);
        let before = load_aws_integration(path.to_str()).all_profiles[0].clone();
        std::fs::write(&path, edit_outside(initial)).unwrap();
        let mut after = before.clone();
        change(&mut after);

        assert!(save(&path, &before, after).is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
    }

    let (_directory, path) = config_file(BASE);
    std::fs::write(&path, &outside).unwrap();
    let op = AwsProfileOp::Delete {
        name: "target".to_string(),
    };
    assert!(save_aws_config(&op, path.to_str()).unwrap().is_empty());
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        &outside[outside.find("[profile other]").unwrap()..]
    );
}

#[test]
fn a_tui_change_overrides_the_same_setting_changed_outside_and_reports_it() {
    let (_directory, path) = config_file(BASE);
    let before = load_aws_integration(path.to_str()).all_profiles[0].clone();
    let outside = edit_outside(BASE)
        .replacen("region = us-east-1", "region = ap-northeast-1", 1)
        .replacen("output = json", "output = yaml", 1);
    std::fs::write(&path, &outside).unwrap();
    let mut after = before.clone();
    after.region = Some("eu-central-1".to_string());
    after.extra.insert("output".to_string(), "yaml".to_string());

    // Region was changed both places: TUI wins and it is reported. Output was
    // changed to the same value both places, so nothing was overridden.
    assert_eq!(save(&path, &before, after), ["region"]);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        outside.replacen("region = ap-northeast-1", "region = eu-central-1", 1)
    );
}

#[test]
fn creating_or_renaming_onto_a_name_added_outside_is_rejected_without_writing() {
    let (_directory, path) = config_file(BASE);
    let before = load_aws_integration(path.to_str()).all_profiles[0].clone();
    let outside = edit_outside(BASE);
    std::fs::write(&path, &outside).unwrap();
    let mut after = before.clone();
    after.name = "outside".to_string();

    for before in [None, Some(before)] {
        let op = AwsProfileOp::Upsert {
            before,
            after: after.clone(),
        };
        assert!(matches!(
            save_aws_config(&op, path.to_str()),
            Err(SaveError::Exists(name)) if name == "outside"
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), outside);
    }
}

#[test]
fn changing_a_profile_removed_outside_is_rejected_without_writing() {
    let (_directory, path) = config_file(BASE);
    let before = load_aws_integration(path.to_str()).all_profiles[0].clone();
    let outside = "[profile other]\nregion = us-west-2\n";
    std::fs::write(&path, outside).unwrap();
    let mut renamed = before.clone();
    renamed.name = "renamed".to_string();

    for op in [
        AwsProfileOp::Upsert {
            before: Some(before.clone()),
            after: before.clone(),
        },
        AwsProfileOp::Upsert {
            before: Some(before),
            after: renamed,
        },
        AwsProfileOp::Delete {
            name: "target".to_string(),
        },
    ] {
        assert!(matches!(
            save_aws_config(&op, path.to_str()),
            Err(SaveError::Missing(name)) if name == "target"
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), outside);
    }
}

#[test]
fn duplicate_and_default_sections_survive_editing_another_profile() {
    let contents = "[default]\nregion = us-east-1\n\n[profile default]\nregion = us-east-2\n\n\
                    [profile dup]\nregion = eu-west-1\n\n[profile target]\nregion = us-west-2\n\n\
                    [profile dup]\noutput = json\n";
    let (_directory, path) = config_file(contents);
    let profiles = load_aws_integration(path.to_str()).all_profiles;
    let target = profiles.iter().find(|p| p.name == "target").unwrap();
    let mut edited = target.clone();
    edited.region = Some("ap-southeast-2".to_string());

    save(&path, target, edited);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        contents.replacen("us-west-2", "ap-southeast-2", 1)
    );
}
