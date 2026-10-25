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

/// Names of the `config.bak.*` files next to `path`, sorted.
fn backups(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("config.bak."))
        .collect();
    names.sort();
    names
}

fn edit_region(path: &Path, region: &str) {
    let before = load_aws_integration(path.to_str()).all_profiles[0].clone();
    let mut after = before.clone();
    after.region = Some(region.to_string());
    save(path, &before, after);
}

#[test]
fn saving_backs_up_the_previous_file_privately() {
    let (_directory, path) = config_file(BASE);
    edit_region(&path, "eu-central-1");

    let backups = backups(&path);
    assert_eq!(backups.len(), 1, "{backups:?}");
    let backup = path.with_file_name(&backups[0]);
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), BASE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&backup).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // `config.bak.` + `YYYYMMDDTHHMMSS.mmmZ`
    let timestamp = &backups[0]["config.bak.".len()..];
    assert_eq!(timestamp.len(), 20, "{timestamp}");
    assert_eq!(&timestamp[8..9], "T");
    assert!(timestamp.ends_with('Z'));
}

#[test]
fn no_backup_when_the_file_is_missing_or_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config");
    let profile = super::parse_aws_config(BASE).remove(0);
    let op = AwsProfileOp::Upsert {
        before: None,
        after: profile.clone(),
    };
    save_aws_config(&op, path.to_str()).unwrap();
    assert!(backups(&path).is_empty());

    save_unchanged(&path, &[profile]);
    assert!(backups(&path).is_empty());
}

#[test]
fn backups_are_pruned_to_the_newest_ten_and_other_files_are_kept() {
    let (directory, path) = config_file(BASE);
    let old: Vec<String> = (0..12)
        .map(|n| format!("config.bak.200001{:02}T000000.000Z", n + 1))
        .collect();
    let unrelated = [
        "config.bak",
        "config.bak-20261001-tag",
        "config.bak.20000101T000000.000Z.orig",
        "config.bak.notatimestamp",
        "other.bak.20000101T000000.000Z",
    ];
    for name in old.iter().map(String::as_str).chain(unrelated) {
        std::fs::write(directory.path().join(name), "old").unwrap();
    }

    edit_region(&path, "eu-central-1");

    let backups = backups(&path);
    let kept: Vec<&String> = backups.iter().filter(|name| old.contains(name)).collect();
    assert_eq!(kept, old[3..].iter().collect::<Vec<_>>());
    let new: Vec<&String> = backups
        .iter()
        .filter(|name| !old.contains(name) && !unrelated.contains(&name.as_str()))
        .collect();
    assert_eq!(new.len(), 1, "{backups:?}");
    assert_eq!(
        std::fs::read_to_string(path.with_file_name(new[0])).unwrap(),
        BASE
    );
    for name in unrelated {
        assert!(directory.path().join(name).exists(), "{name} was removed");
    }
}

#[test]
fn back_to_back_saves_keep_every_backup() {
    let (_directory, path) = config_file(BASE);
    for region in ["eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3"] {
        edit_region(&path, region);
    }
    assert_eq!(backups(&path).len(), 4);
}

#[test]
fn a_backup_name_clash_gets_the_next_numeric_suffix() {
    let (directory, path) = config_file(BASE);
    let now = chrono::DateTime::parse_from_rfc3339("2026-10-25T10:15:30.123Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let stem = "config.bak.20261025T101530.123Z";
    std::fs::write(directory.path().join(stem), "taken").unwrap();

    for expected in ["-1", "-2"] {
        super::backup_aws_config(&path, BASE, now).unwrap();
        let backup = directory.path().join(format!("{stem}{expected}"));
        assert_eq!(std::fs::read_to_string(backup).unwrap(), BASE, "{expected}");
    }
    assert_eq!(
        backups(&path),
        [stem.to_string(), format!("{stem}-1"), format!("{stem}-2")]
    );
    let order = |suffix: &str| super::backup_order("config", &format!("{stem}{suffix}"));
    assert!(order("") < order("-1") && order("-1") < order("-2"));
}

#[test]
fn a_signed_clash_suffix_is_not_a_backup_and_survives_pruning() {
    let (directory, path) = config_file(BASE);
    let signed = "config.bak.20000101T000000.000Z-+5";
    std::fs::write(directory.path().join(signed), "keep").unwrap();
    for n in 0..12 {
        let name = format!("config.bak.200001{:02}T000000.000Z", n + 1);
        std::fs::write(directory.path().join(name), "old").unwrap();
    }

    edit_region(&path, "eu-central-1");

    assert!(directory.path().join(signed).exists());
    assert_eq!(backups(&path).len(), 11);
}

#[test]
fn backup_names_match_strictly_and_clashes_sort_after_their_timestamp() {
    let order = |file_name: &str| super::backup_order("config", file_name);
    let base = "config.bak.20261025T101530.123Z";
    assert_eq!(order(base), Some(("20261025T101530.123Z".to_string(), 0)));
    assert!(order(&format!("{base}-2")) < order(&format!("{base}-10")));
    for other in [
        "config.bak.20261025T101530.123Z-",
        "config.bak.20261025T101530.123Z-x",
        "config.bak.20261025T101530.123Z-+5",
        "config.bak.20261025T101530.123Z--1",
        "config.bak.20261025T101530.123",
        "config.bak.20261025-101530.123Z",
        "config.bak-20261025-tag",
        "configx.bak.20261025T101530.123Z",
    ] {
        assert_eq!(order(other), None, "{other}");
    }
}
