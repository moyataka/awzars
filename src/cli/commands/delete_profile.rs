//! `delete-profile` command: remove an awzars profile and all owned state.
//!
//! Does not touch `~/.aws/config`. AWS profiles still pointing at the deleted
//! awzars profile are listed as a warning so the user can edit them by hand.

use crate::config::cleanup::delete_awzars_profile;
use crate::error::{AwzarsError, Result};
use std::io::IsTerminal;

pub fn run(profile: &str, yes: bool, quiet: bool) -> Result<()> {
    if !yes {
        if !std::io::stdin().is_terminal() {
            return Err(AwzarsError::Dialog(
                "can't ask for confirmation because stdin is not a terminal; \
                 pass --yes to delete without asking"
                    .into(),
            ));
        }
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Delete awzars profile '{}' and its credentials, cookies, and cached data?",
                profile
            ))
            .default(false)
            .interact()
            .map_err(|e| AwzarsError::Dialog(e.to_string()))?;
        if !confirmed {
            if !quiet {
                println!("Aborted.");
            }
            return Ok(());
        }
    }

    let report = delete_awzars_profile(profile)?;

    if !quiet {
        println!("Deleted awzars profile '{}'.", profile);
    }

    for w in &report.warnings {
        tracing::warn!("{}", w);
    }

    if !quiet && !report.orphaned_aws_profiles.is_empty() {
        eprintln!(
            "\nThe following profiles in your configured AWS file still reference '{}':",
            profile
        );
        for p in &report.orphaned_aws_profiles {
            eprintln!("  - {}", p);
        }
        eprintln!("Edit your configured AWS file to remove or repoint them.");
    }

    if let Some(reason) = report.keyring_error {
        return Err(AwzarsError::Keyring(format!(
            "profile '{}' is deleted, but {}",
            profile, reason
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AzureConfig, Config, Profile};
    use crate::storage::keyring::{test_keychain, KeyringStorage};

    #[test]
    fn delete_reports_keychain_items_it_could_not_remove() {
        const TEST_DIRECTORY: &str = "AWZARS_DELETE_PROFILE_KEYRING_TEST";
        let Ok(directory) = std::env::var(TEST_DIRECTORY) else {
            // The config directory override is process-wide, so the test
            // body runs in a child process with its own directory.
            let directory = tempfile::tempdir().unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cli::commands::delete_profile::tests::delete_reports_keychain_items_it_could_not_remove",
                ])
                .env(TEST_DIRECTORY, directory.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        };
        crate::config::set_config_dir_override(&directory).unwrap();
        test_keychain::install();
        let aws_path = std::path::Path::new(&directory).join("aws-config");
        std::fs::write(&aws_path, "").unwrap();
        let mut config = Config {
            aws_config_path: Some(aws_path.to_string_lossy().into()),
            ..Default::default()
        };
        let profile = Profile {
            azure: AzureConfig::new(
                "11111111-2222-3333-4444-aaaaaaaaaaaa",
                "https://signin.aws.amazon.com/saml",
            ),
            ..Default::default()
        };
        config.set_profile("gone", profile);
        config.save().unwrap();
        let keyring = KeyringStorage::new("gone").unwrap();
        let entry = keyring.entry_for_field("cookie_key").unwrap();
        entry.set_password("stored").unwrap();

        test_keychain::fail_deletes(true);
        let result = run("gone", true, true);
        test_keychain::fail_deletes(false);

        let error = result.expect_err("a keychain failure must not report success");
        assert!(matches!(error, AwzarsError::Keyring(_)), "{error}");
        let message = error.to_string();
        assert!(message.contains("profile 'gone' is deleted"), "{message}");
        assert!(message.contains("gone:cookie_key ("), "{message}");
        assert!(
            entry.get_password().is_ok(),
            "the cookie key is still stored"
        );
        assert!(!Config::load().unwrap().profiles.contains_key("gone"));
    }
}
