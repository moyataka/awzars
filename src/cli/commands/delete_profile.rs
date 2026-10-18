//! `delete-profile` command: remove an awzars profile and all owned state.
//!
//! Does not touch `~/.aws/config`. AWS profiles still pointing at the deleted
//! awzars profile are listed as a warning so the user can edit them by hand.

use crate::config::cleanup::delete_awzars_profile;
use crate::error::{AwzarsError, Result};

pub fn run(profile: &str, yes: bool, quiet: bool) -> Result<()> {
    if !yes {
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

    Ok(())
}
