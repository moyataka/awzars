//! `set-password` command: set, change, or remove a profile's password lock.

use crate::auth::lock;
use crate::config::Config;
use crate::error::{AwzarsError, Result};
use std::io::IsTerminal;
use zeroize::Zeroizing;

pub fn run(profile_name: &str, remove: bool) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err(AwzarsError::LockRequiresTty);
    }

    let mut config = Config::load()?;
    {
        // Scope the immutable borrow so we can mutate later.
        let profile = config.get_profile(profile_name)?;

        // If currently locked, the old password is required for any change
        // (set new, or remove). Otherwise an attacker with file-system access
        // could disable the lock without knowing the secret.
        if let Some(phc) = profile.lock_verifier.clone() {
            let old: lock::PasswordInput = Zeroizing::new(
                dialoguer::Password::new()
                    .with_prompt(format!(
                        "Current password for awzars profile '{}'",
                        profile_name
                    ))
                    .interact()
                    .map_err(|e| AwzarsError::Dialog(e.to_string()))?,
            );
            lock::verify_password_or_fail(&old, &phc, profile_name)?;
        } else if remove {
            println!("Profile '{}' is not password-locked.", profile_name);
            return Ok(());
        }
    }

    if remove {
        let profile = config.get_profile_mut(profile_name)?;
        profile.lock_verifier = None;
        profile.lock_ttl_hours = None;
        profile.lock_ai_markers = None;
        config.save()?;
        let _ = lock::remove_unlock(profile_name);
        println!("Password lock removed from profile '{}'.", profile_name);
        return Ok(());
    }

    let new: lock::PasswordInput = Zeroizing::new(
        dialoguer::Password::new()
            .with_prompt(format!(
                "New password for awzars profile '{}'",
                profile_name
            ))
            .with_confirmation("Confirm new password", "Passwords do not match")
            .interact()
            .map_err(|e| AwzarsError::Dialog(e.to_string()))?,
    );

    let phc = lock::hash_password(&new)?;

    let profile = config.get_profile_mut(profile_name)?;
    profile.lock_verifier = Some(phc);
    config.save()?;

    // Changing the password invalidates any existing session token: callers
    // must re-unlock with the new secret.
    let _ = lock::remove_unlock(profile_name);

    println!(
        "Password lock set on profile '{}'. Run `awzars unlock {}` in any \
         terminal session before using credentials there.",
        profile_name, profile_name
    );
    Ok(())
}
