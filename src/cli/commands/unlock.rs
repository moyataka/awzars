//! `unlock` command: clear the session gate for one profile.
//!
//! For a password-locked profile, prompts for the password and writes a
//! session token that lets credential operations through.
//!
//! For an unlocked profile, the command is only useful with `--allow-ai`:
//! it asks the user to confirm AI consent and writes a token tagged
//! `allow_ai = true`. Without `--allow-ai`, the command prints a no-op
//! message.

use crate::auth::lock;
use crate::cli::args::{LOCK_TTL_HARD_CAP_HOURS, LOCK_TTL_SOFT_CAP_HOURS};
use crate::config::Config;
use crate::error::{AwzarsError, Result};
use std::io::IsTerminal;
use zeroize::Zeroizing;

pub fn run(
    profile_name: &str,
    allow_ai: bool,
    ttl_hours: Option<u64>,
    allow_long_ttl: bool,
) -> Result<()> {
    // Soft-cap the CLI override at 24 h unless the operator explicitly opts
    // into a long-lived token. The profile-stored `lock_ttl_hours` is left
    // alone — it is a deliberate one-time edit, not the per-call easy
    // ratchet the audit (L-3) flagged. Checked before the TTY gate so a
    // shape error is reported even from a non-interactive shell.
    if let Some(h) = ttl_hours {
        if h > LOCK_TTL_SOFT_CAP_HOURS && !allow_long_ttl {
            return Err(AwzarsError::Config(format!(
                "--ttl-hours {} exceeds the {} h default cap; pass \
                 --allow-long-ttl to extend up to {} h ({} days). Long-lived \
                 unlock tokens approach \"always unlocked\" semantics on \
                 shared hosts — pick the smallest workable window.",
                h,
                LOCK_TTL_SOFT_CAP_HOURS,
                LOCK_TTL_HARD_CAP_HOURS,
                LOCK_TTL_HARD_CAP_HOURS / 24,
            )));
        }
    }

    if !std::io::stdin().is_terminal() {
        return Err(AwzarsError::LockRequiresTty);
    }

    let config = Config::load()?;
    let profile = config.get_profile(profile_name)?;

    lock::gc_stale_unlocks();

    let ttl_secs = lock::resolve_ttl_secs(ttl_hours, profile);

    if let Some(phc) = profile.lock_verifier.as_deref() {
        let pw: lock::PasswordInput = Zeroizing::new(
            dialoguer::Password::new()
                .with_prompt(format!("Password for awzars profile '{}'", profile_name))
                .interact()
                .map_err(|e| AwzarsError::Dialog(e.to_string()))?,
        );
        lock::verify_password_or_fail(&pw, phc, profile_name)?;
        let token = lock::write_unlock(profile_name, ttl_secs, allow_ai, true)?;
        print_unlocked(profile_name, &token);
        return Ok(());
    }

    // Unlocked profile.
    if !allow_ai {
        println!(
            "Profile '{}' is not password-locked; nothing to unlock. \
             Pass `--allow-ai` to grant AI agents session consent for this profile.",
            profile_name
        );
        return Ok(());
    }

    let answer = dialoguer::Confirm::new()
        .with_prompt(format!(
            "Profile '{}' is not password-locked. Grant AI agents session \
             consent to use it from this terminal?",
            profile_name
        ))
        .default(false)
        .interact()
        .map_err(|e| AwzarsError::Dialog(e.to_string()))?;
    if !answer {
        println!("Aborted.");
        return Ok(());
    }
    let token = lock::write_unlock(profile_name, ttl_secs, true, false)?;
    print_unlocked(profile_name, &token);
    Ok(())
}

fn print_unlocked(profile_name: &str, token: &lock::UnlockToken) {
    let expires_at = chrono::DateTime::<chrono::Local>::from(
        std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(token.created_at.saturating_add(token.ttl_secs)),
    );
    let ai = if token.allow_ai { "allowed" } else { "blocked" };
    let raw_sid = lock::current_sid().ok();
    let sid_note = match raw_sid {
        Some(raw) if raw != token.sid => format!(
            " [terminal session via TTY-owning ancestor; this process's getsid(0) = {}]",
            raw
        ),
        _ => String::new(),
    };
    println!(
        "Profile '{}' unlocked for terminal session {} until {} (AI access: {}).{}",
        profile_name,
        token.sid,
        expires_at.format("%Y-%m-%d %H:%M:%S %Z"),
        ai,
        sid_note,
    );
}
