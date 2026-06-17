//! `unlock` command: clear the session gate for one profile.
//!
//! For a password-locked profile, prompts for the password and writes a
//! session token that lets credential operations through. Always requires
//! an interactive TTY — typing a password through piped stdin is the
//! footgun the lock exists to prevent.
//!
//! For an unlocked profile, the command is only useful with `--allow-ai`:
//! it writes a token tagged `allow_ai = true`. When stdin is a TTY, the
//! user is asked to confirm via a y/N dialoguer prompt. When stdin is
//! piped (typical when invoked through Claude Code's Bash tool, which
//! has already prompted the user to approve running this exact command
//! via its own permission layer), the explicit `--allow-ai` flag is
//! treated as the consent and the prompt is skipped — same end state,
//! same audit trail, no need to escape to a real terminal.
//!
//! Without `--allow-ai`, the command prints a no-op message.
//!
//! `--no-expire` writes a token with `ttl_secs = 0`, the sentinel that
//! `UnlockToken::is_expired` treats as "never". The token still dies with
//! the terminal session — `$XDG_RUNTIME_DIR` is tmpfs (auto-reaped on
//! logout) and `gc_stale_unlocks` drops tokens whose SID is no longer
//! alive. There is no time fallback, so a forgotten unlock on a
//! long-lived session has no safety net beyond logging out.

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
    no_expire: bool,
) -> Result<()> {
    // Soft-cap the CLI override at 24 h unless the operator explicitly opts
    // into a long-lived token. The profile-stored `lock_ttl_hours` is left
    // alone — it is a deliberate one-time edit, not the per-call easy
    // ratchet the audit (L-3) flagged. Checked before the TTY gate so a
    // shape error is reported even from a non-interactive shell. Bypassed
    // for `--no-expire` (clap also enforces mutual exclusion with
    // `--ttl-hours` / `--allow-long-ttl`, but defence-in-depth).
    if !no_expire {
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
    }

    let config = Config::load()?;
    let profile = config.get_profile(profile_name)?;

    let stdin_is_tty = std::io::stdin().is_terminal();
    let is_password_locked = profile.lock_verifier.is_some();

    // Password-locked profiles always require a TTY — the password is read
    // through dialoguer's raw-mode stdin reader and must come from a human
    // at a real terminal, not a pipe. Refuse early so a piped caller gets
    // a clear error instead of a hang inside dialoguer.
    if is_password_locked && !stdin_is_tty {
        return Err(AwzarsError::LockRequiresTty);
    }

    lock::gc_stale_unlocks();

    // `ttl_secs = 0` is the "never expires" sentinel. `is_expired()` returns
    // false for it; the token then dies only with the session (tmpfs reap +
    // SID liveness check).
    let ttl_secs = if no_expire {
        0
    } else {
        lock::resolve_ttl_secs(ttl_hours, profile)
    };

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

    // Unlocked + --allow-ai. On a TTY, ask for an explicit y/N confirmation
    // (the historical interactive flow). When stdin is piped — as it is
    // under Claude Code's Bash tool — the explicit `--allow-ai` flag *is*
    // the consent, and the AI tool's own command-approval layer has already
    // prompted the user. Skip the prompt rather than hanging.
    if stdin_is_tty {
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
    }

    let token = lock::write_unlock(profile_name, ttl_secs, true, false)?;
    print_unlocked(profile_name, &token);
    Ok(())
}

fn print_unlocked(profile_name: &str, token: &lock::UnlockToken) {
    let ai = if token.allow_ai { "allowed" } else { "blocked" };
    let expiry = if token.ttl_secs == 0 {
        "until session ends (no time expiry)".to_string()
    } else {
        let at = chrono::DateTime::<chrono::Local>::from(
            std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(token.created_at.saturating_add(token.ttl_secs)),
        );
        format!("until {}", at.format("%Y-%m-%d %H:%M:%S %Z"))
    };
    println!(
        "Profile '{}' unlocked for session {} {} (AI access: {}).",
        profile_name, token.scope_key, expiry, ai,
    );
}
