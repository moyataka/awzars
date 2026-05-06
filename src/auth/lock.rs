//! Per-profile password lock with session-scoped unlock tokens.
//!
//! Two protection levels:
//!
//! - **Password-locked profile** (`Profile.lock_verifier = Some(_)`): credential
//!   operations require a prior `awzars unlock <profile>` that took a password.
//! - **Unlocked profile under AI**: even without a password, an AI agent
//!   (detected via env markers like `CLAUDECODE`) cannot use the profile in a
//!   terminal session until the user consents via
//!   `awzars unlock <profile> --allow-ai`.
//!
//! Session boundary is the Linux session ID — but resolved by walking the
//! ppid chain to the first ancestor with a controlling TTY (see
//! `terminal_session_sid`), not `getsid(0)`. This matters because tools that
//! re-`setsid()` their subprocesses (Claude Code's Bash tool is the canonical
//! example) would otherwise see a fresh SID that doesn't match the unlock the
//! user just performed in their interactive shell. Walking up to the
//! TTY-owning ancestor restores the "everything sharing this terminal shares
//! the unlock" promise.
//!
//! The unlock token is a short JSON blob written under
//! `$XDG_RUNTIME_DIR/awzars/sessions/` (mode 0o600), so it is automatically
//! reaped on logout (tmpfs).
//!
//! AI marker check is best-effort — an agent that strips its env defeats it.
//! The strong AI defense lives in the AI tool's own permission system
//! (e.g. Claude Code `permissions`/`hooks` in `settings.json`).

use crate::config::Profile;
use crate::error::{AwzarsError, Result};
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Default unlock token lifetime, used when neither the CLI flag nor the
/// profile config supply one.
pub const DEFAULT_TTL_HOURS: u64 = 8;

/// Default AI environment markers checked against `std::env`. A profile may
/// override this via `Profile.lock_ai_markers`. An empty override list disables
/// AI detection for that profile.
pub const DEFAULT_AI_MARKERS: &[&str] = &["CLAUDECODE", "AI_AGENT"];

// --- Argon2id password hashing ---

/// Argon2id parameters pinned in source so the policy survives upstream
/// crate-default changes. m = 64 MiB, t = 3, p = 4 — meets OWASP's
/// "second-recommended" preset and is well clear of the crate's m=19 MiB,
/// t=2, p=1 default.
const ARGON2_M_COST_KIB: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

fn argon2_instance() -> argon2::Argon2<'static> {
    let params = argon2::Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, None)
        .expect("static argon2 params must validate");
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

/// Hash `plain` with the pinned Argon2id parameters and return a PHC string
/// suitable for `Profile.lock_verifier`.
pub fn hash_password(plain: &str) -> Result<String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = argon2_instance();
    let phc = argon2
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| AwzarsError::Config(format!("password hashing failed: {}", e)))?
        .to_string();
    Ok(phc)
}

/// Verify `plain` against a stored Argon2id PHC string. Returns `false` for any
/// mismatch (wrong password OR malformed PHC) without distinguishing — both are
/// "this password is not valid for this profile".
///
/// Verification uses the parameters embedded in the stored PHC string, not
/// the local pinned ones, so old hashes keep working after a parameter bump.
pub fn verify_password(plain: &str, phc: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;

    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

// --- Failed-attempt backoff ---

/// Per-(session, profile) state for rate-limiting failed unlock attempts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FailureCounter {
    count: u32,
    /// UNIX seconds of the most recent failure; used to age the counter so
    /// that a long-quiet session doesn't carry forward yesterday's typos.
    last_failure: u64,
}

const FAILURE_RESET_SECS: u64 = 3600;
const FAILURE_BACKOFF_CAP_SECS: u64 = 60;

fn failure_path(profile: &str) -> Result<PathBuf> {
    let sid = terminal_session_sid()?;
    Ok(unlock_dir()?.join(format!("{}-{}.fails", sid, profile)))
}

fn read_failure_counter(profile: &str) -> FailureCounter {
    let Ok(path) = failure_path(profile) else {
        return FailureCounter::default();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return FailureCounter::default();
    };
    let mut fc: FailureCounter = serde_json::from_slice(&bytes).unwrap_or_default();
    // Age out a stale counter so a session that typed wrong once last week
    // doesn't start its next attempt at a 60 s wait.
    if now_unix().saturating_sub(fc.last_failure) > FAILURE_RESET_SECS {
        fc = FailureCounter::default();
    }
    fc
}

fn write_failure_counter(profile: &str, fc: &FailureCounter) {
    let Ok(path) = failure_path(profile) else {
        return;
    };
    let Ok(bytes) = serde_json::to_vec(fc) else {
        return;
    };
    let _ = crate::util::atomic_write(&path, &bytes, 0o600);
}

fn clear_failure_counter(profile: &str) {
    if let Ok(path) = failure_path(profile) {
        let _ = std::fs::remove_file(&path);
    }
}

fn backoff_secs(count: u32) -> u64 {
    // Doubles per failure, capped: 2, 4, 8, 16, 32, 60, 60, …
    let raw = 2u64.saturating_pow(count.min(8));
    raw.min(FAILURE_BACKOFF_CAP_SECS)
}

/// Sleep proportionally to the current per-session failure count, then bump
/// it on disk. Call this on every failed password verify so a brute-force
/// loop pays escalating wall-clock cost — not just the original fixed 2 s.
pub fn record_failed_unlock(profile: &str) {
    let mut fc = read_failure_counter(profile);
    fc.count = fc.count.saturating_add(1);
    fc.last_failure = now_unix();
    write_failure_counter(profile, &fc);
    std::thread::sleep(Duration::from_secs(backoff_secs(fc.count)));
}

/// Clear the per-session failure counter on a successful verify or any
/// path that should reset escalation.
pub fn clear_failed_unlocks(profile: &str) {
    clear_failure_counter(profile);
}

/// Verify `plain` against `phc` for `profile_name`. On success, clears the
/// per-session failure counter and returns `Ok(())`. On failure, records
/// the attempt (which sleeps for the current backoff) and returns
/// `LockVerificationFailed`.
pub fn verify_password_or_fail(plain: &str, phc: &str, profile_name: &str) -> Result<()> {
    if verify_password(plain, phc) {
        clear_failed_unlocks(profile_name);
        Ok(())
    } else {
        record_failed_unlock(profile_name);
        Err(AwzarsError::LockVerificationFailed)
    }
}

/// Type alias for an Argon2 password input that zeros its heap on drop.
/// `dialoguer::Password::interact()` returns a plain `String` whose `Drop`
/// does **not** scrub memory, so we wrap it as soon as we own it.
pub type PasswordInput = Zeroizing<String>;

/// Whether the controlling terminal is reachable.
///
/// dialoguer reads from the *stderr* file descriptor (via `console::Term::stderr`),
/// which AWS CLI captures with `subprocess.PIPE` when invoking us as a
/// `credential_process` subprocess — so `stdin().is_terminal()` returning `true`
/// does not predict whether dialoguer will succeed. `/dev/tty` is the controlling
/// terminal, and is reachable from any subprocess that has one regardless of
/// stdio redirections.
pub fn tty_available() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
}

/// Prompt for a password directly on `/dev/tty`, with terminal echo disabled.
///
/// Bypasses dialoguer entirely so the prompt works even when the parent process
/// has captured stderr (AWS CLI's `credential_process` invocation, build tools,
/// any pipeline-style invocation). Echo is restored even if the read errors.
pub fn read_password_via_tty(prompt: &str) -> Result<PasswordInput> {
    use nix::sys::termios::{self, LocalFlags, SetArg};
    use std::io::{BufRead, BufReader, Write};

    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| AwzarsError::Dialog(format!("cannot open /dev/tty: {}", e)))?;

    let original =
        termios::tcgetattr(&tty).map_err(|e| AwzarsError::Dialog(format!("tcgetattr: {}", e)))?;
    let mut quiet = original.clone();
    // Disable the visible echos but keep ECHONL so the user's `Enter` still
    // advances the cursor to the next line for a tidy prompt.
    quiet
        .local_flags
        .remove(LocalFlags::ECHO | LocalFlags::ECHOE | LocalFlags::ECHOK);
    quiet.local_flags.insert(LocalFlags::ECHONL);
    termios::tcsetattr(&tty, SetArg::TCSANOW, &quiet)
        .map_err(|e| AwzarsError::Dialog(format!("tcsetattr (off): {}", e)))?;

    let read_result = match write!(tty, "{}: ", prompt).and_then(|_| tty.flush()) {
        Ok(()) => {
            // Read from a fresh `/dev/tty` handle so the BufReader doesn't
            // accidentally consume our writer.
            match std::fs::OpenOptions::new().read(true).open("/dev/tty") {
                Ok(file) => {
                    let mut reader = BufReader::new(file);
                    let mut line = String::new();
                    reader
                        .read_line(&mut line)
                        .map(|_| line)
                        .map_err(|e| AwzarsError::Dialog(format!("read /dev/tty: {}", e)))
                }
                Err(e) => Err(AwzarsError::Dialog(format!(
                    "cannot open /dev/tty for read: {}",
                    e
                ))),
            }
        }
        Err(e) => Err(AwzarsError::Dialog(format!("write /dev/tty: {}", e))),
    };

    let _ = termios::tcsetattr(&tty, SetArg::TCSANOW, &original);

    let mut line = read_result?;
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
    Ok(Zeroizing::new(line))
}

// --- Session ID ---

/// Raw `getsid(0)` for the current process. Prefer `terminal_session_sid`
/// for token storage — `getsid(0)` returns a fresh SID inside any subprocess
/// that has been `setsid()`-detached from the user's terminal, which would
/// silo unlock tokens away from the rest of the same terminal session.
pub fn current_sid() -> Result<u32> {
    use nix::unistd::{getsid, Pid};
    let sid = getsid(Some(Pid::from_raw(0)))
        .map_err(|e| AwzarsError::Config(format!("getsid failed: {}", e)))?;
    Ok(sid.as_raw() as u32)
}

/// Best-effort: is the process group leader for `sid` still alive?
fn sid_alive(sid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    kill(Pid::from_raw(sid as i32), None).is_ok()
}

/// Subset of `/proc/<pid>/stat` we care about. Field numbering (1-indexed,
/// per `proc(5)`): 4=ppid, 6=session, 7=tty_nr, 22=starttime. The `comm`
/// field (2) is parenthesised and may itself contain whitespace or `)`, so
/// the parser splits off everything up to the LAST `)` before tokenising the
/// remainder; in that remainder, field 3 (state) sits at zero-indexed slot 0.
#[cfg(target_os = "linux")]
struct ProcStat {
    ppid: i32,
    sid: u32,
    tty_nr: i32,
    start_time: u64,
}

#[cfg(target_os = "linux")]
fn read_proc_stat(pid: u32) -> Option<ProcStat> {
    let raw = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let close = raw.rfind(')')?;
    let tail = raw.get(close + 1..)?.trim_start();
    let f: Vec<&str> = tail.split_ascii_whitespace().collect();
    Some(ProcStat {
        ppid: f.get(1)?.parse().ok()?,
        sid: f.get(3)?.parse().ok()?,
        tty_nr: f.get(4)?.parse().ok()?,
        start_time: f.get(19)?.parse().ok()?,
    })
}

/// Linux: starttime (jiffies since boot) of process `pid`. Used to bind
/// an unlock token to a specific process incarnation so a stale token can't
/// be honoured after PID reuse hands the same SID to an unrelated process.
///
/// Returns `None` on non-Linux, on any IO/parse error, or if the field
/// cannot be located. Callers must treat `None` as "no extra check
/// performed" rather than "process is dead".
#[cfg(target_os = "linux")]
pub fn process_start_time(pid: u32) -> Option<u64> {
    read_proc_stat(pid).map(|s| s.start_time)
}

#[cfg(not(target_os = "linux"))]
pub fn process_start_time(_pid: u32) -> Option<u64> {
    None
}

/// Resolve the SID that scopes unlock tokens for the current process.
///
/// Walks the ppid chain (self first, up to a small bounded depth) looking
/// for the first ancestor with a non-zero `tty_nr` in `/proc/<pid>/stat`,
/// and returns that ancestor's session ID. This is the user's "logical
/// terminal session" — the SID of the shell that owns the controlling TTY.
///
/// Why not `getsid(0)`: tools that re-`setsid()` their child processes
/// (Claude Code's Bash tool subprocess is the canonical case) get a fresh
/// session ID with no controlling terminal. `getsid(0)` from inside such a
/// subprocess returns *that* fresh SID, not the user's shell's SID, so an
/// `awzars unlock` performed by the user in the same terminal is invisible
/// to the subprocess. Walking up to the first TTY-owning ancestor recovers
/// the user-shell SID and restores token sharing.
///
/// Falls back to `current_sid()` on non-Linux, on `/proc` read failure, on
/// chain length exhaustion, or when no ancestor up to PID 1 has a
/// controlling TTY (genuine daemon — there's nothing better to key off).
pub fn terminal_session_sid() -> Result<u32> {
    #[cfg(target_os = "linux")]
    {
        // Bound the walk so a malformed /proc, a refcount cycle that
        // shouldn't be possible, or a deep ancestry can't loop forever.
        const MAX_HOPS: usize = 32;
        let mut pid = std::process::id();
        for hop in 0..MAX_HOPS {
            let Some(stat) = read_proc_stat(pid) else {
                tracing::debug!(
                    pid,
                    hop,
                    "terminal_session_sid: /proc read failed; falling back to getsid(0)"
                );
                break;
            };
            if stat.tty_nr != 0 {
                tracing::debug!(
                    pid,
                    hop,
                    sid = stat.sid,
                    tty_nr = stat.tty_nr,
                    "terminal_session_sid: resolved via TTY-owning ancestor"
                );
                return Ok(stat.sid);
            }
            if stat.ppid <= 1 {
                tracing::debug!(
                    pid,
                    hop,
                    "terminal_session_sid: reached init with no TTY ancestor; \
                     falling back to getsid(0)"
                );
                break;
            }
            pid = stat.ppid as u32;
        }
    }
    let sid = current_sid()?;
    tracing::debug!(sid, "terminal_session_sid: using raw getsid(0)");
    Ok(sid)
}

// --- Unlock token storage ---

/// Where session unlock tokens live. Prefers `$XDG_RUNTIME_DIR/awzars/sessions/`
/// (tmpfs, auto-reaped on logout). Falls back to `~/.cache/awzars/sessions/`.
pub fn unlock_dir() -> Result<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        PathBuf::from(xdg)
    } else {
        directories::ProjectDirs::from("com", "awzars", "awzars")
            .ok_or_else(|| {
                AwzarsError::Config("could not determine cache directory for unlock tokens".into())
            })?
            .cache_dir()
            .to_path_buf()
    };
    let dir = base.join("awzars").join("sessions");
    // Idempotent: create_dir_all returns Ok if the target already exists,
    // closing the TOCTOU race between the existence check and the mkdir
    // when several processes (or parallel tests) hit this in lockstep.
    std::fs::create_dir_all(&dir)?;
    // Symlink-safe chmod: refuse to follow a symlink at the leaf so a
    // same-UID actor can't redirect the 0o700 onto something outside the
    // session-token directory. Best-effort — a permissions error here is
    // not fatal, the writes that follow are mode-pinned via atomic_write.
    let _ = crate::util::enforce_perms_no_symlink(&dir, 0o700);
    Ok(dir)
}

fn token_path(profile: &str, sid: u32) -> Result<PathBuf> {
    Ok(unlock_dir()?.join(format!("{}-{}.json", sid, profile)))
}

/// In-session approval record. Existence (under the current SID) means the
/// terminal session has cleared the gate for this profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockToken {
    pub profile: String,
    pub sid: u32,
    /// Seconds since UNIX_EPOCH.
    pub created_at: u64,
    pub ttl_secs: u64,
    /// `true` if the user explicitly opted this session into AI use.
    pub allow_ai: bool,
    /// `true` if the token was issued after a password verification (locked
    /// profile). `false` for consent-only tokens on unlocked profiles.
    pub password_unlocked: bool,
    /// Linux session-leader process start time (jiffies since boot, from
    /// `/proc/<sid>/stat` field 22). When present and the current
    /// session-leader's start time differs, the token is rejected — this
    /// defeats stale tokens being honoured after PID reuse. `None` means
    /// the host couldn't supply it (non-Linux, /proc unreadable); the check
    /// degrades to PID-presence only, matching pre-fix behaviour.
    #[serde(default)]
    pub start_time: Option<u64>,
}

impl UnlockToken {
    fn is_expired(&self, now: u64) -> bool {
        now >= self.created_at.saturating_add(self.ttl_secs)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Persist an unlock/consent token for the current session.
pub fn write_unlock(
    profile: &str,
    ttl_secs: u64,
    allow_ai: bool,
    password_unlocked: bool,
) -> Result<UnlockToken> {
    let sid = terminal_session_sid()?;
    let token = UnlockToken {
        profile: profile.to_string(),
        sid,
        created_at: now_unix(),
        ttl_secs,
        allow_ai,
        password_unlocked,
        start_time: process_start_time(sid),
    };
    let path = token_path(profile, sid)?;
    let bytes = serde_json::to_vec(&token)?;
    crate::util::atomic_write(&path, &bytes, 0o600)?;
    Ok(token)
}

/// Load the current session's unlock token for `profile`, if it exists, the
/// SID matches, and it has not expired.
pub fn read_valid_unlock(profile: &str) -> Option<UnlockToken> {
    let sid = terminal_session_sid().ok()?;
    let path = token_path(profile, sid).ok()?;
    let bytes = std::fs::read(&path).ok()?;
    let token: UnlockToken = serde_json::from_slice(&bytes).ok()?;
    if token.sid != sid || token.profile != profile {
        return None;
    }
    // PID-reuse defence: if the token recorded a session-leader start time,
    // the current session leader must match it. Mismatch = the original
    // process is gone and the kernel handed its SID to something new.
    if let Some(recorded) = token.start_time {
        match process_start_time(sid) {
            Some(now_start) if now_start != recorded => {
                let _ = std::fs::remove_file(&path);
                return None;
            }
            _ => {}
        }
    }
    if token.is_expired(now_unix()) {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    Some(token)
}

/// Remove the current session's unlock token for `profile`, if any.
pub fn remove_unlock(profile: &str) -> Result<()> {
    let sid = terminal_session_sid()?;
    let path = token_path(profile, sid)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Read at most `max` bytes from `path`. Returns `Err` on any IO error or
/// if the file exceeds the cap. Used by `gc_stale_unlocks` to keep a
/// hostile / corrupt file in the session dir from blowing up the GC pass.
fn read_capped(path: &std::path::Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    let read = (&mut file).take(max + 1).read_to_end(&mut buf)?;
    if read as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds gc read cap",
        ));
    }
    Ok(buf)
}

/// Best-effort: drop tokens whose session leader is no longer alive. Called
/// from interactive `unlock` / `lock` commands so stale entries don't pile up
/// across reboots when XDG_RUNTIME_DIR is missing.
///
/// Two file shapes live in this directory:
///
/// - `<sid>-<profile>.json`  — an `UnlockToken`
/// - `<sid>-<profile>.fails` — a `FailureCounter` (per-session backoff)
///
/// Both are reaped when the recorded SID is no longer alive. Tokens are
/// also reaped on TTL expiry; failure counters are reaped on age-out.
pub fn gc_stale_unlocks() {
    /// Hard cap on bytes read from any session-dir file during GC. Real
    /// tokens and failure counters are tens of bytes; an unbounded read
    /// would let a same-UID actor plant a multi-GB file and OOM the gc
    /// pass. 8 KiB leaves comfortable headroom.
    const MAX_GC_FILE_BYTES: u64 = 8 * 1024;

    let Ok(dir) = unlock_dir() else { return };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(bytes) = read_capped(&path, MAX_GC_FILE_BYTES) else {
            continue;
        };

        // Dispatch on extension so unrelated future files don't get touched.
        match path.extension().and_then(|s| s.to_str()) {
            Some("json") => {
                let Ok(token) = serde_json::from_slice::<UnlockToken>(&bytes) else {
                    // Parse failure: leave alone rather than silently deleting.
                    continue;
                };
                if !sid_alive(token.sid) || token.is_expired(now_unix()) {
                    let _ = std::fs::remove_file(&path);
                }
            }
            Some("fails") => {
                // Filename shape `<sid>-<profile>.fails` — recover the SID so
                // we can liveness-check it. If the filename doesn't parse,
                // fall back to age-out only.
                let sid_alive_guess = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.split_once('-'))
                    .and_then(|(s, _)| s.parse::<u32>().ok())
                    .is_some_and(sid_alive);
                let Ok(fc) = serde_json::from_slice::<FailureCounter>(&bytes) else {
                    continue;
                };
                let aged_out = now_unix().saturating_sub(fc.last_failure) > FAILURE_RESET_SECS;
                if !sid_alive_guess || aged_out {
                    let _ = std::fs::remove_file(&path);
                }
            }
            _ => {
                // Unknown extension: leave alone.
            }
        }
    }
}

// --- AI context detection ---

/// Return the first AI marker name found in the environment, or `None`.
pub fn is_ai_context(markers: &[String]) -> Option<String> {
    for m in markers {
        if std::env::var_os(m).is_some() {
            return Some(m.clone());
        }
    }
    None
}

/// Resolve effective markers for `profile`. An explicit empty `Some(vec![])`
/// disables AI detection for that profile.
pub fn effective_markers(profile: &Profile) -> Vec<String> {
    match &profile.lock_ai_markers {
        Some(v) => v.clone(),
        None => DEFAULT_AI_MARKERS.iter().map(|s| s.to_string()).collect(),
    }
}

/// Hard cap (in hours) on any resolved unlock TTL, mirroring the CLI ratchet
/// in `cli::args::LOCK_TTL_HARD_CAP_HOURS`. Pinned here too so the
/// profile-stored override (`Profile.lock_ttl_hours`) cannot quietly defeat
/// the ratchet by setting an absurd value (e.g. 87600 = 10 years) directly
/// in `config.toml`.
const RESOLVED_TTL_HARD_CAP_HOURS: u64 = 720;

/// Resolve the TTL for an unlock, in seconds. Priority is CLI override,
/// then profile setting, then `DEFAULT_TTL_HOURS`. The resolved value is
/// clamped to `RESOLVED_TTL_HARD_CAP_HOURS` (30 days) so that an
/// out-of-band edit to `Profile.lock_ttl_hours` cannot effectively turn
/// the lock into a one-time PIN; a `tracing::warn!` records the clamp
/// for the operator.
pub fn resolve_ttl_secs(cli_hours: Option<u64>, profile: &Profile) -> u64 {
    let raw = cli_hours
        .or(profile.lock_ttl_hours)
        .unwrap_or(DEFAULT_TTL_HOURS);
    let hours = if raw > RESOLVED_TTL_HARD_CAP_HOURS {
        tracing::warn!(
            "unlock TTL {} h exceeds hard cap of {} h; clamping",
            raw,
            RESOLVED_TTL_HARD_CAP_HOURS
        );
        RESOLVED_TTL_HARD_CAP_HOURS
    } else {
        raw
    };
    hours.saturating_mul(3600)
}

// --- Gate ---

/// Outcome of an inline gate check that may consume user input on a TTY.
pub enum GateOutcome {
    /// No action needed.
    NotLocked,
    /// Existing token cleared the gate.
    AlreadyUnlocked,
    /// Inline password prompt cleared the gate and a token was written.
    UnlockedNow { allow_ai: bool },
    /// One-shot AI consent prompt cleared the gate; no token written. Next
    /// invocation will prompt again. Caller asked not to persist.
    ConsentedOnce,
}

/// Verify a credential operation may proceed for `profile_name`.
///
/// `allow_inline_prompt = true` permits an inline TTY prompt (password for a
/// locked profile when no AI is detected; y/N consent for an unlocked
/// profile under AI). `false` (used by `credential-process`) hard-fails with
/// an actionable error message.
///
/// `persist_consent` only affects the unlocked-profile + AI consent path.
/// `false` (default for `login`/`list-roles`) means the y/N prompt fires on
/// every invocation. `true` writes a session token after the first "yes" so
/// subsequent calls under the same session ID skip the prompt.
pub fn enforce(
    profile_name: &str,
    profile: &Profile,
    allow_inline_prompt: bool,
    persist_consent: bool,
) -> Result<GateOutcome> {
    let is_locked = profile.lock_verifier.is_some();
    let markers = effective_markers(profile);
    let ai_marker = is_ai_context(&markers);

    // Fast path: nothing to enforce.
    if !is_locked && ai_marker.is_none() {
        return Ok(GateOutcome::NotLocked);
    }

    let token = read_valid_unlock(profile_name);

    // Locked profile must have a password-derived token. Ask-every-time is
    // not applied here: re-typing a password on every aws call would be
    // unworkable, so a successful inline password prompt always writes a
    // session token (subject to the configured TTL).
    if is_locked {
        let token_ok = token
            .as_ref()
            .is_some_and(|t| t.password_unlocked && (ai_marker.is_none() || t.allow_ai));

        if token_ok {
            return Ok(GateOutcome::AlreadyUnlocked);
        }

        // No valid token — refuse, even if a TTY is attached. Inline password
        // prompts under AI gaze are a footgun; keep the unlock flow explicit.
        if let Some(marker) = ai_marker {
            return Err(AwzarsError::AiContextBlocked {
                profile: profile_name.to_string(),
                marker,
            });
        }

        // No AI: optionally inline-prompt for password, otherwise refuse.
        // Read directly from /dev/tty rather than via dialoguer so the prompt
        // works under credential-process (AWS CLI captures the subprocess
        // stderr, which is the file descriptor dialoguer reads from).
        if allow_inline_prompt && tty_available() {
            let pw =
                read_password_via_tty(&format!("Password for awzars profile '{}'", profile_name))?;

            let phc = profile
                .lock_verifier
                .as_deref()
                .expect("checked is_locked above");
            verify_password_or_fail(&pw, phc, profile_name)?;
            let ttl = resolve_ttl_secs(None, profile);
            write_unlock(profile_name, ttl, false, true)?;
            return Ok(GateOutcome::UnlockedNow { allow_ai: false });
        }

        return Err(AwzarsError::LockedProfile {
            profile: profile_name.to_string(),
        });
    }

    // Unlocked profile + AI marker detected.
    //
    // Default behaviour is "ask every time": the y/N prompt fires on every
    // invocation and the answer is NOT persisted. The caller can opt into
    // session-scoped remembering by passing `persist_consent = true`
    // (typically driven by the user's `--session-remember` flag).
    let consent_ok = token.as_ref().is_some_and(|t| t.allow_ai);
    if consent_ok {
        return Ok(GateOutcome::AlreadyUnlocked);
    }

    if allow_inline_prompt && std::io::stdin().is_terminal() {
        let marker = ai_marker.expect("checked above");
        let prompt = if persist_consent {
            format!(
                "AI context detected ({}). Allow AI agents to use AWS credentials \
                 for profile '{}' for the rest of this terminal session?",
                marker, profile_name
            )
        } else {
            format!(
                "AI context detected ({}). Allow this single AWS use for profile '{}'? \
                 (will ask again next time; pass --session-remember to persist)",
                marker, profile_name
            )
        };
        let answer = dialoguer::Confirm::new()
            .with_prompt(prompt)
            .default(false)
            .interact()
            .map_err(|e| AwzarsError::Dialog(e.to_string()))?;
        if !answer {
            return Err(AwzarsError::AiContextBlocked {
                profile: profile_name.to_string(),
                marker,
            });
        }
        if persist_consent {
            let ttl = resolve_ttl_secs(None, profile);
            write_unlock(profile_name, ttl, true, false)?;
            return Ok(GateOutcome::UnlockedNow { allow_ai: true });
        }
        return Ok(GateOutcome::ConsentedOnce);
    }

    Err(AwzarsError::AiContextBlocked {
        profile: profile_name.to_string(),
        marker: ai_marker.expect("checked above"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize tests that mutate process-global env vars. `cargo test`
    /// runs each test in a thread by default; without this, two tests both
    /// calling `set_var("XDG_RUNTIME_DIR", ...)` race and one observes the
    /// other's tempdir.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _tmp: tempfile::TempDir,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    fn temp_xdg() -> EnvGuard {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_RUNTIME_DIR", tmp.path());
        EnvGuard {
            _tmp: tmp,
            _lock: lock,
        }
    }

    #[test]
    fn argon2_round_trip() {
        let phc = hash_password("hunter2hunter2").unwrap();
        assert!(verify_password("hunter2hunter2", &phc));
        assert!(!verify_password("wrong", &phc));
        assert!(!verify_password("", &phc));
    }

    #[test]
    fn verify_rejects_malformed_phc() {
        assert!(!verify_password("anything", "not a phc string"));
    }

    /// Pin the Argon2id parameters so an accidental downgrade (e.g. someone
    /// switching back to `Argon2::default()`) fails CI rather than silently
    /// weakening every new password hash.
    #[test]
    fn argon2_params_are_pinned() {
        let phc = hash_password("regression-anchor").unwrap();
        // PHC format: `$argon2id$v=19$m=<m>,t=<t>,p=<p>$<salt>$<hash>`
        assert!(
            phc.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"),
            "expected pinned m=65536,t=3,p=4 params, got: {}",
            phc
        );
    }

    #[test]
    fn backoff_grows_then_caps() {
        assert_eq!(backoff_secs(1), 2);
        assert_eq!(backoff_secs(2), 4);
        assert_eq!(backoff_secs(3), 8);
        assert_eq!(backoff_secs(5), 32);
        // Cap kicks in.
        assert_eq!(backoff_secs(6), FAILURE_BACKOFF_CAP_SECS);
        assert_eq!(backoff_secs(50), FAILURE_BACKOFF_CAP_SECS);
        assert_eq!(backoff_secs(u32::MAX), FAILURE_BACKOFF_CAP_SECS);
    }

    #[test]
    fn failure_counter_persists_and_clears() {
        let _g = temp_xdg();
        let prof = format!("test_fail_{}", std::process::id());
        clear_failed_unlocks(&prof);

        // Synthesize three failed attempts without paying real backoff cost
        // (record_failed_unlock sleeps; bypass it here for test speed).
        for expected in 1..=3 {
            let mut fc = read_failure_counter(&prof);
            fc.count = fc.count.saturating_add(1);
            fc.last_failure = now_unix();
            write_failure_counter(&prof, &fc);
            assert_eq!(read_failure_counter(&prof).count, expected);
        }

        clear_failed_unlocks(&prof);
        assert_eq!(read_failure_counter(&prof).count, 0);
    }

    #[test]
    fn failure_counter_ages_out() {
        let _g = temp_xdg();
        let prof = format!("test_age_{}", std::process::id());
        clear_failed_unlocks(&prof);

        // Plant a stale failure record from "yesterday".
        let stale = FailureCounter {
            count: 7,
            last_failure: now_unix().saturating_sub(FAILURE_RESET_SECS + 60),
        };
        write_failure_counter(&prof, &stale);

        // Reads must reset the counter rather than carry the stale value.
        let fresh = read_failure_counter(&prof);
        assert_eq!(fresh.count, 0);
    }

    #[test]
    fn terminal_session_sid_resolves() {
        // Smoke test: must succeed and return a real SID for the host. We
        // can't assert the value (depends on whether the test runner has a
        // controlling terminal), only that the function returns Ok and
        // produces a positive integer.
        let sid = terminal_session_sid().expect("must resolve");
        assert!(sid > 0);
    }

    #[test]
    fn terminal_session_sid_matches_self_when_owning_tty() {
        // When the test process itself has a controlling TTY, the walk
        // should stop at level 0 and return our own SID. When it doesn't
        // (typical under `cargo test`), we can't assert anything specific,
        // so just confirm the call shape.
        if !cfg!(target_os = "linux") {
            return;
        }
        let resolved = terminal_session_sid().unwrap();
        let raw = current_sid().unwrap();
        // If self has a TTY, resolved == raw. If not, resolved is some
        // ancestor's SID — either way both are valid u32s.
        let _ = (resolved, raw);
    }

    #[test]
    fn unlock_token_records_start_time_on_linux() {
        let _g = temp_xdg();
        let prof = format!("test_st_{}", std::process::id());
        let _ = remove_unlock(&prof);

        let token = write_unlock(&prof, 3600, false, true).unwrap();
        // On Linux we must capture a start_time; on other platforms it's None.
        if cfg!(target_os = "linux") {
            assert!(
                token.start_time.is_some(),
                "Linux build must record session-leader start_time"
            );
        }
        let _ = remove_unlock(&prof);
    }

    #[test]
    fn unlock_token_with_mismatched_start_time_is_rejected() {
        // Skip on non-Linux: process_start_time always returns None there
        // so the mismatch branch is unreachable.
        if !cfg!(target_os = "linux") {
            return;
        }
        let _g = temp_xdg();
        let prof = format!("test_st_mm_{}", std::process::id());
        let _ = remove_unlock(&prof);

        // Hand-craft a token whose start_time can't possibly match the
        // current session leader's, then verify read_valid_unlock rejects it.
        // Must key off `terminal_session_sid` (what read_valid_unlock uses),
        // not `current_sid` — these differ inside any setsid()-detached
        // subprocess such as `cargo test` under some runners.
        let sid = terminal_session_sid().unwrap();
        let bogus = UnlockToken {
            profile: prof.clone(),
            sid,
            created_at: now_unix(),
            ttl_secs: 3600,
            allow_ai: false,
            password_unlocked: true,
            start_time: Some(u64::MAX),
        };
        let path = token_path(&prof, sid).unwrap();
        std::fs::write(&path, serde_json::to_vec(&bogus).unwrap()).unwrap();

        assert!(read_valid_unlock(&prof).is_none());
        // Read-side rejection must also unlink the bad token.
        assert!(!path.exists());
    }

    #[test]
    fn unlock_token_round_trip() {
        let _g = temp_xdg();
        let prof = format!("test_rt_{}", std::process::id());
        let _ = remove_unlock(&prof);

        assert!(read_valid_unlock(&prof).is_none());
        let written = write_unlock(&prof, 3600, true, true).unwrap();
        let read = read_valid_unlock(&prof).expect("token should exist");
        assert_eq!(read.profile, written.profile);
        assert_eq!(read.sid, written.sid);
        assert!(read.allow_ai);
        assert!(read.password_unlocked);

        remove_unlock(&prof).unwrap();
        assert!(read_valid_unlock(&prof).is_none());
    }

    #[test]
    fn expired_token_returns_none() {
        let _g = temp_xdg();
        let prof = format!("test_exp_{}", std::process::id());
        let _ = remove_unlock(&prof);

        // ttl=0 → instantly expired
        write_unlock(&prof, 0, false, true).unwrap();
        assert!(read_valid_unlock(&prof).is_none());
    }

    #[test]
    fn ai_context_detection() {
        // Use a unique marker name to avoid colliding with real env vars.
        let marker = format!("AWZARS_TEST_AI_{}", std::process::id());
        std::env::remove_var(&marker);
        assert!(is_ai_context(std::slice::from_ref(&marker)).is_none());

        std::env::set_var(&marker, "1");
        assert_eq!(
            is_ai_context(std::slice::from_ref(&marker)),
            Some(marker.clone())
        );

        std::env::remove_var(&marker);
    }

    #[test]
    fn effective_markers_default_when_unset() {
        let p = Profile {
            lock_ai_markers: None,
            ..Profile::default()
        };
        let got = effective_markers(&p);
        assert!(got.iter().any(|m| m == "CLAUDECODE"));
    }

    #[test]
    fn effective_markers_override_can_disable() {
        let p = Profile {
            lock_ai_markers: Some(vec![]),
            ..Profile::default()
        };
        assert!(effective_markers(&p).is_empty());
    }
}
