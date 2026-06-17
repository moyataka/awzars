# Security Audit — `awzars`

| Field | Value |
|---|---|
| Last updated | 2026-06-15 |
| Scope | Rust CLI for Azure AD to AWS SAML federation |
| Method | Manual review of credential, cookie, config, browser, SAML, lock, and AWS config paths |
| Out of scope | Chromium runtime exploitation; rustls/ring/aws-lc-rs primitives |

## Summary

No current critical, high, medium, or low exploitable issues were identified in the reviewed tree. No hard-coded secrets, command injection paths, cleartext persisted AWS credentials, SQL injection paths, or `unsafe` Rust were found.

Current residual risks are accepted by the project threat model and documented below.

## Verification

- `rtk cargo test`: 137 tests passed.
- `rtk cargo fmt --check`: failed due to existing formatting drift in `src/cli/commands/login.rs`, `src/tui/manager/handlers.rs`, and `src/tui/manager/render.rs`.
- `rtk cargo audit`: unavailable locally (`cargo-audit` not installed).
- `rtk cargo deny check`: unavailable locally (`cargo-deny` not installed).

## Current Findings

### M-2 — Failure-counter backoff is same-UID resettable

`src/auth/lock.rs:88-160`

Failed unlock attempts are tracked in `<unlock_dir>/<scope_key>-<profile>.fails` (where `<scope_key>` is `sid-<n>` or `env-<key>`). A same-UID actor can delete that file and reset the escalating backoff.

Accepted because the backoff is anti-fat-finger pacing, not the real brute-force defense. Password resistance comes from Argon2id parameters, and an adversarial same-UID AI/process could also bypass marker detection by changing its environment.

### L-2 — Session start-time binding is Linux-only

`src/auth/lock.rs` (`process_start_time`, `read_valid_unlock`)

Linux `sid-` scoped unlock tokens bind to `/proc/<sid>/stat` start time to reject stale tokens after SID reuse. Non-Linux hosts — and `env-` scoped tokens (`AWZARS_SESSION_ID`, which have no session-leader PID) — fall back to scope-key + TTL only.

Accepted because SID reuse attacks are outside the AI-consent threat model. If this changes, implement macOS `proc_pidinfo` support.

### L-8 — Config loading follows `config.toml` symlinks

`src/config/profile.rs:83-125`, `src/config/mod.rs:56-90`

`Config::load()` opens `config.toml` with path-following `File::open`. The default config directory is tightened to `0o700`, so this is not a cross-UID issue, but a same-UID actor or user-controlled `--config-dir` can point awzars at another readable TOML file.

Accepted because local config is already trusted: a same-UID actor who can control it can directly change tenant ID, app ID URI, role ARN, and lock metadata. `config.toml` does not contain STS secrets, SAML assertions, browser cookies, or cookie encryption keys.

### L-9 — Unlock scope: Claude conversation id, else controlling-terminal session

`src/auth/lock.rs` (`session_scope`, `terminal_session_id`, `ProcStat`)

The unlock/consent token is no longer keyed on `getsid(0)` (one session per controlling terminal). Under an AI agent, `getsid(0)` returns a *fresh throwaway id per command* — Claude Code's Bash tool spawns each command in its own `setsid` session (and, in some configurations, its own PTY), so an unlock written by one command was invisible to the next and the lock could never be cleared from the agent. The scope is now resolved by priority:

1. `AWZARS_SESSION_ID` — explicit operator override (`env-<key>`), validated `[A-Za-z0-9_]{1,64}`.
2. `CLAUDE_CODE_SESSION_ID` — the Claude conversation id (`claude-<hex>`), exported into every command Claude spawns. This is the stable per-agent anchor that survives the per-command setsid/PTY isolation; it is what makes `awzars unlock --allow-ai` run from the Claude prompt visible to the agent's later `credential-process` / `login` calls.
3. The controlling-terminal session via a bounded `/proc` ancestry walk (`sid-<n>`), for plain interactive (non-agent) use — distinct per terminal / zellij pane — falling back to `getsid(0)` when no ancestor owns a tty.

Filenames are type-tagged (`sid-` / `claude-` / `env-`) so the key spaces cannot collide.

Security implication of the Claude-conversation scope (accepted):

- The scope is "this Claude conversation", not "this human". Every command in the conversation — including the agent's own tool calls — shares it. So once anyone runs `awzars unlock --allow-ai` for the profile in that conversation, the agent can use the credentials for the rest of it. This is the intended grant ("the human unlocks, the agent works"), but it also means the AI could issue that unlock itself: for an *unlocked* (no-password) profile the only thing between an autonomous agent and the credentials is the AI tool's own command-approval layer (which surfaces the `awzars unlock --allow-ai` invocation for the human to approve or deny). This is the same "honest limit" already documented for AI-marker detection — `awzars` makes the casual path safe and the grant explicit; it does not defeat a tool permitted to run arbitrary commands. **For a hard gate, password-lock the profile** (`awzars set-password`): a password unlock requires a real TTY (`/dev/tty`), which the agent's piped stdio cannot supply, so the agent cannot self-unlock a password-locked profile.
- Before this change the per-command throwaway sid *incidentally* stopped a self-issued unlock from persisting across the agent's commands; that side effect is gone. The protection now rests explicitly on the approval layer and (for the strong case) the password lock — not on a scoping accident.

Residual risks, accepted:

- **Ancestry trust** (the `sid-` walk). The walk reads ancestor `/proc/<pid>/stat` (ppid / session / tty_nr). A same-UID actor could craft a process tree to steer which session is selected, but a same-UID actor can already read the unlock token and the OS keyring directly, so this grants no new capability. The walk is bounded (32 hops) and falls back to `getsid(0)` when no ancestor owns a tty.
- **`AWZARS_SESSION_ID` / `CLAUDE_CODE_SESSION_ID` keys.** Both become a filename component. `AWZARS_SESSION_ID` is validated `[A-Za-z0-9_]{1,64}` (no separators, no `.`/`..` traversal, `-`-free so `<scope_key>-<profile>` splits unambiguously; a malformed value is ignored with a warning); `CLAUDE_CODE_SESSION_ID` is sanitized to its alphanumerics before use. Neither `claude-` nor `env-` tokens carry a session-leader PID, so they lose the start-time PID-reuse binding (L-2) and `kill(0)` liveness — they rely on the TTL and the tmpfs logout reap.

## Positive Controls

- AWS STS credentials are stored in the OS keyring and in process memory only.
- Browser cookies are stored as `cookies.enc` using ChaCha20-Poly1305 and keyring-backed versioned keys.
- SAML assertions are size-capped, namespace-scoped, issuer/audience/time/recipient checked, and wrapped in `Zeroizing<String>`.
- Remote Chrome requires `wss://` by default; `ws://` requires an explicit insecure flag.
- File writes use atomic temp-file replacement with `O_EXCL | O_NOFOLLOW`; AWS config writes reject symlinked targets.
- CLI parsers validate profile names, tenant UUIDs, role ARNs, session duration, and app ID URI shape.
- Panic handling wipes cached cookie keys and restores terminal state even with `panic = "abort"`.
- Lock-gate password prompts read from `/dev/tty`, so they fire under AWS CLI's `credential_process` pipeline where stdio is captured. AI agents cannot self-answer: keystroke injection requires `TIOCSTI`, privileged on modern Linux kernels.
- AI y/N consent is gated on `stdin().is_terminal()` — deliberately not `/dev/tty`. Under Claude Code's Bash tool, stdin is piped but `/dev/tty` is reachable; a `/dev/tty` read would block on keystrokes the AI tool never forwards. The gate refuses with `AiContextBlocked` instead, pointing at `awzars unlock --allow-ai`.
- `awzars unlock --allow-ai` drops the TTY requirement for *unlocked* profiles only: the `--allow-ai` flag is treated as the consent, so the command can run via Claude Code's Bash tool with the user approving through the AI tool's command-permission prompt. **Password-locked profiles still hard-require a TTY** (`is_password_locked && !stdin_is_tty → LockRequiresTty`, `unlock.rs`). Net effect: an AI with shell execution can autonomously unlock an unlocked profile (subject to its tool's permission layer); set a password lock for the strong physical-keyboard gate. The resulting token is scoped to the Claude conversation (`CLAUDE_CODE_SESSION_ID`) when present, else the controlling-terminal session, so the agent's later `credential-process` / `login` calls in the same conversation honour it — see L-9 (including why this means an unlocked profile offers no defence against an agent allowed to run the unlock itself).

## Caveats

- CI remains the authoritative source for live `cargo audit` and `cargo deny` advisory tracking.
- macOS Keychain and Windows Credential Manager behavior were not smoke-tested locally.
- Chromium and browser runtime exploitation are delegated to upstream Chromium.

*End of audit.*
