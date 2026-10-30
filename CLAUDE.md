# awzars

Modern Rust-based Azure AD to AWS credential federation tool. Replaces `aws-azure-login` with a single static binary.

## Build

Requires `cargo-zigbuild` and `zig` (no Docker needed).

```bash
# Install build tools
pip install ziglang cargo-zigbuild

# Static build (no GLIBC dependency)
cargo zigbuild --release --target x86_64-unknown-linux-musl

# Run tests
cargo zigbuild --test '*' --target x86_64-unknown-linux-musl

# Binary location
target/x86_64-unknown-linux-musl/release/awzars
```

Supported platforms: macOS on Apple Silicon (arm64; Intel macOS is not supported) and Linux (glibc or static musl). Windows is not supported yet: `auth/lock.rs` uses `nix` (termios, `getsid`, `kill`) without a platform guard and `nix` is Unix-only, so the crate does not build for Windows; CI does not build it. Rust 1.91.1 or newer is required with the committed Cargo.lock (the AWS SDK crates declare it); `refresh_lock.rs` alone needs 1.89 for `std::fs::File::try_lock`.

## Releasing

Releases are built by `.github/workflows/release.yml` when a `v*` tag is pushed. Don't build or upload release assets by hand.

1. In a PR to `dev`, bump `version` in `Cargo.toml` and move `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z] - YYYY-MM-DD`. The workflow uses that section as the release notes.
2. Merge `dev` into `main`.
3. On `main`: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`. The workflow fails if the tag doesn't match `Cargo.toml`, the commit isn't on `main`, the CHANGELOG section is missing, or a release for the tag already exists.
4. Review the draft release (notes, `SHA256SUMS`, provenance attestations) and publish it.

Assets are named `awzars-vX.Y.Z-{target}.tar.gz` and contain only the `awzars` binary. Targets:
- `x86_64-unknown-linux-musl`: built on Linux with `cargo zigbuild`
- `aarch64-apple-darwin`: built on macOS Apple Silicon

## Usage

```bash
# Configure a profile
awzars configure

# Login and get AWS credentials
awzars login

# Login with specific role, skip selector
awzars login --role-arn arn:aws:iam::123456789012:role/MyRole

# Force re-authentication
awzars login --force-refresh

# Persist browser session (skip re-auth on future logins)
awzars login --remember-me

# Use with remote Chrome (for headless/CI); only ws:// works today, see Remote Chrome Setup
CHROME_REMOTE_URL="ws://localhost:9222/devtools/browser/xxx" awzars login --allow-insecure-remote-chrome

# Clear cached credentials (prompts for confirmation; pass --yes to skip)
awzars clear-cache

# AWS CLI integration (~/.aws/config)
[profile work]
credential_process = /usr/local/bin/awzars credential-process --profile work
```

### credential-process

`credential-process` is designed for AWS CLI/SDK integration. The browser flow is always non-interactive. Password prompts for locked profiles read from `/dev/tty` so they fire under AWS CLI's piped stdio. AI consent does *not* prompt here — refuses with `AiContextBlocked` pointing at `awzars unlock --allow-ai`.

- **Defaults to headless + remember-me**: When credentials expire, it automatically attempts silent headless re-authentication using saved browser cookies (no config needed)
- **Pre-flight check**: Before launching a browser, verifies a session exists. Returns a clear error if no prior `awzars login --remember-me` session is found
- **Skips check for remote Chrome**: When `CHROME_REMOTE_URL` is set, connects to remote Chrome directly (no local session needed)

```bash
# First time: establish a persistent session
awzars login --remember-me

# After that, credential-process works automatically via AWS CLI
aws s3 ls  # calls awzars credential-process behind the scenes
```

## Architecture

```
src/
├── main.rs                       # Entry point, CLI routing, exit codes (UserQuit → 0)
├── lib.rs                        # Library root, re-exports modules
├── error.rs                      # AwzarsError enum (thiserror), Result type alias
├── cli/
│   ├── args.rs                  # clap definitions, validators (parse_*), LoginArgs/ConfigureArgs
│   └── commands/
│       ├── login.rs             # Pipeline: launch_browser → authenticate → shutdown browser → select_role → STS → persist; role resolution (resolve_role / choose_role / suggest_roles, missing-role fallback and save prompt)
│       ├── configure.rs         # Interactive profile creation (validators on every prompt)
│       ├── list_roles.rs        # Browser-driven role listing (browser shut down after SAML extraction)
│       ├── credential_process.rs # AWS credential_process integration (auto-reauth via cookies)
│       ├── delete_profile.rs    # Drop a profile + all its persisted state
│       ├── set_password.rs      # Set / change / --remove the per-profile password lock
│       ├── unlock.rs            # Unlock a locked profile (or grant AI consent) for the session
│       ├── lock.rs              # Drop the session's unlock token
│       └── tui.rs               # TUI command entry point
│       # `clear-cache` is inline in main.rs; its cleanup is `config::cleanup::clear_stored_credentials`
├── browser/
│   ├── chromium.rs              # chromiumoxide automation, cookie store, remote-Chrome connect
│   ├── cookie_crypto.rs         # ChaCha20-Poly1305 cookie encryption with versioned key rotation
│   ├── saml_capture.rs          # Captures the SAMLResponse from the browser's POST to an AWS sign-in host before it is submitted
│   └── selectors/               # Azure login page CSS selectors + versioning
├── auth/
│   ├── azure/
│   │   ├── saml.rs              # SAML assertion parsing, validation, role extraction
│   │   └── protocol.rs          # Pure SAML-build/extract/AWS-redirect helpers (no chromium dep)
│   ├── aws/
│   │   ├── arn.rs               # IAM ARN parsing (role / SAML provider; aws, aws-cn, aws-us-gov partitions)
│   │   └── sts.rs               # STS AssumeRoleWithSAML
│   ├── credentials/
│   │   ├── pipeline.rs          # try_load_credentials: cache → keyring fallback (single source of truth)
│   │   └── refresh_lock.rs      # Per-profile cross-process refresh lock (<config-dir>/refresh-<profile>.lock, 60 s wait bound)
│   └── lock.rs                  # Per-profile password lock + AI consent gate (Argon2id; session-scoped tokens bound to lock verifier + boot)
├── storage/
│   ├── cache.rs                 # In-memory credential cache (per-profile)
│   └── keyring.rs               # OS keychain integration (single JSON entry per profile)
├── credential_process/
│   └── protocol.rs              # AWS credential_process output (Zeroizing<String> writers)
├── config/
│   ├── azure_config.rs          # AzureConfig (tenant_id, app_id_uri)
│   ├── profile.rs               # Profile + Config structs, atomic TOML I/O, 0o600 perms
│   └── cleanup.rs               # delete_awzars_profile: shared cleanup for CLI + TUI; clear_stored_credentials for clear-cache
├── tui/
│   ├── app.rs                   # ratatui role selector (mouse + search/filter)
│   ├── aws_config.rs            # AWS config INI parser + atomic writer, configurable path, role_session_name
│   ├── aws_config/document.rs   # Line-preserving edits: applies one profile's changes to the current ~/.aws/config
│   ├── form.rs                  # ProfileForm + AwsProfileForm with autocomplete, visible-field indices
│   ├── form_ops.rs              # Pure FieldOp + key_to_field_op + move_index helpers
│   ├── regions.rs               # AWS region list for autocomplete
│   ├── tui_error.rs             # TuiResultExt: .tui()? wraps any Display error → AwzarsError::Tui
│   └── manager/
│       ├── mod.rs               # ConfigManager type, event loop, key/mouse routing
│       ├── handlers.rs          # Per-mode key handlers + form save/refresh
│       └── render.rs            # Widget construction (impl ConfigManager block)
└── util/
    ├── atomic_write.rs          # unlink → O_EXCL|O_NOFOLLOW open → fchmod → rename, used by all on-disk persistence
    └── perms.rs                 # enforce_perms_no_symlink: symlink-safe chmod helper
```

The `manager/` directory is a single Rust module split across three files: each
contains an `impl ConfigManager` block, and submodules of `manager` see the
struct's private fields directly — no `pub(super)` on data, only on the few
methods that cross the file boundary.

## Commands & Key CLI Options

```
awzars login              # Login and get credentials
awzars configure          # Create or update a profile
awzars list-roles         # List available AWS roles
awzars credential-process # For AWS CLI integration
awzars clear-cache        # Clear cached credentials for a profile (prompts; --yes to skip)
awzars delete-profile     # Delete an awzars profile + credentials/cookies/cache (does NOT touch ~/.aws/config)
awzars tui                # Interactive config manager (profiles + AWS config)
awzars set-password       # Set / change / --remove the password lock on a profile
awzars unlock             # Unlock a locked profile (or grant AI consent on an unlocked one) for this terminal session
awzars lock               # Drop this session's unlock token for a profile
```

Global options: `-p`/`--profile` (default: "default"; commands take no positional profile, e.g. `awzars --profile work unlock`), `-v`/`-vv`/`-vvv`, `-q`/`--quiet`, `--config-dir` (env: `AWZARS_CONFIG_DIR`).

Environment variables:
- `AWZARS_AZURE_TENANT_ID` / `AWZARS_AZURE_APP_ID_URI`: defaults for `--azure-tenant` / `--azure-app` on `login` and `configure` (flags win; the generic `AZURE_TENANT_ID` / `AZURE_APP_ID_URI` are ignored).
- `AWZARS_REFRESH_LOCK_TIMEOUT_SECS`: how long a `login` / `credential-process` waits for another refresh of the same profile (positive whole seconds; default 60; anything else falls back to 60). On timeout the call fails with exit code 5.
- `AWZARS_SESSION_ID` (`[A-Za-z0-9_]{1,64}`): overrides the unlock token's session scope, for detached/headless/CI contexts where no controlling terminal sits in the process ancestry. `CLAUDE_CODE_SESSION_ID` is used as the scope when it is set and `AWZARS_SESSION_ID` is not (see Profile Locking).
- `CHROME_REMOTE_URL`: use a remote Chrome (see Remote Chrome Setup). `CHROME`: path to the local Chrome binary (a macOS `.app` bundle is resolved to its binary).
- `RUST_LOG`: log filter when `--quiet` is not set.

Login options: `--role-arn`, `--azure-tenant`, `--azure-app`, `--session-duration`, `--headless`, `--no-sandbox`, `--force-refresh`, `-o`/`--output` (text/json/table), `--credential-process`, `--show-secrets`, `--remember-me`, `--allow-insecure-remote-chrome`, `--session-remember` (persist AI consent for the session; default re-prompts every call)

Login role resolution (`login.rs` `resolve_role` / `choose_role`): if the profile's configured `role_arn` is missing from the SAML assertion and a person can answer (stdin and stdout are terminals, no `--credential-process`), login warns and opens the role picker (a single remaining role is confirmed with y/N, default No), then asks whether to save the chosen role (default No). Declining stores neither the role nor the credentials. An explicit `--role-arn` is never replaced. Otherwise the error `RoleNotInAssertion` (exit 3) lists up to 5 closest roles (case-only match, then same account, then edit distance) and the two ways to fix the profile. `list-roles` (table/text output) prints a note on stderr when the configured role is missing.

Credential-process options: `--refresh` (ignore stored credentials), `--headless`, `--no-sandbox`, `--allow-insecure-remote-chrome` (each overrides the profile setting).

Credential freshness: stored credentials are reused until `min(15 min, session_duration / 2)` before expiry (`credential_process/protocol.rs` `refresh_buffer`), judged by the profile's `session_duration`. Cache hits never take the refresh lock; misses take `<config-dir>/refresh-<profile>.lock`, re-check, then sign in. Interactive login prompts (remember-me, role picker, save-role) run outside the lock.

Configure options: `--azure-tenant`, `--azure-app`, `--role-arn`, `--session-duration`, `--non-interactive`

Clear-cache options: `--yes` (skip confirmation prompt). Clears the in-process cache and the profile's stored STS credentials in the keyring (`config::cleanup::clear_stored_credentials` → `KeyringStorage::delete_session_credentials`). `cookie_key` is kept, so the remembered browser session (`cookies.enc`) still works; `delete-profile` removes it.

Delete-profile options: `--yes` (skip confirmation prompt). Cleans up the awzars config entry, keyring credentials (incl. cookie key), in-memory cache, and the per-profile chromium dir. **Does not** modify `~/.aws/config` — AWS profiles still pointing at the deleted awzars profile are listed as a warning so they can be edited by hand.

Set-password options: `--remove` (clear the lock; still requires the old password). TTY-only; refuses if stdin is not a terminal so passwords can never be piped in. Argon2id PHC string lives in `<config-dir>/config.toml` under the profile entry. No minimum password length is enforced — typing speed is prioritized, with the dialoguer confirmation step (entered twice) as the only safety net against typos.

Unlock options: `--allow-ai` (permit AI agents in this session — `CLAUDECODE` / `AI_AGENT` env markers — to use the credentials), `--ttl-hours <N>` (override the default 8h; soft-capped at 24h, raise to the 720h / 30-day hard cap with `--allow-long-ttl`), `--allow-long-ttl` (opt-in for `--ttl-hours > 24`), `--no-expire` (skip time expiry; the token still ends at reboot, a `sid-` token ends with its terminal session, and tokens under `$XDG_RUNTIME_DIR` go at logout; conflicts with `--ttl-hours` / `--allow-long-ttl`). Fails with `SessionUnlockUnavailable` (exit 11) before prompting when the boot cannot be identified. Password-locked profiles require a TTY and prompt for the password. Unlocked profiles only need `--allow-ai` — TTY not required, so it can be invoked through Claude Code's Bash tool. See `SECURITY_AUDIT.md` for the tradeoff.

Lock options: none. Idempotent: removes the current session's unlock token if any.

## Profile Locking (password lock + AI consent)

Opt-in per-profile gate that fences credential-producing operations (`login`, `credential-process`, `list-roles`) behind a session-scoped checkpoint. Designed so AI agents (Claude Code, Cursor, etc.) cannot autonomously invoke AWS commands without an explicit human checkpoint.

**Two protection levels** (independent — either, both, or neither apply per profile):

1. **Password lock**: enabled by `awzars --profile <profile> set-password`. Stores an Argon2id PHC string in the profile entry. Every credential operation in a fresh terminal session prompts for the password (or refuses, if non-interactive — see below).
2. **AI consent**: applies whenever the environment contains a known AI marker (`CLAUDECODE` or `AI_AGENT` by default, configurable via the profile's `lock_ai_markers`). Even *unlocked* profiles refuse credential operations under AI until the user consents. The y/N prompt is gated on `stdin().is_terminal()`: fires per call during interactive `login` / `list-roles` (pass `--session-remember` to persist), skipped under piped stdin (AWS CLI's `credential_process`, Claude Code's Bash tool) — those refuse with `AiContextBlocked` pointing at `awzars unlock --allow-ai`. Password prompts for locked profiles are separate (read from `/dev/tty`). Locked + AI refuses without any prompt; see `SECURITY_AUDIT.md` for rationale.

**Session boundary** is resolved by priority: (1) `AWZARS_SESSION_ID` (`[A-Za-z0-9_]{1,64}`, explicit override → `env-<key>`); (2) `CLAUDE_CODE_SESSION_ID` (the Claude conversation id → `claude-<hex>`) — exported into every command Claude spawns, so an `awzars unlock` run from the Claude prompt and the agent's later AWS calls share one scope even though each command runs in its own `setsid`/PTY session (this is what fixes "unlock doesn't work under claude agents"); (3) the controlling-terminal session via a bounded (32-hop) ancestry walk to the nearest tty-owning ancestor (`sid-<n>`, distinct per terminal / zellij pane) — `/proc/<pid>/stat` on Linux, `proc_pidinfo(PROC_PIDTBSDINFO)` + `getsid(pid)` on macOS — falling back to `getsid(0)`. Token is a JSON file `<scope_key>-<profile>.json` (mode 0o600) in `$XDG_RUNTIME_DIR/awzars/sessions/` (auto-reaped on logout where that is a tmpfs); when `XDG_RUNTIME_DIR` is unset, in `ProjectDirs` `cache_dir()` + `awzars/sessions/`: `~/Library/Caches/com.awzars.awzars/awzars/sessions/` on macOS, `${XDG_CACHE_HOME:-~/.cache}/awzars/awzars/sessions/` on Linux.

**Token binding** (`UnlockToken`, format `v: 2`): a token is honoured only if (a) its scope key and profile match; (b) its `boot_id` equals the current boot (`/proc/sys/kernel/random/boot_id` on Linux, `sysctl kern.bootsessionuuid` on macOS; with no well-formed boot id no token is minted or honoured and gated commands fail with `SessionUnlockUnavailable`, exit 11); (c) for `sid-` tokens, the recorded session-leader start time matches (Linux `/proc/<sid>/stat`; macOS `proc_pidinfo`, best-effort because a root-owned `login` leader is usually unreadable); (d) it is unexpired; and (e) in `enforce`, its `verifier_fp` (domain-separated SHA-256 of the profile's `lock_verifier`, truncated to 128 bits) matches the profile's current verifier — a consent token for an unlocked profile must carry none. Tokens with `v < 2` are refused and removed. `set-password` (set, change, `--remove`) and profile deletion (`delete-profile`, TUI delete) call `revoke_all_unlocks`, which removes the profile's `.json` tokens and `.fails` counters in every scope. The Claude-conversation scope means the agent itself shares the unlock, so an unlocked profile is no barrier to an agent allowed to run `awzars unlock --allow-ai` — **password-lock the profile for a hard gate** (a password unlock needs a real TTY the agent can't supply). See the L-9 entry in `SECURITY_AUDIT.md`.

**TTL**: default 8 h. Override per-profile (`Profile.lock_ttl_hours`) or per-unlock (`--ttl-hours`, soft-capped at 24 h; pass `--allow-long-ttl` to extend up to the 720 h / 30-day hard ceiling). The profile-stored override is *not* gated — it is treated as a deliberate one-time edit; the per-call CLI ratchet is the one that needs an opt-in.

**Gate placement** (`crate::auth::lock::enforce(name, profile, allow_inline_prompt, persist_consent)`):

- `awzars login [--session-remember]`: TTY-attached. Locked profile + no AI: inline password prompt → token persists for TTL. Unlocked profile + AI: y/N consent every call by default; `--session-remember` writes a token after the first "yes". Locked profile + AI: refuse, user must run `awzars unlock --allow-ai`.
- `awzars credential-process`: Locked + no AI: opens `/dev/tty` for the password prompt → writes a session token. Unlocked + AI: refuses (`AiContextBlocked`); user runs `awzars unlock --allow-ai`. Locked + AI: refuses without prompt; user runs `awzars unlock --allow-ai` first. Locked + no AI also refuses when `/dev/tty` is unreachable (CI / scripted callers / genuine daemons).
- `awzars list-roles [--session-remember]`: same shape as `login`.

**Honest limit**: AI-marker detection stops *casual* leakage (you forgot you'd unlocked, then opened claude in the same shell). An adversarial AI that runs `unset CLAUDECODE` before invoking `aws` defeats it. For stronger protection, layer Claude Code's own `permissions` / `hooks` in `~/.claude/settings.json` — e.g. deny `awzars credential-process` outright or require per-call user approval. Awzars makes the casual path safe and the malicious path obvious; the AI tool's own policy layer is where to harden against the malicious case.

Schema additions on `Profile` (all `Option<_>`, omitted when unset): `lock_verifier` (Argon2id PHC), `lock_ttl_hours`, `lock_ai_markers`. The TUI form does not directly edit these fields, but on **add** of a brand-new awzars profile (Tab 1, `a`) the TUI offers a y/N modal "Set a password lock?" that suspends ratatui and runs the same dialoguer-driven flow as `awzars set-password`. On **edit** the form preserves existing lock state untouched. The CLI `awzars configure` mirrors this behavior — it asks the same y/N question after creating a new profile when stdin is a TTY.

## Key Dependencies

- **chromiumoxide** (0.9, default features off — CDP client only, no browser download): Chrome DevTools Protocol for browser automation
- **aws-config / aws-sdk-sts** (`default-https-client` → `rustls-aws-lc`,
  rustls 0.23): STS AssumeRoleWithSAML. The legacy `rustls` feature flag
  (which pulled rustls 0.21 via `legacy-rustls-ring`) is deliberately not
  used (see the comment in `Cargo.toml`).
- **keyring** (3.x with `apple-native` / `windows-native` /
  `sync-secret-service` / `crypto-rust` / `vendored`): OS keychain storage
  (`windows-native` is enabled but Windows is not a supported target). The published
  `keyring 4.0` is a CLI binary, not the library; the library line stays
  on 3.x until `keyring-core 1.0` settles.
- **ratatui** + **crossterm**: Terminal UI for role selection
- **tokio**: Async runtime
- **zeroize**: Secure memory cleanup for sensitive data (Drop-based)
- **thiserror**: Error type derive
- **dialoguer**: Interactive prompts (configure, remember-me prompt)
- **tempfile**: Ephemeral browser data directories (auto-cleaned on drop)
- **argon2**: Argon2id password hashing for the per-profile lock verifier
- **sha2**: SHA-256 fingerprint of the lock verifier stored in session unlock tokens
- **nix** (`process`, `signal`, `term`): `getsid()` / `kill(sid, 0)` for session-scoped unlock tokens and termios to disable echo for `/dev/tty` password prompts (the `sid-` scope's session id is resolved by walking up to the controlling-terminal ancestor via `/proc` on Linux or `proc_pidinfo` on macOS — see Profile Locking / L-9). Unix-only, not platform-guarded: this is why Windows does not build
- **libc** (macOS-only dependency): `proc_pidinfo` for the ancestry walk and `sysctlbyname("kern.bootsessionuuid")` for the boot id

## Security

- Config dir (`<config-dir>/`) permissions enforced to 0o700 (Unix) on every access — mitigates TOCTOU where adversary pre-creates dir with loose perms
- Config files written with mode 0o600 (Unix); `config.toml` size capped at 1 MiB on load to prevent OOM from a hostile or corrupted file
- Chromium data dir (`<config-dir>/chromium/<profile>/`) permissions enforced to 0o700
- Cookie store (`cookies.enc`) written with mode 0o600 — ChaCha20-Poly1305 AEAD with random nonce per encryption; format `[1 byte key_id][12 byte nonce][ciphertext+tag]`
- Cookie key rotation: 30-day rotation window, 90-day retention. Keystore is one OS-keyring item per profile (`{profile}:cookie_key`) holding a JSON `{current, keys, created_at}` blob — single keyring item means macOS Keychain ACL is granted once and rotation never re-prompts. Legacy single-key entries auto-migrate on first read.
- All atomic on-disk writes go through `util::atomic_write`. It creates a uniquely named `.awzars-*` temp file in the target's directory with the `tempfile` crate (`O_CREAT | O_EXCL`, mode 0o600 on Unix), sets the open file to the requested mode (Unix), writes and `fsync`s it, then `persist`s it with `rename(2)` over the target and `fsync`s the directory (Unix). A failed write removes its own temp file. Because the temp name is random and created exclusively, and `rename` replaces a symlink at the target instead of following it, a same-UID symlink planted at either path cannot redirect the write. This covers every persisted secret (`config.toml`, `cookies.enc`, unlock tokens, failure counters, `~/.aws/config` and its backups).
- `util::enforce_perms_no_symlink(path, mode)` wraps every directory- and file-perm tighten so a planted symlink at the leaf is rejected rather than silently traversed; applied at `ensure_config_dir` / `enforce_config_dir_perms` / the chromium data dir / the cookie store dir / `unlock_dir` / `Config::load`'s auto-tighten.
- `~/.aws/config` writer additionally rejects a symlinked parent `~/.aws/` (extra layer on top of the `atomic_write` hardening)
- Profile names validated at both CLI and library level (e.g. `chromium_data_dir()`) to prevent path traversal
- SAML assertion size capped at 256 KB before decode to prevent memory exhaustion (DoS)
- Sensitive data (SAML assertions, credentials, cookie keys) zeroized on drop via `zeroize`
- Panic hook (installed in `main.rs`) restores terminal state (raw mode, alternate screen, mouse capture, cursor) and wipes the in-process cookie key cache before the default handler runs — important because `panic = "abort"` (release profile) skips Drop impls
- TLS 1.2+ via rustls (no native-tls/OpenSSL)
- SAML assertions never written to disk
- SAML extraction gated on an HTTPS POST to `/saml` on port 443 of an AWS sign-in host (`signin.aws.amazon.com`, `signin.amazonaws.cn`, `signin.amazonaws-us-gov.com`, `browser/saml_capture.rs`); non-AWS pages never harvested
- Remote Chrome: `wss://` required by default; `ws://` only with `--allow-insecure-remote-chrome` + warning; session IDs redacted from logs; userinfo in URLs rejected. Current limitation: the WebSocket stack (chromiumoxide → async-tungstenite) is built without a TLS feature, so `wss://` URLs pass validation but cannot connect
- Keychain reads (`storage::keyring::read_secret`) treat only `NoEntry` as missing; any other error (locked keychain, denied access) is returned, so an unreadable item is never regenerated or overwritten
- XML-escaped `app_id_uri` in AuthnRequest to prevent injection
- Ephemeral `--user-data-dir` with `tempfile::TempDir` auto-cleanup (non-remember-me sessions)
- SAML client-side validation: issuer (URL-normalized), audience, Recipient, time window (30s skew), inverted-time-window rejection. **No XML-DSIG verification client-side** — integrity is delegated to TLS-to-Azure plus AWS STS re-verification in `AssumeRoleWithSAML`.
- Error messages redacted to avoid leaking tenant IDs, issuer URLs, or Recipient values
- Safe Rust except for small, `SAFETY`-commented macOS FFI calls in `auth/lock.rs` (`proc_pidinfo`, `sysctlbyname`)
- CI (`.github/workflows/ci.yml`) runs on push/PR to `dev`/`main` and weekly: `cargo fmt --check` on Linux, `cargo clippy --all-targets -- -D warnings` and `cargo test --all-targets` on Linux and macOS; `cargo deny check`; a static musl build via cargo-zigbuild; and, on pull requests only, the `.pre-commit-config.yaml` hooks on the files the PR changes. Windows is not built in CI yet. Release artifacts are built by `.github/workflows/release.yml` from `v*` tags (see Releasing).

## Configuration

Stored in `<config-dir>/config.toml`. `<config-dir>` is `$XDG_CONFIG_HOME/awzars` (or `~/.config/awzars`) on Linux and `~/Library/Application Support/com.awzars.awzars` on macOS (on Windows, which is not supported yet, `ProjectDirs` would give `%APPDATA%\awzars\awzars\config`). An absolute `--config-dir` overrides `AWZARS_CONFIG_DIR`, which overrides these defaults. Top-level field `aws_config_path` (optional string) overrides `AWS_CONFIG_FILE`, which overrides the default `~/.aws/config` path used by the TUI and deletion orphan scan. In both, a leading `~/` is expanded to the home directory, and a relative path resolves against the current working directory. Chromium persistent sessions (from `--remember-me`) are stored in `<config-dir>/chromium/<profile>/`.

**AWS region for STS**: the per-profile `region` field is the region used for the `AssumeRoleWithSAML` call. Resolution precedence (`auth::aws::sts::build_region_provider`): profile `region` → AWS default chain (`AWS_REGION` / `AWS_DEFAULT_REGION`, `~/.aws/config`, IMDS with a 500 ms limit) → `us-east-1` fallback. So a region set only in `<config-dir>/config.toml` is honored (it was previously parsed/stored but ignored by STS), and the call never fails purely for lack of a configured region. The profile `region` takes precedence over the `AWS_REGION` env var because it is an explicit awzars-profile setting; blank/whitespace values are treated as unset.

## Cookie Store (Remote → Local Session Transfer)

When authenticating via remote Chrome (`CHROME_REMOTE_URL`) with `--remember-me`, session cookies are extracted and saved locally to `<config-dir>/chromium/<profile>/cookies.enc` (mode 0o600, ChaCha20-Poly1305 encrypted). Unset `CHROME_REMOTE_URL` to let subsequent `credential-process` calls silently re-authenticate using **local** headless Chrome. While the variable remains set, browser refreshes continue using remote Chrome and require the explicit `ws://` permission.

Flow:
1. `CHROME_REMOTE_URL=ws://... awzars login --remember-me --allow-insecure-remote-chrome` → authenticate via remote Chrome, cookies saved locally
2. `awzars credential-process` → launches local headless Chrome, injects saved cookies, silent re-auth

The cookie store is also used when a persistent Chrome user-data-dir would cause SingletonLock conflicts (another Chrome using the same profile). In this case, cookies are injected into a fresh temp directory instead.

## credential-process Auto-Reauth

When `credential-process` needs new credentials (cache/keyring expired):

1. **Pre-flight check**: Verifies a browser session exists (cookie store `cookies.enc` or Chrome session data). Returns clear error with instructions if not found
2. **Defaults**: `headless=true`, `remember_me=true` (always non-interactive; profile config overrides if explicitly set)
3. **Cookie store exists**: Launches local headless Chrome with temp dir + injects cookies (avoids SingletonLock)
4. **Chrome session data exists**: Launches local headless Chrome with persistent user-data-dir
5. **CHROME_REMOTE_URL set**: Skips pre-flight, connects to remote Chrome directly

## Headless Mode

`--headless` runs Chrome without a visible window. It **requires** `--remember-me` with an existing persistent session (from a prior headed `--remember-me` login) or a cookie store (from remote Chrome auth):

```bash
# First: establish a persistent session (opens browser window)
awzars login --remember-me

# Subsequent: headless re-auth using saved session cookies (30s timeout)
awzars login --headless --remember-me
```

Without `--remember-me`, `--headless` is an error unless a cookie store exists (injected cookies from a prior remote Chrome session). If session cookies are expired, headless mode fails with a message to re-run interactively.

When `CHROME_REMOTE_URL` is set, awzars connects to an already-running browser. Its `--headless` flag does not change that remote browser's window; Chrome's own launch command determines whether it is headless.

## Remote Chrome Setup

Set `CHROME_REMOTE_URL` to a Chrome DevTools Protocol WebSocket URL to delegate browser automation to a remote Chrome instance. The tool connects via WebSocket, navigates the login flow, and extracts the SAML response — credentials traverse this connection.

When used with `--remember-me`, session cookies are automatically extracted and saved locally so that subsequent `credential-process` calls can use local headless Chrome instead of requiring the remote instance.

Security:
- `wss://` is required by default (TLS-encrypted WebSocket)
- `ws://` (unencrypted) is rejected unless `--allow-insecure-remote-chrome` is passed (`credential-process` also honours the profile's `allow_insecure_remote_chrome`; `login` reads only the flag)
- `--allow-insecure-remote-chrome` prints a prominent warning about unencrypted credential exposure, plus a separate warning when the host is not loopback
- WebSocket session IDs are redacted from log output
- URLs with embedded userinfo (`user:pass@host`) are rejected

Current limitation: `chromiumoxide` connects through `async-tungstenite` without any TLS feature enabled (see `Cargo.lock`), so a `wss://` URL passes `validate_ws_url` but the connection fails. Remote Chrome therefore works only over `ws://` with `--allow-insecure-remote-chrome`; keep it on loopback (SSH tunnel). `list-roles` always passes `allow_insecure = false` (`list_roles.rs`), so it cannot use a remote Chrome today.

### Option 1: Chrome on macOS, awzars on Linux

On macOS, start Chrome with remote debugging:

```bash
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222 \
  --user-data-dir="/tmp/chrome_dev_session" \
  --no-first-run \
  --no-default-browser-check \
  "about:blank"
```

This opens a visible window with a separate browser profile. The profile keeps
its session while the directory remains intact; `/tmp` may be cleaned up. Use
a persistent directory if the session needs to survive temporary-file cleanup.
The `--no-first-run` and `--no-default-browser-check` flags skip Chrome's setup
prompts, and `about:blank` opens a blank page.

```text
awzars (Linux) -- CDP via SSH tunnel --> Chrome (macOS)
      |
      +-- save credentials --> OS keyring (Linux)
```

SSH port forward from Linux to Mac:

```bash
# On Linux: make Linux's localhost:9222 reach the Mac's port 9222
ssh -L 9222:localhost:9222 user@mac-host -N
```

Or reverse (if Mac connects to Linux):

```bash
# On Mac: expose the Mac's port 9222 as localhost:9222 on Linux
ssh -R 9222:localhost:9222 user@linux-host -N
```

Then on Linux:

```bash
# Read webSocketDebuggerUrl through the tunnel; repeat after Chrome restarts.
curl http://localhost:9222/json/version
export CHROME_REMOTE_URL="ws://localhost:9222/devtools/browser/xxx"
awzars login --profile default --remember-me --allow-insecure-remote-chrome
```

The OS keyring on Linux must also be unlocked to save credentials and cookie
encryption keys. This is independent of the macOS browser session; see
[Headless / SSH keyring unlock](docs/headless-keyring.md). For AWS CLI refreshes
that continue using remote Chrome, add `--allow-insecure-remote-chrome` to the
existing `credential_process` command, or set
`allow_insecure_remote_chrome = true` in the awzars profile.

### Option 2: Chrome on remote Linux

```bash
# On remote machine
chromium --remote-debugging-port=9222 --headless --no-sandbox

# Get WebSocket URL
curl http://remote:9222/json/version

# Use with awzars (ws:// is unencrypted: prefer an SSH tunnel to localhost)
export CHROME_REMOTE_URL="ws://remote:9222/devtools/browser/xxx"
awzars login --allow-insecure-remote-chrome
```

## TUI Config Manager

`awzars tui` opens a full-screen terminal UI for managing both awzars and AWS config profiles.

### Tabs

| Tab | Content |
|-----|---------|
| **Tab 1: awzars** | Profiles from `<config-dir>/config.toml` — full CRUD |
| **Tab 2: AWS Config** | All profiles from `~/.aws/config` — full CRUD for awzars-linked, edit-only for others |

### AWS Config Profile Types

- **Base profiles** (`◆`): Have `credential_process` (awzars or other), or plain profiles with no auth chain. Shown cyan for awzars, white for others.
- **Assume-role profiles** (`↗`): Have `source_profile` + `role_arn`. Shown yellow with arrow to source profile. Form shows `source_profile`, `role_arn`, and `role_session_name` fields (no `credential_process`).

### Key Bindings

**Browse**: `↑/k` `↓/j` navigate, `a` add, `e`/`Enter` edit, `d` delete, `Tab`/`Shift+Tab` switch tabs, `q` quit
**Edit/Add**: `↑/↓`/`Tab` move between fields, `Enter` start/confirm field edit, `Esc` cancel, `Ctrl+S` save, `Ctrl+D` clear focused field
**Autocomplete**: `↑/↓` navigate suggestions, `Tab` accept — available for `credential_process` (awzars profile names) and `source_profile` (all non-assume-role AWS profile names, awzars-bound ones tagged `[awzars]`)

### Restrictions

- Non-awzars AWS profiles can be edited but not deleted
- `credential_process` and `source_profile` are mutually exclusive — setting one clears the other
- Assume-role profile form: Name, Region, Output, Source Profile, Role ARN, Role Session Name (no Credential Process)
- Base profile form: Name, Region, Output, Credential Process
- `source_profile` autocomplete shows all non-assume-role profiles (including those without `credential_process`, e.g. SSO, plain profiles)
- `role_session_name` is written to/read from the AWS config file as `role_session_name = <value>`

## SAML Flow

1. Build SAML AuthnRequest (DEFLATE + base64 encoded, XML-escaped app_id_uri)
2. Navigate to Azure AD login URL (tenant_id validated as UUID)
3. User authenticates (MFA supported)
4. Capture the SAMLResponse from the browser's HTTPS POST to an AWS sign-in host's `/saml` endpoint (`browser/saml_capture.rs`), before the AWS console receives it
5. **Shut down the browser** before any further processing: a graceful CDP close for a Chrome that awzars launched; with `CHROME_REMOTE_URL`, close only the page awzars opened and disconnect, leaving the remote Chrome running. This avoids spurious chromiumoxide WARN messages and prevents the AWS role-selection page from appearing live alongside the terminal TUI selector.
6. Parse roles from assertion, validate issuer/audience/recipient/time-window
7. Call STS AssumeRoleWithSAML (region resolved as profile `region` → AWS default chain → `us-east-1` fallback)
8. Cache credentials in memory and store in keychain
