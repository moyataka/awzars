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

# Alternative: cross (see Cross.toml)
cross build --release --target x86_64-unknown-linux-musl
```

## Release

GitHub releases use the naming convention `awzars-v{version}-{target}.tar.gz`.

```bash
# Package (example for x86_64 Linux musl)
cd target/x86_64-unknown-linux-musl/release
tar czf awzars-v1.0.1-x86_64-unknown-linux-musl.tar.gz awzars

# Upload to existing tag
gh release upload v1.0.1 /path/to/awzars-v1.0.1-x86_64-unknown-linux-musl.tar.gz
```

Current release targets:
- `x86_64-unknown-linux-musl` — built on Linux with `cargo zigbuild`
- `aarch64-apple-darwin` — built on macOS Apple Silicon

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

# Use with remote Chrome (for headless/CI)
CHROME_REMOTE_URL="ws://host:9222/devtools/browser/xxx" awzars login

# Clear cached credentials (prompts for confirmation; pass --yes to skip)
awzars clear-cache

# AWS CLI integration (~/.aws/config)
[profile work]
credential_process = /usr/local/bin/awzars credential-process --profile work
```

### credential-process

`credential-process` is designed for AWS CLI/SDK integration. It is always non-interactive:

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
│       ├── login.rs             # Pipeline: launch_browser → authenticate → shutdown browser → select_role → STS → persist
│       ├── configure.rs         # Interactive profile creation (validators on every prompt)
│       ├── list_roles.rs        # Browser-driven role listing (browser shut down after SAML extraction)
│       ├── credential_process.rs # AWS credential_process integration (auto-reauth via cookies)
│       ├── delete_profile.rs    # Drop a profile + all its persisted state
│       ├── set_password.rs      # Set / change / --remove the per-profile password lock
│       ├── unlock.rs            # Unlock a locked profile (or grant AI consent) for the session
│       ├── lock.rs              # Drop the session's unlock token
│       └── tui.rs               # TUI command entry point
│       # `clear-cache` is inline in main.rs (small enough not to warrant a module)
├── browser/
│   ├── chromium.rs              # chromiumoxide automation, cookie store, remote-Chrome connect
│   ├── cookie_crypto.rs         # ChaCha20-Poly1305 cookie encryption with versioned key rotation
│   └── selectors/               # Azure login page CSS selectors + versioning
├── auth/
│   ├── azure/
│   │   ├── saml.rs              # SAML assertion parsing, validation, role extraction
│   │   └── protocol.rs          # Pure SAML-build/extract/AWS-redirect helpers (no chromium dep)
│   ├── aws/sts.rs               # STS AssumeRoleWithSAML
│   ├── credentials/
│   │   └── pipeline.rs          # try_load_credentials: cache → keyring fallback (single source of truth)
│   └── lock.rs                  # Per-profile password lock + AI consent gate (Argon2id, getsid-scoped tokens)
├── storage/
│   ├── cache.rs                 # In-memory credential cache (per-profile)
│   └── keyring.rs               # OS keychain integration (single JSON entry per profile)
├── credential_process/
│   └── protocol.rs              # AWS credential_process output (Zeroizing<String> writers)
├── config/
│   ├── azure_config.rs          # AzureConfig (tenant_id, app_id_uri)
│   ├── profile.rs               # Profile + Config structs, atomic TOML I/O, 0o600 perms
│   └── cleanup.rs               # delete_awzars_profile: shared cleanup for CLI + TUI
├── tui/
│   ├── app.rs                   # ratatui role selector (mouse + search/filter)
│   ├── aws_config.rs            # AWS config INI parser + atomic writer, configurable path, role_session_name
│   ├── form.rs                  # ProfileForm + AwsProfileForm with autocomplete, visible-field indices
│   ├── form_ops.rs              # Pure FieldOp + key_to_field_op + move_index helpers
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

Global options: `--profile` (default: "default"), `-v`/`-vv`/`-vvv`, `--quiet`, `--config-dir` (env: `AWZARS_CONFIG_DIR`)

Login options: `--role-arn`, `--azure-tenant`, `--azure-app`, `--session-duration`, `--headless`, `--no-sandbox`, `--force-refresh`, `--output` (text/json/table), `--credential-process`, `--show-secrets`, `--remember-me`, `--allow-insecure-remote-chrome`, `--session-remember` (persist AI consent for the session; default re-prompts every call)

Configure options: `--azure-tenant`, `--azure-app`, `--role-arn`, `--session-duration`, `--non-interactive`

Clear-cache options: `--yes` (skip confirmation prompt).

Delete-profile options: `--yes` (skip confirmation prompt). Cleans up the awzars config entry, keyring credentials (incl. cookie key), in-memory cache, and the per-profile chromium dir. **Does not** modify `~/.aws/config` — AWS profiles still pointing at the deleted awzars profile are listed as a warning so they can be edited by hand.

Set-password options: `--remove` (clear the lock; still requires the old password). TTY-only; refuses if stdin is not a terminal so passwords can never be piped in. Argon2id PHC string lives in `~/.awzars/config.toml` under the profile entry. No minimum password length is enforced — typing speed is prioritized, with the dialoguer confirmation step (entered twice) as the only safety net against typos.

Unlock options: `--allow-ai` (permit AI agents in this session — `CLAUDECODE` / `AI_AGENT` env markers — to use the credentials), `--ttl-hours <N>` (override the default 8h; soft-capped at 24h, raise to the 720h / 30-day hard cap with `--allow-long-ttl`), `--allow-long-ttl` (opt-in for `--ttl-hours > 24`). For password-locked profiles the command prompts for the password; for unlocked profiles it only does anything when `--allow-ai` is passed (y/N consent). TTY-only.

Lock options: none. Idempotent: removes the current session's unlock token if any.

## Profile Locking (password lock + AI consent)

Opt-in per-profile gate that fences credential-producing operations (`login`, `credential-process`, `list-roles`) behind a session-scoped checkpoint. Designed so AI agents (Claude Code, Cursor, etc.) cannot autonomously invoke AWS commands without an explicit human checkpoint.

**Two protection levels** (independent — either, both, or neither apply per profile):

1. **Password lock**: enabled by `awzars set-password <profile>`. Stores an Argon2id PHC string in the profile entry. Every credential operation in a fresh terminal session prompts for the password (or refuses, if non-interactive — see below).
2. **AI consent**: applies whenever the environment contains a known AI marker (`CLAUDECODE` or `AI_AGENT` by default, configurable via the profile's `lock_ai_markers`). Even *unlocked* profiles refuse credential operations under AI until the user consents. Default is **ask every invocation** during interactive `login` / `list-roles` — every call gets its own y/N. Pass `--session-remember` (or run `awzars unlock <profile> --allow-ai` once) to persist the answer for the session. `credential-process` inherits the parent shell's TTY when invoked from an interactive shell, so it inline-prompts for the password under those conditions; AI markers still refuse the inline prompt and require an explicit prior `awzars unlock --allow-ai`.

**Session boundary** is the Linux session ID — but resolved by walking the ppid chain (`/proc/<pid>/stat` field 7) to the first ancestor with a controlling TTY, not by calling `getsid(0)` from the current process. The TTY-owning ancestor's SID is the user's interactive shell, which is what we want to share unlocks across. Tools that re-`setsid()` their subprocesses — Claude Code's Bash tool is the canonical case — would otherwise see a fresh SID with no controlling terminal and silo their unlock state away from the rest of the session. Falls back to raw `getsid(0)` on non-Linux, on `/proc` errors, or if no ancestor up to PID 1 has a controlling TTY (genuine daemon). Token is a JSON file at `$XDG_RUNTIME_DIR/awzars/sessions/<sid>-<profile>.json` (mode 0o600), auto-reaped on logout (tmpfs). Falls back to `~/.cache/awzars/sessions/` when XDG_RUNTIME_DIR is unset.

**TTL**: default 8 h. Override per-profile (`Profile.lock_ttl_hours`) or per-unlock (`--ttl-hours`, soft-capped at 24 h; pass `--allow-long-ttl` to extend up to the 720 h / 30-day hard ceiling). The profile-stored override is *not* gated — it is treated as a deliberate one-time edit; the per-call CLI ratchet is the one that needs an opt-in.

**Gate placement** (`crate::auth::lock::enforce(name, profile, allow_inline_prompt, persist_consent)`):

- `awzars login [--session-remember]`: TTY-attached. Locked profile + no AI: inline password prompt → token persists for TTL. Unlocked profile + AI: y/N consent every call by default; `--session-remember` writes a token after the first "yes". Locked profile + AI: refuse, user must run `awzars unlock --allow-ai`.
- `awzars credential-process`: inherits the parent shell's stdin. When stdin is a TTY (typical when invoked by AWS CLI from an interactive shell), inline-prompts for the password and writes a session unlock token on success. Refuses without prompting when stdin is not a TTY (CI / scripted callers) or AI markers are present.
- `awzars list-roles [--session-remember]`: same shape as `login`.

**Honest limit**: AI-marker detection stops *casual* leakage (you forgot you'd unlocked, then opened claude in the same shell). An adversarial AI that runs `unset CLAUDECODE` before invoking `aws` defeats it. For stronger protection, layer Claude Code's own `permissions` / `hooks` in `~/.claude/settings.json` — e.g. deny `awzars credential-process` outright or require per-call user approval. Awzars makes the casual path safe and the malicious path obvious; the AI tool's own policy layer is where to harden against the malicious case.

Schema additions on `Profile` (all `Option<_>`, omitted when unset): `lock_verifier` (Argon2id PHC), `lock_ttl_hours`, `lock_ai_markers`. The TUI form does not directly edit these fields, but on **add** of a brand-new awzars profile (Tab 1, `a`) the TUI offers a y/N modal "Set a password lock?" that suspends ratatui and runs the same dialoguer-driven flow as `awzars set-password`. On **edit** the form preserves existing lock state untouched. The CLI `awzars configure` mirrors this behavior — it asks the same y/N question after creating a new profile when stdin is a TTY.

## Key Dependencies

- **chromiumoxide** (0.9, rustls): Chrome DevTools Protocol for browser automation
- **aws-config / aws-sdk-sts** (`default-https-client` → `rustls-aws-lc`,
  rustls 0.23): STS AssumeRoleWithSAML. The legacy `rustls` feature flag
  (which pulled rustls 0.21 via `legacy-rustls-ring`) is deliberately not
  used; see the L-6 entry in `SECURITY_AUDIT.md`.
- **keyring** (3.x with `apple-native` / `windows-native` /
  `sync-secret-service` / `crypto-rust`): OS keychain storage. The published
  `keyring 4.0` is a CLI binary, not the library; the library line stays
  on 3.x until `keyring-core 1.0` settles.
- **ratatui** + **crossterm**: Terminal UI for role selection
- **tokio**: Async runtime
- **zeroize**: Secure memory cleanup for sensitive data (Drop-based)
- **thiserror**: Error type derive
- **dialoguer**: Interactive prompts (configure, remember-me prompt)
- **tempfile**: Ephemeral browser data directories (auto-cleaned on drop)
- **argon2**: Argon2id password hashing for the per-profile lock verifier
- **nix**: `getsid()` / `kill(sid, 0)` for session-scoped unlock tokens

## Security

- Config dir (`~/.awzars/`) permissions enforced to 0o700 (Unix) on every access — mitigates TOCTOU where adversary pre-creates dir with loose perms
- Config files written with mode 0o600 (Unix); `config.toml` size capped at 1 MiB on load to prevent OOM from a hostile or corrupted file
- Chromium data dir (`~/.awzars/chromium/<profile>/`) permissions enforced to 0o700
- Cookie store (`cookies.enc`) written with mode 0o600 — ChaCha20-Poly1305 AEAD with random nonce per encryption; format `[1 byte key_id][12 byte nonce][ciphertext+tag]`
- Cookie key rotation: 30-day rotation window, 90-day retention. Keystore is one OS-keyring item per profile (`{profile}:cookie_key`) holding a JSON `{current, keys, created_at}` blob — single keyring item means macOS Keychain ACL is granted once and rotation never re-prompts. Legacy single-key entries auto-migrate on first read.
- All atomic on-disk writes go through `util::atomic_write`, which (Unix) opens the temp file with `O_CREAT | O_EXCL | O_NOFOLLOW` after first unlinking any stale `<path>.tmp`, then `fchmod`s the open fd to the requested mode. This defeats same-UID symlink-planting on every persisted secret (`config.toml`, `cookies.enc`, unlock tokens, failure counters, `~/.aws/config`).
- `util::enforce_perms_no_symlink(path, mode)` wraps every directory- and file-perm tighten so a planted symlink at the leaf is rejected rather than silently traversed; applied at `ensure_config_dir` / `enforce_config_dir_perms` / the chromium data dir / the cookie store dir / `unlock_dir` / `Config::load`'s auto-tighten.
- `~/.aws/config` writer additionally rejects a symlinked parent `~/.aws/` (extra layer on top of the `atomic_write` hardening)
- Profile names validated at both CLI and library level (e.g. `chromium_data_dir()`) to prevent path traversal
- SAML assertion size capped at 256 KB before decode to prevent memory exhaustion (DoS)
- Sensitive data (SAML assertions, credentials, cookie keys) zeroized on drop via `zeroize`
- Panic hook (installed in `main.rs`) restores terminal state (raw mode, alternate screen, mouse capture, cursor) and wipes the in-process cookie key cache before the default handler runs — important because `panic = "abort"` (release profile) skips Drop impls
- TLS 1.2+ via rustls (no native-tls/OpenSSL)
- SAML assertions never written to disk
- SAML extraction gated on verified AWS URL (`signin.aws.amazon.com`); non-AWS pages never harvested
- Remote Chrome: `wss://` enforced by default; `ws://` only with `--allow-insecure-remote-chrome` + warning; session IDs redacted from logs; userinfo in URLs rejected
- XML-escaped `app_id_uri` in AuthnRequest to prevent injection
- Ephemeral `--user-data-dir` with `tempfile::TempDir` auto-cleanup (non-remember-me sessions)
- SAML client-side validation: issuer (URL-normalized), audience, Recipient, time window (30s skew), inverted-time-window rejection. **No XML-DSIG verification client-side** — integrity is delegated to TLS-to-Azure plus AWS STS re-verification in `AssumeRoleWithSAML`.
- Error messages redacted to avoid leaking tenant IDs, issuer URLs, or Recipient values
- 100% safe Rust (no `unsafe` blocks)
- CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`, `clippy -D warnings`, tests, `cargo deny check`, `cargo audit` on every PR

## Configuration

Stored in `~/.awzars/config.toml`. Top-level field `aws_config_path` (optional string) overrides the default `~/.aws/config` path used by the TUI. Chromium persistent sessions (from `--remember-me`) stored in `~/.awzars/chromium/<profile>/`.

## Cookie Store (Remote → Local Session Transfer)

When authenticating via remote Chrome (`CHROME_REMOTE_URL`) with `--remember-me`, session cookies are extracted and saved locally to `~/.awzars/chromium/<profile>/cookies.enc` (mode 0o600, ChaCha20-Poly1305 encrypted). This enables subsequent `credential-process` calls to silently re-authenticate using **local** headless Chrome — no remote Chrome needed after the initial login.

Flow:
1. `CHROME_REMOTE_URL=ws://... awzars login --remember-me` → authenticate via remote Chrome, cookies saved locally
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

When `CHROME_REMOTE_URL` is set, `--headless` controls whether the remote browser is expected to have a display (headless remote Chrome should also have been launched with `--headless`).

## Remote Chrome Setup

Set `CHROME_REMOTE_URL` to a Chrome DevTools Protocol WebSocket URL to delegate browser automation to a remote Chrome instance. The tool connects via WebSocket, navigates the login flow, and extracts the SAML response — credentials traverse this connection.

When used with `--remember-me`, session cookies are automatically extracted and saved locally so that subsequent `credential-process` calls can use local headless Chrome instead of requiring the remote instance.

Security:
- `wss://` is required by default (TLS-encrypted WebSocket)
- `ws://` (unencrypted) is rejected unless `--allow-insecure-remote-chrome` is passed
- `--allow-insecure-remote-chrome` prints a prominent warning about unencrypted credential exposure
- WebSocket session IDs are redacted from log output
- URLs with embedded userinfo (`user:pass@host`) are rejected

### Option 1: Chrome on macOS, awzars on Linux

On macOS, start Chrome with remote debugging:

```bash
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222 \
  --remote-debugging-address=0.0.0.0 \
  --user-data-dir="/tmp/chrome_dev_session"
```

SSH port forward from Linux to Mac:

```bash
# On Linux, forward local 9222 to Mac's 9222
ssh -R 9222:localhost:9222 user@mac-host -N
```

Or reverse (if Mac connects to Linux):

```bash
# On Mac, forward local 9222 to Linux's 9222
ssh -L 9222:localhost:9222 user@linux-host -N
```

Then on Linux:

```bash
export CHROME_REMOTE_URL="ws://localhost:9222/devtools/browser/xxx"
awzars login
```

### Option 2: Chrome on remote Linux

```bash
# On remote machine
chromium --remote-debugging-port=9222 --headless --no-sandbox

# Get WebSocket URL
curl http://remote:9222/json/version

# Use with awzars
export CHROME_REMOTE_URL="ws://remote:9222/devtools/browser/xxx"
awzars login
```

## TUI Config Manager

`awzars tui` opens a full-screen terminal UI for managing both awzars and AWS config profiles.

### Tabs

| Tab | Content |
|-----|---------|
| **Tab 1: awzars** | Profiles from `~/.awzars/config.toml` — full CRUD |
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
4. Extract SAMLResponse from verified AWS redirect page only
5. **Shut down the browser** (graceful CDP close before any further processing — avoids spurious chromiumoxide WARN messages and prevents the AWS role-selection page from appearing live alongside the terminal TUI selector)
6. Parse roles from assertion, validate issuer/audience/recipient/time-window
7. Call STS AssumeRoleWithSAML
8. Cache credentials in memory and store in keychain
