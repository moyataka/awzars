# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Azure overrides now use `AWZARS_AZURE_TENANT_ID` / `AWZARS_AZURE_APP_ID_URI` instead of the generic `AZURE_*` variables (#10).
- Roles are listed in a stable order, by account and then by name (#18).

### Fixed
- Unlock on macOS now resolves the terminal's session like Linux does, so commands run in their own `setsid` session (e.g. by agent harnesses) match the terminal's unlock (#25).
- `~/.aws/config` handling: commented section headers, preservation of non-profile sections, comments and unexposed keys, and rejection of name collisions (#1, #2, #3, #15, #16).
- Login: identity overrides no longer reuse cached credentials (#5); SAML role/provider pairs are accepted in either order (#6); the profile's `session_duration` is honoured (#9).
- Browser: SAML is captured before console submission (#8); remembered sessions are reused and renewed on local logins (#13).
- Credentials: refreshes are serialized across processes (#11) and happen before the SDK's advisory window (#12).
- TUI: no panic when editing non-ASCII text (#7).
- TUI: saving an AWS profile applies only that change to the current ~/.aws/config, keeping profiles and settings edited elsewhere while the TUI is open (#24).
- CLI: `-q/--quiet` is honoured (#17); inline AI consent requires an interactive stderr (#14).
- Docs: per-platform configuration paths (#19).
- Credentials from short sessions (under 30 minutes) are reused from the cache instead of re-running the browser login on every call (#22).
- Keychain read errors are reported instead of being treated as a missing entry, so existing keys are kept.
- Concurrent `credential-process`/`login` calls no longer hang indefinitely on the profile refresh lock: prompts run outside the lock and waiters give up after 60 s (configurable with `AWZARS_REFRESH_LOCK_TIMEOUT_SECS`) with a clear message (#23).
- Session unlock tokens are tied to the profile's current password lock and to the current boot, and are cleared in every session when the lock changes or the profile is deleted. Run `awzars unlock` once after upgrading.

## [1.0.3] - 2026-06-17

### Added
- Unlock can be scoped to the Claude Code conversation (`CLAUDE_CODE_SESSION_ID`); `unlock --no-expire`.

### Fixed
- STS `AssumeRoleWithSAML` uses the profile region (#4).
- Chrome detection on macOS with a broken Homebrew Cask install.
