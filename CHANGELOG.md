# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Login: when the profile's role is missing from the SAML assertion, warn and offer the role picker, then optionally save the choice (#33).
- Continuous integration: formatting on Linux, lints and tests on Linux and macOS, a static Linux build, and dependency checks (cargo-deny) (#36).
- Tag-driven release workflow: pushing a `v*` tag builds macOS and static Linux binaries with checksums and build provenance, as a draft release.

### Changed
- A missing role now reports the closest available roles and how to fix the profile, instead of `Principal not found` (#33).
- Dependencies refreshed and an unused browser-download feature removed.
- Documentation updated to match current behaviour (platform support, session unlock tokens, refresh lock, role fallback, remote Chrome).

## [1.0.4] - 2026-10-20

### Upgrade notes
- Run `awzars unlock` once per profile after upgrading. Session unlock tokens from earlier versions are no longer honoured.
- Azure overrides moved from the generic `AZURE_TENANT_ID` / `AZURE_APP_ID_URI` to `AWZARS_AZURE_TENANT_ID` / `AWZARS_AZURE_APP_ID_URI` (#10).

### Added
- `AWZARS_REFRESH_LOCK_TIMEOUT_SECS` sets how long a call waits for another awzars refresh of the same profile (default 60 s) (#23).
- Exit code `11`: session unlock is unavailable because the current boot session cannot be identified.

### Changed
- Azure overrides use `AWZARS_AZURE_TENANT_ID` / `AWZARS_AZURE_APP_ID_URI` (#10).
- Roles are listed in a stable order, by account and then by name (#18).
- Session unlock tokens are tied to the profile's current password lock and to the current boot, and are cleared in every session when the lock changes or the profile is deleted.

### Fixed
- `~/.aws/config` handling: commented section headers, preservation of non-profile sections, comments and unexposed keys, and rejection of name collisions (#1, #2, #3, #15, #16).
- TUI: saving an AWS profile applies only that change to the current `~/.aws/config`, keeping profiles and settings edited elsewhere while the TUI is open (#24); no panic when editing non-ASCII text (#7).
- Login: identity overrides no longer reuse cached credentials (#5); SAML role/provider pairs are accepted in either order (#6); the profile's `session_duration` is honoured (#9).
- Browser: SAML is captured before console submission (#8); remembered sessions are reused and renewed on local logins (#13).
- Credentials:
  - Refreshes are serialized across processes (#11) and happen before the SDK's advisory window (#12).
  - Short sessions (under 30 minutes) are reused from the cache (#22).
  - Concurrent calls no longer hang on the refresh lock, and prompts run outside it (#23).
- Keychain read errors are reported instead of being treated as a missing entry, so existing keys are kept.
- Unlock on macOS resolves the terminal's session like Linux does, so commands run in their own `setsid` session (e.g. by agent harnesses) match the terminal's unlock (#25).
- CLI: `-q/--quiet` is honoured (#17); inline AI consent requires an interactive stderr (#14).
- Docs: per-platform configuration paths (#19).

## [1.0.3] - 2026-06-17

### Added
- Unlock can be scoped to the Claude Code conversation (`CLAUDE_CODE_SESSION_ID`); `unlock --no-expire`.

### Fixed
- STS `AssumeRoleWithSAML` uses the profile region (#4).
- Chrome detection on macOS with a broken Homebrew Cask install.

[Unreleased]: https://github.com/moyataka/awzars/compare/v1.0.4...dev
[1.0.4]: https://github.com/moyataka/awzars/compare/v1.0.2...v1.0.4
