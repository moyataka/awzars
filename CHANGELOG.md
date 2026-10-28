# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- The declared licence is now `MIT`, matching the `LICENSE` file. Earlier metadata also listed Apache-2.0, but no Apache-2.0 text was included (#61).
- Security reports now go through GitHub private vulnerability reporting, described in the new `SECURITY.md`. The issue forms and `CONTRIBUTING.md` link to it (#86).

### Fixed
- Unit tests always use an in-memory keychain, so `cargo test` never creates, reads or deletes entries in the developer's OS keychain, whatever the test order (#68).

## [1.0.5] - 2026-10-26

### Upgrade notes
- Each profile signs in once after upgrading. Stored credentials from earlier versions don't record which role and tenant they were issued for, so they are no longer reused (#41). With a remembered browser session this happens silently.
- If `AWS_CONFIG_FILE` is set, `awzars tui` and the `delete-profile` orphan check now use that file, as the AWS CLI does. `aws_config_path` in awzars' `config.toml` still takes precedence (#47).
- `awzars clear-cache` keeps the remembered browser session. Use `awzars delete-profile` to remove it (#43).
- Each TUI save that changes the AWS config file first writes `<config>.bak.<UTC timestamp>` next to it, with the newest 10 kept (#40).
- An existing AWS config directory's permissions are no longer changed when the TUI saves (#45).
- `awzars login --credential-process` with no role configured and several roles available now exits with an error instead of opening the role picker. Set the role with `--role-arn` or `awzars configure` (#44).

### Added
- Login: when the profile's role is missing from the SAML assertion, warn and offer the role picker, then optionally save the choice (#33).
- Continuous integration: formatting on Linux, lints and tests on Linux and macOS, a static Linux build, and dependency checks (cargo-deny) (#36).
- Tag-driven release workflow: pushing a `v*` tag builds macOS and static Linux binaries with checksums and build provenance, as a draft release (#37).
- Contributor guide, `CONTRIBUTING.md` (#56).
- Issue forms and a pull request template (#57).

### Changed
- A missing role now reports the closest available roles and how to fix the profile, instead of `Principal not found` (#33).
- Dependencies refreshed and an unused browser-download feature removed (#35).
- Documentation updated to match current behaviour (platform support, session unlock tokens, refresh lock, role fallback, remote Chrome) (#38).
- `clear-cache` now keeps the remembered browser session; use `delete-profile` to remove it (#43).

### Fixed
- `configure` now keeps a profile's other settings when updating an existing profile.
- Headless sign-in with a saved browser session that cannot be decrypted now fails at once and says to run `awzars login --remember-me`, instead of waiting for the timeout (#46).
- TUI: saving an AWS profile now first copies the previous AWS config to `<config>.bak.<UTC timestamp>` (mode 0600, newest 10 kept) and aborts the save if that copy fails (#40).
- TUI: saving no longer changes the permissions of an existing AWS config directory (only a directory it creates is set to 0700), and an `aws_config_path` that is a bare file name now saves instead of failing (#45, #51).
- The TUI and the profile-deletion orphan check now honour `AWS_CONFIG_FILE` when `aws_config_path` is not set, like the AWS CLI (#47).
- `aws_config_path` and `AWS_CONFIG_FILE` expand a leading `~/` (#60).
- Stored credentials are reused only for the tenant, app and role they were issued for; a profile whose identity changed re-authenticates (#41).
- `login --credential-process` with no configured role and several roles available now fails with guidance instead of opening the role picker on stdout (#44).
- STS failures that never reached the service (DNS, TLS, proxy, timeout) now show their cause instead of `AssumeRoleWithSAML failed: Unknown` (#42).
- Login output no longer shows repeated `WS Invalid message` warnings from the browser connection (#48).

### Security
- The debug log of a failed STS call no longer includes the raw response (#66).
- Dependencies updated for RustSec advisories RUSTSEC-2026-0381, -0382, -0385 and -0386 (#39).

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

[Unreleased]: https://github.com/moyataka/awzars/compare/v1.0.5...dev
[1.0.5]: https://github.com/moyataka/awzars/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/moyataka/awzars/compare/v1.0.2...v1.0.4
