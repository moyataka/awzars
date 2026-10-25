# Contributing to awzars

Thanks for helping. awzars handles cloud credentials, so we keep changes small and well tested, and we review them.

## Before you start

- **Found a bug?** Open an issue first, even if you plan to fix it yourself. Describe the impact and how to reproduce it.
  Leave out account IDs, tenant IDs, profile names, emails and hostnames from your environment.
  **Exception:** if it is a security issue, don't open a public issue, discussion or pull request. Contact a maintainer privately first.
- **Want a feature or a behaviour change?** Open an issue to discuss it before writing code.
- **Adding a dependency** (a new crate or a new crate feature) needs a maintainer's agreement in the issue first.

## Labels

Each issue and pull request gets one type label and any extra labels that apply. Maintainers set them if you can't.

| Label | Use for |
|---|---|
| `bug` | behaviour that is wrong compared with the docs or reasonable expectation, failing checks, a vulnerable dependency |
| `enhancement` | a new option, behaviour or feature |
| `documentation` | docs and user-facing messages only |
| `dependencies` | dependency version updates (Dependabot adds it automatically) |
| `security` | publicly known security-relevant items, such as published advisories. Report undisclosed problems privately, never in a public issue. |

## Branches and pull requests

- Branch from `dev` and open your pull request against `dev`. `main` only receives release merges from maintainers.
- One fix or feature per pull request. Reference its issue (`Fixes #123`).
- Keep the change focused. Don't reformat, rename or refactor code your change doesn't need; send that separately if it's worth doing.
- Match the style and structure of the surrounding code.

## What every pull request needs

1. **A regression test** for a bug fix: it must fail without your fix and pass with it. New behaviour needs tests too.
2. **A CHANGELOG line** under `## [Unreleased]` in `CHANGELOG.md` ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/) style).
3. **Green checks.** Run these locally before you push. CI runs clippy and the tests on Linux and macOS, and `cargo fmt` and `cargo deny` on Linux:

   ```bash
   cargo fmt --all --check
   cargo clippy --all-targets --locked -- -D warnings
   cargo test --all-targets --locked
   cargo deny --locked check
   ```

   Rust 1.91.1 or newer is required with the committed `Cargo.lock`. `cargo deny` needs [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) installed.
4. **No secrets or personal data** in code, tests, fixtures, commit messages or the PR description. Use documentation placeholders such as `123456789012` and `example.com`.

## Testing safely

- Never run tests or the TUI against your real `~/.aws/config`. Point awzars at a copy with `aws_config_path` in its `config.toml`, and use a throwaway `--config-dir` (it must be an absolute path).
- Don't paste real credentials, SAML assertions or tokens into issues or logs. If you need to show output, redact it.

## Reviews and merging

- A maintainer reviews every pull request. Expect questions about edge cases and failure modes.
- Pull requests are merged into `dev` once checks pass and review is done.
- Maintainers cut releases from `main` by pushing a `vX.Y.Z` tag; see [How releases are built](README.md#how-releases-are-built).

## Licence

By contributing you agree that your contribution is licensed under the same terms as the project.
