# Security Audit — `awzars`

| Field | Value |
|---|---|
| Last updated | 2026-05-05 |
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

Failed unlock attempts are tracked in `<unlock_dir>/<sid>-<profile>.fails`. A same-UID actor can delete that file and reset the escalating backoff.

Accepted because the backoff is anti-fat-finger pacing, not the real brute-force defense. Password resistance comes from Argon2id parameters, and an adversarial same-UID AI/process could also bypass marker detection by changing its environment.

### L-2 — Session start-time binding is Linux-only

`src/auth/lock.rs:289-305`, `src/auth/lock.rs:412-420`

Linux unlock tokens bind to `/proc/<sid>/stat` start time to reject stale tokens after SID reuse. Non-Linux hosts fall back to SID liveness only.

Accepted because SID reuse attacks are outside the AI-consent threat model. If this changes, implement macOS `proc_pidinfo` support.

### L-8 — Config loading follows `config.toml` symlinks

`src/config/profile.rs:83-125`, `src/config/mod.rs:56-90`

`Config::load()` opens `config.toml` with path-following `File::open`. The default config directory is tightened to `0o700`, so this is not a cross-UID issue, but a same-UID actor or user-controlled `--config-dir` can point awzars at another readable TOML file.

Accepted because local config is already trusted: a same-UID actor who can control it can directly change tenant ID, app ID URI, role ARN, and lock metadata. `config.toml` does not contain STS secrets, SAML assertions, browser cookies, or cookie encryption keys.

## Positive Controls

- AWS STS credentials are stored in the OS keyring and in process memory only.
- Browser cookies are stored as `cookies.enc` using ChaCha20-Poly1305 and keyring-backed versioned keys.
- SAML assertions are size-capped, namespace-scoped, issuer/audience/time/recipient checked, and wrapped in `Zeroizing<String>`.
- Remote Chrome requires `wss://` by default; `ws://` requires an explicit insecure flag.
- File writes use atomic temp-file replacement with `O_EXCL | O_NOFOLLOW`; AWS config writes reject symlinked targets.
- CLI parsers validate profile names, tenant UUIDs, role ARNs, session duration, and app ID URI shape.
- Panic handling wipes cached cookie keys and restores terminal state even with `panic = "abort"`.

## Caveats

- CI remains the authoritative source for live `cargo audit` and `cargo deny` advisory tracking.
- macOS Keychain and Windows Credential Manager behavior were not smoke-tested locally.
- Chromium and browser runtime exploitation are delegated to upstream Chromium.

*End of audit.*
