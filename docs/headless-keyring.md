# Headless / SSH Keyring Unlock (awzars on Linux + GNOME Keyring)

Notes on why `awzars login` fails to persist credentials over SSH, and how to
fix it. Specific to Linux boxes using the GNOME Keyring (Secret Service) as the
`keyring` backend.

## Symptom

```
Waiting for authentication...
WARN awzars::cli::commands::login: Failed to save cookies for local re-auth:
  Keyring error: ... Secret Service: unlock prompt was dismissed
Error: Keyring error: Failed to store credentials:
  ... Secret Service: unlock prompt was dismissed
```

## What actually happened

The Azure SAML auth **succeeded** — browser flow ran, STS returned credentials.
It died on the *last* step: persisting to the OS keyring.

- `perform_login` → `persist_credentials` writes the in-memory cache (fine) then
  the keyring (`src/cli/commands/login.rs:170-174`).
- The keyring write returns `Err`, which propagates with `?` out of
  `perform_login` (`login.rs:66`) → `execute` (`login.rs:252`) **before** the
  credentials are ever printed (output is at `login.rs:262`).
- The in-memory cache dies with the process, so **the freshly-minted (MFA'd)
  credentials are discarded** — nothing survives.

## Root cause

The GNOME login keyring collection is **locked**, and a headless session has no
graphical prompter to answer the unlock dialog, so every Secret Service write
comes back as "unlock prompt was dismissed."

Confirm:

```bash
busctl --user call org.freedesktop.secrets \
  /org/freedesktop/secrets/collection/login \
  org.freedesktop.DBus.Properties Get ss \
  org.freedesktop.Secret.Collection Locked
# v b true   → locked (the problem)
# v b false  → unlocked (good)
```

## Why it worked before (desktop) but not over SSH

- At **desktop login**, GDM's PAM stack runs `pam_gnome_keyring.so`, which
  unlocks the login keyring automatically using the password you typed at the
  login screen. awzars then writes to an already-unlocked keyring.
- That unlocked state lives **in the keyring daemon's memory**, not on disk. It
  dies on logout/reboot and is **not** shared with a fresh, dbus-activated
  daemon spawned by an SSH session.
- This box authenticates SSH with a **public key** (`Accepted publickey` in the
  journal), so PAM never sees a password → it cannot auto-unlock the keyring on
  SSH login. Hence: works right after a desktop session, broken on pure SSH.

## Fix options

### 1. Unlock per SSH session (keeps the keyring encrypted)

Run in your terminal. The `printf` **pipe** matters: with `--daemonize`, a
password typed interactively races the fork and never reaches the daemon;
piping guarantees delivery. The keyring password is your **account/login
password** (that's what the desktop set it to).

```fish
read -s -P 'login password: ' PW
printf '%s' "$PW" | gnome-keyring-daemon --replace --daemonize --components=secrets --unlock
set -e PW
busctl --user call org.freedesktop.secrets /org/freedesktop/secrets/collection/login \
  org.freedesktop.DBus.Properties Get ss org.freedesktop.Secret.Collection Locked
```

Want `v b false`, then re-run `awzars login`. This lasts as long as that daemon
lives — redo after a reboot. Can be wrapped in a fish function for convenience.

> Note: `--unlock` only *opens* the keyring if the password matches; it does
> **not** set/change the password. If this stays `v b true`, the current keyring
> password isn't your login password (e.g. the system password was changed
> later) — go to option 2.

### 2. Empty-password keyring (no manual step, ever)

Recreate the login keyring with **no** password → gnome-keyring auto-unlocks it
at every daemon start, on desktop and over SSH, with no prompt.

```fish
pkill -u $USER gnome-keyring-daemon
rm -f ~/.local/share/keyrings/login.keyring
printf '' | gnome-keyring-daemon --replace --daemonize --components=secrets --unlock
```

- ⚠️ Deleting `login.keyring` **wipes every secret in it**, not just awzars'.
  On a single-user headless box where nothing else uses it, no real loss (just
  re-login to awzars).
- Trade-off: secrets sit **unencrypted at rest** under your UID. This only
  weakens you against *offline disk/backup theft* — anyone with shell access as
  you could run `awzars` anyway. Same posture as the AWS CLI's own plaintext STS
  cache (`~/.aws/cli/cache/`, `~/.aws/sso/cache/`).

### 3. File fallback in awzars (code change — not yet implemented)

Make the keyring the preferred store, fall back to a `0600` file in `~/.awzars/`
when the keyring errors, and read from both on load. Drops the keyring
dependency for the credential path entirely; existing keyring users unaffected.
(The cookie store still encrypts with a keyring-held key, so fully keyring-free
`--remember-me` headless re-auth would need the same fallback there.) Same
security posture as option 2.

Worth pairing with: make keyring-store failure in the `login` path **non-fatal**
— print the credentials and `warn!` with an actionable message instead of
discarding them with a raw `?`.

## Keyring password vs. desktop UI — the rules

Two separate things, easy to conflate:

- **Account login** (desktop / sudo) uses your *account* password. Changing the
  keyring password **never** affects this — you can always log in.
- **Keyring auto-unlock** at desktop login only happens silently when the
  **keyring password == your account login password** (PAM reuses the password
  you typed at the login screen).

| Keyring password | Desktop UI | SSH |
|---|---|---|
| **= login password** (default) | logs in + auto-unlocks silently ✅ | type it to unlock each session |
| **any other password** | logs in fine, but an "unlock keyring" popup every session ⚠️ | type that other password |
| **empty** | logs in + auto-unlocks silently, no popup ✅ | auto-unlocks, no typing ✅ (no encryption at rest) |

Setting an *arbitrary third* password is the worst choice — you'd type it on
**both** the desktop popup and SSH.

## Recommendation

- Want encryption at rest, occasional typing is fine → **option 1** (unlock per
  SSH session with your login password).
- Want zero friction on a single-user headless box → **option 2** (empty
  keyring) or **option 3** (file fallback in awzars).
- Don't set an arbitrary keyring password — it gives you the worst of both.
