# Security policy

awzars turns an Azure AD sign-in into AWS credentials.

## Supported versions

Only the latest release receives security fixes. Please upgrade before you report.

## Reporting a vulnerability

**Please don't open a public issue, discussion or pull request for a security problem.**

[Report a vulnerability](https://github.com/moyataka/awzars/security/advisories/new) privately through
GitHub's private vulnerability reporting (the "Report a vulnerability" button on the repository's
Security tab). Include:

- the affected version or commit
- what an attacker can do (impact), and what they need first (preconditions)
- steps to reproduce, with all real account IDs, tenant IDs, tokens and hostnames removed

We aim to acknowledge reports within 7 days and to agree a disclosure date with you once a fix is ready.

## What counts as a security issue

Report privately anything that could:

- expose credentials, tokens, SAML assertions, cookies or keys (on disk, in logs, in process lists or over the network)
- give a user credentials for a different role, account or tenant than the one they asked for
- bypass the profile password lock (including the scope of `unlock --allow-ai`) or the AI-agent consent gate
- let another local user or process read or replace awzars' stored secrets

The threat model and accepted residual risks are in [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md). Limits
documented there or in the [README](README.md#security) are not vulnerabilities. For example, the
AI-agent consent gate doesn't stop an agent that runs `unset CLAUDECODE` before it calls awzars.

Ordinary bugs (crashes, wrong messages, config handling) go in public issues; see [CONTRIBUTING.md](CONTRIBUTING.md).
If you're not sure, report privately. We'll move it to a public issue if it isn't sensitive.

## How we handle reports

1. We confirm the problem and rate it (low, medium, high or critical) by impact and preconditions.
2. **High and critical** issues stay private until a fixed release is out. The fix lands with a neutral description, and we publish an advisory after the release.
3. **Low and medium** issues may be moved to a public issue, described by impact only, without exploit steps.
4. We credit reporters in the advisory unless they prefer otherwise.
