# Security policy

Security fixes target the current `main` branch and the latest release. There
is no promised backport or response-time commitment.

## Reporting a vulnerability

Use **Security → Advisories → Report a vulnerability** on this repository when
GitHub private vulnerability reporting is enabled. Include the affected commit
or version, platform, reproduction steps, expected trust boundary, and observed
impact. Use synthetic inputs and redact credentials or personal data.

If private reporting is unavailable, open an issue requesting a private
reporting channel without exploit details, secrets, or sensitive attachments.
Do not publish an exploit in a normal bug report while seeking that channel.

## Scope

Relevant issues include unsafe handling of untrusted input or paths, unintended
file or subprocess effects, secret disclosure, memory-safety defects, and release
or dependency supply-chain problems. A crash, resource spike, or confusing error
may be a regular bug; describe the input and impact so it can be assessed.

targetwarden has no hosted service or production credentials to test. It
only deletes verified Cargo build-cache paths under user-owned directories
and runs `lsof` / `git` / `tmutil` / `statvfs` read-only for the current user; a
way to make it delete source files, tracked files, symlinks targets, or paths
outside Cargo `target/` is in scope. Do not scan third-party systems or include
their private data in a reproduction.
