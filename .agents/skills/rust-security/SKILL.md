---
name: rust-security
description: "Attacker paths. Use when untrusted paths, symlinks, mount points, subprocess outputs, terminal escaping, privilege checks, or resource amplification affect safety."
---

# Rust Security

**Attacker paths.** Trace untrusted filesystem entries, Git metadata, and process outputs across every boundary to their enforcement point and observable effect, naming the protected invariant (e.g., never deleting source code, tracked Git files, symlink targets, cross-volume files, or non-Cargo data), the blast radius on bypass, and the negative test that proves fail-closed enforcement.

**Trust owners.** Extend the established fail-closed owners in `src/discover.rs`, `src/safety.rs`, `src/execute.rs`, `src/platform.rs`, and `src/error.rs` for root refusal (`uid == 0`), `CACHEDIR.TAG` / `HeuristicNoTag` top-level whitelisting, symlink/mount refusal, Git tracked-file checks, `O_NOFOLLOW` + `st_dev` fd-anchored deletion, and control-character escaping in `error::diagnostic()`.

**Trust boundaries and fail-closed checks.** Validate paths (`lossless` `Path`/`OsStr`, `follow_links(false)`), `/sbin/mount` records, `git ls-files` outputs, and `/usr/sbin/lsof -n -P -F0pcftn` NUL records at their owning boundary before trusting them downstream. Fail closed whenever `lsof`, `/sbin/mount`, `git` inside a Git repo, `statvfs`, or `File::try_lock()` produces missing, truncated, or ambiguous evidence—never treat probe failure as "safe to delete."

**Diagnostic safety and redaction.** Escape ANSI escapes and ASCII control bytes in untrusted paths or error messages via `error::diagnostic()` before printing to `stderr`, never leak arbitrary unrelated command arguments (`lsof` reads paths/FD types without `ps args`), and keep `--format json` free of raw control sequences.

**Resource amplification and proof.** Enforce explicit bounds on traversal depth (`max_depth`), visited entries (`max_entries`), walk duration (`15 s`), `.rustc_info.json` / `fingerprint/*.json` file sizes, subprocess stdout caps (`16 MiB` + `10 s` timeout + `killpg` cleanup), and `actions.jsonl` rotation (`2 MiB`), verifying negative bounds with concrete tests rather than relying on happy-path assertions.
