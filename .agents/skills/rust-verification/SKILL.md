---
name: rust-verification
description: "Evidence boundary. Use for verification-only work or deciding whether existing evidence supports a claim at its stated scope."
---

# Rust Verification

**Evidence boundary.** Bound every verification claim to the exact behavior whose failure the executed check would catch, naming that observable before running the command.

**Surface mapping.** Map each repository check to what it actually proves: `make check` (`cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked --all-targets`, `cargo test --locked --doc`) proves static formatting, lint conformance (`unsafe_code = "forbid"`), pure-core logic, `tempfile` fixture invariants, and built CLI tests (`tests/cli.rs`); `make template-check` proves pinned skill integrity, documentation link validity, and Python maintenance tests; `make verify` combines both; `make template-smoke` proves disposable consumer testing and `cargo package`; `make audit` checks `deny.toml`; and live macOS runs (`status --format json`, `flock` competitor tests, `git worktree` tests) prove host process/filesystem/lock interaction.

**Executed scope.** Count only executed, non-skipped checks that observe the claimed boundary—separating compilation, lockfile resolution, and `FakePlatform` unit runs from real macOS `lsof`/`flock`/`statvfs`/`tmutil`/`launchctl` proof, and separating local test passes from CI or unattended LaunchAgent behavior.
