# Changelog

Notable changes to targetwarden. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). The release workflow publishes the
section of the tagged version as its release notes.

## [Unreleased]

## [0.1.0] - 2026-11-27

### Added

- Read-only discovery and status commands (`status`, `scan`) with GiB tables
  and `schema_version = 1` JSON output across `BuildDirV2` (Cargo `1.100+`),
  `LegacyV1` (`1.98`–`1.99`), `MixedV1V2`, and `ArtifactsOnly` layouts.
- Surgical intra-target sweep (`R2` build-unit BFS reachability graph, stale
  `target/doc/` pruning, orphaned V1 `deps/`/`build/` cleanup, empty V2
  package directory cleanup, and two-level `R3` `incremental/` pruning) that
  preserves hot caches and active builds.
- Disk-pressure-aware full target eviction (`R1` merged/dead linked worktrees,
  `R4` cooled linked worktrees, `R5` pressure LRU with APFS GiB hysteresis and
  `ReclaimHoldState` local-snapshot circuit breaker).
- Six fail-closed safety barriers (`O_RDONLY` `File::try_lock()`, bounded NUL
  `lsof -n -P -F0pcftn` with `rust-analyzer-proc-macro-srv` `.dylib`
  auto-pinning, `/sbin/mount` and symlink validation, local Git inspection,
  nested `--target-dir` protection propagation, `pin`/`unpin`/`.targetwarden-pin`,
  and TOCTOU-safe staging rename + `rustix` fd-anchored safe removal with crash
  recovery).
- Adaptive background daemon (`watch`), graceful `SIGTERM`/`SIGINT` self-pipe
  shutdown, rotating `actions.jsonl` history (`history`), shell completions
  (`completions`), and macOS LaunchAgent management (`install [--dry-run] [--watch-dry-run]`,
  `uninstall`).
- Native macOS release archives (`aarch64-apple-darwin`, `x86_64-apple-darwin`),
  `SHA256SUMS`, build provenance attestations, and `install.sh`.

[Unreleased]: https://github.com/Dankosik/targetwarden/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Dankosik/targetwarden/releases/tag/v0.1.0
