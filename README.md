<p align="center">
  <img src="https://raw.githubusercontent.com/Dankosik/targetwarden/main/.github/assets/logo.png" alt="targetwarden logo" width="180" />
</p>

<h1 align="center">targetwarden</h1>

<p align="center">
  <strong>Automatic safe Cargo <code>target/</code> disk reclaimer for macOS workstations running parallel AI coding agents and <code>git worktree</code>s.</strong>
</p>

<p align="center">
  <a href="https://github.com/Dankosik/targetwarden/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Dankosik/targetwarden/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/Dankosik/targetwarden/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/Dankosik/targetwarden?sort=semver"></a>
  <a href="#install"><img alt="Platform: macOS" src="https://img.shields.io/badge/platform-macOS-lightgrey"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

<p align="center">
  <a href="specs/targetwarden/README.md">Specification</a> ·
  <a href="specs/targetwarden/research.md">Empirical Research</a> ·
  <a href="specs/targetwarden/plan.md">Implementation Plan</a> ·
  <a href="docs/architecture.md">Architecture</a>
</p>

> **Status:** `v0.1.0` ready for macOS (`aarch64-apple-darwin` and `x86_64-apple-darwin`) — `status`, `scan`, `reclaim`, `watch`, `pin`, `unpin`, `history`, `install`, `uninstall`, and `completions`.

## Install

```sh
curl -fsSL https://github.com/Dankosik/targetwarden/releases/latest/download/install.sh | sh
```

Requires macOS (Apple Silicon or Intel). After installing, check your workspace with `targetwarden status`, run a one-shot sweep with `targetwarden reclaim --profile sweep-only`, or install the background LaunchAgent with `targetwarden install` (or `targetwarden install --watch-dry-run` for observation first).

## What `targetwarden` solves

On workstations running parallel AI agents (`Antigravity`, `Codex`, `Claude Code`, `OpenCode`) across dozens of `git worktree`s, Cargo `target/` directories grow to tens of gigabytes even with `sccache` and `debug = "line-tables-only"`. Real captures on macOS showed ~83 GiB inside a single active `target/debug/` split across stale `build/` unit hashes and abandoned `incremental/` sessions while final binaries took ~520 MiB.

`targetwarden` combines two safety-first layers instead of blind `cargo clean`:

1. **Surgical intra-target sweep (`R2` + `R3`):** builds an exact dependency reachability graph from `fingerprint/*.json` (supporting `BuildDirV2` in Cargo `1.100+`, `LegacyV1` in `1.98`–`1.99`, and `MixedV1V2` profiles) and prunes two-level `incremental/` sessions (`Finalized` vs orphaned `Working`), preserving hot caches without touching active builds.
2. **Pressure-aware target eviction (`R1`, `R4`, `R5`):** evicts dead/merged worktree targets and cooled worktrees under an APFS GiB hysteresis state machine (`Calm` / `Elevated` / `High` / `Critical`) with a `ReclaimHoldState` circuit breaker for macOS local APFS snapshots (`tmutil`).

## CLI interface

```sh
targetwarden status [--format text|json]
targetwarden scan [PATH...] [--format text|json]
targetwarden reclaim [--dry-run] [--profile sweep-only|full] [--ignore-snapshot-hold] [--format text|json]
targetwarden watch [--dry-run]
targetwarden pin <PATH> [--allow-sweep] [--note TEXT]
targetwarden unpin <PATH>
targetwarden history [--limit 20] [--format text|json]
targetwarden install [--dry-run] [--watch-dry-run]
targetwarden uninstall
targetwarden completions <bash|zsh|fish>
```

Global flags: `--format <text|json>` (`TARGETWARDEN_FORMAT`), `--config <PATH>` (`TARGETWARDEN_CONFIG`), `--root <PATH>`.

## Build and verify

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
make verify
make template-smoke
```

Requires Rust `1.98.1` (`rust-toolchain.toml`, edition `2024`, `unsafe_code = "forbid"`). See [Contributing](CONTRIBUTING.md) and [Security](SECURITY.md).

## Origin and license

Initialized from the [Dankosik/rust-cli-template](https://github.com/Dankosik/rust-cli-template) structure and [Dankosik/rust-cli-skills](https://github.com/Dankosik/rust-cli-skills) engineering standards.

[MIT license](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md)
