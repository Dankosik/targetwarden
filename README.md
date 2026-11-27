# targetwarden

Automatic safe Cargo `target/` disk reclaimer for macOS workstations running parallel AI coding agents and `git worktree`s.

[Specification](specs/targetwarden/README.md) · [Empirical Research](specs/targetwarden/research.md) · [Implementation Plan](specs/targetwarden/plan.md) · [Architecture](docs/architecture.md)

> **Status:** Stages 1–4 (`T1–T14`) implemented and verified on macOS (`status`, `scan`, `reclaim`, `watch`, `pin`, `unpin`, `history`, `install`, `uninstall`, `completions`). Next: 48-hour `watch --dry-run` field soak (`T15`) and `v0.1.0` release packaging (`T16`).

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
