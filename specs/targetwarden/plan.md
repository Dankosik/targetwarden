# `targetwarden`: Implementation Plan

Date: `2026-11-27`. Sources: [specification](README.md), [empirical research](research.md), and [architecture](../../docs/architecture.md).

Work proceeds in reviewable vertical slices (`Stages 0–4`). Every stage ends with `make verify` passing (`cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked --all-targets`, `cargo test --locked --doc`, `make template-check`).

## Stages & Tasks

### Stage 0 — Repository Scaffold & Contracts (Done)

| Task | Scope | Done when |
| --- | --- | --- |
| T0 | Repository init, [specification](README.md), [research](research.md), [plan](plan.md), [architecture](../../docs/architecture.md), `Cargo.toml` blueprint, `deny.toml`, 17-file `src/` skeleton, Stage 0 `cli.rs` + `tests/cli.rs` | `make verify` and `make template-smoke` pass; clean initial commit on `main` |

### Stage 1 — Read-Only Core (`status`, `scan`)

| Task | Scope | Depends | Done when |
| --- | --- | --- | --- |
| T1 | `model.rs`, `config.rs`, `state.rs`, `pressure.rs`: full domain types, optional `config.toml`, `DiskPressure` GiB hysteresis + 4-condition `ReclaimHoldState` reset | T0 | Pure-core unit tests cover every pressure transition, hold reset, and config precedence |
| T2 | `platform.rs`: `trait Platform`, `rustix::fs::statvfs`, `tmutil`, bounded subprocess runner, strict NUL `lsof -F0pcftn` parser, `/sbin/mount` parser, `run_git`, `O_RDONLY` `File::try_lock()`, `NoPlatform` non-macOS stub | T1 | Recorded `lsof`/`mount`/`tmutil` fixture tests pass (including `\xHH`, 31B `comm`, `NOFD`, `PIPE\|NPOLICY\|NEXUS`) |
| T3 | `discover.rs`: budgeted walk (`max_depth`, `max_entries`, `15s`, non-Rust `.git` `+2` cutoff), `VerifiedCargoTag` vs `HeuristicNoTag` whitelist, 4 layout classifiers (`BuildDirV2`, `LegacyV1`, `MixedV1V2`, `ArtifactsOnly`), `fingerprint/*.json` parsing, `st_blocks` hardlink dedup, nested targets | T2 | `tempfile` fixture tests cover all 4 layouts, false `CACHEDIR.TAG`, `verification.log` refusal, symlinks, mounts, and Git tracked files |
| T4 | `safety.rs`: 6-barrier evaluator (Hard vs Soft blocks, `rust-analyzer-proc-macro-srv` `.dylib` auto-pin, nested target propagation, strict `mtime`-only cooling, fail-closed errors) | T1 | Pure-core matrix tests verify every `ProtectedReason` and `SweepOnlyReason` |
| T5 | `report.rs` + `lib.rs`: `status` and `scan` text (GiB) & `schema_version = 1` JSON; live `rust-analyzer` `lsof` check + `~/Projects` latency run | T3, T4 | Live `targetwarden status --format json` runs in `< 2 s` on host without modifying any target; `make check` green |

### Stage 2 — Surgical Sweeper (`reclaim --profile sweep-only`, `history`)

| Task | Scope | Depends | Done when |
| --- | --- | --- | --- |
| T6 | `sweep.rs`: V2/V1 independent reachability graphs (`dep[3]` BFS, multi-JSON anchors, active `rustc_hash`, `MixedV1V2` stale layer expiry, `Incomplete` units, `target/doc/`), 2-level `R3` `incremental/` (`Finalized` vs `WorkingOnly`) | T1 | Unit tests prove 5-day live dependencies survive, `WorkingOnly` never evicts `Finalized`, and stale `rustc_hash` sweeps cleanly |
| T7 | `rules.rs` (sweep slice) + `store.rs`: `R2`/`R3` planning, `run.lock` single-instance coordination, `FileStamp` `StateCache`, atomic `state.json`, rotating `actions.jsonl` | T4, T6 | Unit + `tempfile` tests verify `StateCache`, log rotation at `2 MiB`, and `run.lock` contention |
| T8 | `execute.rs`: sorted lock acquisition, post-lock TOCTOU revalidation, V1 `.fingerprint/`-first staging rename, immediate unlock, `rustix` fd-anchored `remove_tree_safe`, dual staging crash recovery | T2, T7 | Real macOS tests with live `File::try_lock()` competitor (`.cargo-build-lock`, `doc/.lock`, `s-*.lock`), V1 partial rename, symlink safety, and dual staging cleanup |
| T9 | `lib.rs` + `tests/cli.rs`: `reclaim --dry-run` / `--profile sweep-only`, `history`, exit codes `0`/`1`/`2`/`3` | T5, T8 | Dry-run audit on live host projects + real sweep on a disposable target copy confirming subsequent `cargo check` has `recompiled = []` |

### Stage 3 — Full Eviction, Pins & Pressure (`R1`, `R4`, `R5`, `pin`, `unpin`)

| Task | Scope | Depends | Done when |
| --- | --- | --- | --- |
| T10 | `rules.rs`: `R1` (`dead-worktree-target`), `R4` (`cooled-worktree-target`), `R5` (`pressure-lru-evict` headroom stop), `ReclaimHoldState` trigger & reset wiring | T7 | Unit tests cover priority ordering, headroom stop, and APFS hold trip/reset |
| T11 | `pin` / `unpin` commands + `.targetwarden-pin` marker handling; `EvictTarget` parent+nested lock acquisition & post-lock `lsof` check | T8, T10 | Live `git worktree` integration tests cover `merged`, `unmerged`, `dirty`, `locked`, tracked file in `target/`, missing worktree, and `index.lock` |
| T12 | Full `reclaim` integration tests (`assert_cmd`, `PARTIAL = 3`, `BrokenPipe` = `0`) | T9, T11 | `make verify` green |

### Stage 4 — Watch Daemon, LaunchAgent & Field Rollout

| Task | Scope | Depends | Done when |
| --- | --- | --- | --- |
| T13 | `lib.rs` + `platform.rs`: bare-`watch` fast-path, `180 s` / `60 s` adaptive loop, `10 min` full-walk cache, `signal-hook` self-pipe + `rustix::event::poll` graceful `SIGTERM`/`SIGINT` shutdown | T12 | Two-pass fixture test + live `SIGTERM` shutdown completes atomic step and flushes state cleanly |
| T14 | `install.rs`: `render_plist(exe, home)` (`io.github.dankosik.targetwarden`, `Nice = 10`, no `ProcessType=Background`/`LowPriorityIO`) + `install`/`uninstall` over `&impl Platform` | T2, T13 | Unit tests verify XML escaping and `FakePlatform` `launchctl` sequence |
| T15 | 48-hour `watch --dry-run` field soak on host; audit `actions.jsonl` and daemon RSS | T14 | Zero false positives across active AI agents and worktrees |
| T16 | `install.sh` + `scripts/tests/test_install.py` + `CHANGELOG.md` release prep (`v0.1.0`) | T15 | `make verify`, `make template-smoke`, and local release archive smoke test pass |
