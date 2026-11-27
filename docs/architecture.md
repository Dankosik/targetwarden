# Architecture

`targetwarden` is one synchronous macOS CLI and LaunchAgent daemon structured
around **Functional Core / Imperative Shell** with **deep modules and narrow
interfaces**. There is no async runtime, SQLite database, FSEvents watcher, or
plugin registry, and the crate enforces `#![forbid(unsafe_code)]` via Cargo
lints (`unsafe_code = "forbid"`).

The [specification](../specs/targetwarden/README.md) owns behavioral rules, the
safety contract, and data-model invariants; the [research](../specs/targetwarden/research.md)
captures empirical measurements (`R1`–`R5`) on macOS `26.4` with Cargo `1.98.1`,
`1.99.0`, and `1.100.0`; the [implementation plan](../specs/targetwarden/plan.md)
tracks vertical-slice delivery across Stages 0–4.

## Responsibility boundaries (17 files in `src/`)

| File | Layer | Owns |
| --- | --- | --- |
| `src/main.rs` | Root | Thin executable entry point calling `targetwarden::run()` |
| `src/lib.rs` | Root | CLI dispatch, bare-`watch` fast-path, `run.lock`, `watch` loop with `SIGTERM`/`SIGINT`, exit codes `0`/`1`/`2`/`3` |
| `src/cli.rs` | Root | `clap` command grammar, global flags (`--format`, `--config`, `--root`), help, and shell completions |
| `src/error.rs` | Leaf | Typed `AppError` (`thiserror`), `BrokenPipe` handling, control-character escaping in `diagnostic()` |
| `src/model.rs` | Core | Zero-I/O domain types making invalid states unrepresentable (`CargoTarget`, `ProfileDir`, `BuildUnit`, `IncrementalDir`, `SafetyVerdict`, `ReclaimPlan`, `ReclaimAction`, `ActionReceipt`) |
| `src/config.rs` | Core | Built-in zero-config defaults plus optional `~/.config/targetwarden/config.toml` parsing and validation |
| `src/state.rs` | Core | Persistent `State` (`KnownTargetEntry`, `PinEntry`, `ReclaimHoldState`, `DiskPressure`) and pure transitions |
| `src/pressure.rs` | Core | APFS GiB hysteresis state machine (`Calm`/`Elevated`/`High`/`Critical`) and 4-condition `ReclaimHoldState` reset logic |
| `src/safety.rs` | Core | Pure evaluator for all 6 safety barriers, parent-to-child nested target propagation, and idle `rust-analyzer-proc-macro-srv` `.dylib` auto-pinning |
| `src/sweep.rs` | Core | Pure build-unit reachability graph (`V2` and `V1` independently for `MixedV1V2`), multi-JSON anchoring, active `rustc_hash`, two-level `incremental/` (`Finalized` vs `WorkingOnly`), and `target/doc/` |
| `src/rules.rs` | Core | Pure deterministic planner `plan(&ScanSnapshot, &State, &Config, PlanMode) -> ReclaimPlan` (`R1`–`R5`) |
| `src/report.rs` | Core | Pure text (GiB) and `schema_version = 1` JSON formatter into `impl Write` (depends only on `model`, `state`, `config`, `error`) |
| `src/platform.rs` | Shell | Narrow `trait Platform` and macOS adapter (`rustix`, `signal-hook`, `File::try_lock`, bounded `lsof`/`mount`/`tmutil`/`git`/`launchctl`) plus non-macOS `NoPlatform` |
| `src/store.rs` | Shell | State directory `~/Library/Application Support/targetwarden/`: `run.lock`, `FileStamp`-validated `StateCache`, atomic `state.json`, rotating `actions.jsonl` |
| `src/discover.rs` | Shell | Budgeted root walk (`max_depth`, `max_entries`, non-Rust `.git` cutoff), `CACHEDIR.TAG` / `HeuristicNoTag` verification, 4 layout classifiers, `fingerprint/*.json` reading, local Git checks, hardlink-dedup `st_blocks` |
| `src/execute.rs` | Shell | Sorted lock acquisition → TOCTOU revalidation → crash-consistent staging rename (V1 `.fingerprint/` first) → unlock → `rustix` fd-anchored `remove_tree_safe` → dual staging crash recovery |
| `src/install.rs` | Shell | Pure `render_plist(exe, home)` (`io.github.dankosik.targetwarden`, `Nice = 10`, without `ProcessType=Background` / `LowPriorityIO`) and `install`/`uninstall` over `&impl Platform` |

## Acyclic dependency DAG

```text
Layer 0 (leaves):       error, model
Layer 1 (policy/state): config   -> {error, model}
                        state    -> {model}
                        pressure -> {model, config, state}
Layer 2 (pure core):    safety   -> {model, config, state}
                        sweep    -> {model, config}
                        report   -> {model, state, config, error}
Layer 3 (planner):      rules    -> {model, config, state, pressure, safety, sweep}
Layer 4 (boundaries):   platform -> {error, model}
                        store    -> {error, model, state}
Layer 5 (shell):        discover -> {error, model, config, platform}
                        execute  -> {error, model, platform}
                        install  -> {error, platform}
Layer 6 (wiring):       cli      -> {model}
                        lib      -> {cli, config, discover, error, execute, install, model,
                                     platform, pressure, report, rules, state, store}
                        main     -> {lib}
```

`report` has no edges from `discover`, `execute`, or `platform`: reporting operates strictly on core domain outputs.

## Narrow `Platform` boundary

All OS interaction (`statvfs`, `tmutil listlocalsnapshots`, `/usr/sbin/lsof -n -P -F0pcftn`, `/sbin/mount`, `git`, `O_RDONLY` `File::try_lock()`, `rustix` fd-anchored tree removal, self-pipe `poll`, and `launchctl`) sits behind `trait Platform` in `src/platform.rs`. Pure-core rules, safety, sweep, parsers, and LaunchAgent `install` logic are tested deterministically with recorded fixtures and a `FakePlatform` without touching real system processes or `launchd`.

## Sibling tool boundaries

| Tool | Owns | Automation model |
| --- | --- | --- |
| `agentwarden` | RAM / swap: idle and orphaned AI agent helpers and MCP servers | Zero-config LaunchAgent daemon (`watch`) |
| `targetwarden` | Disk (Cargo caches): intra-target `build/` + `incremental/` sweep (`R2`+`R3`) and cooled/dead worktree target eviction (`R1`+`R4`+`R5`) | Zero-config LaunchAgent daemon (`watch`) + one-shot CLI |
| `worktree-tidy` | Git lifecycle: completed `git worktree` retirement + opt-in non-Cargo artifact cleanup | Opt-in (`--apply`, 7-day observation, `--allow`) |

## Platforms

Only macOS (`aarch64-apple-darwin` and `x86_64-apple-darwin`) is implemented in v1. Other platforms compile and execute all pure-core and CLI grammar tests; system-dependent commands exit cleanly with `targetwarden supports macOS only`.
