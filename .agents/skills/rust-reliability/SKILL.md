---
name: rust-reliability
description: "Budget arithmetic. Use for traversal budgets, subprocess timeouts, lock contention, APFS hold circuit breakers, crash recovery, or watch shutdown budgets."
---

# Rust Reliability

**Budget arithmetic.** Bound every traversal, subprocess, lock section, journal, and shutdown path explicitly so background `watch` passes cannot stall a workstation or wedge active Cargo builds under heavy load.

**Bounded discovery and subprocesses.** Enforce hard budgets in `src/discover.rs` (`max_depth = 6`/`8`, `max_entries = 250_000`, cooperative `15 s` walk timeout, `max_open(64)`, non-Rust `.git` `+2` cutoff) and in `src/platform.rs` (`10 s` timeout and `16 MiB` stdout cap with `process_group(0)` + `kill_process_group(SIGKILL)` cleanup for `lsof`, `5 s` for `git`/`tmutil`/`mount`/`launchctl`). On budget exhaustion, preserve cached `known_targets` and degrade safely without blind eviction.

**Lock contention and TOCTOU safety.** Never wait blocking on Cargo or `rustc` locks: acquire `O_RDONLY` `File::try_lock()` in fixed lexicographical order, hold locks only for the `< 15 ms` staging `renameat` window (after TOCTOU revalidation), drop locks immediately before `remove_tree_safe`, and coordinate concurrent mutating `targetwarden` invocations via `run.lock` (5 s bounded retry for CLI, fail-fast for `watch`).

**Circuit breakers and crash recovery.** Bound APFS snapshot retention waste via `ReclaimHoldState` (halting `R5` after `>= 5 GiB` removed with `< 20%` `statvfs` gain, resetting cleanly on any of the 4 documented conditions), bound `actions.jsonl` size via `2 MiB` rotation, rename V1 units `.fingerprint/`-first for crash consistency, and run dual leftover-staging recovery (`<target>/.targetwarden-reap.*` and sibling `<parent>/.<name>.targetwarden-reap.*`) at the start of every mutating pass.

**Graceful `watch` drain.** In `watch`, sleep via `rustix::event::poll` on a non-blocking `signal-hook` self-pipe (`SIGTERM`/`SIGINT`), complete any active atomic `lock -> rename -> unlock` step cleanly upon signal, sync `state.json` and `actions.jsonl` before exiting `0`, and omit `ProcessType=Background` / `LowPriorityIO` from the LaunchAgent plist so Darwin QoS does not starve cleanup under disk pressure.
