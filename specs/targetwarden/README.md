# `targetwarden`: Specification & Technical Architecture (v1)

> **Status:** Active design specification (`Stage 0` scaffold complete; empirically verified on macOS `26.4` in [research](research.md)).
> **Target platform (v1):** macOS (`aarch64-apple-darwin`, `x86_64-apple-darwin`, APFS); Rust `1.98.1`, edition `2024`, `unsafe_code = "forbid"`.
> **Architecture & delivery:** [architecture](../../docs/architecture.md) · [research](research.md) · [implementation plan](plan.md).

---

## 1. Problem & Scope

### 1.1. Workstation workload

On an Apple Silicon Mac (16 GB RAM, 494.33 GB / 460.38 GiB APFS SSD) running parallel AI coding agents (`Antigravity`, `Codex`, `Claude Code`, `OpenCode`) across dozens of `git worktree`s, Cargo `target/` directories exhaust free disk space rapidly even with global `sccache` (`8G`), `debug = "line-tables-only"`, and `profile.dev.package."*".debug = false` in `~/.cargo/config.toml`.

Live inspection on this machine (recorded in [research](research.md)) showed a single active `target/debug/` reaching `83.09 GiB` (`44.47 GiB` `build/` across `4 657` units + `38.62 GiB` `incremental/` across `1 696` directories) while producing only ~520 MiB of final binaries. `sccache` does not cache incremental workspace compilation or obsolete feature/test unit hashes, and Cargo never garbage-collects old `<unit-hash>` directories or abandoned incremental sessions on stable toolchains.

### 1.2. Sibling tool boundaries & macOS pattern reuse

`targetwarden` forms an orthogonal trio with `agentwarden` and `worktree-tidy`:

| Tool | Owns | Automation model | Reused macOS patterns | Deliberately excluded |
| --- | --- | --- | --- | --- |
| **`agentwarden`** | **RAM / swap:** idle and orphaned AI agent helpers and MCP servers | Zero-config LaunchAgent daemon (`watch`) | `Cargo.toml` lints (`unsafe_code = "forbid"`, edition `2024`, MSRV `1.98.1`), `deny.toml` (`MIT`, `Apache-2.0`, `Unicode-3.0`), `PARTIAL = 3`, bare-`watch` fast-path skipping `clap`, `FileStamp`-cached `StateCache` + atomic `state.json` under `~/Library/Application Support/targetwarden/` + rotating `actions.jsonl` (`memchr`), LaunchAgent plist (`Nice = 10`, no `ProcessType=Background` / `LowPriorityIO`), `diagnostic()` control-char escaping | `top`/MCP/SQLite parsers, process ownership tree, `IOHIDSystem`, `nix` (replaced by `rustix` + `signal-hook`) |
| **`worktree-tidy`** | **Git lifecycle:** completed `git worktree` retirement + opt-in non-Cargo artifact cleanup | Strictly opt-in (7-day observation, `--allow`, `--apply`) | Bounded subprocess runner (`process_group(0)`, output cap, `killpg` cleanup), fail-closed NUL-delimited `lsof` parser architecture (`decode_name`, `NOFD`, `PIPE\|NPOLICY\|NEXUS`) **extended** from `-F0pftn` to `-F0pcftn` for `comm` + `ftxt`, `/sbin/mount` prefix validation, hardlink deduplication by `(st_dev, st_ino)` for `st_nlink > 1` | `unsafe` FFI `getattrlist(ATTR_CMNEXT_PRIVATESIZE)`, `rusqlite`, `dialoguer`, `toml_edit`, 7-day observation gate, network `git fetch`, Docker UNIX-socket client |
| **`targetwarden`** | **Disk (Cargo caches):** intra-target surgical sweep (`R2`+`R3`) and pressure-aware target eviction (`R1`+`R4`+`R5`) | Zero-config adaptive LaunchAgent (`watch`) + one-shot CLI | — | Deleting source files, `.git`, worktrees themselves, Git branches, or `~/.cargo/registry` |

### 1.3. Rejected complexity in v1 (Non-goals)

1. **`tokio` / `async` runtime:** `watch` sleeps `60–180 s` between passes and executes one bounded `lsof` + synchronous filesystem operations. Async doubles binary size and dependency footprint for zero benefit.
2. **SQLite (`rusqlite`):** `state.json` (`< 32 KiB`) + rotating `actions.jsonl` (`<= 2 MiB`) load atomically, avoid WAL files, and stay directly inspectable with `jq`.
3. **FSEvents / `kqueue` file watchers:** Watching `50 000+` files under `target/` burns descriptors and CPU during builds. Periodic ticks plus cached `known_targets` are near-zero overhead.
4. **Plugin/provider framework (Docker volumes, `.git/{codex,wt,claude}`, `node_modules`):** Conflates incompatible safety contracts. `v1` handles Cargo `target/` exclusively.
5. **Complex config DSL (`figment`, `toml_edit`):** Zero-config by default; optional `~/.config/targetwarden/config.toml` uses plain `serde` + read-only `toml` only if present (or `--config`).
6. **`unsafe` FFI (`libproc`, `getattrlist`):** Keeping `unsafe_code = "forbid"` and `deny.toml` license compliance (`MIT`, `Apache-2.0`, `Unicode-3.0`) outweighs saving `~110 ms` once per `180 s` tick.
7. **Virtual filesystem trait (`trait FileSystem`):** Mocked filesystems hide real `symlink`/`flock`/`st_dev` bugs. `discover`, `execute`, and `store` test against real `tempfile::TempDir`.
8. **Premature Linux/Windows implementation:** All OS calls sit behind `trait Platform`. Non-macOS targets compile cleanly, pass all pure-core/CLI tests, and fail closed with `targetwarden supports macOS only`.
9. **Network `git fetch` and Docker UNIX-socket inspection in v1:** Zero network I/O; `R1` uses local Git refs only, and custom bind-mounted targets are handled by `targetwarden pin` / `.targetwarden-pin`.

---

## 2. Cargo Target Layouts & Verification Contract

### 2.1. Four observed `target/<profile>/` layouts

Empirical tests on `+1.98.1` (`stable` default), `+1.99.0`, and `+1.100.0` established that `build-dir-new-layout` became default in **`1.100.0`** (projects pinned to `1.98.1`/`1.99.0` create legacy layout):

1. **`BuildDirV2`:** `target/<profile>/build/<crate>/<16-hex>/{fingerprint/, out/}` + `incremental/<crate>-<13-base36>/`; no `.fingerprint/` or `deps/`.
2. **`LegacyV1`:** `target/<profile>/{.fingerprint/<crate>-<16-hex>/, deps/*-<16-hex>*, build/<crate>-<16-hex>/, incremental/}`.
3. **`MixedV1V2`:** **Both** V1 and V2 units coexist inside the **same** profile directory (observed live when switching toolchains `1.98.1` ↔ `1.100.0`). `ProfileDir` therefore stores `v2_units` and `v1_units` independently rather than using a mutually exclusive layout enum.
4. **`ArtifactsOnly`:** `.rustc_info.json`, `tmp/`, and `<profile>/{.cargo-*lock, examples/, binaries, *.rlib, *.d}` without `build/`, `deps/`, `.fingerprint/`, or `incremental/` (observed live in separate pre-trimmed artifact targets where `target_directory == build_directory`).
   - **Contract for `ArtifactsOnly`:** Surgical sweep rules (`R2`, `R3`) are a safe no-op; full eviction (`R1`, `R4`, `R5`) runs normally under all 6 safety barriers.

### 2.2. Positive proof & anti-false-positive rules

- **`TargetOrigin::VerifiedCargoTag`:** `CACHEDIR.TAG` (`<= 4 KiB`) starts with `Signature: 8a477f597d28d172789f06886806bc55` **and** contains ASCII case-insensitive `cargo` in its comment lines (rejects `.ruff_cache/`, `.venv/`, `.pytest_cache/`).
- **`TargetOrigin::HeuristicNoTag`:** No `CACHEDIR.TAG`, valid JSON `.rustc_info.json` (`<= 4 MiB`, keys `rustc_fingerprint` and `outputs`), at least one profile directory with Cargo markers, **and** a strict top-level whitelist (`{.rustc_info.json, .rustdoc_fingerprint.json, tmp, doc, package, <valid profiles>, <valid nested CargoTarget>}`). Any unknown file (e.g., `verification.log`) triggers `Protected(UnverifiedNonCargoEntries)`.
- **Nested `--target-dir` invariant:** Direct children with their own `CACHEDIR.TAG` / `.rustc_info.json` (e.g., `target/grpc-codegen/`) register as independent `CargoTarget`s with `parent_target` and are recorded in the parent's `nested_target_roots`. Full eviction (`R1`/`R4`/`R5`) of a parent target is forbidden unless **all** nested child targets are also `Eligible`.
- **Hard refusals (fail-closed):** symlinks at/above `target/`, mount points (`st_dev != parent.st_dev` or `/sbin/mount` match), Git tracked files (`git ls-files -z -- <rel_target>` non-empty) or failed `git` check, running as `uid == 0`.

---

## 3. Data Model (`src/model.rs`, `src/state.rs`)

Invalid combinations are unrepresentable at the type level:
- `ProfileDir` separates `v2_units` and `v1_units`.
- `UnitMetadata::Complete` holds `targets: SmallVec<[UnitTargetAnchor; 2]>` to represent multi-JSON units (`doc-bin-console.json` + `doc-lib-service.json` sharing one `<unit-hash>`).
- `IncrementalDir::has_finalized()` distinguishes finalized caches from abandoned `Working`-only directories.
- `ReclaimAction` separates `SweepBuildUnits` (`R2`), `RemoveDoc` (`R2-doc`), `PruneIncremental` (`R3`), and `EvictTarget` (`EvictRule::{R1DeadWorktree, R4CooledWorktree, R5PressureLru}`).
- `ReclaimHoldState` retains `free_bytes_at_detection` and `pressure_at_detection` so all 4 reset conditions are deterministic.

```rust
use std::collections::BTreeMap;
use std::path::PathBuf;
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskStats {
    pub mount: PathBuf,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub local_snapshots: Option<Vec<CompactString>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub comm: CompactString,       // lsof `c` field (<= 31 bytes on Darwin, spaces preserved)
    pub exe_path: Option<PathBuf>, // first `ftxt`/`REG` path (avoids 31-byte comm truncation)
    pub cwd: Option<PathBuf>,
    pub open_paths: Vec<PathBuf>,  // REG/DIR open FDs + txt mmaps
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub captured_at_unix: u64,
    pub processes: Vec<ProcessEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeKind { MainCheckout, LinkedWorktree, NonGit }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitInspection {
    pub repo_common_dir: PathBuf,
    pub worktree_root: PathBuf,
    pub worktree_kind: WorktreeKind,
    pub worktree_dir_missing: bool,
    pub is_dirty: bool,
    pub git_op_in_progress: bool,          // index.lock, MERGE/REBASE/CHERRY_PICK/REVERT_HEAD, BISECT_LOG
    pub worktree_locked: bool,             // .git/worktrees/<name>/locked
    pub branch_merged_into_default: Option<bool>,
    pub has_tracked_files_in_target: bool, // git ls-files -z -- <target_rel>
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetOrigin { VerifiedCargoTag, HeuristicNoTag }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetLayout { BuildDirV2, LegacyV1, MixedV1V2, ArtifactsOnly }

#[derive(Clone, Debug)]
pub struct DocDirInfo {
    pub path: PathBuf,
    pub lock_file: Option<PathBuf>, // target/doc/.lock if present
    pub locked_now: bool,
    pub last_activity_unix: u64,
    pub allocated_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct CargoTarget {
    pub root: PathBuf,
    pub dev_id: u64,
    pub ino: u64,
    pub origin: TargetOrigin,
    pub layout: TargetLayout,
    pub has_unverified_top_entries: bool,
    pub has_pin_marker: bool,
    pub parent_target: Option<PathBuf>,
    pub nested_target_roots: Vec<PathBuf>,
    pub worktree_kind: WorktreeKind,
    pub git: Option<GitInspection>,
    pub profiles: Vec<ProfileDir>,
    pub doc_dir: Option<DocDirInfo>,
    pub allocated_bytes: u64,    // st_blocks * 512 (hardlinks deduplicated)
    pub last_activity_unix: u64, // strictly max(mtime), ignoring atime/ctime
}

#[derive(Clone, Debug)]
pub struct ProfileDir {
    pub name: CompactString,
    pub rel_path: PathBuf,
    pub layout: TargetLayout,
    pub lock_files: SmallVec<[PathBuf; 4]>, // sorted existing locks
    pub locked_now: bool,
    pub v2_units: Vec<BuildUnit>,
    pub v1_units: Vec<BuildUnit>,
    pub incremental_dirs: Vec<IncrementalDir>,
    pub allocated_bytes: u64,
    pub last_activity_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BuildUnitId {
    V2 { pkg: CompactString, unit_hash: CompactString },
    V1 { fingerprint_dir: CompactString, unit_hash: CompactString },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnitTargetKind {
    Lib, Bin, Test, Example, Bench, BuildScriptBuild, RunBuildScript, Doc, Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitTargetAnchor {
    pub target_kind: UnitTargetKind,
    pub target_name: CompactString,
    pub fingerprint_hash: Option<u64>, // u64::from_le_bytes from 16-hex file
}

#[derive(Clone, Debug)]
pub enum UnitMetadata {
    Complete {
        targets: SmallVec<[UnitTargetAnchor; 2]>,
        rustc_hash: u64,
        dep_fp_hashes: SmallVec<[u64; 8]>,
        mtime_unix: u64,
    },
    Incomplete { mtime_unix: u64 },
}

#[derive(Clone, Debug)]
pub struct BuildUnit {
    pub id: BuildUnitId,
    pub pkg_group: CompactString,
    pub metadata: UnitMetadata,
    pub v1_build_dir: Option<CompactString>,
    pub v1_dep_entries: Vec<CompactString>, // files and .dSYM dirs in deps/
    pub allocated_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState { Finalized, Working }

#[derive(Clone, Debug)]
pub struct IncrementalSession {
    pub dir_name: CompactString,
    pub lock_file: Option<CompactString>,
    pub state: SessionState,
    pub locked: bool,
    pub mtime_unix: u64,
    pub allocated_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct IncrementalDir {
    pub dir_name: CompactString,
    pub crate_name: CompactString,
    pub sessions: Vec<IncrementalSession>,
    pub any_locked: bool,
    pub latest_mtime_unix: u64,
    pub allocated_bytes: u64,
}

impl IncrementalDir {
    pub fn has_finalized(&self) -> bool {
        self.sessions.iter().any(|s| s.state == SessionState::Finalized)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProtectedReason {
    ActiveCargoLock { profile: CompactString },
    ActiveDocLock,
    HardBlockedProcess { pid: u32, comm: CompactString, detail: CompactString },
    GitOperationInProgress,
    TrackedFilesInTarget,
    SymlinkOrMountBoundary,
    UnverifiedNonCargoEntries,
    NestedTargetProtected { child: PathBuf },
    PinnedFull,
    PinMarkerFile,
    Cooling { remaining_secs: u64 },
    ProcessSnapshotUnavailable,
    MountTableUnavailable,
    GitInspectionFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SweepOnlyReason {
    OpenInteractiveSession { pid: u32, comm: CompactString },
    IdleRustAnalyzer { pid: u32 },
    PinnedAllowSweep,
    DirtyOrUnmergedWorktree,
    MainCheckoutProtected,
    EvictionCooling { remaining_secs: u64 },
    SnapshotHoldActive,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SafetyVerdict {
    Eligible,
    SweepOnly {
        reasons: SmallVec<[SweepOnlyReason; 2]>,
        pinned_unit_paths: Vec<PathBuf>,
    },
    Protected(SmallVec<[ProtectedReason; 4]>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskPressure { Calm, Elevated, High, Critical }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReclaimHoldState {
    pub detected_at_unix: u64,
    pub reclaimed_allocated_bytes: u64,
    pub observed_free_gain_bytes: u64,
    pub free_bytes_at_detection: u64,
    pub pressure_at_detection: DiskPressure,
    pub snapshots_at_detection: Vec<CompactString>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictRule { R1DeadWorktree, R4CooledWorktree, R5PressureLru }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleId {
    CrashRecovery,
    R1DeadWorktree,
    R2BuildSweep,
    R2DocPrune,
    R3IncrementalPrune,
    R4CooledWorktree,
    R5PressureLru,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SweepUnitReason { StaleRustcHash, UnreachableDuplicate, IncompleteAbortedUnit }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2UnitRemoval {
    pub pkg: CompactString,
    pub unit_hash: CompactString,
    pub allocated_bytes: u64,
    pub reason: SweepUnitReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1UnitRemoval {
    pub fingerprint_dir: CompactString,
    pub build_dir: Option<CompactString>,
    pub dep_entries: Vec<CompactString>,
    pub allocated_bytes: u64,
    pub reason: SweepUnitReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SweepOps {
    V2(Vec<V2UnitRemoval>),
    V1(Vec<V1UnitRemoval>),
    Mixed { v2: Vec<V2UnitRemoval>, v1: Vec<V1UnitRemoval> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IncrementalRemoval {
    WholeCrateDir { dir_name: CompactString, allocated_bytes: u64 },
    SingleSession {
        crate_dir: CompactString,
        session_dir: CompactString,
        lock_file: Option<CompactString>,
        allocated_bytes: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReclaimAction {
    ReapLeftoverStaging { staging_dir: PathBuf, expected_dev: u64 },
    SweepBuildUnits {
        target_root: PathBuf,
        target_dev: u64,
        profile_rel: PathBuf,
        profile_locks: SmallVec<[PathBuf; 4]>,
        ops: SweepOps,
        estimated_allocated_bytes: u64,
    },
    RemoveDoc {
        target_root: PathBuf,
        target_dev: u64,
        locks: SmallVec<[PathBuf; 5]>,
        estimated_allocated_bytes: u64,
    },
    PruneIncremental {
        target_root: PathBuf,
        target_dev: u64,
        profile_rel: PathBuf,
        profile_locks: SmallVec<[PathBuf; 4]>,
        removals: Vec<IncrementalRemoval>,
        estimated_allocated_bytes: u64,
    },
    EvictTarget {
        rule: EvictRule,
        target_root: PathBuf,
        target_dev: u64,
        all_locks: Vec<PathBuf>,
        estimated_allocated_bytes: u64,
        reason: CompactString,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReclaimPlan {
    pub generated_at_unix: u64,
    pub disk: DiskStats,
    pub pressure: DiskPressure,
    pub hold_active: bool,
    pub actions: Vec<ReclaimAction>,
    pub estimated_allocated_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ActionOutcome {
    Applied,
    DryRun,
    SkippedContested { reason: CompactString },
    SkippedRevalidateChanged { reason: CompactString },
    Failed { error: CompactString },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionReceipt {
    pub ts_unix: u64,
    pub rule: RuleId,
    pub target_root: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_rel: Option<PathBuf>,
    pub outcome: ActionOutcome,
    pub units_removed: u32,
    pub allocated_bytes: u64,
    pub free_before_bytes: u64,
    pub free_after_bytes: u64,
    pub duration_ms: u64,
    pub pressure: DiskPressure,
    pub reason: CompactString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinScope { Full, AllowSweep }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinEntry {
    pub pinned_at_unix: u64,
    pub scope: PinScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownTargetEntry {
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub last_layout: TargetLayout,
    pub last_allocated_bytes: u64,
    pub last_activity_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub schema_version: u32, // = 1
    pub pressure: DiskPressure,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_full_walk_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reclaim_hold: Option<ReclaimHoldState>,
    #[serde(default)]
    pub known_targets: BTreeMap<PathBuf, KnownTargetEntry>,
    #[serde(default)]
    pub pins: BTreeMap<PathBuf, PinEntry>,
    #[serde(default)]
    pub cumulative_reclaimed_allocated_bytes: u64,
}
```

### 3.1. Persistence schemas (`~/Library/Application Support/targetwarden/`)

`state.json` (written atomically via `NamedTempFile` + `sync_all` + `persist`, overridable via `TARGETWARDEN_STATE_DIR` in tests):

```json
{
  "schema_version": 1,
  "pressure": "elevated",
  "last_full_walk_unix": 1795656000,
  "reclaim_hold": {
    "detected_at_unix": 1795655400,
    "reclaimed_allocated_bytes": 6442450944,
    "observed_free_gain_bytes": 314572800,
    "free_bytes_at_detection": 41231686041,
    "pressure_at_detection": "high",
    "snapshots_at_detection": ["com.apple.os.update-MSUPrepareUpdate"]
  },
  "known_targets": {
    "/Users/example/Projects/repo/target": {
      "first_seen_unix": 1795570000,
      "last_seen_unix": 1795656000,
      "last_layout": "build_dir_v2",
      "last_allocated_bytes": 18253611008,
      "last_activity_unix": 1795652110
    }
  },
  "pins": {
    "/Users/example/Projects/pinned-repo": {
      "pinned_at_unix": 1795500000,
      "scope": "allow_sweep",
      "note": "active release branch"
    }
  },
  "cumulative_reclaimed_allocated_bytes": 94600000000
}
```

`actions.jsonl` (append-only, rotated above `2 MiB` keeping the latest `2 000` lines):

```json
{"ts_unix":1795656012,"rule":"r2_build_sweep","target_root":"/Users/example/Projects/repo/target","profile_rel":"debug","outcome":{"status":"applied"},"units_removed":412,"allocated_bytes":11489037516,"free_before_bytes":84517836000,"free_after_bytes":95891210240,"duration_ms":1842,"pressure":"calm","reason":"unreachable_duplicates_and_incomplete_units"}
```

---

## 4. Core Algorithms & Race Protection

### 4.1. Discovery (`src/discover.rs`)

- **Default roots:** existing `~/Projects`, `~/Developer`, `~/src`, `~/work`, `$CARGO_TARGET_DIR`, explicit `--root` arguments, and cached `state.known_targets`, deduplicated by `(st_dev, st_ino)`.
- **Traversal budgets:** `max_depth = 6` (`8` for explicit `--root`), `max_entries = 250_000`, cooperative timeout `15 s`. Budget exhaustion marks the walk partial without evicting unseen `known_targets`.
- **Pruning:** `WalkDir::new(root).follow_links(false).max_open(64)` prunes `.git`, `.hg`, `.svn`, `node_modules`, `vendor`, `.venv`, `venv`, `__pycache__`, `.ruff_cache`, `.pytest_cache`, `.next`, `.nuxt`, `.turbo`, `.cache`, `Pods`, `.gradle`, `.codegraph`, `dist`, `Library`, `.Trash`.
- **Non-Rust Git repo optimization:** Entering a `.git` repository with no `Cargo.toml`, `CACHEDIR.TAG`, or `.rustc_info.json` at depth 0–1 caps remaining descent inside that repo to `+2` (avoids scanning `330k+` entries across dozens of Go/TS worktrees).
- **Nested targets, mounts, and Git tracking:** Validated per Section 2.2; `/sbin/mount` prefix check catches same-device bind mounts; `git ls-files -z -- <rel_target>` fails closed; allocation sums `st_blocks * 512` deduplicating `(st_dev, st_ino)` for `st_nlink > 1`.

### 4.2. Activity & Locking (`src/safety.rs`, `src/platform.rs`)

- **Non-creating lock probes:** Existing lock files `{.cargo-artifact-lock, .cargo-build-lock, .cargo-lock}` (+ legacy `target/.cargo-lock`, `target/doc/.lock`, `incremental/*/s-*.lock`) are sorted lexicographically and probed via `File::open(O_RDONLY)` + `File::try_lock()`. `WouldBlock` or any non-`NotFound` error fails closed.
- **Process snapshot (`/usr/sbin/lsof -n -P -F0pcftn`):** `LC_ALL=C`, `10 s` timeout, `16 MiB` stdout cap, `process_group(0)` + `killpg(SIGKILL)` on timeout. Non-zero exit, non-empty `stderr`, `fNOFD`, invalid escapes, or unexpected empty `n` outside `{PIPE, NPOLICY, NEXUS}` fails closed (0 mutations in pass). Matches processes using both `comm` (`<= 31` bytes) and `exe_path` (first `ftxt`/`REG`).
  - **Hard Block (blocks `R1–R5`):** any process (except `rust-analyzer-proc-macro-srv` mapping `.dylib`s) with `cwd` or `open_paths` inside `target.root`; any active compiler/tool (`cargo`, `cargo-*`, `rustc`, `clippy-driver`, `rustdoc`, `miri`, `lldb`, `gdb`, `sccache` with `cwd != /`, `sqlx`, `ld`, `lld`) inside worktree; busy lock; Git operation (`index.lock`, `MERGE_HEAD`, `REBASE_HEAD`, `CHERRY_PICK_HEAD`, `REVERT_HEAD`, `BISECT_LOG`); full pin or `.targetwarden-pin`.
  - **Soft Block (`SweepOnly` — allows `R2`/`R3`, blocks `R1`/`R4`/`R5`):** open shell/IDE/agent (`zsh`, `bash`, `fish`, `nu`, `Antigravity*`, `Cursor`, `Code`, `Zed`, `claude`, `codex*`, `opencode*`) with `cwd` in worktree; idle `rust-analyzer` / `rust-analyzer-proc-macro-srv` (auto-pins build units whose `.dylib` paths are open/mapped); `pin --allow-sweep`.
- **Freshness strictly by `mtime`:** `max(mtime)` across `.rustc_info.json`, `.rustdoc_fingerprint.json`, `fingerprint/invoked.timestamp`, `fingerprint/*.json`, `incremental/*/s-*.lock`, and top-level profile files. `atime` and `ctime` are ignored.

### 4.3. TOCTOU-Safe Execution & Crash Recovery (`src/execute.rs`)

Protocol: **Crash Recovery → Sorted Locks → Revalidate → Staging Rename → Unlock → Safe Remove**:

1. **Dual crash recovery:** At the start of `reclaim`/`watch`, collect leftover `<target>/.targetwarden-reap.*` and sibling `<parent>/.<name>.targetwarden-reap.*` (verifying `st_dev` and zero open FDs in `ProcessSnapshot`).
2. **Acquire sorted locks non-blocking (`< 15 ms`):** Any `WouldBlock` drops all held locks and returns `ActionOutcome::SkippedContested`.
3. **Post-lock TOCTOU revalidation:** Verify `lstat(target_root)` (`st_dev`, `st_ino`, non-symlink), mount table, unchanged `mtime`, and fresh `process_snapshot()` without Hard Block (plus 0 processes in worktree for `EvictTarget`).
4. **Atomic staging rename on same APFS volume:**
   - **V1 crash-consistency ordering:** rename `.fingerprint/<fingerprint_dir>` **first** (so Cargo immediately treats the unit as absent rather than reading half-removed `deps/`), then `build/<build_dir>`, then `deps/*`.
   - **V2:** single atomic `renameat` of `build/<pkg>/<unit_hash>`.
   - **EvictTarget:** rename `<parent>/<name>` to sibling `<parent>/.<name>.targetwarden-reap.<id>` holding all parent + nested locks. *(Mitigation against `< 5 ms` concurrent double-start lock-inode split: `EvictTarget` requires 0 processes in worktree + cooldown `>= 30m` + post-lock `lsof`.)*
5. **Immediate unlock:** `drop(lock_guards)` right after `renameat`.
6. **FD-anchored safe remove (`rustix::fs`):** `openat(O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` → `fstat.st_dev == expected_dev` → bounded depth-64 `Dir` + `statat(SYMLINK_NOFOLLOW)` → `unlinkat(REMOVEDIR)` for dirs and `unlinkat(empty)` for files/symlinks (never traverses symlinks or mount points).

### 4.4. Surgical Sweep (`R2` + `R3`) & Pressure Rules (`R1`, `R4`, `R5`)

- **R2 (`build/` sweep, V2 & V1 independently):**
  - Active `rustc_hash` derived from `Complete` units within `max_mtime - 24h` (never `.rustc_info.json["rustc_fingerprint"]`).
  - Group active units by `(pkg_group, target_kind, target_name)` for every anchor in `targets` (multi-JSON anchored in all groups); keep top `K` (`K = 2` in `Calm`/`Elevated`, `K = 1` in `High`/`Critical`; `testK = 1` always for leaf `Test` binaries). Add `pinned_unit_paths` and units newer than `dup_cooldown`.
  - BFS across `dep_fp_hashes` protects all reachable libraries, proc-macros, and build scripts regardless of `mtime`.
  - In `MixedV1V2`, if one layer is completely older than the active layer by `> 7d` (`Calm`) / `24h` (`Elevated`) / `2h` (`High`/`Critical`), the stale layer drops anchor slots (retaining only `dup_cooldown`).
  - Unreachable units and `Incomplete` units older than `dup_cooldown` (`Calm: 2h` / `Elevated: 1h` / `High: 30m` / `Critical: 15m` — justified by 100%-accurate BFS protection of live dependencies) are swept; `target/doc/` older than `7d` (`Calm`/`Elevated`) or `24h` (`High`/`Critical`) with free `doc/.lock` is removed.
- **R3 (2-level `incremental/` prune):**
  - Level 1 (`<crate>-<13-base36>/` grouped by `crate_name`): partition into `has_finalized()` vs `WorkingOnly`. Keep top `M` `Finalized` (`M = 2` in `Calm`/`Elevated`, `M = 1` in `High`/`Critical`) plus locked/cooling dirs; unlocked `WorkingOnly` older than `inc_cooldown` (`2h`/`1h`/`30m`/`15m`) are removed without consuming `M` slots.
  - Level 2 (inside kept `<crate>-<base36>/`): keep newest `Finalized` `s-*` session (+ locked/cooling); prune older `Finalized` and orphaned `Working` sessions.
- **DiskPressure (`1 << 30` GiB hysteresis on `/System/Volumes/Data`):**
  - `Calm → Elevated`: `< 75 GiB` (exit `>= 85 GiB`)
  - `Elevated → High`: `< 45 GiB` (exit `>= 55 GiB`)
  - `High → Critical`: `< 25 GiB` (exit `>= 35 GiB`)
- **Full eviction (`Eligible` only):**
  - `R1`: `worktree_dir_missing` or clean merged unlocked `LinkedWorktree` (`age >= 30m`, from `Calm`).
  - `R4`: `LinkedWorktree` (`age >= 72h` Calm / `6h` Elevated / `2h` High / `30m` Critical).
  - `R5`: `High` (target `55 GiB` free) / `Critical` (target `45 GiB` free) in priority: (1) `LinkedWorktree` → (2) `NonGit` → (3) `MainCheckout` (`age >= 24h` High / `2h` Critical), re-checking `statvfs` after each target.
- **`ReclaimHoldState` circuit breaker:** Triggers if R5 removes `>= 5 GiB` `allocated_bytes` with `< 20%` `statvfs.free_bytes` gain; halts `R5` while `R1–R3` continue. Resets when **any** of 4 conditions holds: (1) snapshot list changed via `tmutil`; (2) `free_bytes >= free_bytes_at_detection + 5 GiB`; (3) pressure escalates strictly above `pressure_at_detection`; (4) `6h` TTL expires (or `--ignore-snapshot-hold`).

### 4.5. Concurrency, Watch Loop & LaunchAgent

- **`run.lock`:** Mutating commands (`reclaim` without `--dry-run`, `watch`, `pin`, `unpin`) acquire `File::try_lock()` on `~/Library/Application Support/targetwarden/run.lock` (`watch` exits immediately if busy; CLI commands retry up to `5 s` then fail closed with exit `1`). Read-only commands never lock.
- **Watch loop:** Bare `targetwarden watch` skips `clap` and `stdout` locking (~2–5 MiB RSS). Ticks every `180 s` (`Calm`/`Elevated`) or `60 s` (`High`/`Critical`), performs full root walks at most every `10 min` (or upon entering `High`/`Critical`), and reuses `StateCache` via `FileStamp`.
- **Graceful shutdown:** `signal-hook` self-pipe (`SIGTERM`/`SIGINT`) + `rustix::event::poll` wakes immediately (`< 1 ms`), completes the active atomic `lock -> rename -> unlock` step, flushes `state.json`/`actions.jsonl`, and exits `0`.
- **LaunchAgent (`io.github.dankosik.targetwarden`):** `~/Library/LaunchAgents/io.github.dankosik.targetwarden.plist` with `ProgramArguments = [<exe>, "watch"]`, `LimitLoadToSessionType = Aqua`, `RunAtLoad = true`, `KeepAlive = true`, `ThrottleInterval = 60`, `Nice = 10`, `StandardErrorPath = ~/Library/Logs/targetwarden.log`, **without** `ProcessType = Background` or `LowPriorityIO`.

---

## 5. `Cargo.toml` Dependency Blueprint

Base policy (`deny.toml`): `edition = "2024"`, `rust-version = "1.98.1"`, `unsafe_code = "forbid"`, licenses `MIT`, `Apache-2.0`, `Unicode-3.0`.

| Crate | Minimal features | Role | Why not `std` / alternatives | `unsafe_code = "forbid"` / license |
| --- | --- | --- | --- | --- |
| `clap` `4.6` | `["derive", "env"]` | CLI parsing, help, version, exit `2` | Standard; avoids brittle manual parser | Yes (`MIT OR Apache-2.0`) |
| `clap_complete` `4.6` | default | Shell completions from `Cli` | Prevents drift vs flags | Yes (`MIT OR Apache-2.0`) |
| `serde` `1.0` | `["derive"]` | State, JSONL, JSON report, config serialization | Not in `std` | Yes (`MIT OR Apache-2.0`) |
| `serde_json` `1.0` | default | `fingerprint/*.json`, `.rustc_info.json`, JSON/JSONL | Standard | Yes (`MIT OR Apache-2.0`) |
| `toml` `1.1` | `default-features = false`, `["parse", "serde", "std"]` | Optional read-only `config.toml` | `toml_edit` unnecessary (never mutated) | Yes (`MIT OR Apache-2.0`) |
| `thiserror` `2.0` | default | Typed `AppError` for exit codes & fail-closed | Preserves typed error branches unlike `anyhow` | Yes (`MIT OR Apache-2.0`) |
| `walkdir` `2.5` | default | Budgeted root walk (`max_depth`, `max_open`, `follow_links(false)`) | `std::fs::read_dir` lacks `max_open` & pruning | Yes (`Unlicense OR MIT`) |
| `tempfile` `3.27` | default | Atomic `state.json` / `actions.jsonl` (`NamedTempFile::persist`) + tests | Safe `O_EXCL` temp file + cleanup | Yes (`MIT OR Apache-2.0`) |
| `memchr` `2.8` | default | Reverse `\n` tail reader + NUL parsing | Fast, zero-unsafe | Yes (`Unlicense OR MIT`) |
| `compact_str` `0.10` | `default-features = false`, `["serde", "std"]` | Inline `<= 24 B` crate/hash/process strings | Avoids thousands of small heap allocs | Yes (`MIT`) |
| `smallvec` `1.16` | `default-features = false`, `["const_generics", "serde", "union"]` | Inline `lock_files`, `targets`, `dep_fp_hashes`, reasons | Avoids per-unit `Vec` allocs | Yes (`MIT OR Apache-2.0`) |
| `rustix` `1.1` *(unix)* | `default-features = false`, `["std", "fs", "process", "event"]` | `statvfs`, `openat(O_NOFOLLOW)`, `fstat`, `statat`, `unlinkat`, `renameat`, `Dir`, `geteuid`, `kill_process_group`, `poll` | Already in `tempfile` tree; replaces `nix`, `libc`, `fs4` with 100% safe API | Yes (`Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`) |
| `signal-hook` `0.3` *(unix)* | `default-features = false` | Non-blocking self-pipe `SIGTERM`/`SIGINT` wakeups | Only pulls `signal-hook-registry`; no POSIX signal API in `std` | Yes (`Apache-2.0 OR MIT`) |
| `assert_cmd` `2.2` *(dev)* | default | Binary integration tests | Standard CLI framing verification | Dev-only (`MIT OR Apache-2.0`) |

---

## 6. CLI Contract, Error Policy, Exit Codes & Testing

### 6.1. CLI & stream framing

```sh
targetwarden status [--format text|json]
targetwarden scan [PATH...] [--format text|json]
targetwarden reclaim [--dry-run] [--profile sweep-only|full] [--ignore-snapshot-hold] [--format text|json]
targetwarden watch [--dry-run]
targetwarden pin <PATH> [--allow-sweep] [--note TEXT]
targetwarden unpin <PATH>
targetwarden history [--limit 20] [--format text|json]
targetwarden install [--dry-run]
targetwarden uninstall
targetwarden completions <bash|zsh|fish>
```

- `stdout`: strictly structured output (GiB table or single JSON document `schema_version = 1`). `BrokenPipe` exits `0`.
- `stderr`: diagnostics and errors sanitized via `error::diagnostic()`. `watch` never writes to `stdout`.
- `--help`, `--version`, and `completions` never read `config.toml`/`state.json` or invoke `platform`.
- **Exit codes:** `0` success (including nothing to reclaim, contested/revalidation skips, `--dry-run`, `BrokenPipe`); `1` fatal runtime/fail-closed error (`lsof`/`statvfs`/`run.lock`/`root`/non-macOS/`store`); `2` CLI usage error (`clap`); `3` (`PARTIAL`) `reclaim` completed and reported but `>= 1` action failed with `ActionOutcome::Failed`.

### 6.2. Fail-closed error matrix

- `lsof` failure / timeout / `stderr` / `NOFD` / parse error → global fail-closed (`0` deletions).
- `/sbin/mount` failure or ambiguous entry → fail-closed (`0` deletions).
- `git` failure in a repo → local fail-closed (`Protected(GitInspectionFailed)` for that target).
- Corrupt `fingerprint/*.json` → profile-local fail-closed (`R2` skipped for that profile; `R3` & others continue).
- `statvfs` failure → global fail-closed (`exit 1`).
- `tmutil` failure → graceful degradation (`local_snapshots = None`); `ReclaimHoldState` still triggers on `< 20%` gain.
- Corrupt `state.json` → `watch` logs diagnostic to `stderr` and starts cleanly (on-disk `.targetwarden-pin` markers remain active).

### 6.3. Testing strategy

1. **Pure-core unit tests (cross-platform, 0 I/O):** `pressure` hysteresis + 4 hold resets; `safety` 6-barrier matrix + nested propagation + proc-macro `.dylib` pin; `sweep` V2/V1/`MixedV1V2` BFS + multi-JSON + `Incomplete` + `WorkingOnly` protection; `rules` priorities + headroom stop; `lsof`/`mount` parsers; `install` XML + `FakePlatform` `launchctl` trace.
2. **Real filesystem fixtures (`tempfile::TempDir`):** `BuildDirV2`, `LegacyV1` (including `.dSYM` dirs), `MixedV1V2`, `ArtifactsOnly`, nested `grpc-codegen`, false `CACHEDIR.TAG`, `HeuristicNoTag` rejection of `verification.log`, V1 `.fingerprint/`-first staging rename, dual staging crash recovery, symlink refusal.
3. **Live macOS integration tests (`tests/`):** live `File::try_lock()` competitor on `.cargo-build-lock`/`doc/.lock`/`s-*.lock`; live `git worktree` states (`merged`/`unmerged`/`dirty`/`locked`/tracked/`index.lock`); concurrent `run.lock`; built CLI contract (`assert_cmd` exit codes `0`/`1`/`2`/`3`, `--help`/`--version`/`completions` without `HOME`, `BrokenPipe`).
4. **Field dry-run protocol (before enabling live `watch`):** `status --format json` (`< 2 s`) and `reclaim --dry-run --format json` across live projects, test-copy `reclaim --profile sweep-only` verifying `cargo check` has `recompiled = []`, plus 48h `watch --dry-run` observation.

### 6.4. Product defaults owner-tunable before Stage 4

1. **Disk pressure thresholds:** defaults to `85/75/45/25 GiB` (`1 << 30`, hysteresis `10 GiB`); tunable without schema changes (e.g., raising `High` to `< 60 GiB` or exposing overrides in `config.toml`).
2. **Initial LaunchAgent rollout mode:** defaults to `watch --dry-run` (or live `R1–R3` + `--dry-run` `R4–R5`) for 48 hours before full `R1–R5`.
3. **Optional `~/.config/targetwarden/config.toml`:** defaults to optional read-only `roots` and pressure thresholds only (100% zero-config when absent); can be removed if strict CLI-only `--root` configuration is preferred.
