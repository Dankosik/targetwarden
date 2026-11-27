//! Core zero-I/O domain types for `targetwarden`.

use std::path::{Path, PathBuf};

use clap::ValueEnum;
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

pub(crate) const GIB: u64 = 1 << 30;
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// Output framing selected on the command line or via `TARGETWARDEN_FORMAT`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// Scope selector for `targetwarden reclaim --profile`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum ReclaimProfile {
    /// Surgical intra-target sweep only (`R2` + `R3`).
    SweepOnly,
    /// Full rule set (`R1`–`R5`).
    #[default]
    Full,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlanMode {
    pub profile: ReclaimProfile,
    pub ignore_snapshot_hold: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DiskStats {
    pub mount: PathBuf,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub local_snapshots: Option<Vec<CompactString>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MountEntry {
    pub source: CompactString,
    pub mount_point: PathBuf,
    pub fstype: CompactString,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProcessEntry {
    pub pid: u32,
    pub comm: CompactString,
    pub exe_path: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub open_paths: Vec<PathBuf>,
}

impl ProcessEntry {
    pub(crate) fn exe_name(&self) -> Option<&str> {
        self.exe_path
            .as_deref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
    }

    pub(crate) fn is_rust_analyzer_proc_macro_srv(&self) -> bool {
        let matches_name = |name: &str| {
            name == "rust-analyzer-proc-macro-srv" || name.starts_with("rust-analyzer-proc-macro")
        };
        matches_name(self.comm.as_str()) || self.exe_name().is_some_and(matches_name)
    }

    pub(crate) fn is_rust_analyzer(&self) -> bool {
        let matches_name = |name: &str| name == "rust-analyzer";
        matches_name(self.comm.as_str()) || self.exe_name().is_some_and(matches_name)
    }

    pub(crate) fn is_active_compiler_or_tool(&self) -> bool {
        let matches_sccache = |name: &str| name == "sccache";
        if matches_sccache(self.comm.as_str()) || self.exe_name().is_some_and(matches_sccache) {
            // Background `sccache` daemon has `cwd == /`; only block when `cwd != /`.
            return self.cwd.as_deref().is_some_and(|cwd| cwd != Path::new("/"));
        }

        let matches_tool = |name: &str| {
            matches!(
                name,
                "cargo"
                    | "rustc"
                    | "clippy-driver"
                    | "rustdoc"
                    | "miri"
                    | "lldb"
                    | "gdb"
                    | "sqlx"
                    | "ld"
                    | "lld"
                    | "rust-lld"
            ) || name.starts_with("cargo-")
        };
        matches_tool(self.comm.as_str()) || self.exe_name().is_some_and(matches_tool)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProcessSnapshot {
    pub captured_at_unix: u64,
    pub self_pid: u32,
    pub processes: Vec<ProcessEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WorktreeKind {
    MainCheckout,
    LinkedWorktree,
    NonGit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GitInspection {
    pub repo_common_dir: PathBuf,
    pub worktree_root: PathBuf,
    pub worktree_kind: WorktreeKind,
    pub worktree_dir_missing: bool,
    pub is_dirty: bool,
    pub git_op_in_progress: bool,
    pub worktree_locked: bool,
    pub branch_merged_into_default: Option<bool>,
    pub has_tracked_files_in_target: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GitDiscovery {
    NotInGitRepo,
    Inspected(GitInspection),
    Failed(CompactString),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TargetOrigin {
    VerifiedCargoTag,
    HeuristicNoTag,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TargetLayout {
    BuildDirV2,
    LegacyV1,
    MixedV1V2,
    ArtifactsOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DocDirInfo {
    pub path: PathBuf,
    pub lock_file: Option<PathBuf>,
    pub locked_now: bool,
    pub last_activity_unix: u64,
    pub allocated_bytes: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct CargoTarget {
    pub root: PathBuf,
    pub dev_id: u64,
    pub ino: u64,
    pub origin: TargetOrigin,
    pub layout: TargetLayout,
    pub symlink_or_mount_boundary: bool,
    pub has_unverified_top_entries: bool,
    pub has_pin_marker: bool,
    pub parent_target: Option<PathBuf>,
    pub nested_target_roots: Vec<PathBuf>,
    pub worktree_kind: WorktreeKind,
    pub git: GitDiscovery,
    pub project_dir: Option<PathBuf>,
    pub profiles: Vec<ProfileDir>,
    pub doc_dir: Option<DocDirInfo>,
    pub root_lock_file: Option<PathBuf>,
    pub root_locked_now: bool,
    pub allocated_bytes: u64,
    pub last_activity_unix: u64,
}

impl CargoTarget {
    pub fn worktree_root(&self) -> Option<&Path> {
        match &self.git {
            GitDiscovery::Inspected(git) => Some(git.worktree_root.as_path()),
            GitDiscovery::NotInGitRepo | GitDiscovery::Failed(_) => self.project_dir.as_deref(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProfileDir {
    pub name: CompactString,
    pub rel_path: PathBuf,
    pub layout: TargetLayout,
    pub lock_files: SmallVec<[PathBuf; 4]>,
    pub locked_now: bool,
    pub fingerprint_corrupt: bool,
    pub v2_unit_count: usize,
    pub v1_unit_count: usize,
    pub incremental_dir_count: usize,
    pub v2_units: Vec<BuildUnit>,
    pub v1_units: Vec<BuildUnit>,
    pub incremental_dirs: Vec<IncrementalDir>,
    pub allocated_bytes: u64,
    pub last_activity_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum BuildUnitId {
    V2 {
        pkg: CompactString,
        unit_hash: CompactString,
    },
    V1 {
        fingerprint_dir: CompactString,
        unit_hash: CompactString,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum UnitTargetKind {
    Lib,
    Bin,
    Test,
    Example,
    Bench,
    BuildScriptBuild,
    RunBuildScript,
    Doc,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnitTargetAnchor {
    pub target_kind: UnitTargetKind,
    pub target_name: CompactString,
    pub fingerprint_hash: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) enum UnitMetadata {
    Complete {
        targets: SmallVec<[UnitTargetAnchor; 2]>,
        rustc_hash: u64,
        dep_fp_hashes: SmallVec<[u64; 8]>,
        mtime_unix: u64,
    },
    Incomplete {
        mtime_unix: u64,
    },
}

impl UnitMetadata {
    pub fn mtime_unix(&self) -> u64 {
        match self {
            Self::Complete { mtime_unix, .. } | Self::Incomplete { mtime_unix } => *mtime_unix,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BuildUnit {
    pub id: BuildUnitId,
    pub pkg_group: CompactString,
    pub metadata: UnitMetadata,
    pub v1_build_dir: Option<CompactString>,
    pub v1_dep_entries: Vec<CompactString>,
    pub allocated_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionState {
    Finalized,
    Working,
}

#[derive(Clone, Debug)]
pub(crate) struct IncrementalSession {
    pub dir_name: CompactString,
    pub lock_file: Option<CompactString>,
    pub state: SessionState,
    pub locked: bool,
    pub mtime_unix: u64,
    pub allocated_bytes: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct IncrementalDir {
    pub dir_name: CompactString,
    pub crate_name: CompactString,
    pub sessions: Vec<IncrementalSession>,
    pub any_locked: bool,
    pub latest_mtime_unix: u64,
    pub allocated_bytes: u64,
}

impl IncrementalDir {
    pub fn has_finalized(&self) -> bool {
        self.sessions
            .iter()
            .any(|session| session.state == SessionState::Finalized)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ProtectedReason {
    ActiveCargoLock {
        profile: CompactString,
    },
    ActiveDocLock,
    HardBlockedProcess {
        pid: u32,
        comm: CompactString,
        detail: CompactString,
    },
    GitOperationInProgress,
    TrackedFilesInTarget,
    SymlinkOrMountBoundary,
    UnverifiedNonCargoEntries,
    NestedTargetProtected {
        child: PathBuf,
    },
    PinnedFull,
    PinMarkerFile,
    Cooling {
        remaining_secs: u64,
    },
    ProcessSnapshotUnavailable,
    MountTableUnavailable,
    GitInspectionFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum SweepOnlyReason {
    OpenInteractiveSession { pid: u32, comm: CompactString },
    IdleRustAnalyzer { pid: u32 },
    PinnedAllowSweep,
    DirtyOrUnmergedWorktree,
    MainCheckoutProtected,
    EvictionCooling { remaining_secs: u64 },
    SnapshotHoldActive,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SafetyVerdict {
    Eligible,
    SweepOnly {
        reasons: SmallVec<[SweepOnlyReason; 2]>,
        pinned_unit_paths: Vec<PathBuf>,
    },
    Protected(SmallVec<[ProtectedReason; 4]>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DiskPressure {
    Calm,
    Elevated,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReclaimHoldState {
    pub detected_at_unix: u64,
    pub reclaimed_allocated_bytes: u64,
    pub observed_free_gain_bytes: u64,
    pub free_bytes_at_detection: u64,
    pub pressure_at_detection: DiskPressure,
    pub snapshots_at_detection: Vec<CompactString>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EvictRule {
    R1DeadWorktree,
    R4CooledWorktree,
    R5PressureLru,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuleId {
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
pub(crate) enum SweepUnitReason {
    StaleRustcHash,
    UnreachableDuplicate,
    IncompleteAbortedUnit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct V2UnitRemoval {
    pub pkg: CompactString,
    pub unit_hash: CompactString,
    pub allocated_bytes: u64,
    pub reason: SweepUnitReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct V1UnitRemoval {
    pub fingerprint_dir: CompactString,
    pub build_dir: Option<CompactString>,
    pub dep_entries: Vec<CompactString>,
    pub allocated_bytes: u64,
    pub reason: SweepUnitReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SweepOps {
    V2(Vec<V2UnitRemoval>),
    V1(Vec<V1UnitRemoval>),
    Mixed {
        v2: Vec<V2UnitRemoval>,
        v1: Vec<V1UnitRemoval>,
    },
}

impl SweepOps {
    pub fn unit_count(&self) -> usize {
        match self {
            Self::V2(units) => units.len(),
            Self::V1(units) => units.len(),
            Self::Mixed { v2, v1 } => v2.len().saturating_add(v1.len()),
        }
    }

    pub fn summary_reason(&self) -> CompactString {
        let mut stale = false;
        let mut dup = false;
        let mut incomplete = false;
        let mut record = |reason: SweepUnitReason| match reason {
            SweepUnitReason::StaleRustcHash => stale = true,
            SweepUnitReason::UnreachableDuplicate => dup = true,
            SweepUnitReason::IncompleteAbortedUnit => incomplete = true,
        };
        match self {
            Self::V2(v2) => v2.iter().for_each(|u| record(u.reason)),
            Self::V1(v1) => v1.iter().for_each(|u| record(u.reason)),
            Self::Mixed { v2, v1 } => {
                v2.iter().for_each(|u| record(u.reason));
                v1.iter().for_each(|u| record(u.reason));
            }
        }
        let mut parts: SmallVec<[&'static str; 3]> = SmallVec::new();
        if stale {
            parts.push("stale_rustc");
        }
        if dup {
            parts.push("unreachable_duplicates");
        }
        if incomplete {
            parts.push("incomplete_units");
        }
        if parts.is_empty() {
            CompactString::new("build_sweep")
        } else {
            CompactString::from(parts.join("_and_"))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IncrementalRemoval {
    WholeCrateDir {
        dir_name: CompactString,
        allocated_bytes: u64,
    },
    SingleSession {
        crate_dir: CompactString,
        session_dir: CompactString,
        lock_file: Option<CompactString>,
        allocated_bytes: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReclaimAction {
    ReapLeftoverStaging {
        staging_dir: PathBuf,
        expected_dev: u64,
    },
    SweepBuildUnits {
        target_root: PathBuf,
        target_dev: u64,
        target_ino: u64,
        expected_activity_unix: u64,
        expected_target_activity_unix: u64,
        worktree_root: Option<PathBuf>,
        profile_rel: PathBuf,
        profile_locks: SmallVec<[PathBuf; 4]>,
        ops: SweepOps,
        estimated_allocated_bytes: u64,
    },
    RemoveDoc {
        target_root: PathBuf,
        target_dev: u64,
        target_ino: u64,
        expected_doc_mtime_unix: u64,
        worktree_root: Option<PathBuf>,
        locks: SmallVec<[PathBuf; 5]>,
        estimated_allocated_bytes: u64,
    },
    PruneIncremental {
        target_root: PathBuf,
        target_dev: u64,
        target_ino: u64,
        expected_activity_unix: u64,
        expected_target_activity_unix: u64,
        worktree_root: Option<PathBuf>,
        profile_rel: PathBuf,
        profile_locks: SmallVec<[PathBuf; 4]>,
        removals: Vec<IncrementalRemoval>,
        estimated_allocated_bytes: u64,
    },
    EvictTarget {
        rule: EvictRule,
        target_root: PathBuf,
        target_dev: u64,
        target_ino: u64,
        expected_activity_unix: u64,
        worktree_root: Option<PathBuf>,
        all_locks: Vec<PathBuf>,
        estimated_allocated_bytes: u64,
        reason: CompactString,
    },
}

impl ReclaimAction {
    pub fn rule_id(&self) -> RuleId {
        match self {
            Self::ReapLeftoverStaging { .. } => RuleId::CrashRecovery,
            Self::SweepBuildUnits { .. } => RuleId::R2BuildSweep,
            Self::RemoveDoc { .. } => RuleId::R2DocPrune,
            Self::PruneIncremental { .. } => RuleId::R3IncrementalPrune,
            Self::EvictTarget { rule, .. } => match rule {
                EvictRule::R1DeadWorktree => RuleId::R1DeadWorktree,
                EvictRule::R4CooledWorktree => RuleId::R4CooledWorktree,
                EvictRule::R5PressureLru => RuleId::R5PressureLru,
            },
        }
    }

    pub fn target_root(&self) -> &Path {
        match self {
            Self::ReapLeftoverStaging { staging_dir, .. } => staging_dir.as_path(),
            Self::SweepBuildUnits { target_root, .. }
            | Self::RemoveDoc { target_root, .. }
            | Self::PruneIncremental { target_root, .. }
            | Self::EvictTarget { target_root, .. } => target_root.as_path(),
        }
    }

    pub fn profile_rel(&self) -> Option<&Path> {
        match self {
            Self::SweepBuildUnits { profile_rel, .. }
            | Self::PruneIncremental { profile_rel, .. } => Some(profile_rel.as_path()),
            Self::ReapLeftoverStaging { .. }
            | Self::RemoveDoc { .. }
            | Self::EvictTarget { .. } => None,
        }
    }

    pub fn estimated_allocated_bytes(&self) -> u64 {
        match self {
            Self::ReapLeftoverStaging { .. } => 0,
            Self::SweepBuildUnits {
                estimated_allocated_bytes,
                ..
            }
            | Self::RemoveDoc {
                estimated_allocated_bytes,
                ..
            }
            | Self::PruneIncremental {
                estimated_allocated_bytes,
                ..
            }
            | Self::EvictTarget {
                estimated_allocated_bytes,
                ..
            } => *estimated_allocated_bytes,
        }
    }

    pub fn unit_count(&self) -> u32 {
        let count = match self {
            Self::ReapLeftoverStaging { .. }
            | Self::RemoveDoc { .. }
            | Self::EvictTarget { .. } => 1,
            Self::SweepBuildUnits { ops, .. } => ops.unit_count(),
            Self::PruneIncremental { removals, .. } => removals.len(),
        };
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    pub fn reason(&self) -> CompactString {
        match self {
            Self::ReapLeftoverStaging { .. } => CompactString::new("leftover_staging_recovery"),
            Self::SweepBuildUnits { ops, .. } => ops.summary_reason(),
            Self::RemoveDoc { .. } => CompactString::new("stale_doc_dir"),
            Self::PruneIncremental { .. } => CompactString::new("stale_incremental_sessions"),
            Self::EvictTarget { reason, .. } => reason.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReclaimPlan {
    pub generated_at_unix: u64,
    pub disk: DiskStats,
    pub pressure: DiskPressure,
    pub hold_active: bool,
    pub actions: Vec<ReclaimAction>,
    pub estimated_allocated_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum ActionOutcome {
    Applied,
    DryRun,
    SkippedContested { reason: CompactString },
    SkippedRevalidateChanged { reason: CompactString },
    Failed { error: CompactString },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ActionReceipt {
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
pub(crate) enum PinScope {
    Full,
    AllowSweep,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PinEntry {
    pub pinned_at_unix: u64,
    pub scope: PinScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct KnownTargetEntry {
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub last_layout: TargetLayout,
    pub last_allocated_bytes: u64,
    pub last_activity_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeftoverStaging {
    pub staging_dir: PathBuf,
    pub expected_dev: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ScanSnapshot {
    pub captured_at_unix: u64,
    pub disk: DiskStats,
    pub processes: Option<ProcessSnapshot>,
    pub process_snapshot_error: Option<String>,
    pub mount_table_available: bool,
    pub mount_table_error: Option<String>,
    pub targets: Vec<CargoTarget>,
    pub walk_partial: bool,
    pub leftover_staging: Vec<LeftoverStaging>,
    pub scanned_roots: Vec<PathBuf>,
}

pub(crate) fn bytes_to_gib(bytes: u64) -> f64 {
    bytes as f64 / GIB as f64
}
