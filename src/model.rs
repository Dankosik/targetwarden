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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
#[allow(dead_code)]
pub(crate) struct UnitTargetAnchor {
    pub target_kind: UnitTargetKind,
    pub target_name: CompactString,
    pub fingerprint_hash: Option<u64>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
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

#[derive(Clone, Debug)]
#[allow(dead_code)]
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
#[allow(dead_code)]
pub(crate) struct IncrementalSession {
    pub dir_name: CompactString,
    pub lock_file: Option<CompactString>,
    pub state: SessionState,
    pub locked: bool,
    pub mtime_unix: u64,
    pub allocated_bytes: u64,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct IncrementalDir {
    pub dir_name: CompactString,
    pub crate_name: CompactString,
    pub sessions: Vec<IncrementalSession>,
    pub any_locked: bool,
    pub latest_mtime_unix: u64,
    pub allocated_bytes: u64,
}

impl IncrementalDir {
    #[allow(dead_code)]
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
#[allow(dead_code)]
pub(crate) struct LeftoverStaging {
    pub staging_dir: PathBuf,
    pub expected_dev: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ScanSnapshot {
    pub captured_at_unix: u64,
    pub disk: DiskStats,
    pub processes: Option<ProcessSnapshot>,
    pub mount_table_available: bool,
    pub targets: Vec<CargoTarget>,
    pub walk_partial: bool,
    #[allow(dead_code)]
    pub leftover_staging: Vec<LeftoverStaging>,
    pub scanned_roots: Vec<PathBuf>,
}

pub(crate) fn bytes_to_gib(bytes: u64) -> f64 {
    bytes as f64 / GIB as f64
}
