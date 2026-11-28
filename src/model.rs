//! Core zero-I/O domain types for `targetwarden`.

use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

pub(crate) const GIB: u64 = 1 << 30;
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// Fast SplitMix64-based `u64` hasher for non-adversarial local keys (`st_ino`, fingerprint hashes).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FastU64BuildHasher;

#[derive(Default)]
pub(crate) struct FastU64Hasher(u64);

impl BuildHasher for FastU64BuildHasher {
    type Hasher = FastU64Hasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        FastU64Hasher(0)
    }
}

impl Hasher for FastU64Hasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut h = self.0;
        for &byte in bytes {
            h = h
                .wrapping_mul(0x517c_c1b7_2722_0a95)
                .wrapping_add(u64::from(byte));
        }
        self.0 = h;
    }

    #[inline]
    fn write_u64(&mut self, value: u64) {
        let mut x = value ^ self.0;
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        self.0 = x ^ (x >> 31);
    }
}

/// Precomputed path prefix enabling fast O(len) byte-slice prefix checks on clean Unix paths,
/// falling back to `Path::starts_with` whenever either side has non-normalized components.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PathPrefix<'a> {
    path: &'a Path,
    #[cfg(unix)]
    clean_bytes: Option<&'a [u8]>,
}

impl<'a> PathPrefix<'a> {
    #[inline]
    pub(crate) fn new(path: &'a Path) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let raw = path.as_os_str().as_bytes();
            let trimmed = trim_trailing_slashes(raw);
            let clean_bytes = is_clean_unix_path(trimmed).then_some(trimmed);
            Self { path, clean_bytes }
        }
        #[cfg(not(unix))]
        {
            Self { path }
        }
    }
}

#[cfg(unix)]
#[inline]
fn trim_trailing_slashes(mut bytes: &[u8]) -> &[u8] {
    while bytes.len() > 1 && bytes.last() == Some(&b'/') {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(unix)]
#[inline]
pub(crate) fn is_clean_unix_path(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes[0] != b'/' {
        return false;
    }
    if bytes.len() == 1 {
        return true;
    }
    if bytes.last() == Some(&b'/') {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' {
            let next = i + 1;
            if next < bytes.len() {
                if bytes[next] == b'/' {
                    return false;
                }
                if bytes[next] == b'.' {
                    let after_dot = next + 1;
                    if after_dot == bytes.len() || bytes[after_dot] == b'/' {
                        return false;
                    }
                    if bytes[after_dot] == b'.'
                        && (after_dot + 1 == bytes.len() || bytes[after_dot + 1] == b'/')
                    {
                        return false;
                    }
                }
            }
        }
        i += 1;
    }
    true
}

#[cfg(unix)]
#[inline]
fn clean_bytes_has_prefix(path_bytes: &[u8], prefix_bytes: &[u8]) -> bool {
    if prefix_bytes == b"/" {
        return path_bytes.first() == Some(&b'/');
    }
    path_bytes.starts_with(prefix_bytes)
        && (path_bytes.len() == prefix_bytes.len() || path_bytes[prefix_bytes.len()] == b'/')
}

/// Compact handle into a `PathPool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PathRef {
    #[cfg(unix)]
    start: u32,
    #[cfg(unix)]
    len: u32,
    #[cfg(not(unix))]
    index: u32,
}

/// Contiguous path arena avoiding thousands of individual `PathBuf` heap allocations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PathPool {
    #[cfg(unix)]
    bytes: Vec<u8>,
    #[cfg(unix)]
    all_clean: bool,
    #[cfg(not(unix))]
    paths: Vec<PathBuf>,
}

impl Default for PathPool {
    fn default() -> Self {
        Self::new()
    }
}

impl PathPool {
    pub(crate) fn new() -> Self {
        #[cfg(unix)]
        {
            Self {
                bytes: Vec::new(),
                all_clean: true,
            }
        }
        #[cfg(not(unix))]
        {
            Self { paths: Vec::new() }
        }
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn with_capacity(bytes_hint: usize) -> Self {
        #[cfg(unix)]
        {
            Self {
                bytes: Vec::with_capacity(bytes_hint),
                all_clean: true,
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                paths: Vec::with_capacity(bytes_hint / 64),
            }
        }
    }

    #[cfg(unix)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn try_push_bytes(&mut self, raw: &[u8]) -> Option<PathRef> {
        let start = u32::try_from(self.bytes.len()).ok()?;
        let len = u32::try_from(raw.len()).ok()?;
        let _ = start.checked_add(len)?;
        if self.all_clean && !is_clean_unix_path(raw) {
            self.all_clean = false;
        }
        self.bytes.extend_from_slice(raw);
        Some(PathRef { start, len })
    }

    #[cfg(not(unix))]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn try_push_bytes(&mut self, raw: &[u8]) -> Option<PathRef> {
        let index = u32::try_from(self.paths.len()).ok()?;
        self.paths
            .push(PathBuf::from(String::from_utf8_lossy(raw).into_owned()));
        Some(PathRef { index })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn push_path(&mut self, path: &Path) -> PathRef {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            self.try_push_bytes(path.as_os_str().as_bytes())
                .expect("test path pool exceeded 4 GiB")
        }
        #[cfg(not(unix))]
        {
            let index =
                u32::try_from(self.paths.len()).expect("test path pool exceeded 4B entries");
            self.paths.push(path.to_path_buf());
            PathRef { index }
        }
    }

    #[inline]
    pub(crate) fn get(&self, r: PathRef) -> &Path {
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            let start = r.start as usize;
            let end = start + r.len as usize;
            Path::new(OsStr::from_bytes(&self.bytes[start..end]))
        }
        #[cfg(not(unix))]
        {
            self.paths[r.index as usize].as_path()
        }
    }

    #[cfg(unix)]
    #[inline]
    pub(crate) fn get_bytes(&self, r: PathRef) -> &[u8] {
        let start = r.start as usize;
        let end = start + r.len as usize;
        &self.bytes[start..end]
    }

    #[inline]
    pub(crate) fn has_prefix(&self, r: PathRef, prefix: &PathPrefix<'_>) -> bool {
        #[cfg(unix)]
        if self.all_clean
            && let Some(pref) = prefix.clean_bytes
        {
            return clean_bytes_has_prefix(self.get_bytes(r), pref);
        }
        self.get(r).starts_with(prefix.path)
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    #[inline]
    pub(crate) fn bytes_eq(&self, r: PathRef, decoded: &[u8]) -> bool {
        #[cfg(unix)]
        {
            self.get_bytes(r) == decoded
        }
        #[cfg(not(unix))]
        {
            self.get(r).to_string_lossy().as_bytes() == decoded
        }
    }
}

/// Return `true` if `s` is an exact 16-character lowercase ASCII hex digest.
#[inline]
pub(crate) fn is_16_lower_hex(s: &str) -> bool {
    s.len() == 16
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parse an exact 16-character lowercase ASCII hex string into a big-endian `u64`.
#[inline]
pub(crate) fn parse_16_lower_hex_u64(s: &str) -> Option<u64> {
    let bytes = s.as_bytes();
    if bytes.len() != 16 {
        return None;
    }
    let mut val = 0u64;
    for &b in bytes {
        let nibble = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => return None,
        };
        val = (val << 4) | u64::from(nibble);
    }
    Some(val)
}

/// Format a `u64` into an exact 16-character lowercase ASCII hex `CompactString`.
pub(crate) fn format_16_lower_hex(val: u64) -> CompactString {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    for (i, slot) in buf.iter_mut().enumerate() {
        let shift = (15 - i) * 4;
        *slot = HEX[((val >> shift) & 0xF) as usize];
    }
    let s = std::str::from_utf8(&buf).expect("ascii hex");
    CompactString::from(s)
}

/// Extract the trailing `-<16-lower-hex>` hash from a Cargo V1 `deps/` entry name
/// (e.g., `libfoo-0123456789abcdef.rlib`, `cli-263e2b71e466964d.dSYM`, `crate-0123456789abcdef.*.rcgu.o`).
pub(crate) fn extract_16hex_from_dep_name(name: &str) -> Option<&str> {
    let bytes = name.as_bytes();
    for idx in (0..bytes.len()).rev() {
        if bytes[idx] != b'-' {
            continue;
        }
        let start = idx + 1;
        let end = start + 16;
        if end > bytes.len() {
            continue;
        }
        let next_ok = end == bytes.len() || bytes[end] == b'.';
        if next_ok && is_16_lower_hex(&name[start..end]) {
            return Some(&name[start..end]);
        }
    }
    None
}

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
    pub exe_path: Option<PathRef>,
    pub cwd: Option<PathRef>,
    pub open_paths_start: u32,
    pub open_paths_len: u32,
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct TestProcessEntry {
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
    pub self_exe_path: Option<PathBuf>,
    pub processes: Vec<ProcessEntry>,
    pub open_path_refs: Vec<PathRef>,
    pub path_pool: PathPool,
}

impl ProcessSnapshot {
    #[cfg(test)]
    pub(crate) fn empty(captured_at_unix: u64, self_pid: u32) -> Self {
        Self {
            captured_at_unix,
            self_pid,
            self_exe_path: None,
            processes: Vec::new(),
            open_path_refs: Vec::new(),
            path_pool: PathPool::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_entries(
        captured_at_unix: u64,
        self_pid: u32,
        entries: Vec<TestProcessEntry>,
    ) -> Self {
        let mut path_pool = PathPool::new();
        let mut open_path_refs = Vec::new();
        let mut processes = Vec::with_capacity(entries.len());
        for entry in entries {
            let exe_path = entry.exe_path.as_deref().map(|p| path_pool.push_path(p));
            let cwd = entry.cwd.as_deref().map(|p| path_pool.push_path(p));
            let open_paths_start = u32::try_from(open_path_refs.len()).unwrap_or(u32::MAX);
            for path in &entry.open_paths {
                open_path_refs.push(path_pool.push_path(path));
            }
            let open_paths_len = u32::try_from(entry.open_paths.len()).unwrap_or(u32::MAX);
            processes.push(ProcessEntry {
                pid: entry.pid,
                comm: entry.comm,
                exe_path,
                cwd,
                open_paths_start,
                open_paths_len,
            });
        }
        Self {
            captured_at_unix,
            self_pid,
            self_exe_path: None,
            processes,
            open_path_refs,
            path_pool,
        }
    }

    /// True when `entry` is this process or another instance of the exact same `targetwarden`
    /// binary (which can only be read-only `status`/`scan`/`--dry-run` while `run.lock` is held).
    #[inline]
    pub(crate) fn is_self_or_sibling(&self, entry: &ProcessEntry) -> bool {
        if self.self_pid != 0 && entry.pid == self.self_pid {
            return true;
        }
        if let (Some(self_exe), Some(exe_ref)) = (self.self_exe_path.as_deref(), entry.exe_path) {
            return self.path(exe_ref) == self_exe;
        }
        false
    }

    #[inline]
    pub(crate) fn path(&self, r: PathRef) -> &Path {
        self.path_pool.get(r)
    }

    #[inline]
    pub(crate) fn exe_path(&self, entry: &ProcessEntry) -> Option<&Path> {
        entry.exe_path.map(|r| self.path_pool.get(r))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub(crate) fn cwd(&self, entry: &ProcessEntry) -> Option<&Path> {
        entry.cwd.map(|r| self.path_pool.get(r))
    }

    #[inline]
    pub(crate) fn open_path_refs(&self, entry: &ProcessEntry) -> &[PathRef] {
        let start = entry.open_paths_start as usize;
        let end = start + entry.open_paths_len as usize;
        &self.open_path_refs[start..end]
    }

    #[inline]
    pub(crate) fn path_has_prefix(&self, r: PathRef, prefix: &PathPrefix<'_>) -> bool {
        self.path_pool.has_prefix(r, prefix)
    }

    #[inline]
    pub(crate) fn cwd_has_prefix(&self, entry: &ProcessEntry, prefix: &PathPrefix<'_>) -> bool {
        entry
            .cwd
            .is_some_and(|r| self.path_pool.has_prefix(r, prefix))
    }

    #[inline]
    pub(crate) fn any_open_has_prefix(
        &self,
        entry: &ProcessEntry,
        prefix: &PathPrefix<'_>,
    ) -> bool {
        self.open_path_refs(entry)
            .iter()
            .any(|&r| self.path_pool.has_prefix(r, prefix))
    }

    #[inline]
    pub(crate) fn exe_name(&self, entry: &ProcessEntry) -> Option<&str> {
        self.exe_path(entry)
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
    }

    #[inline]
    pub(crate) fn is_rust_analyzer_proc_macro_srv(&self, entry: &ProcessEntry) -> bool {
        let matches_name = |name: &str| {
            name == "rust-analyzer-proc-macro-srv" || name.starts_with("rust-analyzer-proc-macro")
        };
        matches_name(entry.comm.as_str()) || self.exe_name(entry).is_some_and(matches_name)
    }

    #[inline]
    pub(crate) fn is_rust_analyzer(&self, entry: &ProcessEntry) -> bool {
        let matches_name = |name: &str| name == "rust-analyzer";
        matches_name(entry.comm.as_str()) || self.exe_name(entry).is_some_and(matches_name)
    }

    #[inline]
    pub(crate) fn is_active_compiler_or_tool(&self, entry: &ProcessEntry) -> bool {
        let matches_sccache = |name: &str| name == "sccache";
        if matches_sccache(entry.comm.as_str()) || self.exe_name(entry).is_some_and(matches_sccache)
        {
            // Background `sccache` daemon has `cwd == /`; only block when `cwd != /`.
            return entry
                .cwd
                .is_some_and(|r| self.path_pool.get(r) != Path::new("/"));
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
        matches_tool(entry.comm.as_str()) || self.exe_name(entry).is_some_and(matches_tool)
    }
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
    pub root_mtime_unix: u64,
    pub allocated_bytes: u64,
    pub last_activity_unix: u64,
    pub inventory_stamp: u64,
    pub inventory_computed_at_unix: u64,
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
    /// Contiguous pool of dependency fingerprint hashes referenced by `UnitMetadata::Complete`
    /// `(dep_fp_start, dep_fp_len)` spans across `v2_units` and `v1_units`.
    pub dep_fp_pool: Vec<u64>,
    pub incremental_dirs: Vec<IncrementalDir>,
    pub profile_mtime_unix: u64,
    pub inc_root_mtime_unix: u64,
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
        /// `None` for orphaned V1 `deps/` or `build/` artifacts whose `.fingerprint/` dir is absent.
        fingerprint_dir: Option<CompactString>,
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
        targets: SmallVec<[UnitTargetAnchor; 1]>,
        rustc_hash: u64,
        dep_fp_start: u32,
        dep_fp_len: u32,
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

/// V1-only metadata boxed out of `BuildUnit` so V2 units pay 8 bytes instead of 64 bytes.
#[derive(Clone, Debug)]
pub(crate) struct V1UnitExtras {
    pub pkg_group: CompactString,
    pub build_dir: Option<CompactString>,
    /// Count of uniquely owned `deps/` artifacts (`> 0` iff this unit's 16-hex hash is unique
    /// across `.fingerprint/` or orphaned and matched at least one `deps/` entry).
    pub dep_entry_count: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct BuildUnit {
    pub id: BuildUnitId,
    pub metadata: UnitMetadata,
    pub v1: Option<Box<V1UnitExtras>>,
    pub allocated_bytes: u64,
}

impl BuildUnit {
    #[inline]
    pub(crate) fn pkg_group(&self) -> &str {
        match &self.id {
            BuildUnitId::V2 { pkg, .. } => pkg.as_str(),
            BuildUnitId::V1 { .. } => self
                .v1
                .as_deref()
                .map_or("", |extras| extras.pkg_group.as_str()),
        }
    }

    #[inline]
    pub(crate) fn v1_build_dir(&self) -> Option<&CompactString> {
        self.v1.as_deref().and_then(|e| e.build_dir.as_ref())
    }

    #[inline]
    pub(crate) fn v1_dep_entry_count(&self) -> u32 {
        self.v1.as_deref().map_or(0, |e| e.dep_entry_count)
    }
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
    pub sessions: SmallVec<[IncrementalSession; 1]>,
    pub any_locked: bool,
    pub dir_mtime_unix: u64,
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
    pub fingerprint_dir: Option<CompactString>,
    pub unit_hash: CompactString,
    pub build_dir: Option<CompactString>,
    /// Explicit `deps/` filenames (used by direct callers/tests). When empty and
    /// `sweep_deps_by_hash` is `true`, `execute` resolves `deps/*-<unit_hash>*` entries in one
    /// single-pass scan without retaining tens of thousands of `.rcgu.o` strings in `ScanSnapshot`.
    pub dep_entries: Vec<CompactString>,
    pub sweep_deps_by_hash: bool,
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
        expected_dir_mtime_unix: u64,
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
        expected_profile_mtime_unix: u64,
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
        expected_inc_root_mtime_unix: u64,
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
        expected_root_mtime_unix: u64,
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
pub(crate) struct CachedProfileInventory {
    pub rel_path: PathBuf,
    pub layout: TargetLayout,
    pub allocated_bytes: u64,
    pub last_activity_unix: u64,
    pub v2_unit_count: usize,
    pub v1_unit_count: usize,
    pub incremental_dir_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CachedTargetInventory {
    pub stamp: u64,
    #[serde(default)]
    pub computed_at_unix: u64,
    pub allocated_bytes: u64,
    pub last_activity_unix: u64,
    pub has_doc_dir: bool,
    pub doc_allocated_bytes: u64,
    pub doc_last_activity_unix: u64,
    #[serde(default)]
    pub profiles: Vec<CachedProfileInventory>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct KnownTargetEntry {
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub last_layout: TargetLayout,
    pub last_allocated_bytes: u64,
    pub last_activity_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory_cache: Option<CachedTargetInventory>,
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        PathPool, PathPrefix, extract_16hex_from_dep_name, format_16_lower_hex,
        parse_16_lower_hex_u64,
    };

    #[test]
    fn path_pool_and_prefix_match_std_starts_with_across_edge_cases() {
        let mut pool = PathPool::new();
        let samples = [
            "/",
            "/tmp",
            "/tmp/a",
            "/tmp/a/b",
            "/tmp/ab",
            "/tmp/ab/c",
            "/Users/dev/repo/target",
            "/Users/dev/repo/target/debug/deps/libfoo.dylib",
        ];
        let refs: Vec<_> = samples
            .iter()
            .map(|s| pool.push_path(Path::new(s)))
            .collect();

        let prefixes = [
            "/",
            "/tmp",
            "/tmp/",
            "/tmp/a",
            "/tmp/a/",
            "/tmp/ab",
            "/tmp//a",
            "/tmp/./a",
            "/tmp/a/../a",
            "/Users/dev/repo/target",
            "/Users/dev/repo/target/",
            "relative/path",
        ];

        for p in prefixes {
            let prefix = PathPrefix::new(Path::new(p));
            for (s, &r) in samples.iter().zip(&refs) {
                assert_eq!(
                    pool.has_prefix(r, &prefix),
                    Path::new(s).starts_with(p),
                    "mismatch for path={s:?} prefix={p:?}"
                );
            }
        }

        // Dirty pool (contains `..`, `.`, `//`, or trailing `/`) must still match `Path::starts_with`.
        let mut dirty_pool = PathPool::new();
        let dirty_samples = [
            "/tmp//a/b",
            "/tmp/./a",
            "/tmp/a/",
            "/tmp/a/../b",
            "relative/sub",
        ];
        let dirty_refs: Vec<_> = dirty_samples
            .iter()
            .map(|s| dirty_pool.push_path(Path::new(s)))
            .collect();
        for p in prefixes {
            let prefix = PathPrefix::new(Path::new(p));
            for (s, &r) in dirty_samples.iter().zip(&dirty_refs) {
                assert_eq!(
                    dirty_pool.has_prefix(r, &prefix),
                    Path::new(s).starts_with(p),
                    "dirty pool mismatch for path={s:?} prefix={p:?}"
                );
            }
        }

        #[cfg(unix)]
        {
            let mut raw_pool = PathPool::new();
            let non_utf8 = b"/tmp/dir/\xff\xfe/file.o";
            let r = raw_pool.try_push_bytes(non_utf8).unwrap();
            assert!(raw_pool.bytes_eq(r, non_utf8));
            assert!(!raw_pool.bytes_eq(r, b"/tmp/dir/other"));
            assert!(raw_pool.has_prefix(r, &PathPrefix::new(Path::new("/tmp/dir"))));
            assert!(!raw_pool.has_prefix(r, &PathPrefix::new(Path::new("/tmp/di"))));
        }
    }

    #[test]
    fn hex_hash_and_dep_name_helpers_cover_edge_cases() {
        for (val, text) in [
            (0u64, "0000000000000000"),
            (0xau64, "000000000000000a"),
            (0x0123_4567_89ab_cdef_u64, "0123456789abcdef"),
            (u64::MAX, "ffffffffffffffff"),
        ] {
            assert_eq!(parse_16_lower_hex_u64(text), Some(val));
            assert_eq!(format_16_lower_hex(val).as_str(), text);
        }
        for bad in [
            "",
            "0123456789abcde",
            "0123456789abcdef0",
            "0123456789ABCDEF",
            "0123456789abcdeg",
            "0123456789abcde/",
        ] {
            assert!(
                parse_16_lower_hex_u64(bad).is_none(),
                "expected None for {bad:?}"
            );
        }
        assert_eq!(
            extract_16hex_from_dep_name("libfoo-0123456789abcdef.rlib"),
            Some("0123456789abcdef")
        );
        assert_eq!(
            extract_16hex_from_dep_name("cli-263e2b71e466964d.dSYM"),
            Some("263e2b71e466964d")
        );
        assert_eq!(
            extract_16hex_from_dep_name("app-7a40948c2737c8c4.3k0wux272k1dcstj9vqgjo6t7.rcgu.o"),
            Some("7a40948c2737c8c4")
        );
        assert_eq!(extract_16hex_from_dep_name("nohash.rlib"), None);
    }

    #[test]
    fn is_self_or_sibling_matches_own_pid_or_exact_exe_only() {
        use std::path::PathBuf;

        use compact_str::CompactString;

        use super::{ProcessSnapshot, TestProcessEntry};

        let mut snap = ProcessSnapshot::from_test_entries(
            1000,
            42,
            vec![
                TestProcessEntry {
                    pid: 42,
                    comm: CompactString::new("targetwarden"),
                    exe_path: Some(PathBuf::from("/Users/dev/.local/bin/targetwarden")),
                    cwd: None,
                    open_paths: vec![],
                },
                TestProcessEntry {
                    pid: 99,
                    comm: CompactString::new("targetwarden"),
                    exe_path: Some(PathBuf::from("/Users/dev/.local/bin/targetwarden")),
                    cwd: None,
                    open_paths: vec![],
                },
                TestProcessEntry {
                    pid: 100,
                    comm: CompactString::new("targetwarden"),
                    exe_path: Some(PathBuf::from("/tmp/repo/target/debug/targetwarden")),
                    cwd: None,
                    open_paths: vec![],
                },
                TestProcessEntry {
                    pid: 101,
                    comm: CompactString::new("cargo"),
                    exe_path: Some(PathBuf::from("/Users/dev/.cargo/bin/cargo")),
                    cwd: None,
                    open_paths: vec![],
                },
            ],
        );
        // Without self_exe_path, only self_pid matches
        assert!(snap.is_self_or_sibling(&snap.processes[0]));
        assert!(!snap.is_self_or_sibling(&snap.processes[1]));
        assert!(!snap.is_self_or_sibling(&snap.processes[2]));
        assert!(!snap.is_self_or_sibling(&snap.processes[3]));

        // With self_exe_path, exact sibling binary matches, but differently located binary does NOT
        snap.self_exe_path = Some(PathBuf::from("/Users/dev/.local/bin/targetwarden"));
        assert!(snap.is_self_or_sibling(&snap.processes[0]));
        assert!(snap.is_self_or_sibling(&snap.processes[1]));
        assert!(!snap.is_self_or_sibling(&snap.processes[2]));
        assert!(!snap.is_self_or_sibling(&snap.processes[3]));
    }
}
