//! Imperative Shell (Layer 5): budgeted root traversal (`max_depth`, `max_entries`,
//! non-Rust `.git` cutoff), `CACHEDIR.TAG` / `HeuristicNoTag` verification,
//! 4-layout detection, `fingerprint/*.json` reading, local Git checks, and `st_blocks` accounting.
//!
//! Allowed dependencies: `error`, `model`, `config`, `platform`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use compact_str::CompactString;
use serde::Deserialize;
use smallvec::SmallVec;
#[cfg(not(unix))]
use walkdir::WalkDir;

use crate::config::Config;
use crate::error::AppError;
use crate::model::{
    BuildUnit, BuildUnitId, CachedTargetInventory, CargoTarget, DocDirInfo, FastU64BuildHasher,
    GitDiscovery, GitInspection, IncrementalDir, IncrementalSession, LeftoverStaging, MountEntry,
    PathPrefix, ProcessEntry, ProcessSnapshot, ProfileDir, ScanSnapshot, SessionState,
    TargetLayout, TargetOrigin, UnitMetadata, UnitTargetAnchor, UnitTargetKind, V1UnitExtras,
    WorktreeKind, extract_16hex_from_dep_name, format_16_lower_hex, is_16_lower_hex,
    parse_16_lower_hex_u64,
};
use crate::platform::{
    DEFAULT_VOLUME_MOUNT, LockProbe, Platform, crosses_mount_boundary, has_symlink_boundary,
    normalize_macos_system_symlinks_cow,
};

const CACHEDIR_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";
const MAX_CACHEDIR_TAG_BYTES: u64 = 4 * 1024;
const MAX_RUSTC_INFO_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FINGERPRINT_JSON_BYTES: u64 = 2 * 1024 * 1024;
const MAX_COMPANION_HASH_BYTES: u64 = 64;
const STAGING_PREFIX: &str = ".targetwarden-reap.";
const SIBLING_STAGING_MARKER: &str = ".targetwarden-reap.";
const PIN_MARKER_FILE: &str = ".targetwarden-pin";
const MAX_GIT_WORKERS: usize = 4;

fn bounded_git_worker_count() -> usize {
    std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .clamp(2, MAX_GIT_WORKERS)
}

/// Strictly sorted for O(log N) binary search.
const PRUNED_DIR_NAMES: &[&str] = &[
    ".Trash",
    ".cache",
    ".codegraph",
    ".git",
    ".gradle",
    ".hg",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".turbo",
    ".venv",
    "Library",
    "Pods",
    "__pycache__",
    "dist",
    "node_modules",
    "vendor",
    "venv",
];

/// Non-target subdirectories pruned only once inside a `.git` repository (never at scan root,
/// so default roots such as `~/src` remain scanned normally). Strictly sorted for O(log N) lookup.
const REPO_INNER_PRUNED_DIR_NAMES: &[&str] = &[
    ".agents",
    ".beads",
    ".cargo",
    ".ci",
    ".claude",
    ".cloud",
    ".codex",
    ".config",
    ".cursor",
    ".cursor-plugin",
    ".gemini",
    ".githooks",
    ".github",
    ".grok",
    ".idea",
    ".kilo",
    ".local",
    ".mise",
    ".opencode",
    ".qwen",
    ".railway",
    ".sqlx",
    ".vscode",
    "_bmad",
    "_bmad-output",
    "ansible",
    "api",
    "archive",
    "assets",
    "brands",
    "campaigns",
    "charts",
    "clients",
    "cmd",
    "compose",
    "contracts",
    "deploy",
    "design",
    "docs",
    "env",
    "envoy",
    "evals",
    "fixtures",
    "helm",
    "inbox",
    "infra",
    "internal",
    "k8s",
    "licenses",
    "migrations",
    "observability",
    "openapi",
    "patches",
    "pkg",
    "plans",
    "plugins",
    "postgres",
    "proto",
    "public",
    "quality",
    "research",
    "research_notes",
    "roadmap",
    "scripts",
    "specs",
    "src",
    "static",
    "studio",
    "templates",
    "testdata",
];

/// Controls how deeply target internals are parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScanDetail {
    /// Fast read-only inventory (`status` / `scan`): counts units and incremental dirs without
    /// opening/parsing thousands of `fingerprint/*.json` files or `flock`ing `s-*.lock`.
    Inventory,
    /// Full sweep metadata (`reclaim` / `watch`): reads every `fingerprint/*.json`, companion
    /// hash, `deps/` match, and `incremental/*/s-*.lock` status.
    Full,
}

#[derive(Clone, Debug)]
pub(crate) struct ScanRoot {
    pub path: PathBuf,
    pub max_depth: usize,
    pub explicit: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ScanRequest {
    pub roots: Vec<ScanRoot>,
    pub known_targets: Vec<PathBuf>,
    pub full_walk: bool,
    pub detail: ScanDetail,
    pub volume_mount: PathBuf,
    pub inventory_cache: HashMap<PathBuf, CachedTargetInventory>,
}

impl ScanRequest {
    pub(crate) fn with_default_volume(
        roots: Vec<ScanRoot>,
        known_targets: Vec<PathBuf>,
        full_walk: bool,
        detail: ScanDetail,
    ) -> Self {
        let volume_mount = if Path::new(DEFAULT_VOLUME_MOUNT).exists() {
            PathBuf::from(DEFAULT_VOLUME_MOUNT)
        } else {
            PathBuf::from("/")
        };
        Self {
            roots,
            known_targets,
            full_walk,
            detail,
            volume_mount,
            inventory_cache: HashMap::new(),
        }
    }

    pub(crate) fn with_inventory_cache(
        mut self,
        inventory_cache: HashMap<PathBuf, CachedTargetInventory>,
    ) -> Self {
        self.inventory_cache = inventory_cache;
        self
    }
}

/// Build the default list of roots for `status`, `reclaim`, `watch`, or bare `scan`.
pub(crate) fn build_default_scan_roots(
    home: &Path,
    config: &Config,
    cli_roots: &[PathBuf],
    cargo_target_dir: Option<&Path>,
) -> Result<Vec<ScanRoot>, AppError> {
    let mut roots = Vec::new();
    for path in Config::default_roots(home) {
        if path.is_dir() {
            roots.push(ScanRoot {
                path,
                max_depth: config.discovery.default_max_depth,
                explicit: false,
            });
        }
    }
    if let Some(target_dir) = cargo_target_dir
        && target_dir.is_dir()
    {
        roots.push(ScanRoot {
            path: target_dir.to_path_buf(),
            max_depth: config.discovery.explicit_max_depth,
            explicit: false,
        });
    }
    for path in &config.configured_roots {
        if path.is_dir() {
            roots.push(ScanRoot {
                path: path.clone(),
                max_depth: config.discovery.explicit_max_depth,
                explicit: true,
            });
        }
    }
    for path in cli_roots {
        if !path.exists() {
            return Err(AppError::InvalidPath {
                path: path.clone(),
                message: "root path does not exist".to_owned(),
            });
        }
        roots.push(ScanRoot {
            path: path.clone(),
            max_depth: config.discovery.explicit_max_depth,
            explicit: true,
        });
    }
    Ok(roots)
}

#[derive(Clone, Debug)]
struct DiscoveredCandidate {
    path: PathBuf,
    origin: TargetOrigin,
    forced_boundary_violation: bool,
}

/// Execute a read-only discovery scan across roots and cached known targets.
pub(crate) fn scan<P: Platform + Sync>(
    platform: &P,
    config: &Config,
    request: &ScanRequest,
) -> Result<ScanSnapshot, AppError> {
    let captured_at_unix = platform.now_unix();

    // Overlap independent OS probes (`statvfs`+`tmutil`+`/sbin/mount` and `lsof`) with the
    // outer directory walk using at most 2 probe threads (minimizes macOS thread-magazine RSS).
    let ((disk_res, mount_res), proc_res, walk_result) = std::thread::scope(|scope| {
        let disk_mount_handle = scope.spawn(|| {
            let disk = platform.disk_stats(&request.volume_mount);
            let mounts = platform.mount_table();
            (disk, mounts)
        });
        let proc_handle = scope.spawn(|| platform.process_snapshot());
        let walk_result = discover_candidates(config, request);
        (
            disk_mount_handle
                .join()
                .expect("disk/mount probe thread panicked"),
            proc_handle
                .join()
                .expect("process_snapshot thread panicked"),
            walk_result,
        )
    });

    let disk = disk_res?;
    let (processes, process_snapshot_error) = match proc_res {
        Ok(snapshot) => (Some(snapshot), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let (mounts, mount_table_error) = match mount_res {
        Ok(table) => (Some(table), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let mount_table_available = mounts.is_some();

    let preinspected_git = preinspect_git_for_candidates(&walk_result.candidates, platform);
    let mut session = ScanSession::new(
        platform,
        captured_at_unix,
        config.cooling.sweep_cooling_secs,
        mounts.as_deref(),
        processes.as_ref(),
        request.detail,
        &request.inventory_cache,
        walk_result.leftover_staging,
        walk_result.seen_staging,
        preinspected_git,
    );
    for cand in &walk_result.candidates {
        session.inspect_target(
            &cand.path,
            cand.origin,
            None,
            None,
            None,
            cand.forced_boundary_violation,
        );
    }

    let ScanSession {
        mut targets,
        mut leftover_staging,
        ..
    } = session;

    targets.sort_by(|a, b| a.root.cmp(&b.root));
    leftover_staging.sort_by(|a, b| a.staging_dir.cmp(&b.staging_dir));

    Ok(ScanSnapshot {
        captured_at_unix,
        disk,
        processes,
        process_snapshot_error,
        mount_table_available,
        mount_table_error,
        targets,
        walk_partial: walk_result.walk_partial,
        leftover_staging,
        scanned_roots: walk_result.scanned_roots,
    })
}

struct WalkResult {
    candidates: Vec<DiscoveredCandidate>,
    leftover_staging: Vec<LeftoverStaging>,
    seen_staging: HashSet<(u64, u64)>,
    scanned_roots: Vec<PathBuf>,
    walk_partial: bool,
}

struct WalkTask {
    path: PathBuf,
    depth: usize,
    max_depth: usize,
    repo_cap: Option<usize>,
}

struct WalkState<'a> {
    config: &'a Config,
    deadline: Instant,
    total_entries: usize,
    walk_partial: bool,
    seen_candidates: HashSet<(u64, u64)>,
    candidates: Vec<DiscoveredCandidate>,
    seen_staging: HashSet<(u64, u64)>,
    leftover_staging: Vec<LeftoverStaging>,
}

impl WalkState<'_> {
    #[inline]
    fn consume_budget(&mut self) -> bool {
        self.total_entries = self.total_entries.saturating_add(1);
        if self.total_entries > self.config.discovery.max_entries
            || ((self.total_entries & 0xFF) == 0 && Instant::now() >= self.deadline)
        {
            self.walk_partial = true;
            return false;
        }
        true
    }

    fn record_candidate(&mut self, path: PathBuf, origin: TargetOrigin) {
        if let Ok(meta) = fs::symlink_metadata(&path) {
            let id = file_identity(&path, &meta);
            if self.seen_candidates.insert(id) {
                self.candidates.push(DiscoveredCandidate {
                    path,
                    origin,
                    forced_boundary_violation: false,
                });
            }
        }
    }
}

fn discover_candidates(config: &Config, request: &ScanRequest) -> WalkResult {
    let mut visited_roots: HashSet<(u64, u64)> = HashSet::new();
    let mut scanned_roots: Vec<PathBuf> = Vec::new();
    let mut state = WalkState {
        config,
        deadline: Instant::now() + Duration::from_secs(config.discovery.walk_timeout_secs),
        total_entries: 0,
        walk_partial: false,
        seen_candidates: HashSet::new(),
        candidates: Vec::new(),
        seen_staging: HashSet::new(),
        leftover_staging: Vec::new(),
    };

    if request.full_walk {
        let mut stack: Vec<WalkTask> = Vec::with_capacity(64);
        for root in &request.roots {
            let Ok(lmeta) = fs::symlink_metadata(&root.path) else {
                continue;
            };
            if lmeta.file_type().is_symlink() {
                if root.explicit
                    && let Ok(target_meta) = fs::metadata(&root.path)
                    && target_meta.is_dir()
                    && let Some(origin) = detect_target_origin(&root.path)
                {
                    push_candidate(
                        &mut state.seen_candidates,
                        &mut state.candidates,
                        &root.path,
                        origin,
                        true,
                    );
                }
                continue;
            }
            if !lmeta.is_dir() {
                continue;
            }
            let Ok(canon_root) = fs::canonicalize(&root.path) else {
                continue;
            };
            let Ok(canon_meta) = fs::symlink_metadata(&canon_root) else {
                continue;
            };
            if !visited_roots.insert(file_identity(&canon_root, &canon_meta)) {
                continue;
            }
            scanned_roots.push(canon_root.clone());
            stack.push(WalkTask {
                path: canon_root,
                depth: 0,
                max_depth: root.max_depth,
                repo_cap: None,
            });
        }

        // Single-threaded DFS walk overlaps with `lsof` + `disk_stats`/`mount_table` probes
        // without spawning extra APFS-contending walk threads or `libmalloc` thread magazines.
        while let Some(task) = stack.pop() {
            if state.walk_partial {
                break;
            }
            visit_walk_dir(&task, &mut state, &mut stack);
        }
    }

    let mut checked_known_parents: HashSet<PathBuf> = HashSet::new();
    for known_raw in &request.known_targets {
        let known_norm = normalize_macos_system_symlinks_cow(known_raw);
        let known = known_norm.as_ref();

        if !request.full_walk
            && let Some(parent) = known.parent()
            && checked_known_parents.insert(parent.to_path_buf())
            && let Ok(entries) = fs::read_dir(parent)
        {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str()
                    && is_staging_dir_name(name)
                    && let Ok(meta) = fs::symlink_metadata(entry.path())
                    && meta.file_type().is_dir()
                    && !meta.file_type().is_symlink()
                {
                    let (dev, ino) = file_identity(&entry.path(), &meta);
                    if state.seen_staging.insert((dev, ino)) {
                        state.leftover_staging.push(LeftoverStaging {
                            staging_dir: entry.path(),
                            expected_dev: dev,
                        });
                    }
                }
            }
        }

        let Ok(lmeta) = fs::symlink_metadata(known) else {
            continue;
        };
        if lmeta.file_type().is_symlink() {
            if let Ok(meta) = fs::metadata(known)
                && meta.is_dir()
                && let Some(origin) = detect_target_origin(known)
            {
                push_candidate(
                    &mut state.seen_candidates,
                    &mut state.candidates,
                    known,
                    origin,
                    true,
                );
            }
            continue;
        }
        if !lmeta.is_dir() {
            continue;
        }
        if let Some(origin) = detect_target_origin(known) {
            push_candidate(
                &mut state.seen_candidates,
                &mut state.candidates,
                known,
                origin,
                false,
            );
        }
    }

    // Prune direct nested children when their non-symlink parent target is already a candidate:
    // `inspect_target(parent)` discovers and inspects direct nested children once with
    // `parent_target = Some(parent)`, preventing redundant I/O and double-accounting.
    let non_symlink_roots: HashSet<PathBuf> = state
        .candidates
        .iter()
        .filter(|c| !c.forced_boundary_violation)
        .map(|c| c.path.clone())
        .collect();
    state.candidates.retain(|c| {
        c.forced_boundary_violation
            || c.path
                .parent()
                .is_none_or(|parent| !non_symlink_roots.contains(parent))
    });

    state.candidates.sort_by(|a, b| a.path.cmp(&b.path));

    WalkResult {
        candidates: state.candidates,
        leftover_staging: state.leftover_staging,
        seen_staging: state.seen_staging,
        scanned_roots,
        walk_partial: state.walk_partial,
    }
}

fn visit_walk_dir(task: &WalkTask, state: &mut WalkState<'_>, stack: &mut Vec<WalkTask>) {
    if !state.consume_budget() {
        return;
    }

    let Ok(rd) = fs::read_dir(&task.path) else {
        return;
    };

    let mut has_cachedir_tag = false;
    let mut has_rustc_info = false;
    let mut has_git = false;
    let mut has_cargo_toml = false;
    let mut child_dirs: Vec<PathBuf> = Vec::new();

    for entry in rd.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let os_name = entry.file_name();
        let name_opt = os_name.to_str();

        if ft.is_file() {
            if let Some(name) = name_opt {
                match name {
                    "CACHEDIR.TAG" => has_cachedir_tag = true,
                    ".rustc_info.json" => has_rustc_info = true,
                    "Cargo.toml" => has_cargo_toml = true,
                    ".git" => has_git = true,
                    _ => {}
                }
            }
            continue;
        }
        if !ft.is_dir() {
            continue;
        }

        if let Some(name) = name_opt {
            if name == ".git" {
                has_git = true;
                continue;
            }
            if is_staging_dir_name(name) {
                let staging_path = entry.path();
                if let Ok(meta) = fs::symlink_metadata(&staging_path) {
                    let (dev, ino) = file_identity(&staging_path, &meta);
                    if state.seen_staging.insert((dev, ino)) {
                        state.leftover_staging.push(LeftoverStaging {
                            staging_dir: staging_path,
                            expected_dev: dev,
                        });
                    }
                }
                continue;
            }
            if PRUNED_DIR_NAMES.binary_search(&name).is_ok() {
                continue;
            }
        }
        child_dirs.push(entry.path());
    }

    if has_cachedir_tag {
        let tag_path = task.path.join("CACHEDIR.TAG");
        if fs::symlink_metadata(&tag_path)
            .is_ok_and(|m| m.file_type().is_file() && m.len() <= MAX_CACHEDIR_TAG_BYTES)
            && is_verified_cargo_cachedir_tag(&tag_path)
        {
            state.record_candidate(task.path.clone(), TargetOrigin::VerifiedCargoTag);
            return;
        }
        // Explicit non-Cargo CACHEDIR.TAG (e.g., .ruff_cache, .venv) must NOT fall through
        // to HeuristicNoTag.
    } else if has_rustc_info {
        let rustc_info = task.path.join(".rustc_info.json");
        if fs::symlink_metadata(&rustc_info)
            .is_ok_and(|m| m.file_type().is_file() && m.len() <= MAX_RUSTC_INFO_BYTES)
            && is_valid_rustc_info(&rustc_info)
            && has_any_profile_child(&task.path)
        {
            state.record_candidate(task.path.clone(), TargetOrigin::HeuristicNoTag);
            return;
        }
    }

    if task.depth >= task.max_depth || task.repo_cap.is_some_and(|cap| task.depth >= cap) {
        return;
    }

    // Entering a `.git` repository caps descent per Section 4.1:
    // - Rust repo (`Cargo.toml` at depth 0): `+2` (`target/`, `<subcrate>/target/`).
    // - Non-Rust `.git` repo: `+non_rust_git_extra_depth` (`+2`), lifted to `child_depth + 2`
    //   automatically if a depth-1 child contains `Cargo.toml` (zero redundant `read_dir`).
    let next_cap = if task.repo_cap.is_none() && has_git {
        if has_cargo_toml {
            Some(task.depth.saturating_add(2))
        } else {
            Some(
                task.depth
                    .saturating_add(state.config.discovery.non_rust_git_extra_depth),
            )
        }
    } else if let Some(existing_cap) = task.repo_cap {
        if has_cargo_toml {
            Some(existing_cap.max(task.depth.saturating_add(2)))
        } else {
            Some(existing_cap)
        }
    } else {
        None
    };

    let next_depth = task.depth + 1;
    let is_leaf = next_depth >= task.max_depth || next_cap.is_some_and(|cap| next_depth >= cap);

    for child_path in child_dirs {
        if next_cap.is_some()
            && child_path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| REPO_INNER_PRUNED_DIR_NAMES.binary_search(&name).is_ok())
        {
            continue;
        }
        if is_leaf {
            if !state.consume_budget() {
                return;
            }
            if let Some(origin) = detect_target_origin(&child_path) {
                state.record_candidate(child_path, origin);
            }
        } else {
            stack.push(WalkTask {
                path: child_path,
                depth: next_depth,
                max_depth: task.max_depth,
                repo_cap: next_cap,
            });
        }
    }
}

fn push_candidate(
    seen_candidates: &mut HashSet<(u64, u64)>,
    candidates: &mut Vec<DiscoveredCandidate>,
    path: &Path,
    origin: TargetOrigin,
    forced_boundary_violation: bool,
) {
    if let Ok(meta) = fs::symlink_metadata(path)
        && seen_candidates.insert(file_identity(path, &meta))
    {
        candidates.push(DiscoveredCandidate {
            path: path.to_path_buf(),
            origin,
            forced_boundary_violation,
        });
    }
}

/// Reusable single-threaded per-target hardlink deduplicator.
///
/// Allocates zero heap bytes on targets with no multi-link (`nlink > 1`) files, requires no
/// locks/atomics or 128 KiB Bloom filter, guarantees 100% deterministic hardlink attribution,
/// and supports exact primary-device `d_ino` `statat` skipping when mount boundaries are verified.
struct HardlinkSet {
    primary_dev: u64,
    #[cfg(unix)]
    allow_ino_skip: bool,
    primary: HashSet<u64, FastU64BuildHasher>,
    other_dev: HashSet<(u64, u64)>,
}

impl HardlinkSet {
    fn new() -> Self {
        Self {
            primary_dev: 0,
            #[cfg(unix)]
            allow_ino_skip: false,
            primary: HashSet::with_hasher(FastU64BuildHasher),
            other_dev: HashSet::new(),
        }
    }

    fn reset(&mut self, primary_dev: u64, allow_ino_skip: bool) {
        self.primary_dev = primary_dev;
        #[cfg(unix)]
        {
            self.allow_ino_skip = allow_ino_skip;
        }
        #[cfg(not(unix))]
        let _ = allow_ino_skip;
        if self.primary.capacity() > 4096 {
            self.primary = HashSet::with_hasher(FastU64BuildHasher);
        } else {
            self.primary.clear();
        }
        if !self.other_dev.is_empty() {
            self.other_dev = HashSet::new();
        }
    }

    /// Exact membership check for a primary-device regular file `d_ino`.
    #[cfg(unix)]
    #[inline]
    fn contains_primary(&self, ino: u64) -> bool {
        self.allow_ino_skip && !self.primary.is_empty() && self.primary.contains(&ino)
    }

    /// Record a multi-link (`nlink > 1`) file inode and return `bytes` on first sight or `0`
    /// if another hardlink to the same `(dev, ino)` was already accounted.
    #[inline]
    fn insert_and_count(&mut self, dev: u64, ino: u64, bytes: u64) -> u64 {
        if dev == self.primary_dev {
            if self.primary.insert(ino) { bytes } else { 0 }
        } else if self.other_dev.insert((dev, ino)) {
            bytes
        } else {
            0
        }
    }
}

/// Reusable scratch buffers avoiding per-directory `CString`, `PathBuf`, and JSON `Vec` churn.
#[derive(Default)]
struct DirScratch {
    #[cfg(unix)]
    name_arena: Vec<u8>,
    #[cfg(unix)]
    name_spans: Vec<(usize, usize)>,
    read_buf: Vec<u8>,
    #[cfg(unix)]
    path_buf: PathBuf,
}

#[derive(Clone, Copy, Debug)]
enum MtimePolicy {
    None,
    UpToDepth(usize),
    /// Track `s-*.lock` files (depth 1) and `s-*` session dirs/files (depth 1..=2) inside
    /// `incremental/<crate>-<base36>/` without folding depth-0 `<crate>/` directory mtime.
    IncrementalCrateDir,
    V2PkgDir,
    #[cfg_attr(not(unix), allow(dead_code))]
    V2UnitFingerprint {
        unit_depth: usize,
    },
}

#[derive(Default)]
struct DirAccountResult {
    bytes: u64,
    max_mtime: u64,
    v2_unit_count: usize,
}

pub(crate) fn is_staging_dir_name(name: &str) -> bool {
    name.starts_with(STAGING_PREFIX)
        || (name.starts_with('.') && name.contains(SIBLING_STAGING_MARKER))
}

/// Detect whether `dir` is a genuine Cargo target directory.
pub(crate) fn detect_target_origin(dir: &Path) -> Option<TargetOrigin> {
    let tag_path = dir.join("CACHEDIR.TAG");
    if let Ok(meta) = fs::symlink_metadata(&tag_path) {
        if meta.file_type().is_file()
            && meta.len() <= MAX_CACHEDIR_TAG_BYTES
            && is_verified_cargo_cachedir_tag(&tag_path)
        {
            return Some(TargetOrigin::VerifiedCargoTag);
        }
        // A non-Cargo CACHEDIR.TAG (e.g., .ruff_cache, .venv, .pytest_cache) is explicitly rejected.
        return None;
    }

    let rustc_info = dir.join(".rustc_info.json");
    if let Ok(meta) = fs::symlink_metadata(&rustc_info)
        && meta.file_type().is_file()
        && meta.len() <= MAX_RUSTC_INFO_BYTES
        && is_valid_rustc_info(&rustc_info)
        && has_any_profile_child(dir)
    {
        return Some(TargetOrigin::HeuristicNoTag);
    }

    None
}

fn is_verified_cargo_cachedir_tag(path: &Path) -> bool {
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; MAX_CACHEDIR_TAG_BYTES as usize + 1];
    let mut len = 0usize;
    loop {
        match file.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => {
                len += n;
                if len as u64 > MAX_CACHEDIR_TAG_BYTES {
                    return false;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return false,
        }
    }
    let slice = &buf[..len];
    if !slice.starts_with(CACHEDIR_SIGNATURE) {
        return false;
    }
    let rest = &slice[CACHEDIR_SIGNATURE.len()..];
    contains_ascii_case_insensitive(rest, b"cargo")
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    haystack
        .windows(needle_lower.len())
        .any(|window| window.eq_ignore_ascii_case(needle_lower))
}

struct NonNullValue;

impl<'de> Deserialize<'de> for NonNullValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<serde::de::IgnoredAny>::deserialize(deserializer)?
            .map(|_| Self)
            .ok_or_else(|| serde::de::Error::custom("expected non-null value"))
    }
}

struct JsonObjectOnly;

impl<'de> Deserialize<'de> for JsonObjectOnly {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjVisitor;
        impl<'de> serde::de::Visitor<'de> for ObjVisitor {
            type Value = JsonObjectOnly;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                while map
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(JsonObjectOnly)
            }
        }
        deserializer.deserialize_map(ObjVisitor)
    }
}

#[derive(Deserialize)]
struct MinimalRustcInfo {
    #[serde(rename = "rustc_fingerprint")]
    _rustc_fingerprint: NonNullValue,
    #[serde(rename = "outputs")]
    _outputs: JsonObjectOnly,
}

fn is_valid_rustc_info(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let mut buf = Vec::new();
    if file
        .take(MAX_RUSTC_INFO_BYTES + 1)
        .read_to_end(&mut buf)
        .is_err()
    {
        return false;
    }
    if buf.len() as u64 > MAX_RUSTC_INFO_BYTES {
        return false;
    }
    serde_json::from_slice::<MinimalRustcInfo>(&buf).is_ok()
}

fn has_any_profile_child(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if !ft.is_dir() || ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        if is_profile_dir(&path) {
            return true;
        }
        // Check one level deeper for `<target-triple>/<profile>/`
        if let Ok(sub_entries) = fs::read_dir(&path) {
            for sub in sub_entries.flatten() {
                if sub
                    .file_type()
                    .is_ok_and(|sft| sft.is_dir() && !sft.is_symlink())
                    && is_profile_dir(&sub.path())
                {
                    return true;
                }
            }
        }
    }
    false
}

fn is_profile_dir(dir: &Path) -> bool {
    const PROFILE_MARKERS: &[&str] = &[
        ".cargo-lock",
        ".cargo-build-lock",
        ".cargo-artifact-lock",
        "build",
        ".fingerprint",
        "deps",
        "incremental",
    ];
    let mut candidate = dir.to_path_buf();
    for marker in PROFILE_MARKERS {
        candidate.push(marker);
        let found = fs::symlink_metadata(&candidate).is_ok_and(|m| !m.file_type().is_symlink());
        candidate.pop();
        if found {
            return true;
        }
    }
    false
}

#[derive(Clone, Copy)]
struct ClassifiedProc<'a> {
    entry: &'a ProcessEntry,
    is_proc_macro_srv: bool,
    is_compiler_or_tool: bool,
}

struct ProfileProbe {
    profile: ProfileDir,
    full_path: PathBuf,
    has_v1_fp_dir: bool,
    has_v1_deps_dir: bool,
    has_build_dir: bool,
    has_inc_dir: bool,
}

#[derive(Clone, Copy, Default)]
struct V1DepHashStats {
    bytes: u64,
    max_mtime: u64,
    count: u32,
}

struct PreinspectedGit {
    by_target: HashMap<PathBuf, GitDiscovery>,
    git_repo_cache: HashMap<PathBuf, Result<RepoGitInfo, CompactString>>,
    default_ref_cache: HashMap<PathBuf, Option<String>>,
}

struct ScanSession<'a, P: Platform + Sync> {
    platform: &'a P,
    captured_at_unix: u64,
    sweep_cooling_secs: u64,
    mounts: Option<&'a [MountEntry]>,
    processes: Option<&'a ProcessSnapshot>,
    classified_procs: Vec<ClassifiedProc<'a>>,
    detail: ScanDetail,
    inventory_cache: &'a HashMap<PathBuf, CachedTargetInventory>,
    visited_targets: HashSet<(u64, u64)>,
    target_idx_by_id: HashMap<(u64, u64), usize>,
    targets: Vec<CargoTarget>,
    leftover_staging: Vec<LeftoverStaging>,
    seen_staging: HashSet<(u64, u64)>,
    precomputed_git: HashMap<PathBuf, GitDiscovery>,
    git_repo_cache: HashMap<PathBuf, Result<RepoGitInfo, CompactString>>,
    default_ref_cache: HashMap<PathBuf, Option<String>>,
    hardlinks: HardlinkSet,
    scratch: DirScratch,
}

impl<'a, P: Platform + Sync> ScanSession<'a, P> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        platform: &'a P,
        captured_at_unix: u64,
        sweep_cooling_secs: u64,
        mounts: Option<&'a [MountEntry]>,
        processes: Option<&'a ProcessSnapshot>,
        detail: ScanDetail,
        inventory_cache: &'a HashMap<PathBuf, CachedTargetInventory>,
        leftover_staging: Vec<LeftoverStaging>,
        seen_staging: HashSet<(u64, u64)>,
        preinspected_git: PreinspectedGit,
    ) -> Self {
        let classified_procs = processes
            .map(|proc_snap| {
                proc_snap
                    .processes
                    .iter()
                    .filter(|p| !proc_snap.is_self_or_sibling(p))
                    .map(|entry| ClassifiedProc {
                        entry,
                        is_proc_macro_srv: proc_snap.is_rust_analyzer_proc_macro_srv(entry),
                        is_compiler_or_tool: proc_snap.is_active_compiler_or_tool(entry),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            platform,
            captured_at_unix,
            sweep_cooling_secs,
            mounts,
            processes,
            classified_procs,
            detail,
            inventory_cache,
            visited_targets: HashSet::new(),
            target_idx_by_id: HashMap::new(),
            targets: Vec::new(),
            leftover_staging,
            seen_staging,
            precomputed_git: preinspected_git.by_target,
            git_repo_cache: preinspected_git.git_repo_cache,
            default_ref_cache: preinspected_git.default_ref_cache,
            hardlinks: HardlinkSet::new(),
            scratch: DirScratch::default(),
        }
    }

    fn lookup_inventory_cache(&self, target_root: &Path) -> Option<&'a CachedTargetInventory> {
        if let Some(hit) = self.inventory_cache.get(target_root) {
            return Some(hit);
        }
        let norm = normalize_macos_system_symlinks_cow(target_root);
        if norm.as_ref() != target_root {
            return self.inventory_cache.get(norm.as_ref());
        }
        None
    }

    fn process_hard_blocks_target(&self, target_root: &Path, worktree_root: Option<&Path>) -> bool {
        let Some(proc_snap) = self.processes else {
            return true;
        };
        let target_prefix = PathPrefix::new(target_root);
        let wt_prefix = worktree_root.map(PathPrefix::new);
        for proc_info in &self.classified_procs {
            let entry = proc_info.entry;
            if proc_snap.cwd_has_prefix(entry, &target_prefix) {
                return true;
            }
            if proc_info.is_proc_macro_srv {
                for &path_ref in proc_snap.open_path_refs(entry) {
                    if proc_snap.path_has_prefix(path_ref, &target_prefix)
                        && proc_snap
                            .path(path_ref)
                            .extension()
                            .and_then(|e| e.to_str())
                            != Some("dylib")
                    {
                        return true;
                    }
                }
                continue;
            }
            if proc_snap.any_open_has_prefix(entry, &target_prefix) {
                return true;
            }
            if proc_info.is_compiler_or_tool
                && let Some(wt) = wt_prefix
                && (proc_snap.cwd_has_prefix(entry, &wt)
                    || proc_snap.any_open_has_prefix(entry, &wt))
            {
                return true;
            }
        }
        false
    }

    fn inspect_target(
        &mut self,
        target_root: &Path,
        origin: TargetOrigin,
        parent_target: Option<PathBuf>,
        parent_project_dir: Option<&Path>,
        parent_clean_git: Option<(&Path, &Path)>,
        forced_boundary_violation: bool,
    ) {
        let Ok(lmeta) = fs::symlink_metadata(target_root) else {
            return;
        };
        let (dev_id, ino) = file_identity(target_root, &lmeta);
        let root_mtime_unix = meta_mtime_unix(&lmeta);
        let target_key = (dev_id, ino);
        if let Some(&existing_idx) = self.target_idx_by_id.get(&target_key) {
            let existing = &mut self.targets[existing_idx];
            if existing.parent_target.is_none() && parent_target.is_some() {
                existing.parent_target = parent_target;
            }
            return;
        }
        if !self.visited_targets.insert(target_key) {
            return;
        }

        let symlink_or_mount_boundary = forced_boundary_violation
            || lmeta.file_type().is_symlink()
            || has_symlink_boundary(target_root)
            || crosses_mount_boundary(target_root, dev_id, self.mounts);

        // Reset reusable per-target hardlink tracker (exact d_ino skip enabled only when
        // mount table was verified and target has no symlink or mount boundary).
        self.hardlinks
            .reset(dev_id, !symlink_or_mount_boundary && self.mounts.is_some());

        let mut profile_probes: Vec<ProfileProbe> = Vec::new();
        let mut doc_dir: Option<DocDirInfo> = None;
        let mut top_account_dirs: Vec<PathBuf> = Vec::new();
        let mut nested_target_roots: Vec<PathBuf> = Vec::new();
        let mut nested_to_inspect: Vec<(PathBuf, TargetOrigin)> = Vec::new();
        let mut has_unverified_top_entries = false;
        let mut has_pin_marker = pin_marker_present_fail_closed(&target_root.join(PIN_MARKER_FILE));
        let mut allocated_bytes: u64 = 0;
        let mut last_activity_unix: u64 = 0;

        let legacy_root_lock = target_root.join(".cargo-lock");
        let has_legacy_root_lock =
            fs::symlink_metadata(&legacy_root_lock).is_ok_and(|m| m.file_type().is_file());
        let root_lock_file = has_legacy_root_lock.then_some(legacy_root_lock.clone());
        let root_locked_now = if has_legacy_root_lock {
            match self.platform.try_lock_readonly(&legacy_root_lock) {
                Ok(LockProbe::Acquired(file)) => {
                    let _ = file.unlock();
                    false
                }
                Ok(LockProbe::NotFound) => false,
                Ok(LockProbe::Contested) | Err(_) => true,
            }
        } else {
            false
        };

        let git = self.precomputed_git.remove(target_root).unwrap_or_else(|| {
            inspect_git_for_target(
                target_root,
                self.platform,
                &mut self.git_repo_cache,
                &mut self.default_ref_cache,
                parent_clean_git,
            )
        });
        let worktree_kind = match &git {
            GitDiscovery::Inspected(info) => info.worktree_kind,
            GitDiscovery::NotInGitRepo | GitDiscovery::Failed(_) => WorktreeKind::NonGit,
        };
        let project_dir = match &git {
            GitDiscovery::Inspected(info) => Some(info.worktree_root.clone()),
            GitDiscovery::NotInGitRepo | GitDiscovery::Failed(_) => {
                infer_non_git_project_dir(target_root)
                    .or_else(|| parent_project_dir.map(Path::to_path_buf))
            }
        };
        if let Some(proj) = &project_dir
            && pin_marker_present_fail_closed(&proj.join(PIN_MARKER_FILE))
        {
            has_pin_marker = true;
        }
        let child_project_dir = project_dir.clone();
        let child_clean_git: Option<(PathBuf, PathBuf)> = match &git {
            GitDiscovery::Inspected(info)
                if !info.has_tracked_files_in_target
                    && !info.worktree_dir_missing
                    && !symlink_or_mount_boundary =>
            {
                Some((
                    info.worktree_root.clone(),
                    normalize_macos_system_symlinks_cow(target_root).into_owned(),
                ))
            }
            _ => None,
        };

        // Fail closed when `target_root` cannot be read: never classify an unreadable
        // target directory as an empty `ArtifactsOnly` `Eligible` target.
        let entries: Vec<_> = match fs::read_dir(target_root) {
            Ok(rd) => rd.flatten().collect(),
            Err(_) => {
                has_unverified_top_entries = true;
                Vec::new()
            }
        };

        for entry in entries {
            let entry_path = entry.path();
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                if origin == TargetOrigin::HeuristicNoTag {
                    has_unverified_top_entries = true;
                }
                continue;
            };
            let Ok(emeta) = fs::symlink_metadata(&entry_path) else {
                continue;
            };
            let ft = emeta.file_type();

            if ft.is_dir() && is_staging_dir_name(&name) {
                let (sdev, sino) = file_identity(&entry_path, &emeta);
                if self.seen_staging.insert((sdev, sino)) {
                    self.leftover_staging.push(LeftoverStaging {
                        staging_dir: entry_path,
                        expected_dev: sdev,
                    });
                }
                continue;
            }

            if name == PIN_MARKER_FILE {
                has_pin_marker = true;
                continue;
            }

            if name == ".rustc_info.json" || name == ".rustdoc_fingerprint.json" {
                last_activity_unix = last_activity_unix.max(meta_mtime_unix(&emeta));
                allocated_bytes = allocated_bytes
                    .saturating_add(entry_allocated_bytes(&emeta, &mut self.hardlinks));
                continue;
            }

            if name == "CACHEDIR.TAG" || name == ".cargo-lock" {
                allocated_bytes = allocated_bytes
                    .saturating_add(entry_allocated_bytes(&emeta, &mut self.hardlinks));
                continue;
            }

            if ft.is_dir() && !ft.is_symlink() {
                if name == "doc" {
                    let info = probe_doc_dir(&entry_path, self.platform);
                    last_activity_unix = last_activity_unix.max(info.last_activity_unix);
                    doc_dir = Some(info);
                    continue;
                }
                if name == "tmp" || name == "package" {
                    top_account_dirs.push(entry_path);
                    continue;
                }
                if let Some(nested_origin) = detect_target_origin(&entry_path) {
                    nested_target_roots.push(entry_path.clone());
                    nested_to_inspect.push((entry_path, nested_origin));
                    continue;
                }
                if is_profile_dir(&entry_path) {
                    profile_probes.push(probe_profile_dir(
                        Path::new(&name),
                        &entry_path,
                        has_legacy_root_lock.then_some(legacy_root_lock.as_path()),
                        self.platform,
                    ));
                    continue;
                }
                // Check `<target-triple>/<profile>/` one level deeper.
                let triple_profiles = find_triple_profiles(&entry_path);
                if !triple_profiles.is_empty() {
                    for sub_name in triple_profiles {
                        let rel = PathBuf::from(&name).join(&sub_name);
                        let full = entry_path.join(&sub_name);
                        profile_probes.push(probe_profile_dir(
                            &rel,
                            &full,
                            has_legacy_root_lock.then_some(legacy_root_lock.as_path()),
                            self.platform,
                        ));
                    }
                    continue;
                }
            }

            // Unknown top-level entry.
            if origin == TargetOrigin::HeuristicNoTag {
                has_unverified_top_entries = true;
            }
            if ft.is_dir() && !ft.is_symlink() {
                top_account_dirs.push(entry_path);
            } else {
                allocated_bytes = allocated_bytes
                    .saturating_add(entry_allocated_bytes(&emeta, &mut self.hardlinks));
            }
        }

        profile_probes.sort_by(|a, b| a.profile.rel_path.cmp(&b.profile.rel_path));
        nested_target_roots.sort();
        top_account_dirs.sort();

        // Downgrade to fast Inventory mode when fast barriers already guarantee `Protected`.
        let any_profile_locked = profile_probes.iter().any(|p| p.profile.locked_now);
        let doc_locked = doc_dir.as_ref().is_some_and(|d| d.locked_now);
        let guaranteed_cooling = last_activity_unix > 0
            && self.captured_at_unix.saturating_sub(last_activity_unix) < self.sweep_cooling_secs;
        let target_hard_blocked = self.processes.is_none()
            || self.mounts.is_none()
            || symlink_or_mount_boundary
            || has_unverified_top_entries
            || root_locked_now
            || any_profile_locked
            || doc_locked
            || has_pin_marker
            || guaranteed_cooling
            || match &git {
                GitDiscovery::Failed(_) => true,
                GitDiscovery::Inspected(info) => {
                    info.git_op_in_progress || info.has_tracked_files_in_target
                }
                GitDiscovery::NotInGitRepo => false,
            }
            || self.process_hard_blocks_target(target_root, project_dir.as_deref());

        let effective_detail = if target_hard_blocked {
            ScanDetail::Inventory
        } else {
            self.detail
        };

        let inventory_stamp = if !symlink_or_mount_boundary {
            compute_target_inventory_stamp(
                target_root,
                &lmeta,
                doc_dir.as_ref(),
                &profile_probes,
                &top_account_dirs,
            )
        } else {
            0
        };

        let cached_hit = if effective_detail == ScanDetail::Inventory && inventory_stamp != 0 {
            self.lookup_inventory_cache(target_root).filter(|cached| {
                cached.stamp == inventory_stamp
                    && cached.has_doc_dir == doc_dir.is_some()
                    && cached.profiles.len() == profile_probes.len()
                    && cached
                        .profiles
                        .iter()
                        .zip(profile_probes.iter())
                        .all(|(c, p)| c.rel_path == p.profile.rel_path)
            })
        } else {
            None
        };

        let mut profiles = Vec::with_capacity(profile_probes.len());
        let inventory_computed_at_unix = if let Some(cached) = cached_hit {
            if let Some(doc) = &mut doc_dir {
                doc.allocated_bytes = cached.doc_allocated_bytes;
                doc.last_activity_unix = doc.last_activity_unix.max(cached.doc_last_activity_unix);
            }
            for (mut probe, cprof) in profile_probes.into_iter().zip(&cached.profiles) {
                probe.profile.layout = cprof.layout;
                probe.profile.allocated_bytes = cprof.allocated_bytes;
                probe.profile.last_activity_unix = cprof.last_activity_unix;
                probe.profile.v2_unit_count = cprof.v2_unit_count;
                probe.profile.v1_unit_count = cprof.v1_unit_count;
                probe.profile.incremental_dir_count = cprof.incremental_dir_count;
                profiles.push(probe.profile);
            }
            allocated_bytes = cached.allocated_bytes;
            last_activity_unix = last_activity_unix.max(cached.last_activity_unix);
            cached.computed_at_unix
        } else {
            // Stream all target subdirectories single-threaded on the main thread:
            // avoids APFS kernel vnode/B-tree lock contention (~2.8x sys CPU savings),
            // eliminates per-target thread spawns and cross-thread `libmalloc` magazine retention,
            // and guarantees 100% deterministic hardlink attribution.
            if let Some(doc) = &mut doc_dir {
                let res = account_tree(
                    &doc.path,
                    MtimePolicy::UpToDepth(2),
                    None,
                    &mut self.hardlinks,
                    &mut self.scratch,
                );
                doc.allocated_bytes = doc.allocated_bytes.saturating_add(res.bytes);
                if res.max_mtime > 0 {
                    doc.last_activity_unix = doc.last_activity_unix.max(res.max_mtime);
                    last_activity_unix = last_activity_unix.max(res.max_mtime);
                }
                allocated_bytes = allocated_bytes.saturating_add(res.bytes);
            }
            for dir_path in top_account_dirs {
                let res = account_tree(
                    &dir_path,
                    MtimePolicy::None,
                    None,
                    &mut self.hardlinks,
                    &mut self.scratch,
                );
                allocated_bytes = allocated_bytes.saturating_add(res.bytes);
            }

            for probe in profile_probes {
                let profile_detail = if probe.profile.locked_now {
                    ScanDetail::Inventory
                } else {
                    effective_detail
                };
                let profile = if profile_detail == ScanDetail::Inventory {
                    inspect_profile_inventory(probe, &mut self.hardlinks, &mut self.scratch)
                } else {
                    inspect_profile_full(
                        probe,
                        self.platform,
                        &mut self.hardlinks,
                        &mut self.scratch,
                    )
                };
                allocated_bytes = allocated_bytes.saturating_add(profile.allocated_bytes);
                last_activity_unix = last_activity_unix.max(profile.last_activity_unix);
                profiles.push(profile);
            }
            if inventory_stamp != 0 {
                self.captured_at_unix
            } else {
                0
            }
        };

        if last_activity_unix == 0 {
            last_activity_unix = root_mtime_unix;
        }

        let layout = classify_target_layout(&profiles);
        let idx = self.targets.len();
        self.target_idx_by_id.insert(target_key, idx);
        self.targets.push(CargoTarget {
            root: target_root.to_path_buf(),
            dev_id,
            ino,
            origin,
            layout,
            symlink_or_mount_boundary,
            has_unverified_top_entries,
            has_pin_marker,
            parent_target,
            nested_target_roots,
            worktree_kind,
            git,
            project_dir,
            profiles,
            doc_dir,
            root_lock_file,
            root_locked_now,
            root_mtime_unix,
            allocated_bytes,
            last_activity_unix,
            inventory_stamp,
            inventory_computed_at_unix,
        });

        for (nested_path, nested_origin) in nested_to_inspect {
            let clean_ref = child_clean_git
                .as_ref()
                .map(|(wt, parent_norm)| (wt.as_path(), parent_norm.as_path()));
            self.inspect_target(
                &nested_path,
                nested_origin,
                Some(target_root.to_path_buf()),
                child_project_dir.as_deref(),
                clean_ref,
                false,
            );
        }
    }
}

fn find_triple_profiles(triple_dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(triple_dir) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        if entry
            .file_type()
            .is_ok_and(|ft| ft.is_dir() && !ft.is_symlink())
            && is_profile_dir(&entry.path())
            && let Some(name) = entry.file_name().to_str()
        {
            found.push(name.to_owned());
        }
    }
    found.sort();
    found
}

fn classify_target_layout(profiles: &[ProfileDir]) -> TargetLayout {
    let mut has_v2 = false;
    let mut has_v1 = false;
    for profile in profiles {
        match profile.layout {
            TargetLayout::MixedV1V2 => return TargetLayout::MixedV1V2,
            TargetLayout::BuildDirV2 => has_v2 = true,
            TargetLayout::LegacyV1 => has_v1 = true,
            TargetLayout::ArtifactsOnly => {}
        }
    }
    match (has_v2, has_v1) {
        (true, true) => TargetLayout::MixedV1V2,
        (true, false) => TargetLayout::BuildDirV2,
        (false, true) => TargetLayout::LegacyV1,
        (false, false) => TargetLayout::ArtifactsOnly,
    }
}

fn probe_doc_dir(doc_path: &Path, platform: &impl Platform) -> DocDirInfo {
    let lock_candidate = doc_path.join(".lock");
    let (lock_file, locked_now) =
        if fs::symlink_metadata(&lock_candidate).is_ok_and(|m| m.file_type().is_file()) {
            let locked = match platform.try_lock_readonly(&lock_candidate) {
                Ok(LockProbe::Acquired(file)) => {
                    let _ = file.unlock();
                    false
                }
                Ok(LockProbe::NotFound) => false,
                Ok(LockProbe::Contested) | Err(_) => true,
            };
            (Some(lock_candidate), locked)
        } else {
            (None, false)
        };
    let last_activity_unix = fs::symlink_metadata(doc_path)
        .map(|m| meta_mtime_unix(&m))
        .unwrap_or(0);

    DocDirInfo {
        path: doc_path.to_path_buf(),
        lock_file,
        locked_now,
        last_activity_unix,
        allocated_bytes: 0,
    }
}

fn probe_profile_dir(
    rel_path: &Path,
    profile_path: &Path,
    legacy_root_lock: Option<&Path>,
    platform: &impl Platform,
) -> ProfileProbe {
    let mut lock_files: SmallVec<[PathBuf; 4]> = SmallVec::new();
    for lock_name in [".cargo-artifact-lock", ".cargo-build-lock", ".cargo-lock"] {
        let candidate = profile_path.join(lock_name);
        if fs::symlink_metadata(&candidate).is_ok_and(|m| m.file_type().is_file()) {
            lock_files.push(candidate);
        }
    }
    if let Some(root_lock) = legacy_root_lock {
        lock_files.push(root_lock.to_path_buf());
    }
    lock_files.sort();
    lock_files.dedup();

    let mut locked_now = false;
    for lock_path in &lock_files {
        match platform.try_lock_readonly(lock_path) {
            Ok(LockProbe::Acquired(file)) => {
                let _ = file.unlock();
            }
            Ok(LockProbe::NotFound) => {}
            Ok(LockProbe::Contested) | Err(_) => {
                locked_now = true;
            }
        }
    }

    let fp_root = profile_path.join(".fingerprint");
    let deps_root = profile_path.join("deps");
    let build_root = profile_path.join("build");
    let inc_root = profile_path.join("incremental");

    let has_v1_fp_dir = fs::symlink_metadata(&fp_root).is_ok_and(|m| m.file_type().is_dir());
    let has_v1_deps_dir = fs::symlink_metadata(&deps_root).is_ok_and(|m| m.file_type().is_dir());
    let has_build_dir = fs::symlink_metadata(&build_root).is_ok_and(|m| m.file_type().is_dir());
    let inc_meta = fs::symlink_metadata(&inc_root).ok();
    let has_inc_dir = inc_meta.as_ref().is_some_and(|m| m.file_type().is_dir());
    let profile_mtime_unix = fs::symlink_metadata(profile_path)
        .map(|m| meta_mtime_unix(&m))
        .unwrap_or(0);
    let inc_root_mtime_unix = inc_meta
        .as_ref()
        .filter(|m| m.file_type().is_dir())
        .map_or(0, meta_mtime_unix);

    ProfileProbe {
        profile: ProfileDir {
            name: CompactString::from(rel_path.to_string_lossy().as_ref()),
            rel_path: rel_path.to_path_buf(),
            layout: TargetLayout::ArtifactsOnly,
            lock_files,
            locked_now,
            fingerprint_corrupt: false,
            v2_unit_count: 0,
            v1_unit_count: 0,
            incremental_dir_count: 0,
            v2_units: Vec::new(),
            v1_units: Vec::new(),
            dep_fp_pool: Vec::new(),
            incremental_dirs: Vec::new(),
            profile_mtime_unix,
            inc_root_mtime_unix,
            allocated_bytes: 0,
            last_activity_unix: 0,
        },
        full_path: profile_path.to_path_buf(),
        has_v1_fp_dir,
        has_v1_deps_dir,
        has_build_dir,
        has_inc_dir,
    }
}

#[cfg(unix)]
fn open_dir_nofollow(path: &Path) -> rustix::io::Result<rustix::fs::Dir> {
    use rustix::fs::{Dir, Mode, OFlags, open};

    let fd = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Dir::new(fd)
}

#[cfg(unix)]
fn open_child_dir_nofollow(
    parent_fd: rustix::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
) -> rustix::io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags, openat};

    openat(
        parent_fd,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Classify a directory entry: returns `Some(true)` for a real directory, `Some(false)` after
/// accounting a non-directory regular entry, or `None` to skip symlinks/unstatable entries.
#[cfg(unix)]
fn dir_entry_is_dir_or_account(
    dir: &rustix::fs::Dir,
    entry: &rustix::fs::DirEntry,
    allocated_bytes: &mut u64,
    hardlinks: &mut HardlinkSet,
) -> Option<bool> {
    use rustix::fs::{AtFlags, FileType, statat};

    let ft = entry.file_type();
    if ft == FileType::Symlink {
        return None;
    }
    if ft == FileType::Directory {
        return Some(true);
    }
    if ft == FileType::RegularFile {
        let ino = entry.ino();
        if ino != 0 && hardlinks.contains_primary(ino) {
            return Some(false);
        }
    }
    let fd = dir.fd().ok()?;
    let st = statat(fd, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW).ok()?;
    let mode_ft = FileType::from_raw_mode(st.st_mode);
    if mode_ft == FileType::Symlink {
        return None;
    }
    if mode_ft == FileType::Directory {
        Some(true)
    } else {
        *allocated_bytes =
            allocated_bytes.saturating_add(stat_allocated_bytes(&st, false, hardlinks));
        Some(false)
    }
}

fn account_profile_top_entries(
    profile_path: &Path,
    profile: &mut ProfileDir,
    hardlinks: &mut HardlinkSet,
    scratch: &mut DirScratch,
) {
    let Ok(entries) = fs::read_dir(profile_path) else {
        return;
    };
    for entry in entries.flatten() {
        let os_name = entry.file_name();
        let Some(name) = os_name.to_str() else {
            continue;
        };
        if matches!(name, ".fingerprint" | "deps" | "build" | "incremental") {
            continue;
        }
        let entry_path = entry.path();
        let Ok(emeta) = fs::symlink_metadata(&entry_path) else {
            continue;
        };
        profile.last_activity_unix = profile.last_activity_unix.max(meta_mtime_unix(&emeta));
        if emeta.file_type().is_dir() && !emeta.file_type().is_symlink() {
            let res = account_tree(&entry_path, MtimePolicy::None, None, hardlinks, scratch);
            profile.allocated_bytes = profile.allocated_bytes.saturating_add(res.bytes);
        } else {
            profile.allocated_bytes = profile
                .allocated_bytes
                .saturating_add(entry_allocated_bytes(&emeta, hardlinks));
        }
    }
}

fn finish_profile_metadata(
    profile: &mut ProfileDir,
    has_v1_fp_dir: bool,
    has_v1_deps_dir: bool,
    has_build_dir: bool,
    has_inc_dir: bool,
) {
    if profile.last_activity_unix == 0 {
        profile.last_activity_unix = profile.profile_mtime_unix;
    }
    let has_v2 = profile.v2_unit_count > 0;
    let has_v1 = profile.v1_unit_count > 0 || has_v1_fp_dir || has_v1_deps_dir;
    profile.layout = classify_profile_layout(has_v2, has_v1, has_build_dir, has_inc_dir);
}

fn inspect_profile_inventory(
    probe: ProfileProbe,
    hardlinks: &mut HardlinkSet,
    scratch: &mut DirScratch,
) -> ProfileDir {
    let ProfileProbe {
        mut profile,
        full_path,
        has_v1_fp_dir,
        has_v1_deps_dir,
        has_build_dir,
        has_inc_dir,
    } = probe;

    let mut v1_fp_names: HashSet<CompactString> = HashSet::new();
    let fp_root = full_path.join(".fingerprint");
    let deps_root = full_path.join("deps");
    let build_root = full_path.join("build");
    let inc_root = full_path.join("incremental");

    #[cfg(unix)]
    {
        // 1. `.fingerprint/` (V1)
        if has_v1_fp_dir && let Ok(mut dir) = open_dir_nofollow(&fp_root) {
            while let Some(entry_res) = dir.read() {
                let Ok(entry) = entry_res else {
                    continue;
                };
                let name = entry.file_name();
                let bytes = name.to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                if dir_entry_is_dir_or_account(
                    &dir,
                    &entry,
                    &mut profile.allocated_bytes,
                    hardlinks,
                ) != Some(true)
                {
                    continue;
                }
                if let Ok(name_str) = std::str::from_utf8(bytes)
                    && split_pkg_and_16hex(name_str).is_some()
                {
                    profile.v1_unit_count += 1;
                    v1_fp_names.insert(CompactString::from(name_str));
                }
                let Ok(fd) = dir.fd() else {
                    break;
                };
                if let Ok(child_fd) = open_child_dir_nofollow(fd, name) {
                    let mut out = DirAccountResult::default();
                    sum_dir_fd_recursive(
                        child_fd,
                        0,
                        MtimePolicy::UpToDepth(1),
                        None,
                        hardlinks,
                        scratch,
                        &mut out,
                    );
                    profile.allocated_bytes = profile.allocated_bytes.saturating_add(out.bytes);
                    profile.last_activity_unix = profile.last_activity_unix.max(out.max_mtime);
                }
            }
        }

        // 2. `deps/` (V1)
        if has_v1_deps_dir {
            let res = account_tree(&deps_root, MtimePolicy::None, None, hardlinks, scratch);
            profile.allocated_bytes = profile.allocated_bytes.saturating_add(res.bytes);
        }

        // 3. `build/` (V1 or V2)
        if has_build_dir && let Ok(mut dir) = open_dir_nofollow(&build_root) {
            while let Some(entry_res) = dir.read() {
                let Ok(entry) = entry_res else {
                    continue;
                };
                let name = entry.file_name();
                let bytes = name.to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                if dir_entry_is_dir_or_account(
                    &dir,
                    &entry,
                    &mut profile.allocated_bytes,
                    hardlinks,
                ) != Some(true)
                {
                    continue;
                }
                let is_v1_build = std::str::from_utf8(bytes).is_ok_and(|s| v1_fp_names.contains(s));
                let policy = if is_v1_build {
                    MtimePolicy::None
                } else {
                    MtimePolicy::V2PkgDir
                };
                let Ok(fd) = dir.fd() else {
                    break;
                };
                if let Ok(child_fd) = open_child_dir_nofollow(fd, name) {
                    let mut out = DirAccountResult::default();
                    sum_dir_fd_recursive(child_fd, 0, policy, None, hardlinks, scratch, &mut out);
                    profile.allocated_bytes = profile.allocated_bytes.saturating_add(out.bytes);
                    profile.v2_unit_count = profile.v2_unit_count.saturating_add(out.v2_unit_count);
                    profile.last_activity_unix = profile.last_activity_unix.max(out.max_mtime);
                }
            }
        }

        // 4. `incremental/`
        if has_inc_dir && let Ok(mut dir) = open_dir_nofollow(&inc_root) {
            while let Some(entry_res) = dir.read() {
                let Ok(entry) = entry_res else {
                    continue;
                };
                let name = entry.file_name();
                let bytes = name.to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                if dir_entry_is_dir_or_account(
                    &dir,
                    &entry,
                    &mut profile.allocated_bytes,
                    hardlinks,
                ) != Some(true)
                {
                    continue;
                }
                profile.incremental_dir_count += 1;
                let Ok(fd) = dir.fd() else {
                    break;
                };
                if let Ok(child_fd) = open_child_dir_nofollow(fd, name) {
                    let mut out = DirAccountResult::default();
                    sum_dir_fd_recursive(
                        child_fd,
                        0,
                        MtimePolicy::IncrementalCrateDir,
                        None,
                        hardlinks,
                        scratch,
                        &mut out,
                    );
                    profile.allocated_bytes = profile.allocated_bytes.saturating_add(out.bytes);
                    profile.last_activity_unix = profile.last_activity_unix.max(out.max_mtime);
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        if has_v1_fp_dir && let Ok(entries) = fs::read_dir(&fp_root) {
            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else {
                    continue;
                };
                if ft.is_symlink() {
                    continue;
                }
                if ft.is_dir() {
                    if let Some(name) = entry.file_name().to_str()
                        && split_pkg_and_16hex(name).is_some()
                    {
                        profile.v1_unit_count += 1;
                        v1_fp_names.insert(CompactString::from(name));
                    }
                    let res = account_tree(
                        &entry.path(),
                        MtimePolicy::UpToDepth(1),
                        None,
                        hardlinks,
                        scratch,
                    );
                    profile.allocated_bytes = profile.allocated_bytes.saturating_add(res.bytes);
                    profile.last_activity_unix = profile.last_activity_unix.max(res.max_mtime);
                } else if let Ok(meta) = fs::symlink_metadata(entry.path()) {
                    profile.allocated_bytes = profile
                        .allocated_bytes
                        .saturating_add(entry_allocated_bytes(&meta, hardlinks));
                }
            }
        }

        if has_v1_deps_dir {
            let res = account_tree(&deps_root, MtimePolicy::None, None, hardlinks, scratch);
            profile.allocated_bytes = profile.allocated_bytes.saturating_add(res.bytes);
        }

        if has_build_dir && let Ok(entries) = fs::read_dir(&build_root) {
            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else {
                    continue;
                };
                if ft.is_symlink() {
                    continue;
                }
                if !ft.is_dir() {
                    if let Ok(meta) = fs::symlink_metadata(entry.path()) {
                        profile.allocated_bytes = profile
                            .allocated_bytes
                            .saturating_add(entry_allocated_bytes(&meta, hardlinks));
                    }
                    continue;
                }
                let is_v1_build = entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| v1_fp_names.contains(name));
                let policy = if is_v1_build {
                    MtimePolicy::None
                } else {
                    MtimePolicy::V2PkgDir
                };
                let res = account_tree(&entry.path(), policy, None, hardlinks, scratch);
                profile.allocated_bytes = profile.allocated_bytes.saturating_add(res.bytes);
                profile.v2_unit_count = profile.v2_unit_count.saturating_add(res.v2_unit_count);
                profile.last_activity_unix = profile.last_activity_unix.max(res.max_mtime);
            }
        }

        if has_inc_dir && let Ok(entries) = fs::read_dir(&inc_root) {
            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else {
                    continue;
                };
                if ft.is_symlink() {
                    continue;
                }
                if ft.is_dir() {
                    profile.incremental_dir_count += 1;
                    let res = account_tree(
                        &entry.path(),
                        MtimePolicy::IncrementalCrateDir,
                        None,
                        hardlinks,
                        scratch,
                    );
                    profile.allocated_bytes = profile.allocated_bytes.saturating_add(res.bytes);
                    profile.last_activity_unix = profile.last_activity_unix.max(res.max_mtime);
                } else if let Ok(meta) = fs::symlink_metadata(entry.path()) {
                    profile.allocated_bytes = profile
                        .allocated_bytes
                        .saturating_add(entry_allocated_bytes(&meta, hardlinks));
                }
            }
        }
    }

    account_profile_top_entries(&full_path, &mut profile, hardlinks, scratch);
    finish_profile_metadata(
        &mut profile,
        has_v1_fp_dir,
        has_v1_deps_dir,
        has_build_dir,
        has_inc_dir,
    );
    profile
}

fn inspect_profile_full(
    probe: ProfileProbe,
    platform: &impl Platform,
    hardlinks: &mut HardlinkSet,
    scratch: &mut DirScratch,
) -> ProfileDir {
    let ProfileProbe {
        mut profile,
        full_path,
        has_v1_fp_dir,
        has_v1_deps_dir,
        has_build_dir,
        has_inc_dir,
    } = probe;

    let fp_root = full_path.join(".fingerprint");
    let deps_root = full_path.join("deps");
    let build_root = full_path.join("build");
    let inc_root = full_path.join("incremental");

    let mut v1_fp_index_by_name: HashMap<CompactString, usize> = HashMap::new();
    let mut v1_hash_to_indices: HashMap<u64, SmallVec<[usize; 2]>, FastU64BuildHasher> =
        HashMap::with_hasher(FastU64BuildHasher);
    let mut orphan_idx_by_hash: HashMap<u64, usize, FastU64BuildHasher> =
        HashMap::with_hasher(FastU64BuildHasher);

    // 1. V1 `.fingerprint/<pkg>-<16hex>/`
    if has_v1_fp_dir {
        #[cfg(unix)]
        match open_dir_nofollow(&fp_root) {
            Ok(mut dir) => {
                while let Some(entry_res) = dir.read() {
                    let Ok(entry) = entry_res else {
                        continue;
                    };
                    let name = entry.file_name();
                    let bytes = name.to_bytes();
                    if bytes == b"." || bytes == b".." {
                        continue;
                    }
                    if dir_entry_is_dir_or_account(
                        &dir,
                        &entry,
                        &mut profile.allocated_bytes,
                        hardlinks,
                    ) != Some(true)
                    {
                        continue;
                    }
                    let Ok(fd) = dir.fd() else {
                        break;
                    };
                    let Ok(name_str) = std::str::from_utf8(bytes) else {
                        profile.fingerprint_corrupt = true;
                        if let Ok(child_fd) = open_child_dir_nofollow(fd, name) {
                            let mut out = DirAccountResult::default();
                            sum_dir_fd_recursive(
                                child_fd,
                                0,
                                MtimePolicy::None,
                                None,
                                hardlinks,
                                scratch,
                                &mut out,
                            );
                            profile.allocated_bytes =
                                profile.allocated_bytes.saturating_add(out.bytes);
                        }
                        continue;
                    };
                    let dir_name = CompactString::from(name_str);
                    let Some((pkg_group, unit_hash)) = split_pkg_and_16hex(&dir_name) else {
                        if let Ok(child_fd) = open_child_dir_nofollow(fd, name) {
                            let mut out = DirAccountResult::default();
                            sum_dir_fd_recursive(
                                child_fd,
                                0,
                                MtimePolicy::None,
                                None,
                                hardlinks,
                                scratch,
                                &mut out,
                            );
                            profile.allocated_bytes =
                                profile.allocated_bytes.saturating_add(out.bytes);
                        }
                        continue;
                    };
                    let parsed = match open_child_dir_nofollow(fd, name) {
                        Ok(child_fd) => parse_fingerprint_dir_fd(
                            child_fd,
                            hardlinks,
                            scratch,
                            &mut profile.dep_fp_pool,
                        ),
                        Err(_) => {
                            let mtime =
                                rustix::fs::statat(fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                                    .map(|st| u64::try_from(st.st_mtime).unwrap_or(0))
                                    .unwrap_or(0);
                            ParsedFingerprintDir {
                                metadata: UnitMetadata::Incomplete { mtime_unix: mtime },
                                allocated_bytes: 0,
                                corrupt: true,
                            }
                        }
                    };
                    if parsed.corrupt {
                        profile.fingerprint_corrupt = true;
                    }
                    profile.last_activity_unix = profile
                        .last_activity_unix
                        .max(unit_metadata_mtime(&parsed.metadata));
                    profile.allocated_bytes = profile
                        .allocated_bytes
                        .saturating_add(parsed.allocated_bytes);

                    let u_idx = profile.v1_units.len();
                    v1_fp_index_by_name.insert(dir_name.clone(), u_idx);
                    if let Some(hash_u64) = parse_16_lower_hex_u64(&unit_hash) {
                        v1_hash_to_indices.entry(hash_u64).or_default().push(u_idx);
                    }
                    profile.v1_units.push(BuildUnit {
                        id: BuildUnitId::V1 {
                            fingerprint_dir: Some(dir_name),
                            unit_hash,
                        },
                        metadata: parsed.metadata,
                        v1: Some(Box::new(V1UnitExtras {
                            pkg_group,
                            build_dir: None,
                            dep_entry_count: 0,
                        })),
                        allocated_bytes: parsed.allocated_bytes,
                    });
                }
            }
            Err(_) => {
                profile.fingerprint_corrupt = true;
            }
        }
        #[cfg(not(unix))]
        match fs::read_dir(&fp_root) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let Ok(ft) = entry.file_type() else {
                        continue;
                    };
                    if ft.is_symlink() {
                        continue;
                    }
                    if !ft.is_dir() {
                        if let Ok(meta) = fs::symlink_metadata(entry.path()) {
                            profile.allocated_bytes = profile
                                .allocated_bytes
                                .saturating_add(entry_allocated_bytes(&meta, hardlinks));
                        }
                        continue;
                    }
                    let Some(dir_name) = entry.file_name().to_str().map(CompactString::from) else {
                        profile.fingerprint_corrupt = true;
                        let res = account_tree(
                            &entry.path(),
                            MtimePolicy::None,
                            None,
                            hardlinks,
                            scratch,
                        );
                        profile.allocated_bytes = profile.allocated_bytes.saturating_add(res.bytes);
                        continue;
                    };
                    let Some((pkg_group, unit_hash)) = split_pkg_and_16hex(&dir_name) else {
                        let res = account_tree(
                            &entry.path(),
                            MtimePolicy::None,
                            None,
                            hardlinks,
                            scratch,
                        );
                        profile.allocated_bytes = profile.allocated_bytes.saturating_add(res.bytes);
                        continue;
                    };
                    let parsed = parse_fingerprint_dir_path(
                        &entry.path(),
                        hardlinks,
                        scratch,
                        &mut profile.dep_fp_pool,
                    );
                    if parsed.corrupt {
                        profile.fingerprint_corrupt = true;
                    }
                    profile.last_activity_unix = profile
                        .last_activity_unix
                        .max(unit_metadata_mtime(&parsed.metadata));
                    profile.allocated_bytes = profile
                        .allocated_bytes
                        .saturating_add(parsed.allocated_bytes);

                    let u_idx = profile.v1_units.len();
                    v1_fp_index_by_name.insert(dir_name.clone(), u_idx);
                    if let Some(hash_u64) = parse_16_lower_hex_u64(&unit_hash) {
                        v1_hash_to_indices.entry(hash_u64).or_default().push(u_idx);
                    }
                    profile.v1_units.push(BuildUnit {
                        id: BuildUnitId::V1 {
                            fingerprint_dir: Some(dir_name),
                            unit_hash,
                        },
                        metadata: parsed.metadata,
                        v1: Some(Box::new(V1UnitExtras {
                            pkg_group,
                            build_dir: None,
                            dep_entry_count: 0,
                        })),
                        allocated_bytes: parsed.allocated_bytes,
                    });
                }
            }
            Err(_) => {
                profile.fingerprint_corrupt = true;
            }
        }
    }

    // 2. V1 `deps/` — aggregates bytes, mtime, and entry counts per 16-hex hash with zero
    //    retention of tens of thousands of `.rcgu.o` filename strings.
    let mut deps_by_hash: HashMap<u64, V1DepHashStats, FastU64BuildHasher> =
        HashMap::with_hasher(FastU64BuildHasher);
    if has_v1_deps_dir {
        let (deps_bytes, corrupt) = inspect_v1_deps_dir(
            &deps_root,
            &v1_hash_to_indices,
            hardlinks,
            scratch,
            &mut deps_by_hash,
        );
        profile.allocated_bytes = profile.allocated_bytes.saturating_add(deps_bytes);
        if corrupt {
            profile.fingerprint_corrupt = true;
        }
    }

    // 3. `build/` (V1 `build/<pkg>-<16hex>/`, V2 `build/<pkg>/<16hex>/`, or orphaned V1 build dir)
    let mut non_v2_build_dirs: Vec<(CompactString, u64, u64)> = Vec::new();
    if has_build_dir {
        #[cfg(unix)]
        match open_dir_nofollow(&build_root) {
            Ok(mut dir) => {
                while let Some(entry_res) = dir.read() {
                    let Ok(entry) = entry_res else {
                        continue;
                    };
                    let name = entry.file_name();
                    let bytes = name.to_bytes();
                    if bytes == b"." || bytes == b".." {
                        continue;
                    }
                    if dir_entry_is_dir_or_account(
                        &dir,
                        &entry,
                        &mut profile.allocated_bytes,
                        hardlinks,
                    ) != Some(true)
                    {
                        continue;
                    }
                    let Ok(fd) = dir.fd() else {
                        break;
                    };
                    let Ok(name_str) = std::str::from_utf8(bytes) else {
                        if let Ok(child_fd) = open_child_dir_nofollow(fd, name) {
                            let mut out = DirAccountResult::default();
                            sum_dir_fd_recursive(
                                child_fd,
                                0,
                                MtimePolicy::None,
                                None,
                                hardlinks,
                                scratch,
                                &mut out,
                            );
                            profile.allocated_bytes =
                                profile.allocated_bytes.saturating_add(out.bytes);
                        }
                        continue;
                    };
                    if let Some(&v1_idx) = v1_fp_index_by_name.get(name_str) {
                        let mut out = DirAccountResult::default();
                        if let Ok(child_fd) = open_child_dir_nofollow(fd, name) {
                            sum_dir_fd_recursive(
                                child_fd,
                                0,
                                MtimePolicy::None,
                                None,
                                hardlinks,
                                scratch,
                                &mut out,
                            );
                        }
                        profile.allocated_bytes = profile.allocated_bytes.saturating_add(out.bytes);
                        let unit = &mut profile.v1_units[v1_idx];
                        if let Some(extras) = unit.v1.as_deref_mut() {
                            extras.build_dir = Some(CompactString::from(name_str));
                        }
                        unit.allocated_bytes = unit.allocated_bytes.saturating_add(out.bytes);
                    } else {
                        let pkg_name = CompactString::from(name_str);
                        let pkg_res = match open_child_dir_nofollow(fd, name) {
                            Ok(pkg_fd) => inspect_v2_pkg_dir_fd_into(
                                pkg_fd,
                                &pkg_name,
                                hardlinks,
                                scratch,
                                &mut profile.v2_units,
                                &mut profile.dep_fp_pool,
                            ),
                            Err(_) => BuildPkgDirResult {
                                total_bytes: 0,
                                non_v2_sibling_bytes: 0,
                                dir_mtime_unix: 0,
                                max_mtime: 0,
                                found_v2_child: false,
                                corrupt: true,
                            },
                        };
                        profile.allocated_bytes =
                            profile.allocated_bytes.saturating_add(pkg_res.total_bytes);
                        profile.last_activity_unix =
                            profile.last_activity_unix.max(pkg_res.max_mtime);
                        if pkg_res.corrupt {
                            profile.fingerprint_corrupt = true;
                        }
                        if !pkg_res.found_v2_child && has_v1_fp_dir {
                            non_v2_build_dirs.push((
                                pkg_name,
                                pkg_res.non_v2_sibling_bytes,
                                pkg_res.dir_mtime_unix,
                            ));
                        }
                    }
                }
            }
            Err(_) => {
                profile.fingerprint_corrupt = true;
            }
        }
        #[cfg(not(unix))]
        match fs::read_dir(&build_root) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let Ok(ft) = entry.file_type() else {
                        continue;
                    };
                    if ft.is_symlink() {
                        continue;
                    }
                    if !ft.is_dir() {
                        if let Ok(meta) = fs::symlink_metadata(entry.path()) {
                            profile.allocated_bytes = profile
                                .allocated_bytes
                                .saturating_add(entry_allocated_bytes(&meta, hardlinks));
                        }
                        continue;
                    }
                    let Some(name_str) = entry.file_name().to_str().map(CompactString::from) else {
                        let res = account_tree(
                            &entry.path(),
                            MtimePolicy::None,
                            None,
                            hardlinks,
                            scratch,
                        );
                        profile.allocated_bytes = profile.allocated_bytes.saturating_add(res.bytes);
                        continue;
                    };
                    if let Some(&v1_idx) = v1_fp_index_by_name.get(name_str.as_str()) {
                        let bytes = account_tree(
                            &entry.path(),
                            MtimePolicy::None,
                            None,
                            hardlinks,
                            scratch,
                        )
                        .bytes;
                        profile.allocated_bytes = profile.allocated_bytes.saturating_add(bytes);
                        let unit = &mut profile.v1_units[v1_idx];
                        if let Some(extras) = unit.v1.as_deref_mut() {
                            extras.build_dir = Some(name_str);
                        }
                        unit.allocated_bytes = unit.allocated_bytes.saturating_add(bytes);
                    } else {
                        let pkg_res = inspect_v2_pkg_dir_path_into(
                            &entry.path(),
                            &name_str,
                            hardlinks,
                            scratch,
                            &mut profile.v2_units,
                            &mut profile.dep_fp_pool,
                        );
                        profile.allocated_bytes =
                            profile.allocated_bytes.saturating_add(pkg_res.total_bytes);
                        profile.last_activity_unix =
                            profile.last_activity_unix.max(pkg_res.max_mtime);
                        if pkg_res.corrupt {
                            profile.fingerprint_corrupt = true;
                        }
                        if !pkg_res.found_v2_child && has_v1_fp_dir {
                            non_v2_build_dirs.push((
                                name_str,
                                pkg_res.non_v2_sibling_bytes,
                                pkg_res.dir_mtime_unix,
                            ));
                        }
                    }
                }
            }
            Err(_) => {
                profile.fingerprint_corrupt = true;
            }
        }
    }

    // Attach V1 `deps/` stats and orphaned V1 units only when `.fingerprint/` was clean.
    let allow_orphans = has_v1_fp_dir && !profile.fingerprint_corrupt;
    for (hash_u64, stats) in deps_by_hash {
        if let Some(indices) = v1_hash_to_indices.get(&hash_u64) {
            if indices.len() == 1 {
                let unit = &mut profile.v1_units[indices[0]];
                unit.allocated_bytes = unit.allocated_bytes.saturating_add(stats.bytes);
                if let Some(extras) = unit.v1.as_deref_mut() {
                    extras.dep_entry_count = extras.dep_entry_count.saturating_add(stats.count);
                }
            }
        } else if allow_orphans {
            let new_idx = profile.v1_units.len();
            orphan_idx_by_hash.insert(hash_u64, new_idx);
            profile.v1_units.push(BuildUnit {
                id: BuildUnitId::V1 {
                    fingerprint_dir: None,
                    unit_hash: format_16_lower_hex(hash_u64),
                },
                metadata: UnitMetadata::Incomplete {
                    mtime_unix: stats.max_mtime,
                },
                v1: Some(Box::new(V1UnitExtras {
                    pkg_group: CompactString::new("orphan"),
                    build_dir: None,
                    dep_entry_count: stats.count,
                })),
                allocated_bytes: stats.bytes,
            });
        }
    }
    if allow_orphans {
        for (pkg_name, bytes, build_mtime) in non_v2_build_dirs {
            if let Some((pkg_group, hash_str)) = split_pkg_and_16hex(&pkg_name)
                && let Some(hash_u64) = parse_16_lower_hex_u64(&hash_str)
                && !v1_hash_to_indices.contains_key(&hash_u64)
            {
                let u_idx = *orphan_idx_by_hash.entry(hash_u64).or_insert_with(|| {
                    let new_idx = profile.v1_units.len();
                    profile.v1_units.push(BuildUnit {
                        id: BuildUnitId::V1 {
                            fingerprint_dir: None,
                            unit_hash: hash_str,
                        },
                        metadata: UnitMetadata::Incomplete { mtime_unix: 0 },
                        v1: Some(Box::new(V1UnitExtras {
                            pkg_group: pkg_group.clone(),
                            build_dir: None,
                            dep_entry_count: 0,
                        })),
                        allocated_bytes: 0,
                    });
                    new_idx
                });
                let unit = &mut profile.v1_units[u_idx];
                if let Some(extras) = unit.v1.as_deref_mut() {
                    extras.pkg_group = pkg_group;
                    extras.build_dir = Some(pkg_name);
                }
                unit.allocated_bytes = unit.allocated_bytes.saturating_add(bytes);
                if let UnitMetadata::Incomplete { mtime_unix } = &mut unit.metadata {
                    *mtime_unix = (*mtime_unix).max(build_mtime);
                }
            }
        }
    }

    // 4. `incremental/`
    if has_inc_dir {
        #[cfg(unix)]
        if let Ok(mut dir) = open_dir_nofollow(&inc_root) {
            while let Some(entry_res) = dir.read() {
                let Ok(entry) = entry_res else {
                    continue;
                };
                let name = entry.file_name();
                let bytes = name.to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                if dir_entry_is_dir_or_account(
                    &dir,
                    &entry,
                    &mut profile.allocated_bytes,
                    hardlinks,
                ) != Some(true)
                {
                    continue;
                }
                let Ok(fd) = dir.fd() else {
                    break;
                };
                let Ok(name_str) = std::str::from_utf8(bytes) else {
                    if let Ok(child_fd) = open_child_dir_nofollow(fd, name) {
                        let mut out = DirAccountResult::default();
                        sum_dir_fd_recursive(
                            child_fd,
                            0,
                            MtimePolicy::None,
                            None,
                            hardlinks,
                            scratch,
                            &mut out,
                        );
                        profile.allocated_bytes = profile.allocated_bytes.saturating_add(out.bytes);
                    }
                    continue;
                };
                let dir_name = CompactString::from(name_str);
                let inc_dir = inspect_incremental_dir_fd(
                    &inc_root, fd, name, dir_name, platform, hardlinks, scratch,
                );
                profile.last_activity_unix =
                    profile.last_activity_unix.max(inc_dir.latest_mtime_unix);
                profile.allocated_bytes = profile
                    .allocated_bytes
                    .saturating_add(inc_dir.allocated_bytes);
                profile.incremental_dirs.push(inc_dir);
            }
        }
        #[cfg(not(unix))]
        if let Ok(entries) = fs::read_dir(&inc_root) {
            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else {
                    continue;
                };
                if ft.is_symlink() {
                    continue;
                }
                if !ft.is_dir() {
                    if let Ok(meta) = fs::symlink_metadata(entry.path()) {
                        profile.allocated_bytes = profile
                            .allocated_bytes
                            .saturating_add(entry_allocated_bytes(&meta, hardlinks));
                    }
                    continue;
                }
                let Some(dir_name) = entry.file_name().to_str().map(CompactString::from) else {
                    let res =
                        account_tree(&entry.path(), MtimePolicy::None, None, hardlinks, scratch);
                    profile.allocated_bytes = profile.allocated_bytes.saturating_add(res.bytes);
                    continue;
                };
                let inc_dir = inspect_incremental_dir_path(
                    &entry.path(),
                    dir_name,
                    platform,
                    hardlinks,
                    scratch,
                );
                profile.last_activity_unix =
                    profile.last_activity_unix.max(inc_dir.latest_mtime_unix);
                profile.allocated_bytes = profile
                    .allocated_bytes
                    .saturating_add(inc_dir.allocated_bytes);
                profile.incremental_dirs.push(inc_dir);
            }
        }
    }

    // 5. Top-level profile entries (excluding already-accounted subdirs)
    account_profile_top_entries(&full_path, &mut profile, hardlinks, scratch);

    // Compact `dep_fp_pool` in-place while spans are strictly monotonic (before sorting units).
    compact_profile_dep_fp_pool(&mut profile);

    profile.v2_units.sort_by(|a, b| match (&a.id, &b.id) {
        (
            BuildUnitId::V2 {
                pkg: pa,
                unit_hash: ha,
            },
            BuildUnitId::V2 {
                pkg: pb,
                unit_hash: hb,
            },
        ) => pa.cmp(pb).then_with(|| ha.cmp(hb)),
        _ => std::cmp::Ordering::Equal,
    });
    profile.v1_units.sort_by(|a, b| match (&a.id, &b.id) {
        (
            BuildUnitId::V1 {
                fingerprint_dir: fa,
                unit_hash: ha,
            },
            BuildUnitId::V1 {
                fingerprint_dir: fb,
                unit_hash: hb,
            },
        ) => fa.cmp(fb).then_with(|| ha.cmp(hb)),
        _ => std::cmp::Ordering::Equal,
    });
    profile
        .incremental_dirs
        .sort_by(|a, b| a.dir_name.cmp(&b.dir_name));

    profile.v2_unit_count = profile.v2_units.len();
    profile.v1_unit_count = profile.v1_units.len();
    profile.incremental_dir_count = profile.incremental_dirs.len();

    finish_profile_metadata(
        &mut profile,
        has_v1_fp_dir,
        has_v1_deps_dir,
        has_build_dir,
        has_inc_dir,
    );
    profile
}

fn collect_layer_anchor_hashes(units: &[BuildUnit]) -> HashSet<u64, FastU64BuildHasher> {
    let mut anchors = HashSet::with_capacity_and_hasher(units.len(), FastU64BuildHasher);
    for unit in units {
        if let UnitMetadata::Complete { targets, .. } = &unit.metadata {
            for anchor in targets {
                if let Some(h) = anchor.fingerprint_hash {
                    anchors.insert(h);
                }
            }
        }
    }
    anchors
}

#[inline]
fn compact_unit_dep_span(
    pool: &mut [u64],
    anchors: &HashSet<u64, FastU64BuildHasher>,
    unit: &mut BuildUnit,
    write: &mut usize,
) {
    if let UnitMetadata::Complete {
        dep_fp_start,
        dep_fp_len,
        ..
    } = &mut unit.metadata
        && *dep_fp_len > 0
    {
        let start = *dep_fp_start as usize;
        let end = start.saturating_add(*dep_fp_len as usize).min(pool.len());
        let new_start = *write;
        if !anchors.is_empty() {
            for read in start..end {
                let h = pool[read];
                if anchors.contains(&h) {
                    pool[*write] = h;
                    *write += 1;
                }
            }
        }
        let new_len = *write - new_start;
        if new_len == 0 {
            *dep_fp_start = 0;
            *dep_fp_len = 0;
        } else {
            *dep_fp_start = new_start as u32;
            *dep_fp_len = new_len as u32;
        }
    }
}

/// Drop dependency hashes that do not match any unit's companion anchor in the same profile layer.
///
/// Must be called while `dep_fp_pool` spans are still in monotonic, non-overlapping allocation order
/// (before sorting `v2_units` / `v1_units`), so compaction runs strictly in-place with zero copies.
fn compact_profile_dep_fp_pool(profile: &mut ProfileDir) {
    if profile.fingerprint_corrupt {
        profile.dep_fp_pool = Vec::new();
        return;
    }
    if profile.dep_fp_pool.is_empty() {
        return;
    }

    let mut write = 0usize;
    if profile.v1_units.is_empty() {
        let v2_anchors = collect_layer_anchor_hashes(&profile.v2_units);
        for unit in &mut profile.v2_units {
            compact_unit_dep_span(&mut profile.dep_fp_pool, &v2_anchors, unit, &mut write);
        }
    } else if profile.v2_units.is_empty() {
        let v1_anchors = collect_layer_anchor_hashes(&profile.v1_units);
        for unit in &mut profile.v1_units {
            compact_unit_dep_span(&mut profile.dep_fp_pool, &v1_anchors, unit, &mut write);
        }
    } else {
        let v2_anchors = collect_layer_anchor_hashes(&profile.v2_units);
        let v1_anchors = collect_layer_anchor_hashes(&profile.v1_units);
        let mut spans: Vec<(u32, bool, usize)> =
            Vec::with_capacity(profile.v2_units.len() + profile.v1_units.len());
        for (idx, u) in profile.v2_units.iter().enumerate() {
            if let UnitMetadata::Complete {
                dep_fp_start,
                dep_fp_len,
                ..
            } = u.metadata
                && dep_fp_len > 0
            {
                spans.push((dep_fp_start, true, idx));
            }
        }
        for (idx, u) in profile.v1_units.iter().enumerate() {
            if let UnitMetadata::Complete {
                dep_fp_start,
                dep_fp_len,
                ..
            } = u.metadata
                && dep_fp_len > 0
            {
                spans.push((dep_fp_start, false, idx));
            }
        }
        spans.sort_unstable_by_key(|x| x.0);
        for (_, is_v2, idx) in spans {
            if is_v2 {
                compact_unit_dep_span(
                    &mut profile.dep_fp_pool,
                    &v2_anchors,
                    &mut profile.v2_units[idx],
                    &mut write,
                );
            } else {
                compact_unit_dep_span(
                    &mut profile.dep_fp_pool,
                    &v1_anchors,
                    &mut profile.v1_units[idx],
                    &mut write,
                );
            }
        }
    }

    if write == 0 {
        profile.dep_fp_pool = Vec::new();
    } else {
        profile.dep_fp_pool.truncate(write);
        if write.saturating_mul(2) < profile.dep_fp_pool.capacity() {
            profile.dep_fp_pool.shrink_to_fit();
        }
    }
}

fn classify_profile_layout(
    has_v2: bool,
    has_v1: bool,
    has_build_dir: bool,
    has_inc_dir: bool,
) -> TargetLayout {
    match (has_v2, has_v1) {
        (true, true) => TargetLayout::MixedV1V2,
        (true, false) => TargetLayout::BuildDirV2,
        (false, true) => TargetLayout::LegacyV1,
        (false, false) => {
            if has_build_dir || has_inc_dir {
                TargetLayout::BuildDirV2
            } else {
                TargetLayout::ArtifactsOnly
            }
        }
    }
}

struct ParsedFingerprintDir {
    metadata: UnitMetadata,
    allocated_bytes: u64,
    corrupt: bool,
}

struct FingerprintDepsSeed<'a>(&'a mut Vec<u64>);

impl<'de> serde::de::DeserializeSeed<'de> for FingerprintDepsSeed<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        struct DepsVisitor<'a>(&'a mut Vec<u64>);
        impl<'de> serde::de::Visitor<'de> for DepsVisitor<'_> {
            type Value = ();
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a sequence of 4-element fingerprint dep tuples")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
                while let Some((_, _, _, dep_hash)) = seq.next_element::<(
                    serde::de::IgnoredAny,
                    serde::de::IgnoredAny,
                    serde::de::IgnoredAny,
                    u64,
                )>()? {
                    self.0.push(dep_hash);
                }
                Ok(())
            }
        }
        deserializer.deserialize_seq(DepsVisitor(self.0))
    }
}

struct FingerprintJsonSeed<'a> {
    dep_hashes: &'a mut Vec<u64>,
}

impl<'de> serde::de::DeserializeSeed<'de> for FingerprintJsonSeed<'_> {
    type Value = u64;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<u64, D::Error> {
        struct ObjVisitor<'a>(&'a mut Vec<u64>);
        impl<'de> serde::de::Visitor<'de> for ObjVisitor<'_> {
            type Value = u64;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a Cargo fingerprint JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<u64, A::Error> {
                enum Field {
                    Rustc,
                    Deps,
                    Ignore,
                }
                impl<'de> Deserialize<'de> for Field {
                    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                        struct FieldVisitor;
                        impl serde::de::Visitor<'_> for FieldVisitor {
                            type Value = Field;
                            fn expecting(
                                &self,
                                f: &mut std::fmt::Formatter<'_>,
                            ) -> std::fmt::Result {
                                f.write_str("fingerprint JSON field name")
                            }
                            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Field, E> {
                                Ok(match v {
                                    "rustc" => Field::Rustc,
                                    "deps" => Field::Deps,
                                    _ => Field::Ignore,
                                })
                            }
                        }
                        d.deserialize_identifier(FieldVisitor)
                    }
                }

                let mut rustc: Option<u64> = None;
                let mut seen_deps = false;
                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::Rustc => {
                            if rustc.is_some() {
                                return Err(serde::de::Error::duplicate_field("rustc"));
                            }
                            rustc = Some(map.next_value::<u64>()?);
                        }
                        Field::Deps => {
                            if seen_deps {
                                return Err(serde::de::Error::duplicate_field("deps"));
                            }
                            seen_deps = true;
                            map.next_value_seed(FingerprintDepsSeed(self.0))?;
                        }
                        Field::Ignore => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                rustc.ok_or_else(|| serde::de::Error::missing_field("rustc"))
            }
        }
        deserializer.deserialize_map(ObjVisitor(self.dep_hashes))
    }
}

fn parse_fingerprint_json_into(bytes: &[u8], dep_hashes: &mut Vec<u64>) -> Option<u64> {
    let start_len = dep_hashes.len();
    let mut de = serde_json::Deserializer::from_slice(bytes);
    match serde::de::DeserializeSeed::deserialize(FingerprintJsonSeed { dep_hashes }, &mut de) {
        Ok(rustc) if de.end().is_ok() => Some(rustc),
        _ => {
            dep_hashes.truncate(start_len);
            None
        }
    }
}

#[cfg(not(unix))]
fn read_file_into_buf(file: fs::File, max_bytes: u64, buf: &mut Vec<u8>) -> bool {
    if buf.capacity() > 256 * 1024 {
        *buf = Vec::new();
    } else {
        buf.clear();
    }
    if file.take(max_bytes + 1).read_to_end(buf).is_err() {
        return false;
    }
    (buf.len() as u64) <= max_bytes
}

#[cfg(unix)]
fn read_fd_bounded(
    fd: &std::os::fd::OwnedFd,
    expected_size: u64,
    max_bytes: u64,
    buf: &mut Vec<u8>,
) -> Option<usize> {
    if expected_size > max_bytes {
        return None;
    }
    let max_len = usize::try_from(max_bytes).ok()?;
    let want = usize::try_from(expected_size).ok()?;
    if buf.len() > 256 * 1024 {
        *buf = Vec::new();
    }
    let initial_cap = want
        .saturating_add(1)
        .min(max_len.saturating_add(1))
        .max(4096);
    if buf.len() < initial_cap {
        buf.resize(initial_cap, 0);
    }

    let mut total = 0usize;
    loop {
        let target = if total < want {
            want.saturating_add(1).min(max_len.saturating_add(1))
        } else {
            total.saturating_add(4096).min(max_len.saturating_add(1))
        };
        if buf.len() < target {
            buf.resize(target, 0);
        }
        let slice = &mut buf[total..target];
        let offered = slice.len();
        match rustix::io::read(fd, slice) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total > max_len {
                    return None;
                }
                // On a regular file, offering `want + 1` bytes and receiving `want` bytes means
                // the kernel already observed EOF in this single `read()` syscall.
                if want > 0 && total == want && n < offered {
                    break;
                }
            }
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return None,
        }
    }
    Some(total)
}

fn finalize_dep_pool_tail(pool: &mut Vec<u64>, start: usize) -> Option<(u32, u32)> {
    let len = pool.len().saturating_sub(start);
    if len == 0 {
        return Some((0, 0));
    }
    if len > 1 {
        let tail = &mut pool[start..];
        tail.sort_unstable();
        let mut write = 1usize;
        for read in 1..tail.len() {
            if tail[read] != tail[write - 1] {
                tail[write] = tail[read];
                write += 1;
            }
        }
        pool.truncate(start + write);
    }
    let final_len = pool.len() - start;
    match (u32::try_from(start), u32::try_from(final_len)) {
        (Ok(s), Ok(l)) => Some((s, l)),
        _ => {
            pool.truncate(start);
            None
        }
    }
}

#[cfg(not(unix))]
fn parse_fingerprint_dir_path(
    fp_dir: &Path,
    hardlinks: &mut HardlinkSet,
    scratch: &mut DirScratch,
    dep_fp_pool: &mut Vec<u64>,
) -> ParsedFingerprintDir {
    let mut allocated_bytes: u64 = 0;
    let mut max_mtime: u64 = fs::symlink_metadata(fp_dir)
        .map(|m| meta_mtime_unix(&m))
        .unwrap_or(0);
    let mut corrupt = false;
    let mut targets: SmallVec<[UnitTargetAnchor; 1]> = SmallVec::new();
    let dep_start = dep_fp_pool.len();
    let mut rustc_hash: Option<u64> = None;

    let Ok(entries) = fs::read_dir(fp_dir) else {
        return ParsedFingerprintDir {
            metadata: UnitMetadata::Incomplete {
                mtime_unix: max_mtime,
            },
            allocated_bytes,
            corrupt: true,
        };
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&entry_path) else {
            continue;
        };
        allocated_bytes = allocated_bytes.saturating_add(entry_allocated_bytes(&meta, hardlinks));

        let os_name = entry.file_name();
        let Some(name) = os_name.to_str() else {
            continue;
        };
        if name == "invoked.timestamp" {
            max_mtime = max_mtime.max(meta_mtime_unix(&meta));
            continue;
        }
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if !meta.file_type().is_file() {
            continue;
        }
        max_mtime = max_mtime.max(meta_mtime_unix(&meta));

        if meta.len() > MAX_FINGERPRINT_JSON_BYTES {
            corrupt = true;
            continue;
        }
        let Ok(file) = fs::File::open(&entry_path) else {
            corrupt = true;
            continue;
        };
        if !read_file_into_buf(file, MAX_FINGERPRINT_JSON_BYTES, &mut scratch.read_buf) {
            corrupt = true;
            continue;
        }
        let Some(rustc) = parse_fingerprint_json_into(&scratch.read_buf, dep_fp_pool) else {
            corrupt = true;
            continue;
        };
        rustc_hash = Some(rustc);

        let (target_kind, target_name) = parse_fingerprint_target_stem(stem);
        let companion_path = fp_dir.join(stem);
        let fingerprint_hash = read_companion_fingerprint_hash_path(&companion_path);
        targets.push(UnitTargetAnchor {
            target_kind,
            target_name,
            fingerprint_hash,
        });
    }

    let metadata = match rustc_hash {
        Some(rustc) if !targets.is_empty() => {
            if let Some((dep_fp_start, dep_fp_len)) = finalize_dep_pool_tail(dep_fp_pool, dep_start)
            {
                UnitMetadata::Complete {
                    targets,
                    rustc_hash: rustc,
                    dep_fp_start,
                    dep_fp_len,
                    mtime_unix: max_mtime,
                }
            } else {
                corrupt = true;
                UnitMetadata::Incomplete {
                    mtime_unix: max_mtime,
                }
            }
        }
        _ => {
            dep_fp_pool.truncate(dep_start);
            UnitMetadata::Incomplete {
                mtime_unix: max_mtime,
            }
        }
    };

    ParsedFingerprintDir {
        metadata,
        allocated_bytes,
        corrupt,
    }
}

#[cfg(unix)]
fn parse_fingerprint_dir_fd(
    fp_fd: std::os::fd::OwnedFd,
    hardlinks: &mut HardlinkSet,
    scratch: &mut DirScratch,
    dep_fp_pool: &mut Vec<u64>,
) -> ParsedFingerprintDir {
    use std::ffi::CStr;

    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, fstat, openat, statat};

    let Ok(mut dir) = Dir::new(fp_fd) else {
        return ParsedFingerprintDir {
            metadata: UnitMetadata::Incomplete { mtime_unix: 0 },
            allocated_bytes: 0,
            corrupt: true,
        };
    };

    let mut max_mtime: u64 = dir
        .stat()
        .map(|st| u64::try_from(st.st_mtime).unwrap_or(0))
        .unwrap_or(0);
    let mut allocated_bytes: u64 = 0;
    let mut corrupt = false;
    let mut rustc_hash: Option<u64> = None;

    let arena_mark = scratch.name_arena.len();
    let dep_start = dep_fp_pool.len();
    let mut json_stems: SmallVec<[(usize, usize); 2]> = SmallVec::new();
    let mut companion_cstrs: SmallVec<[(usize, usize, u8); 4]> = SmallVec::new();

    while let Some(entry_res) = dir.read() {
        let Ok(entry) = entry_res else {
            continue;
        };
        let name = entry.file_name();
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let Ok(fd) = dir.fd() else {
            break;
        };
        let d_ft = entry.file_type();
        let name_str = std::str::from_utf8(bytes).ok();

        // Fast path for regular `*.json` fingerprint files: `openat` + `fstat` avoids a duplicate
        // VFS path lookup compared to `statat` + `openat`, and `read_fd_bounded` reads in 1 syscall.
        if d_ft == FileType::RegularFile
            && let Some(stem) = name_str.and_then(|s| s.strip_suffix(".json"))
            && let Ok(json_fd) = openat(
                fd,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
        {
            let Ok(st) = fstat(&json_fd) else {
                corrupt = true;
                continue;
            };
            let mode_ft = FileType::from_raw_mode(st.st_mode);
            let is_dir = mode_ft == FileType::Directory;
            allocated_bytes =
                allocated_bytes.saturating_add(stat_allocated_bytes(&st, is_dir, hardlinks));
            if mode_ft != FileType::RegularFile {
                continue;
            }
            max_mtime = max_mtime.max(u64::try_from(st.st_mtime).unwrap_or(0));
            let file_size = u64::try_from(st.st_size).unwrap_or(u64::MAX);
            let Some(read_len) = read_fd_bounded(
                &json_fd,
                file_size,
                MAX_FINGERPRINT_JSON_BYTES,
                &mut scratch.read_buf,
            ) else {
                corrupt = true;
                continue;
            };
            let Some(rustc) =
                parse_fingerprint_json_into(&scratch.read_buf[..read_len], dep_fp_pool)
            else {
                corrupt = true;
                continue;
            };
            rustc_hash = Some(rustc);

            let stem_start = scratch.name_arena.len();
            scratch.name_arena.extend_from_slice(stem.as_bytes());
            json_stems.push((stem_start, scratch.name_arena.len()));
            continue;
        }

        let Ok(st) = statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        let mode_ft = FileType::from_raw_mode(st.st_mode);
        let is_dir = mode_ft == FileType::Directory;
        allocated_bytes =
            allocated_bytes.saturating_add(stat_allocated_bytes(&st, is_dir, hardlinks));

        let Some(name_str) = name_str else {
            continue;
        };
        if name_str == "invoked.timestamp" {
            max_mtime = max_mtime.max(u64::try_from(st.st_mtime).unwrap_or(0));
            continue;
        }
        if mode_ft != FileType::RegularFile {
            continue;
        }
        if let Some(stem) = name_str.strip_suffix(".json") {
            max_mtime = max_mtime.max(u64::try_from(st.st_mtime).unwrap_or(0));
            let file_size = u64::try_from(st.st_size).unwrap_or(u64::MAX);
            if file_size > MAX_FINGERPRINT_JSON_BYTES {
                corrupt = true;
                continue;
            }
            let Ok(json_fd) = openat(
                fd,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) else {
                corrupt = true;
                continue;
            };
            let Some(read_len) = read_fd_bounded(
                &json_fd,
                file_size,
                MAX_FINGERPRINT_JSON_BYTES,
                &mut scratch.read_buf,
            ) else {
                corrupt = true;
                continue;
            };
            let Some(rustc) =
                parse_fingerprint_json_into(&scratch.read_buf[..read_len], dep_fp_pool)
            else {
                corrupt = true;
                continue;
            };
            rustc_hash = Some(rustc);

            let stem_start = scratch.name_arena.len();
            scratch.name_arena.extend_from_slice(stem.as_bytes());
            json_stems.push((stem_start, scratch.name_arena.len()));
        } else {
            let file_size = u64::try_from(st.st_size).unwrap_or(u64::MAX);
            if file_size <= MAX_COMPANION_HASH_BYTES {
                let c_start = scratch.name_arena.len();
                scratch
                    .name_arena
                    .extend_from_slice(name.to_bytes_with_nul());
                companion_cstrs.push((c_start, scratch.name_arena.len(), file_size as u8));
            }
        }
    }

    let mut targets: SmallVec<[UnitTargetAnchor; 1]> = SmallVec::with_capacity(json_stems.len());
    if let Ok(fd) = dir.fd() {
        for &(stem_start, stem_end) in &json_stems {
            let stem_bytes = &scratch.name_arena[stem_start..stem_end];
            let Ok(stem_str) = std::str::from_utf8(stem_bytes) else {
                continue;
            };
            let (target_kind, target_name) = parse_fingerprint_target_stem(stem_str);
            let fingerprint_hash = companion_cstrs
                .iter()
                .find(|&&(cs, ce, _)| &scratch.name_arena[cs..ce - 1] == stem_bytes)
                .and_then(|&(cs, ce, expected_size)| {
                    let cstr = CStr::from_bytes_with_nul(&scratch.name_arena[cs..ce]).ok()?;
                    read_companion_fingerprint_hash_fd(fd, cstr, u64::from(expected_size))
                });
            targets.push(UnitTargetAnchor {
                target_kind,
                target_name,
                fingerprint_hash,
            });
        }
    }

    scratch.name_arena.truncate(arena_mark);

    let metadata = match rustc_hash {
        Some(rustc) if !targets.is_empty() => {
            if let Some((dep_fp_start, dep_fp_len)) = finalize_dep_pool_tail(dep_fp_pool, dep_start)
            {
                UnitMetadata::Complete {
                    targets,
                    rustc_hash: rustc,
                    dep_fp_start,
                    dep_fp_len,
                    mtime_unix: max_mtime,
                }
            } else {
                corrupt = true;
                UnitMetadata::Incomplete {
                    mtime_unix: max_mtime,
                }
            }
        }
        _ => {
            dep_fp_pool.truncate(dep_start);
            UnitMetadata::Incomplete {
                mtime_unix: max_mtime,
            }
        }
    };

    ParsedFingerprintDir {
        metadata,
        allocated_bytes,
        corrupt,
    }
}

#[cfg(unix)]
fn read_companion_fingerprint_hash_fd(
    dir_fd: rustix::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
    expected_size: u64,
) -> Option<u64> {
    use rustix::fs::{Mode, OFlags, openat};

    if expected_size > MAX_COMPANION_HASH_BYTES {
        return None;
    }
    let fd = openat(
        dir_fd,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let want = expected_size as usize;
    let mut raw = [0u8; MAX_COMPANION_HASH_BYTES as usize + 1];
    let mut len = 0usize;
    loop {
        let offered = raw.len() - len;
        match rustix::io::read(&fd, &mut raw[len..]) {
            Ok(0) => break,
            Ok(n) => {
                len += n;
                if len as u64 > MAX_COMPANION_HASH_BYTES {
                    return None;
                }
                if want > 0 && len == want && n < offered {
                    break;
                }
            }
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return None,
        }
    }
    decode_le_u64_hex(&raw[..len])
}

#[cfg(not(unix))]
fn read_companion_fingerprint_hash_path(path: &Path) -> Option<u64> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > MAX_COMPANION_HASH_BYTES {
        return None;
    }
    let raw = fs::read(path).ok()?;
    decode_le_u64_hex(&raw)
}

struct BuildPkgDirResult {
    total_bytes: u64,
    non_v2_sibling_bytes: u64,
    dir_mtime_unix: u64,
    max_mtime: u64,
    found_v2_child: bool,
    corrupt: bool,
}

#[cfg(unix)]
fn inspect_v2_pkg_dir_fd_into(
    pkg_fd: std::os::fd::OwnedFd,
    pkg_name: &CompactString,
    hardlinks: &mut HardlinkSet,
    scratch: &mut DirScratch,
    out_units: &mut Vec<BuildUnit>,
    out_deps: &mut Vec<u64>,
) -> BuildPkgDirResult {
    use std::ffi::CStr;

    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, fstat, openat, statat};
    use rustix::io::Errno;

    let Ok(mut dir) = Dir::new(pkg_fd) else {
        return BuildPkgDirResult {
            total_bytes: 0,
            non_v2_sibling_bytes: 0,
            dir_mtime_unix: 0,
            max_mtime: 0,
            found_v2_child: false,
            corrupt: true,
        };
    };

    let dir_mtime_unix = dir
        .stat()
        .map(|st| u64::try_from(st.st_mtime).unwrap_or(0))
        .unwrap_or(0);
    let mut total_bytes: u64 = 0;
    let mut non_v2_sibling_bytes: u64 = 0;
    let mut max_mtime: u64 = 0;
    let mut found_v2_child = false;
    let mut corrupt = false;

    let arena_mark = scratch.name_arena.len();
    let spans_mark = scratch.name_spans.len();

    while let Some(entry_res) = dir.read() {
        let Ok(entry) = entry_res else {
            continue;
        };
        let name = entry.file_name();
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let ft = entry.file_type();
        if ft == FileType::Symlink {
            continue;
        }
        if ft == FileType::Directory {
            let start = scratch.name_arena.len();
            scratch
                .name_arena
                .extend_from_slice(name.to_bytes_with_nul());
            scratch.name_spans.push((start, scratch.name_arena.len()));
            continue;
        }
        if ft == FileType::RegularFile {
            let ino = entry.ino();
            if ino != 0 && hardlinks.contains_primary(ino) {
                continue;
            }
        }
        let Ok(fd) = dir.fd() else {
            break;
        };
        let Ok(st) = statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        let mode_ft = FileType::from_raw_mode(st.st_mode);
        if mode_ft == FileType::Symlink {
            continue;
        }
        if mode_ft == FileType::Directory {
            let start = scratch.name_arena.len();
            scratch
                .name_arena
                .extend_from_slice(name.to_bytes_with_nul());
            scratch.name_spans.push((start, scratch.name_arena.len()));
            continue;
        }
        non_v2_sibling_bytes =
            non_v2_sibling_bytes.saturating_add(stat_allocated_bytes(&st, false, hardlinks));
    }

    let spans_end = scratch.name_spans.len();
    for span_idx in spans_mark..spans_end {
        let Ok(fd) = dir.fd() else {
            break;
        };
        let (start, end) = scratch.name_spans[span_idx];
        let Ok(child_cstr) = CStr::from_bytes_with_nul(&scratch.name_arena[start..end]) else {
            continue;
        };
        let is_v2_hash = std::str::from_utf8(child_cstr.to_bytes())
            .ok()
            .filter(|s| is_16_lower_hex(s))
            .map(CompactString::from);

        let Ok(child_fd) = openat(
            fd,
            child_cstr,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            continue;
        };

        let Some(unit_hash) = is_v2_hash else {
            let mut sub_out = DirAccountResult::default();
            sum_dir_fd_recursive(
                child_fd,
                0,
                MtimePolicy::None,
                None,
                hardlinks,
                scratch,
                &mut sub_out,
            );
            non_v2_sibling_bytes = non_v2_sibling_bytes.saturating_add(sub_out.bytes);
            continue;
        };

        found_v2_child = true;
        let parsed = match openat(
            &child_fd,
            c"fingerprint",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fp_fd) => parse_fingerprint_dir_fd(fp_fd, hardlinks, scratch, out_deps),
            Err(Errno::NOENT | Errno::NOTDIR | Errno::LOOP) => {
                let mtime = fstat(&child_fd)
                    .map(|st| u64::try_from(st.st_mtime).unwrap_or(0))
                    .unwrap_or(0);
                ParsedFingerprintDir {
                    metadata: UnitMetadata::Incomplete { mtime_unix: mtime },
                    allocated_bytes: 0,
                    corrupt: false,
                }
            }
            Err(_) => {
                let mtime = fstat(&child_fd)
                    .map(|st| u64::try_from(st.st_mtime).unwrap_or(0))
                    .unwrap_or(0);
                ParsedFingerprintDir {
                    metadata: UnitMetadata::Incomplete { mtime_unix: mtime },
                    allocated_bytes: 0,
                    corrupt: true,
                }
            }
        };
        if parsed.corrupt {
            corrupt = true;
        }

        let mut other_out = DirAccountResult::default();
        sum_dir_fd_recursive(
            child_fd,
            0,
            MtimePolicy::None,
            Some(b"fingerprint"),
            hardlinks,
            scratch,
            &mut other_out,
        );
        let unit_bytes = parsed.allocated_bytes.saturating_add(other_out.bytes);
        let unit_mtime = unit_metadata_mtime(&parsed.metadata);
        max_mtime = max_mtime.max(unit_mtime);
        total_bytes = total_bytes.saturating_add(unit_bytes);
        out_units.push(BuildUnit {
            id: BuildUnitId::V2 {
                pkg: pkg_name.clone(),
                unit_hash,
            },
            metadata: parsed.metadata,
            v1: None,
            allocated_bytes: unit_bytes,
        });
    }

    scratch.name_arena.truncate(arena_mark);
    scratch.name_spans.truncate(spans_mark);

    total_bytes = total_bytes.saturating_add(non_v2_sibling_bytes);
    BuildPkgDirResult {
        total_bytes,
        non_v2_sibling_bytes,
        dir_mtime_unix,
        max_mtime,
        found_v2_child,
        corrupt,
    }
}

#[cfg(not(unix))]
fn inspect_v2_pkg_dir_path_into(
    pkg_path: &Path,
    pkg_name: &CompactString,
    hardlinks: &mut HardlinkSet,
    scratch: &mut DirScratch,
    out_units: &mut Vec<BuildUnit>,
    out_deps: &mut Vec<u64>,
) -> BuildPkgDirResult {
    let dir_mtime_unix = fs::symlink_metadata(pkg_path)
        .map(|m| meta_mtime_unix(&m))
        .unwrap_or(0);
    let mut total_bytes: u64 = 0;
    let mut non_v2_sibling_bytes: u64 = 0;
    let mut max_mtime: u64 = 0;
    let mut found_v2_child = false;
    let mut corrupt = false;

    match fs::read_dir(pkg_path) {
        Ok(children) => {
            for child in children.flatten() {
                let child_path = child.path();
                let Ok(cft) = child.file_type() else {
                    continue;
                };
                if cft.is_symlink() {
                    continue;
                }
                if !cft.is_dir() {
                    if let Ok(meta) = fs::symlink_metadata(&child_path) {
                        non_v2_sibling_bytes = non_v2_sibling_bytes
                            .saturating_add(entry_allocated_bytes(&meta, hardlinks));
                    }
                    continue;
                }
                let child_os = child.file_name();
                let Some(child_name) = child_os.to_str() else {
                    non_v2_sibling_bytes = non_v2_sibling_bytes.saturating_add(
                        account_tree(&child_path, MtimePolicy::None, None, hardlinks, scratch)
                            .bytes,
                    );
                    continue;
                };
                if !is_16_lower_hex(child_name) {
                    non_v2_sibling_bytes = non_v2_sibling_bytes.saturating_add(
                        account_tree(&child_path, MtimePolicy::None, None, hardlinks, scratch)
                            .bytes,
                    );
                    continue;
                }

                found_v2_child = true;
                let unit_hash = CompactString::from(child_name);
                let fp_sub = child_path.join("fingerprint");
                let parsed = if fs::symlink_metadata(&fp_sub).is_ok_and(|m| m.file_type().is_dir())
                {
                    parse_fingerprint_dir_path(&fp_sub, hardlinks, scratch, out_deps)
                } else {
                    let mtime = fs::symlink_metadata(&child_path)
                        .map(|m| meta_mtime_unix(&m))
                        .unwrap_or(0);
                    ParsedFingerprintDir {
                        metadata: UnitMetadata::Incomplete { mtime_unix: mtime },
                        allocated_bytes: 0,
                        corrupt: false,
                    }
                };
                if parsed.corrupt {
                    corrupt = true;
                }
                let other_bytes = account_tree(
                    &child_path,
                    MtimePolicy::None,
                    Some(b"fingerprint"),
                    hardlinks,
                    scratch,
                )
                .bytes;
                let unit_bytes = parsed.allocated_bytes.saturating_add(other_bytes);
                let unit_mtime = unit_metadata_mtime(&parsed.metadata);
                max_mtime = max_mtime.max(unit_mtime);
                total_bytes = total_bytes.saturating_add(unit_bytes);
                out_units.push(BuildUnit {
                    id: BuildUnitId::V2 {
                        pkg: pkg_name.clone(),
                        unit_hash,
                    },
                    metadata: parsed.metadata,
                    v1: None,
                    allocated_bytes: unit_bytes,
                });
            }
        }
        Err(_) => {
            corrupt = true;
        }
    }

    total_bytes = total_bytes.saturating_add(non_v2_sibling_bytes);
    BuildPkgDirResult {
        total_bytes,
        non_v2_sibling_bytes,
        dir_mtime_unix,
        max_mtime,
        found_v2_child,
        corrupt,
    }
}

fn inspect_v1_deps_dir(
    deps_root: &Path,
    v1_hash_to_indices: &HashMap<u64, SmallVec<[usize; 2]>, FastU64BuildHasher>,
    hardlinks: &mut HardlinkSet,
    scratch: &mut DirScratch,
    out_by_hash: &mut HashMap<u64, V1DepHashStats, FastU64BuildHasher>,
) -> (u64, bool) {
    #[cfg(unix)]
    {
        use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, fstat, open, openat, statat};

        let Ok(deps_fd) = open(
            deps_root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            return (0, true);
        };
        let Ok(mut dir) = Dir::new(deps_fd) else {
            return (0, true);
        };

        let mut total_bytes: u64 = 0;

        while let Some(entry_res) = dir.read() {
            let Ok(entry) = entry_res else {
                continue;
            };
            let name = entry.file_name();
            let bytes_name = name.to_bytes();
            if bytes_name == b"." || bytes_name == b".." {
                continue;
            }
            let hash_u64 = std::str::from_utf8(bytes_name)
                .ok()
                .and_then(extract_16hex_from_dep_name)
                .and_then(parse_16_lower_hex_u64);
            let need_mtime = hash_u64.is_some_and(|h| !v1_hash_to_indices.contains_key(&h));

            let ft = entry.file_type();
            let (entry_bytes, entry_mtime) = if ft == FileType::Directory {
                let Ok(fd) = dir.fd() else {
                    break;
                };
                if let Ok(child_fd) = openat(
                    fd,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    let mtime = if need_mtime {
                        fstat(&child_fd)
                            .map(|st| u64::try_from(st.st_mtime).unwrap_or(0))
                            .unwrap_or(0)
                    } else {
                        0
                    };
                    let mut sub_out = DirAccountResult::default();
                    sum_dir_fd_recursive(
                        child_fd,
                        0,
                        MtimePolicy::None,
                        None,
                        hardlinks,
                        scratch,
                        &mut sub_out,
                    );
                    (sub_out.bytes, mtime)
                } else {
                    (0, 0)
                }
            } else if !need_mtime && ft == FileType::RegularFile {
                let ino = entry.ino();
                if ino != 0 && hardlinks.contains_primary(ino) {
                    (0, 0)
                } else {
                    let Ok(fd) = dir.fd() else {
                        break;
                    };
                    let Ok(st) = statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
                        continue;
                    };
                    (stat_allocated_bytes(&st, false, hardlinks), 0)
                }
            } else {
                let Ok(fd) = dir.fd() else {
                    break;
                };
                let Ok(st) = statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
                    continue;
                };
                let mode_ft = FileType::from_raw_mode(st.st_mode);
                let mtime = u64::try_from(st.st_mtime).unwrap_or(0);
                if mode_ft == FileType::Directory {
                    if let Ok(child_fd) = openat(
                        fd,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    ) {
                        let mut sub_out = DirAccountResult::default();
                        sum_dir_fd_recursive(
                            child_fd,
                            0,
                            MtimePolicy::None,
                            None,
                            hardlinks,
                            scratch,
                            &mut sub_out,
                        );
                        (sub_out.bytes, mtime)
                    } else {
                        (0, mtime)
                    }
                } else {
                    (stat_allocated_bytes(&st, false, hardlinks), mtime)
                }
            };

            total_bytes = total_bytes.saturating_add(entry_bytes);
            if let Some(h) = hash_u64 {
                let slot = out_by_hash.entry(h).or_default();
                slot.bytes = slot.bytes.saturating_add(entry_bytes);
                slot.max_mtime = slot.max_mtime.max(entry_mtime);
                slot.count = slot.count.saturating_add(1);
            }
        }

        (total_bytes, false)
    }
    #[cfg(not(unix))]
    {
        let _ = v1_hash_to_indices;
        let mut total_bytes: u64 = 0;
        match fs::read_dir(deps_root) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    let Ok(emeta) = fs::symlink_metadata(&entry_path) else {
                        continue;
                    };
                    let bytes = if emeta.file_type().is_dir() && !emeta.file_type().is_symlink() {
                        account_tree(&entry_path, MtimePolicy::None, None, hardlinks, scratch).bytes
                    } else {
                        entry_allocated_bytes(&emeta, hardlinks)
                    };
                    total_bytes = total_bytes.saturating_add(bytes);
                    if let Some(name) = entry.file_name().to_str()
                        && let Some(hash_u64) =
                            extract_16hex_from_dep_name(name).and_then(parse_16_lower_hex_u64)
                    {
                        let slot = out_by_hash.entry(hash_u64).or_default();
                        slot.bytes = slot.bytes.saturating_add(bytes);
                        slot.max_mtime = slot.max_mtime.max(meta_mtime_unix(&emeta));
                        slot.count = slot.count.saturating_add(1);
                    }
                }
                (total_bytes, false)
            }
            Err(_) => (0, true),
        }
    }
}

pub(crate) fn parse_fingerprint_target_stem(stem: &str) -> (UnitTargetKind, CompactString) {
    if let Some(rest) = stem.strip_prefix("lib-") {
        (UnitTargetKind::Lib, CompactString::from(rest))
    } else if let Some(rest) = stem.strip_prefix("bin-") {
        (UnitTargetKind::Bin, CompactString::from(rest))
    } else if let Some(rest) = stem.strip_prefix("test-") {
        (UnitTargetKind::Test, CompactString::from(rest))
    } else if let Some(rest) = stem.strip_prefix("example-") {
        (UnitTargetKind::Example, CompactString::from(rest))
    } else if let Some(rest) = stem.strip_prefix("bench-") {
        (UnitTargetKind::Bench, CompactString::from(rest))
    } else if let Some(rest) = stem.strip_prefix("run-build-script-") {
        (UnitTargetKind::RunBuildScript, CompactString::from(rest))
    } else if let Some(rest) = stem.strip_prefix("build-script-") {
        (UnitTargetKind::BuildScriptBuild, CompactString::from(rest))
    } else if let Some(rest) = stem.strip_prefix("doc-") {
        (UnitTargetKind::Doc, CompactString::from(rest))
    } else {
        (UnitTargetKind::Other, CompactString::from(stem))
    }
}

pub(crate) fn decode_le_u64_hex(raw: &[u8]) -> Option<u64> {
    let trimmed = raw
        .iter()
        .copied()
        .take_while(|b| !b.is_ascii_whitespace())
        .collect::<SmallVec<[u8; 16]>>();
    if trimmed.len() != 16 {
        return None;
    }
    let mut bytes = [0u8; 8];
    for i in 0..8 {
        let hi = ascii_hex(trimmed[i * 2])?;
        let lo = ascii_hex(trimmed[i * 2 + 1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Some(u64::from_le_bytes(bytes))
}

fn ascii_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(unix)]
fn inspect_incremental_dir_fd(
    inc_root_path: &Path,
    parent_fd: rustix::fd::BorrowedFd<'_>,
    entry_name: &std::ffi::CStr,
    dir_name: CompactString,
    platform: &impl Platform,
    hardlinks: &mut HardlinkSet,
    scratch: &mut DirScratch,
) -> IncrementalDir {
    use std::ffi::CStr;

    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, statat};

    let crate_name = extract_incremental_crate_name(&dir_name);
    let Ok(dir_fd) = open_child_dir_nofollow(parent_fd, entry_name) else {
        // Fail closed when an incremental crate directory is unreadable: mark `any_locked = true`
        // so `R3` never treats it as an empty unlocked `WorkingOnly` directory.
        let dir_mtime_unix = statat(parent_fd, entry_name, AtFlags::SYMLINK_NOFOLLOW)
            .map(|st| u64::try_from(st.st_mtime).unwrap_or(0))
            .unwrap_or(0);
        return IncrementalDir {
            dir_name,
            crate_name,
            sessions: SmallVec::new(),
            any_locked: true,
            dir_mtime_unix,
            latest_mtime_unix: dir_mtime_unix,
            allocated_bytes: 0,
        };
    };
    let Ok(mut dir) = Dir::new(dir_fd) else {
        return IncrementalDir {
            dir_name,
            crate_name,
            sessions: SmallVec::new(),
            any_locked: true,
            dir_mtime_unix: 0,
            latest_mtime_unix: 0,
            allocated_bytes: 0,
        };
    };

    let dir_mtime_unix = dir
        .stat()
        .map(|st| u64::try_from(st.st_mtime).unwrap_or(0))
        .unwrap_or(0);
    // Compute freshness strictly from `s-*.lock` files and `s-*` session contents so pruning
    // an older session (which bumps the crate dir mtime) never resets target age or top-M rank.
    let mut latest_mtime_unix: u64 = 0;
    let mut allocated_bytes: u64 = 0;

    let arena_mark = scratch.name_arena.len();
    let mut locks: SmallVec<[(CompactString, bool, u64); 4]> = SmallVec::new();
    let mut session_spans: SmallVec<[(usize, usize); 4]> = SmallVec::new();
    let mut other_dir_spans: SmallVec<[(usize, usize); 2]> = SmallVec::new();
    scratch.path_buf.clear();
    scratch.path_buf.push(inc_root_path);
    scratch.path_buf.push(dir_name.as_str());

    while let Some(entry_res) = dir.read() {
        let Ok(entry) = entry_res else {
            continue;
        };
        let name = entry.file_name();
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name_str = std::str::from_utf8(bytes).ok();
        let ft = entry.file_type();
        if ft == FileType::Directory {
            let start = scratch.name_arena.len();
            scratch
                .name_arena
                .extend_from_slice(name.to_bytes_with_nul());
            let span = (start, scratch.name_arena.len());
            if name_str.is_some_and(|s| s.starts_with("s-")) {
                session_spans.push(span);
            } else {
                other_dir_spans.push(span);
            }
            continue;
        }

        let Ok(fd) = dir.fd() else {
            break;
        };
        let Ok(st) = statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        let mode_ft = FileType::from_raw_mode(st.st_mode);
        if mode_ft == FileType::Directory {
            let start = scratch.name_arena.len();
            scratch
                .name_arena
                .extend_from_slice(name.to_bytes_with_nul());
            let span = (start, scratch.name_arena.len());
            if name_str.is_some_and(|s| s.starts_with("s-")) {
                session_spans.push(span);
            } else {
                other_dir_spans.push(span);
            }
            continue;
        }

        if mode_ft == FileType::RegularFile
            && let Some(s) = name_str
            && s.starts_with("s-")
            && s.ends_with(".lock")
        {
            scratch.path_buf.push(s);
            let locked = match platform.try_lock_readonly(&scratch.path_buf) {
                Ok(LockProbe::Acquired(file)) => {
                    let _ = file.unlock();
                    false
                }
                Ok(LockProbe::NotFound) => false,
                Ok(LockProbe::Contested) | Err(_) => true,
            };
            scratch.path_buf.pop();

            let mtime = u64::try_from(st.st_mtime).unwrap_or(0);
            latest_mtime_unix = latest_mtime_unix.max(mtime);
            allocated_bytes =
                allocated_bytes.saturating_add(stat_allocated_bytes(&st, false, hardlinks));
            locks.push((CompactString::from(s), locked, mtime));
        } else {
            allocated_bytes =
                allocated_bytes.saturating_add(stat_allocated_bytes(&st, false, hardlinks));
        }
    }

    let mut any_locked = locks.iter().any(|(_, locked, _)| *locked);
    let mut sessions: SmallVec<[IncrementalSession; 1]> =
        SmallVec::with_capacity(session_spans.len());

    for &(start, end) in &session_spans {
        let Ok(fd) = dir.fd() else {
            break;
        };
        let Ok(cstr) = CStr::from_bytes_with_nul(&scratch.name_arena[start..end]) else {
            continue;
        };
        let Ok(name_str) = cstr.to_str() else {
            continue;
        };
        let sess_name = CompactString::from(name_str);
        let state = if name_str.ends_with("-working") {
            SessionState::Working
        } else {
            SessionState::Finalized
        };
        let lock_match = name_str.rsplit_once('-').and_then(|(prefix, _)| {
            locks.iter().find(|(lname, _, _)| {
                lname.len() == prefix.len() + 5
                    && lname.starts_with(prefix)
                    && lname.ends_with(".lock")
            })
        });
        let (lock_file, locked, lock_mtime) = match lock_match {
            Some((lname, is_locked, lm)) => (Some(lname.clone()), *is_locked, Some(*lm)),
            None => (None, false, None),
        };
        if locked {
            any_locked = true;
        }

        let mut sess_out = DirAccountResult::default();
        if let Ok(sess_fd) = openat(
            fd,
            cstr,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            sum_dir_fd_recursive(
                sess_fd,
                0,
                MtimePolicy::UpToDepth(1),
                None,
                hardlinks,
                scratch,
                &mut sess_out,
            );
        }
        if let Some(lm) = lock_mtime {
            sess_out.max_mtime = sess_out.max_mtime.max(lm);
        }
        latest_mtime_unix = latest_mtime_unix.max(sess_out.max_mtime);
        allocated_bytes = allocated_bytes.saturating_add(sess_out.bytes);

        sessions.push(IncrementalSession {
            dir_name: sess_name,
            lock_file,
            state,
            locked,
            mtime_unix: sess_out.max_mtime,
            allocated_bytes: sess_out.bytes,
        });
    }

    for &(start, end) in &other_dir_spans {
        let Ok(fd) = dir.fd() else {
            break;
        };
        if let Ok(cstr) = CStr::from_bytes_with_nul(&scratch.name_arena[start..end])
            && let Ok(sub_fd) = openat(
                fd,
                cstr,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        {
            let mut sub_out = DirAccountResult::default();
            sum_dir_fd_recursive(
                sub_fd,
                0,
                MtimePolicy::None,
                None,
                hardlinks,
                scratch,
                &mut sub_out,
            );
            allocated_bytes = allocated_bytes.saturating_add(sub_out.bytes);
        }
    }

    scratch.name_arena.truncate(arena_mark);

    if latest_mtime_unix == 0 {
        latest_mtime_unix = dir_mtime_unix;
    }

    IncrementalDir {
        dir_name,
        crate_name,
        sessions,
        any_locked,
        dir_mtime_unix,
        latest_mtime_unix,
        allocated_bytes,
    }
}

#[cfg(not(unix))]
fn inspect_incremental_dir_path(
    dir_path: &Path,
    dir_name: CompactString,
    platform: &impl Platform,
    hardlinks: &mut HardlinkSet,
    scratch: &mut DirScratch,
) -> IncrementalDir {
    let crate_name = extract_incremental_crate_name(&dir_name);
    let mut sessions: SmallVec<[IncrementalSession; 1]> = SmallVec::new();
    let mut locks: SmallVec<[(CompactString, bool, u64); 4]> = SmallVec::new();
    let mut allocated_bytes: u64 = 0;
    let dir_mtime_unix: u64 = fs::symlink_metadata(dir_path)
        .map(|m| meta_mtime_unix(&m))
        .unwrap_or(0);
    let mut latest_mtime_unix: u64 = 0;

    let (entries, dir_unreadable) = match fs::read_dir(dir_path) {
        Ok(rd) => (rd.flatten().collect(), false),
        Err(_) => (Vec::new(), true),
    };

    let mut session_entries: Vec<(CompactString, PathBuf)> = Vec::new();
    for entry in entries {
        let entry_path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&entry_path) else {
            continue;
        };
        let os_name = entry.file_name();
        let Some(name) = os_name.to_str() else {
            continue;
        };
        if meta.file_type().is_file() && name.starts_with("s-") && name.ends_with(".lock") {
            let locked = match platform.try_lock_readonly(&entry_path) {
                Ok(LockProbe::Acquired(file)) => {
                    let _ = file.unlock();
                    false
                }
                Ok(LockProbe::NotFound) => false,
                Ok(LockProbe::Contested) | Err(_) => true,
            };
            let mtime = meta_mtime_unix(&meta);
            latest_mtime_unix = latest_mtime_unix.max(mtime);
            allocated_bytes =
                allocated_bytes.saturating_add(entry_allocated_bytes(&meta, hardlinks));
            locks.push((CompactString::from(name), locked, mtime));
        } else if meta.file_type().is_dir()
            && !meta.file_type().is_symlink()
            && name.starts_with("s-")
        {
            session_entries.push((CompactString::from(name), entry_path));
        } else if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
            allocated_bytes = allocated_bytes.saturating_add(
                account_tree(&entry_path, MtimePolicy::None, None, hardlinks, scratch).bytes,
            );
        } else {
            allocated_bytes =
                allocated_bytes.saturating_add(entry_allocated_bytes(&meta, hardlinks));
        }
    }

    let mut any_locked = dir_unreadable || locks.iter().any(|(_, locked, _)| *locked);
    for (name, entry_path) in session_entries {
        let state = if name.ends_with("-working") {
            SessionState::Working
        } else {
            SessionState::Finalized
        };
        let lock_match = name.rsplit_once('-').and_then(|(prefix, _)| {
            locks.iter().find(|(lname, _, _)| {
                lname.len() == prefix.len() + 5
                    && lname.starts_with(prefix)
                    && lname.ends_with(".lock")
            })
        });
        let (lock_file, locked, lock_mtime) = match lock_match {
            Some((lname, is_locked, lm)) => (Some(lname.clone()), *is_locked, Some(*lm)),
            None => (None, false, None),
        };
        if locked {
            any_locked = true;
        }
        let mut res = account_tree(
            &entry_path,
            MtimePolicy::UpToDepth(1),
            None,
            hardlinks,
            scratch,
        );
        if let Some(lm) = lock_mtime {
            res.max_mtime = res.max_mtime.max(lm);
        }
        latest_mtime_unix = latest_mtime_unix.max(res.max_mtime);
        allocated_bytes = allocated_bytes.saturating_add(res.bytes);
        sessions.push(IncrementalSession {
            dir_name: name,
            lock_file,
            state,
            locked,
            mtime_unix: res.max_mtime,
            allocated_bytes: res.bytes,
        });
    }

    if latest_mtime_unix == 0 {
        latest_mtime_unix = dir_mtime_unix;
    }

    IncrementalDir {
        dir_name,
        crate_name,
        sessions,
        any_locked,
        dir_mtime_unix,
        latest_mtime_unix,
        allocated_bytes,
    }
}

pub(crate) fn extract_incremental_crate_name(dir_name: &str) -> CompactString {
    if let Some((prefix, suffix)) = dir_name.rsplit_once('-')
        && !prefix.is_empty()
        && suffix.len() >= 6
        && suffix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return CompactString::from(prefix);
    }
    CompactString::from(dir_name)
}

pub(crate) fn split_pkg_and_16hex(name: &str) -> Option<(CompactString, CompactString)> {
    let (pkg, hash) = name.rsplit_once('-')?;
    if !pkg.is_empty() && is_16_lower_hex(hash) {
        Some((CompactString::from(pkg), CompactString::from(hash)))
    } else {
        None
    }
}

fn unit_metadata_mtime(meta: &UnitMetadata) -> u64 {
    match meta {
        UnitMetadata::Complete { mtime_unix, .. } | UnitMetadata::Incomplete { mtime_unix } => {
            *mtime_unix
        }
    }
}

#[derive(Clone, Debug)]
struct RepoGitInfo {
    repo_common_dir: PathBuf,
    worktree_root: PathBuf,
    worktree_kind: WorktreeKind,
    worktree_dir_missing: bool,
    is_dirty: bool,
    git_op_in_progress: bool,
    worktree_locked: bool,
    branch_merged_into_default: Option<bool>,
}

fn preinspect_git_for_candidates<P: Platform + Sync>(
    candidates: &[DiscoveredCandidate],
    platform: &P,
) -> PreinspectedGit {
    if candidates.len() <= 1 {
        return PreinspectedGit {
            by_target: HashMap::new(),
            git_repo_cache: HashMap::new(),
            default_ref_cache: HashMap::new(),
        };
    }

    let mut cand_anchors: Vec<(&Path, Option<PathBuf>)> = Vec::with_capacity(candidates.len());
    let mut seen_anchors: HashSet<PathBuf> = HashSet::new();
    let mut unique_anchors: Vec<PathBuf> = Vec::new();
    for cand in candidates {
        let anchor = find_git_ancestor(&cand.path);
        if let Some(ref a) = anchor
            && seen_anchors.insert(a.clone())
        {
            unique_anchors.push(a.clone());
        }
        cand_anchors.push((cand.path.as_path(), anchor));
    }

    let mut by_target: HashMap<PathBuf, GitDiscovery> = HashMap::with_capacity(candidates.len());
    if unique_anchors.is_empty() {
        for (path, _) in cand_anchors {
            by_target.insert(path.to_path_buf(), GitDiscovery::NotInGitRepo);
        }
        return PreinspectedGit {
            by_target,
            git_repo_cache: HashMap::new(),
            default_ref_cache: HashMap::new(),
        };
    }

    let default_ref_cache: Mutex<HashMap<PathBuf, Option<String>>> = Mutex::new(HashMap::new());
    let mut git_repo_cache: HashMap<PathBuf, Result<RepoGitInfo, CompactString>> =
        HashMap::with_capacity(unique_anchors.len());

    if unique_anchors.len() == 1 {
        let anchor = unique_anchors.pop().unwrap();
        let res = inspect_repo_git_shared(&anchor, platform, &default_ref_cache);
        git_repo_cache.insert(anchor, res);
    } else {
        let worker_count = unique_anchors.len().min(bounded_git_worker_count());
        let next_idx = AtomicUsize::new(0);
        let run_worker = || {
            let mut local = Vec::new();
            loop {
                let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                let Some(anchor) = unique_anchors.get(idx) else {
                    break;
                };
                let res = inspect_repo_git_shared(anchor, platform, &default_ref_cache);
                local.push((idx, res));
            }
            local
        };
        let anchor_results: Vec<Vec<(usize, Result<RepoGitInfo, CompactString>)>> =
            std::thread::scope(|scope| {
                let helper_count = worker_count.saturating_sub(1);
                let mut handles = Vec::with_capacity(helper_count);
                for _ in 0..helper_count {
                    handles.push(scope.spawn(run_worker));
                }
                let mut results = Vec::with_capacity(worker_count);
                results.push(run_worker());
                for h in handles {
                    results.push(h.join().expect("git repo preinspection thread panicked"));
                }
                results
            });
        for batch in anchor_results {
            for (idx, res) in batch {
                git_repo_cache.insert(unique_anchors[idx].clone(), res);
            }
        }
    }

    let mut ls_tasks: Vec<(&Path, &RepoGitInfo)> = Vec::new();
    for (path, anchor_opt) in &cand_anchors {
        let Some(anchor) = anchor_opt else {
            by_target.insert(path.to_path_buf(), GitDiscovery::NotInGitRepo);
            continue;
        };
        match git_repo_cache.get(anchor) {
            Some(Ok(info)) => ls_tasks.push((*path, info)),
            Some(Err(reason)) => {
                by_target.insert(path.to_path_buf(), GitDiscovery::Failed(reason.clone()));
            }
            None => {}
        }
    }

    if ls_tasks.len() <= 1 {
        for (path, info) in ls_tasks {
            let disc = finalize_git_discovery_for_target(path, info.clone(), platform, None);
            by_target.insert(path.to_path_buf(), disc);
        }
    } else {
        let worker_count = ls_tasks.len().min(bounded_git_worker_count());
        let next_idx = AtomicUsize::new(0);
        let run_worker = || {
            let mut local = Vec::new();
            loop {
                let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                let Some(&(path, info)) = ls_tasks.get(idx) else {
                    break;
                };
                let disc = finalize_git_discovery_for_target(path, info.clone(), platform, None);
                local.push((path.to_path_buf(), disc));
            }
            local
        };
        let ls_results: Vec<Vec<(PathBuf, GitDiscovery)>> = std::thread::scope(|scope| {
            let helper_count = worker_count.saturating_sub(1);
            let mut handles = Vec::with_capacity(helper_count);
            for _ in 0..helper_count {
                handles.push(scope.spawn(run_worker));
            }
            let mut results = Vec::with_capacity(worker_count);
            results.push(run_worker());
            for h in handles {
                results.push(
                    h.join()
                        .expect("git ls-files preinspection thread panicked"),
                );
            }
            results
        });
        for batch in ls_results {
            for (path, disc) in batch {
                by_target.insert(path, disc);
            }
        }
    }

    PreinspectedGit {
        by_target,
        git_repo_cache,
        default_ref_cache: default_ref_cache
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    }
}

fn inspect_git_for_target(
    target_root: &Path,
    platform: &impl Platform,
    cache: &mut HashMap<PathBuf, Result<RepoGitInfo, CompactString>>,
    default_ref_cache: &mut HashMap<PathBuf, Option<String>>,
    parent_clean_git: Option<(&Path, &Path)>,
) -> GitDiscovery {
    let Some(repo_anchor) = find_git_ancestor(target_root) else {
        return GitDiscovery::NotInGitRepo;
    };

    let repo_info = match cache.get(&repo_anchor) {
        Some(cached) => cached.clone(),
        None => {
            let computed = inspect_repo_git(&repo_anchor, platform, default_ref_cache);
            cache.insert(repo_anchor.clone(), computed.clone());
            computed
        }
    };

    let info = match repo_info {
        Ok(info) => info,
        Err(reason) => return GitDiscovery::Failed(reason),
    };

    finalize_git_discovery_for_target(target_root, info, platform, parent_clean_git)
}

fn finalize_git_discovery_for_target(
    target_root: &Path,
    info: RepoGitInfo,
    platform: &impl Platform,
    parent_clean_git: Option<(&Path, &Path)>,
) -> GitDiscovery {
    let norm_target = normalize_macos_system_symlinks_cow(target_root);
    let has_tracked_files_in_target = if !info.worktree_dir_missing {
        let Ok(rel_target) = norm_target.strip_prefix(&info.worktree_root) else {
            return GitDiscovery::Failed(CompactString::new(
                "target path outside inspected git worktree root",
            ));
        };
        if rel_target.as_os_str().is_empty() {
            return GitDiscovery::Failed(CompactString::new(
                "target path equals git worktree root",
            ));
        }
        let Some(rel_str) = rel_target.to_str() else {
            return GitDiscovery::Failed(CompactString::new(
                "non-utf8 target path inside git worktree",
            ));
        };
        // If our direct parent target in the same worktree already proved zero tracked files
        // recursively via `git ls-files`, any child subtree inside it also has zero tracked files.
        let subsumed_by_clean_parent = parent_clean_git.is_some_and(|(wt_root, parent_norm)| {
            wt_root == info.worktree_root.as_path() && norm_target.starts_with(parent_norm)
        });
        if subsumed_by_clean_parent {
            false
        } else {
            match platform.run_git(&info.worktree_root, &["ls-files", "-z", "--", rel_str]) {
                Ok(out) if out.status_code == Some(0) => !out.stdout.is_empty(),
                Ok(out) => {
                    return GitDiscovery::Failed(CompactString::from(format!(
                        "git ls-files exited {:?}",
                        out.status_code
                    )));
                }
                Err(error) => {
                    return GitDiscovery::Failed(CompactString::from(error.to_string()));
                }
            }
        }
    } else {
        false
    };

    GitDiscovery::Inspected(GitInspection {
        repo_common_dir: info.repo_common_dir,
        worktree_root: info.worktree_root,
        worktree_kind: info.worktree_kind,
        worktree_dir_missing: info.worktree_dir_missing,
        is_dirty: info.is_dirty,
        git_op_in_progress: info.git_op_in_progress,
        worktree_locked: info.worktree_locked,
        branch_merged_into_default: info.branch_merged_into_default,
        has_tracked_files_in_target,
    })
}

fn find_git_ancestor(target_root: &Path) -> Option<PathBuf> {
    let mut current = target_root.parent();
    while let Some(dir) = current {
        if fs::symlink_metadata(dir.join(".git")).is_ok() {
            return Some(dir.to_path_buf());
        }
        current = dir.parent();
    }
    None
}

fn infer_non_git_project_dir(target_root: &Path) -> Option<PathBuf> {
    if target_root.file_name().and_then(|n| n.to_str()) == Some("target")
        && let Some(parent) = target_root.parent()
        && parent.join("Cargo.toml").exists()
    {
        return Some(parent.to_path_buf());
    }
    None
}

fn inspect_repo_git(
    repo_dir: &Path,
    platform: &impl Platform,
    default_ref_cache: &mut HashMap<PathBuf, Option<String>>,
) -> Result<RepoGitInfo, CompactString> {
    inspect_repo_git_core(repo_dir, platform, |wt_root, common_dir| {
        if let Some(cached) = default_ref_cache.get(common_dir) {
            return cached.clone();
        }
        let resolved = resolve_local_default_ref(wt_root, platform);
        default_ref_cache.insert(common_dir.to_path_buf(), resolved.clone());
        resolved
    })
}

fn inspect_repo_git_shared(
    repo_dir: &Path,
    platform: &impl Platform,
    default_ref_cache: &Mutex<HashMap<PathBuf, Option<String>>>,
) -> Result<RepoGitInfo, CompactString> {
    inspect_repo_git_core(repo_dir, platform, |wt_root, common_dir| {
        {
            let guard = default_ref_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(cached) = guard.get(common_dir) {
                return cached.clone();
            }
        }
        let resolved = resolve_local_default_ref(wt_root, platform);
        let mut guard = default_ref_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .entry(common_dir.to_path_buf())
            .or_insert(resolved)
            .clone()
    })
}

fn inspect_repo_git_core<F>(
    repo_dir: &Path,
    platform: &impl Platform,
    resolve_default_ref: F,
) -> Result<RepoGitInfo, CompactString>
where
    F: FnOnce(&Path, &Path) -> Option<String>,
{
    let rev = platform
        .run_git(
            repo_dir,
            &[
                "rev-parse",
                "--show-toplevel",
                "--git-dir",
                "--git-common-dir",
            ],
        )
        .map_err(|e| CompactString::from(e.to_string()))?;
    if rev.status_code != Some(0) {
        return Err(CompactString::from(format!(
            "git rev-parse exited {:?}",
            rev.status_code
        )));
    }
    let rev_text = std::str::from_utf8(&rev.stdout)
        .map_err(|_| CompactString::from("git rev-parse non-utf8 output"))?;
    let mut lines = rev_text.lines();
    let toplevel_raw = lines
        .next()
        .ok_or_else(|| CompactString::from("missing toplevel"))?;
    let git_dir_raw = lines
        .next()
        .ok_or_else(|| CompactString::from("missing git-dir"))?;
    let common_dir_raw = lines
        .next()
        .ok_or_else(|| CompactString::from("missing git-common-dir"))?;

    let worktree_root = resolve_git_path(repo_dir, Path::new(toplevel_raw));
    let git_dir = resolve_git_path(repo_dir, Path::new(git_dir_raw));
    let repo_common_dir = resolve_git_path(repo_dir, Path::new(common_dir_raw));

    let worktree_kind = if git_dir == repo_common_dir {
        WorktreeKind::MainCheckout
    } else {
        WorktreeKind::LinkedWorktree
    };

    let worktree_dir_missing = !worktree_root.exists();
    // Each linked worktree maintains its own `git_dir` (`.git/worktrees/<name>/`); checking
    // `repo_common_dir` would falsely propagate an operation in the main checkout to every worktree.
    let git_op_in_progress = has_git_op_markers(&git_dir);
    let worktree_locked =
        worktree_kind == WorktreeKind::LinkedWorktree && git_dir.join("locked").exists();

    if worktree_dir_missing {
        return Ok(RepoGitInfo {
            repo_common_dir,
            worktree_root,
            worktree_kind,
            worktree_dir_missing: true,
            is_dirty: false,
            git_op_in_progress,
            worktree_locked,
            branch_merged_into_default: None,
        });
    }

    // `is_dirty` and `branch_merged_into_default` are only consulted for unlocked, non-op
    // `LinkedWorktree`s; skipping `git status` on `MainCheckout` / locked / active-op repos
    // avoids expensive full working-tree stat walks on large monorepos.
    let (is_dirty, branch_merged_into_default) =
        if worktree_kind == WorktreeKind::LinkedWorktree && !worktree_locked && !git_op_in_progress
        {
            let status = platform
                .run_git(
                    &worktree_root,
                    &["status", "--porcelain=v1", "-z", "--untracked-files=normal"],
                )
                .map_err(|e| CompactString::from(e.to_string()))?;
            if status.status_code != Some(0) {
                return Err(CompactString::from(format!(
                    "git status exited {:?}",
                    status.status_code
                )));
            }
            let dirty = !status.stdout.is_empty();
            let merged = if !dirty {
                check_branch_merged_locally(
                    &worktree_root,
                    &repo_common_dir,
                    platform,
                    resolve_default_ref,
                )
            } else {
                None
            };
            (dirty, merged)
        } else {
            (false, None)
        };

    Ok(RepoGitInfo {
        repo_common_dir,
        worktree_root,
        worktree_kind,
        worktree_dir_missing,
        is_dirty,
        git_op_in_progress,
        worktree_locked,
        branch_merged_into_default,
    })
}

fn resolve_git_path(base: &Path, raw: &Path) -> PathBuf {
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        base.join(raw)
    };
    fs::canonicalize(&joined).unwrap_or(joined)
}

fn has_git_op_markers(git_dir: &Path) -> bool {
    // Note: standalone `REBASE_HEAD` is intentionally omitted — Git can leave `REBASE_HEAD`
    // behind after rebase completes or resets, whereas active rebases always hold
    // `rebase-merge/` or `rebase-apply/`.
    const MARKERS: &[&str] = &[
        "index.lock",
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
        "rebase-merge",
        "rebase-apply",
    ];
    let mut candidate = git_dir.to_path_buf();
    for marker in MARKERS {
        candidate.push(marker);
        let exists = candidate.exists();
        candidate.pop();
        if exists {
            return true;
        }
    }
    false
}

fn check_branch_merged_locally<F>(
    worktree_root: &Path,
    repo_common_dir: &Path,
    platform: &impl Platform,
    resolve_default_ref: F,
) -> Option<bool>
where
    F: FnOnce(&Path, &Path) -> Option<String>,
{
    let default_ref = resolve_default_ref(worktree_root, repo_common_dir)?;
    let out = platform
        .run_git(
            worktree_root,
            &["merge-base", "--is-ancestor", "HEAD", &default_ref],
        )
        .ok()?;
    match out.status_code {
        Some(0) => Some(true),
        Some(1) => Some(false),
        _ => None,
    }
}

fn resolve_local_default_ref(worktree_root: &Path, platform: &impl Platform) -> Option<String> {
    if let Ok(out) = platform.run_git(
        worktree_root,
        &["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
    ) && out.status_code == Some(0)
        && let Ok(text) = std::str::from_utf8(&out.stdout)
    {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    for candidate in ["refs/heads/main", "refs/heads/master"] {
        if let Ok(out) = platform.run_git(
            worktree_root,
            &["rev-parse", "--verify", "--quiet", candidate],
        ) && out.status_code == Some(0)
        {
            return Some(candidate.to_owned());
        }
    }
    None
}

/// Fast fd-anchored `st_blocks * 512` tree sum with single-threaded exact hardlink dedup.
fn account_tree(
    root: &Path,
    mtime_policy: MtimePolicy,
    exclude_top_child: Option<&[u8]>,
    hardlinks: &mut HardlinkSet,
    scratch: &mut DirScratch,
) -> DirAccountResult {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};

        let mut out = DirAccountResult::default();
        let Ok(fd) = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            return out;
        };

        sum_dir_fd_recursive(
            fd,
            0,
            mtime_policy,
            exclude_top_child,
            hardlinks,
            scratch,
            &mut out,
        );
        out
    }
    #[cfg(not(unix))]
    {
        let _ = scratch;
        let mut out = DirAccountResult::default();
        let mut it = WalkDir::new(root).follow_links(false).into_iter();
        while let Some(next) = it.next() {
            let Ok(entry) = next else { continue };
            if entry.depth() == 1
                && let Some(ex) = exclude_top_child
                && entry.file_name().as_encoded_bytes() == ex
            {
                it.skip_current_dir();
                continue;
            }
            if matches!(mtime_policy, MtimePolicy::V2PkgDir)
                && entry.depth() == 1
                && entry.file_type().is_dir()
                && !entry.file_type().is_symlink()
                && entry.file_name().to_str().is_some_and(is_16_lower_hex)
            {
                out.v2_unit_count += 1;
            }
            if let Ok(meta) = entry.metadata() {
                let bytes = entry_allocated_bytes(&meta, hardlinks);
                out.bytes = out.bytes.saturating_add(bytes);
                let track_mtime = match mtime_policy {
                    MtimePolicy::None => false,
                    MtimePolicy::UpToDepth(max_d) => entry.depth() <= max_d,
                    MtimePolicy::IncrementalCrateDir => entry.depth() >= 1 && entry.depth() <= 2,
                    MtimePolicy::V2PkgDir => entry.depth() <= 3,
                    MtimePolicy::V2UnitFingerprint { unit_depth } => {
                        entry.depth() <= unit_depth + 2
                    }
                };
                if track_mtime {
                    out.max_mtime = out.max_mtime.max(meta_mtime_unix(&meta));
                }
            }
        }
        out
    }
}

#[cfg(unix)]
fn sum_dir_fd_recursive(
    dir_fd: std::os::fd::OwnedFd,
    depth: usize,
    mtime_policy: MtimePolicy,
    exclude_top_child: Option<&[u8]>,
    hardlinks: &mut HardlinkSet,
    scratch: &mut DirScratch,
    out: &mut DirAccountResult,
) {
    use std::ffi::CStr;

    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, statat};

    const MAX_ACCOUNT_DEPTH: usize = 64;
    if depth > MAX_ACCOUNT_DEPTH {
        return;
    }

    let Ok(mut dir) = Dir::new(dir_fd) else {
        return;
    };

    let stat_self_dir = match mtime_policy {
        MtimePolicy::None | MtimePolicy::IncrementalCrateDir | MtimePolicy::V2PkgDir => false,
        MtimePolicy::UpToDepth(max_d) => depth <= max_d,
        MtimePolicy::V2UnitFingerprint { unit_depth } => depth == unit_depth,
    };
    if stat_self_dir && let Ok(st) = dir.stat() {
        out.max_mtime = out.max_mtime.max(u64::try_from(st.st_mtime).unwrap_or(0));
    }

    let track_child_file_mtime = match mtime_policy {
        MtimePolicy::None | MtimePolicy::V2PkgDir | MtimePolicy::V2UnitFingerprint { .. } => false,
        MtimePolicy::IncrementalCrateDir => depth == 0,
        MtimePolicy::UpToDepth(max_d) => depth < max_d,
    };
    let count_v2_units = matches!(mtime_policy, MtimePolicy::V2PkgDir) && depth == 0;

    let arena_mark = scratch.name_arena.len();
    let spans_mark = scratch.name_spans.len();

    while let Some(entry_res) = dir.read() {
        let Ok(entry) = entry_res else {
            continue;
        };
        let name = entry.file_name();
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if depth == 0 && exclude_top_child.is_some_and(|ex| ex == bytes) {
            continue;
        }

        let ft = entry.file_type();
        if ft == FileType::Symlink {
            continue;
        }
        if ft == FileType::Directory {
            if count_v2_units && std::str::from_utf8(bytes).is_ok_and(is_16_lower_hex) {
                out.v2_unit_count += 1;
            }
            let start = scratch.name_arena.len();
            scratch
                .name_arena
                .extend_from_slice(name.to_bytes_with_nul());
            scratch.name_spans.push((start, scratch.name_arena.len()));
            continue;
        }

        // Exact hardlink `statat` skip: when mtime is not needed for this regular file and its
        // primary-device `d_ino` was already accounted by an earlier hardlink, its incremental byte
        // contribution is guaranteed 0.
        if !track_child_file_mtime && ft == FileType::RegularFile {
            let ino = entry.ino();
            if ino != 0 && hardlinks.contains_primary(ino) {
                continue;
            }
        }

        let Ok(fd) = dir.fd() else {
            break;
        };
        let Ok(st) = statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        let mode_ft = FileType::from_raw_mode(st.st_mode);
        if mode_ft == FileType::Symlink {
            continue;
        }
        if mode_ft == FileType::Directory {
            if count_v2_units && std::str::from_utf8(bytes).is_ok_and(is_16_lower_hex) {
                out.v2_unit_count += 1;
            }
            let start = scratch.name_arena.len();
            scratch
                .name_arena
                .extend_from_slice(name.to_bytes_with_nul());
            scratch.name_spans.push((start, scratch.name_arena.len()));
            continue;
        }
        out.bytes = out
            .bytes
            .saturating_add(stat_allocated_bytes(&st, false, hardlinks));
        if track_child_file_mtime {
            out.max_mtime = out.max_mtime.max(u64::try_from(st.st_mtime).unwrap_or(0));
        }
    }

    let spans_end = scratch.name_spans.len();
    for span_idx in spans_mark..spans_end {
        let Ok(fd) = dir.fd() else {
            break;
        };
        let (start, end) = scratch.name_spans[span_idx];
        let Ok(child_cstr) = CStr::from_bytes_with_nul(&scratch.name_arena[start..end]) else {
            continue;
        };
        let child_bytes = child_cstr.to_bytes();
        let child_policy = match mtime_policy {
            MtimePolicy::None => MtimePolicy::None,
            MtimePolicy::IncrementalCrateDir => MtimePolicy::UpToDepth(2),
            MtimePolicy::UpToDepth(max_d) => {
                if depth < max_d {
                    MtimePolicy::UpToDepth(max_d)
                } else {
                    MtimePolicy::None
                }
            }
            MtimePolicy::V2PkgDir => {
                if depth == 0 && std::str::from_utf8(child_bytes).is_ok_and(is_16_lower_hex) {
                    MtimePolicy::V2UnitFingerprint { unit_depth: 1 }
                } else {
                    MtimePolicy::None
                }
            }
            MtimePolicy::V2UnitFingerprint { unit_depth } => {
                if depth == unit_depth && child_bytes == b"fingerprint" {
                    MtimePolicy::UpToDepth(depth + 2)
                } else {
                    MtimePolicy::None
                }
            }
        };
        if let Ok(child_fd) = openat(
            fd,
            child_cstr,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            sum_dir_fd_recursive(
                child_fd,
                depth + 1,
                child_policy,
                None,
                hardlinks,
                scratch,
                out,
            );
        }
    }

    scratch.name_arena.truncate(arena_mark);
    scratch.name_spans.truncate(spans_mark);
}

#[cfg(unix)]
#[inline]
fn stat_allocated_bytes(st: &rustix::fs::Stat, is_dir: bool, hardlinks: &mut HardlinkSet) -> u64 {
    if is_dir {
        return 0;
    }
    let blocks = u64::try_from(st.st_blocks).unwrap_or(0);
    let bytes = blocks.saturating_mul(512);
    if st.st_nlink > 1 {
        #[allow(clippy::unnecessary_cast)]
        let dev = st.st_dev as u64;
        #[allow(clippy::unnecessary_cast)]
        let ino = st.st_ino as u64;
        hardlinks.insert_and_count(dev, ino, bytes)
    } else {
        bytes
    }
}

/// Fail-closed `.targetwarden-pin` check: only `ErrorKind::NotFound` means absent.
fn pin_marker_present_fail_closed(path: &Path) -> bool {
    !matches!(
        fs::symlink_metadata(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

/// Stable `(dev, ino)` identity on Unix; deterministic path-derived fallback on non-Unix so
/// multi-target deduplication never collapses distinct paths into `(0, 0)` on Windows.
fn file_identity(path: &Path, meta: &fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        let _ = path;
        (meta_dev(meta), meta_ino(meta))
    }
    #[cfg(not(unix))]
    {
        use std::hash::{Hash, Hasher};
        let _ = meta;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut hasher);
        (0, hasher.finish())
    }
}

fn entry_allocated_bytes(meta: &fs::Metadata, hardlinks: &mut HardlinkSet) -> u64 {
    if meta.is_dir() {
        return 0;
    }
    let bytes = meta_blocks(meta).saturating_mul(512);
    if meta_nlink(meta) > 1 {
        hardlinks.insert_and_count(meta_dev(meta), meta_ino(meta), bytes)
    } else {
        bytes
    }
}

#[cfg(unix)]
fn meta_dev(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.dev()
}

#[cfg(not(unix))]
fn meta_dev(_meta: &fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn meta_ino(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(not(unix))]
fn meta_ino(_meta: &fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn meta_blocks(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.blocks()
}

#[cfg(not(unix))]
fn meta_blocks(meta: &fs::Metadata) -> u64 {
    meta.len().div_ceil(512)
}

#[cfg(unix)]
fn meta_nlink(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.nlink()
}

#[cfg(not(unix))]
fn meta_nlink(_meta: &fs::Metadata) -> u64 {
    1
}

#[cfg(unix)]
fn meta_mtime_unix(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    u64::try_from(meta.mtime()).unwrap_or(0)
}

#[cfg(not(unix))]
fn meta_mtime_unix(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

#[cfg(unix)]
fn meta_mtime_pair(meta: &fs::Metadata) -> (u64, u32) {
    use std::os::unix::fs::MetadataExt;
    let sec = u64::try_from(meta.mtime()).unwrap_or(0);
    let nsec = u32::try_from(meta.mtime_nsec()).unwrap_or(0);
    (sec, nsec)
}

#[cfg(not(unix))]
fn meta_mtime_pair(meta: &fs::Metadata) -> (u64, u32) {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or((0, 0), |d| (d.as_secs(), d.subsec_nanos()))
}

struct StampHasher(u64);

impl StampHasher {
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    #[inline]
    fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }

    #[inline]
    fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_le_bytes());
    }

    #[inline]
    fn write_meta(&mut self, path: &Path, meta: &fs::Metadata) {
        let (dev, ino) = file_identity(path, meta);
        let (sec, nsec) = meta_mtime_pair(meta);
        self.write_u64(dev);
        self.write_u64(ino);
        self.write_u64(sec);
        self.write_u64(u64::from(nsec));
        self.write_u64(meta.len());
    }

    fn hash_shallow_dir(&mut self, dir_path: &Path, stat_children: bool) {
        let Ok(meta) = fs::symlink_metadata(dir_path) else {
            self.write_u64(0);
            return;
        };
        self.write_meta(dir_path, &meta);
        if !stat_children {
            return;
        }
        let Ok(rd) = fs::read_dir(dir_path) else {
            self.write_u64(u64::MAX);
            return;
        };
        let mut count: u64 = 0;
        let mut xor_acc: u64 = 0;
        let mut sum_acc: u64 = 0;
        for entry in rd.flatten() {
            count = count.saturating_add(1);
            let mut eh = StampHasher::new();
            eh.write_bytes(entry.file_name().as_encoded_bytes());
            let path = entry.path();
            if let Ok(emeta) = fs::symlink_metadata(&path) {
                eh.write_meta(&path, &emeta);
            }
            let h = eh.finish();
            xor_acc ^= h;
            sum_acc = sum_acc.wrapping_add(h);
        }
        self.write_u64(count);
        self.write_u64(xor_acc);
        self.write_u64(sum_acc);
    }

    #[inline]
    fn finish(self) -> u64 {
        if self.0 == 0 { 1 } else { self.0 }
    }
}

/// Compute a fast shallow filesystem stamp for a `target/` directory (~50–400 shallow `lstat`s
/// instead of walking 100k+ files) so unchanged read-only `Inventory` scans can reuse cached
/// byte/unit summaries without thrashing the macOS kernel vnode cache.
fn compute_target_inventory_stamp(
    target_root: &Path,
    root_meta: &fs::Metadata,
    doc_dir: Option<&DocDirInfo>,
    profile_probes: &[ProfileProbe],
    top_account_dirs: &[PathBuf],
) -> u64 {
    let mut h = StampHasher::new();
    h.write_meta(target_root, root_meta);
    h.hash_shallow_dir(target_root, true);

    if let Some(doc) = doc_dir {
        h.write_u64(1);
        h.hash_shallow_dir(&doc.path, true);
    } else {
        h.write_u64(0);
    }

    h.write_u64(u64::try_from(top_account_dirs.len()).unwrap_or(u64::MAX));
    for dir_path in top_account_dirs {
        h.write_bytes(dir_path.as_os_str().as_encoded_bytes());
        h.hash_shallow_dir(dir_path, true);
    }

    h.write_u64(u64::try_from(profile_probes.len()).unwrap_or(u64::MAX));
    for probe in profile_probes {
        h.write_bytes(probe.profile.rel_path.as_os_str().as_encoded_bytes());
        h.hash_shallow_dir(&probe.full_path, true);
        if probe.has_v1_fp_dir {
            h.hash_shallow_dir(&probe.full_path.join(".fingerprint"), false);
        }
        if probe.has_v1_deps_dir {
            h.hash_shallow_dir(&probe.full_path.join("deps"), false);
        }
        if probe.has_build_dir {
            h.hash_shallow_dir(&probe.full_path.join("build"), true);
        }
        if probe.has_inc_dir {
            h.hash_shallow_dir(&probe.full_path.join("incremental"), true);
        }
    }

    h.finish()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use compact_str::CompactString;

    use super::{
        ScanDetail, ScanRequest, ScanRoot, decode_le_u64_hex, extract_incremental_crate_name,
        parse_fingerprint_target_stem, scan,
    };
    use crate::config::Config;
    use crate::error::AppError;
    use crate::model::{
        DiskStats, GIB, GitDiscovery, MountEntry, ProcessSnapshot, TargetLayout, TargetOrigin,
        UnitMetadata, UnitTargetKind, extract_16hex_from_dep_name,
    };
    use crate::platform::{CommandOutput, LockProbe, Platform, crosses_mount_boundary};

    struct TestPlatform {
        now: u64,
        mounts: Vec<MountEntry>,
        run_real_git: bool,
    }

    impl TestPlatform {
        fn new(now: u64) -> Self {
            Self {
                now,
                mounts: vec![MountEntry {
                    source: CompactString::new("/dev/disk3s5"),
                    mount_point: PathBuf::from("/"),
                    fstype: CompactString::new("apfs"),
                }],
                run_real_git: false,
            }
        }
    }

    impl Platform for TestPlatform {
        fn euid(&self) -> Result<u32, AppError> {
            Ok(501)
        }
        fn now_unix(&self) -> u64 {
            self.now
        }
        fn disk_stats(&self, volume: &Path) -> Result<DiskStats, AppError> {
            Ok(DiskStats {
                mount: volume.to_path_buf(),
                total_bytes: 460 * GIB,
                free_bytes: 100 * GIB,
                local_snapshots: Some(vec![]),
            })
        }
        fn process_snapshot(&self) -> Result<ProcessSnapshot, AppError> {
            Ok(ProcessSnapshot::empty(self.now, 1))
        }
        fn mount_table(&self) -> Result<Vec<MountEntry>, AppError> {
            Ok(self.mounts.clone())
        }
        fn run_git(&self, cwd: &Path, args: &[&str]) -> Result<CommandOutput, AppError> {
            if self.run_real_git {
                let output = std::process::Command::new("git")
                    .args(args)
                    .current_dir(cwd)
                    .env("LC_ALL", "C")
                    .output()
                    .map_err(|e| AppError::CommandFailed {
                        program: "git",
                        message: e.to_string(),
                    })?;
                return Ok(CommandOutput {
                    status_code: output.status.code(),
                    stdout: output.stdout,
                    stderr: output.stderr,
                });
            }
            Err(AppError::CommandFailed {
                program: "git",
                message: "disabled in unit test".to_owned(),
            })
        }
        fn try_lock_readonly(&self, path: &Path) -> Result<LockProbe, AppError> {
            if path.exists() {
                Ok(LockProbe::Acquired(fs::File::open(path).unwrap()))
            } else {
                Ok(LockProbe::NotFound)
            }
        }
        fn run_launchctl(&self, _args: &[&str]) -> Result<CommandOutput, AppError> {
            Err(AppError::CommandFailed {
                program: "launchctl",
                message: "disabled in unit test".to_owned(),
            })
        }
    }

    fn write_cargo_tag(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n# This file is a cache directory tag created by cargo.\n",
        )
        .unwrap();
    }

    fn write_rustc_info(dir: &Path) {
        fs::write(
            dir.join(".rustc_info.json"),
            r#"{"rustc_fingerprint":12345,"outputs":{"rustc_vv":{"success":true}}}"#,
        )
        .unwrap();
    }

    #[test]
    fn parses_helper_identifiers_and_companion_hash() {
        assert_eq!(
            decode_le_u64_hex(b"981a801b7e8c2c56"),
            Some(6_209_492_459_492_219_544)
        );
        assert_eq!(
            extract_16hex_from_dep_name("cli-263e2b71e466964d.dSYM"),
            Some("263e2b71e466964d")
        );
        assert_eq!(
            extract_16hex_from_dep_name("libanstyle_parse-2b35cc6701a85e86.rlib"),
            Some("2b35cc6701a85e86")
        );
        assert_eq!(
            extract_incremental_crate_name("my_app-3kxjlcmcx12uh"),
            CompactString::new("my_app")
        );
        assert_eq!(
            parse_fingerprint_target_stem("doc-bin-console"),
            (UnitTargetKind::Doc, CompactString::new("bin-console"))
        );
        assert_eq!(
            parse_fingerprint_target_stem("run-build-script-build-script-build"),
            (
                UnitTargetKind::RunBuildScript,
                CompactString::new("build-script-build")
            )
        );
    }

    #[test]
    fn discovers_all_four_layouts_nested_target_and_rejects_false_positives() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let v2_target = root.join("proj-v2/target");
        write_cargo_tag(&v2_target);
        let v2_fp = v2_target.join("debug/build/console/ebb6e057e015c01f/fingerprint");
        fs::create_dir_all(&v2_fp).unwrap();
        fs::write(
            v2_fp.join("doc-bin-console.json"),
            r#"{"rustc":4106920547260086991,"deps":[[1,"dep",false,6209492459492219544]]}"#,
        )
        .unwrap();
        fs::write(v2_fp.join("doc-bin-console"), b"981a801b7e8c2c56").unwrap();
        fs::write(
            v2_fp.join("doc-lib-service.json"),
            r#"{"rustc":4106920547260086991,"deps":[]}"#,
        )
        .unwrap();
        let inc_sess = v2_target.join("debug/incremental/console-39s3hm2pjgfey/s-abc-123-final");
        fs::create_dir_all(&inc_sess).unwrap();
        fs::write(
            v2_target.join("debug/incremental/console-39s3hm2pjgfey/s-abc-123.lock"),
            b"",
        )
        .unwrap();
        let nested = v2_target.join("grpc-codegen");
        write_cargo_tag(&nested);
        fs::create_dir_all(nested.join("debug/build/proto/1111111111111111/fingerprint")).unwrap();

        let v1_target = root.join("proj-v1/target");
        write_cargo_tag(&v1_target);
        let v1_fp = v1_target.join("debug/.fingerprint/demo-0123456789abcdef");
        fs::create_dir_all(&v1_fp).unwrap();
        fs::write(
            v1_fp.join("lib-demo.json"),
            r#"{"rustc":17329007180185699724,"deps":[]}"#,
        )
        .unwrap();
        fs::create_dir_all(v1_target.join("debug/build/demo-0123456789abcdef/out")).unwrap();
        fs::create_dir_all(v1_target.join("debug/deps/demo-0123456789abcdef.dSYM/Contents"))
            .unwrap();
        fs::write(
            v1_target.join("debug/deps/libdemo-0123456789abcdef.rlib"),
            vec![0u8; 4096],
        )
        .unwrap();

        let mixed_target = root.join("proj-mixed/target");
        write_cargo_tag(&mixed_target);
        fs::create_dir_all(mixed_target.join("debug/.fingerprint/foo-aaaaaaaaaaaaaaaa")).unwrap();
        fs::write(
            mixed_target.join("debug/.fingerprint/foo-aaaaaaaaaaaaaaaa/lib-foo.json"),
            r#"{"rustc":111,"deps":[]}"#,
        )
        .unwrap();
        fs::create_dir_all(mixed_target.join("debug/build/foo/bbbbbbbbbbbbbbbb/fingerprint"))
            .unwrap();
        fs::write(
            mixed_target.join("debug/build/foo/bbbbbbbbbbbbbbbb/fingerprint/lib-foo.json"),
            r#"{"rustc":222,"deps":[]}"#,
        )
        .unwrap();

        let art_target = root.join("proj-artifacts/gen-target");
        fs::create_dir_all(art_target.join("debug/examples")).unwrap();
        write_rustc_info(&art_target);
        fs::write(art_target.join("debug/.cargo-lock"), b"").unwrap();
        fs::write(art_target.join("debug/worker"), vec![1u8; 4096]).unwrap();

        let dirty_heur = root.join("proj-sql-check/tool-target");
        fs::create_dir_all(dirty_heur.join("debug")).unwrap();
        write_rustc_info(&dirty_heur);
        fs::write(dirty_heur.join("debug/.cargo-lock"), b"").unwrap();
        fs::write(dirty_heur.join("verification.log"), b"non cargo output").unwrap();

        let ruff = root.join("proj-py/.ruff_cache");
        fs::create_dir_all(&ruff).unwrap();
        fs::write(
            ruff.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n# Created by ruff.\n",
        )
        .unwrap();

        let platform = TestPlatform::new(1_800_000_000);
        let cfg = Config::default();
        let req = ScanRequest::with_default_volume(
            vec![ScanRoot {
                path: root.to_path_buf(),
                max_depth: 8,
                explicit: true,
            }],
            vec![],
            true,
            ScanDetail::Full,
        );
        let snap = scan(&platform, &cfg, &req).unwrap();

        assert_eq!(snap.targets.len(), 6);
        assert!(!snap.targets.iter().any(|t| t.root.ends_with(".ruff_cache")));

        let by_suffix = |suffix: &str| {
            snap.targets
                .iter()
                .find(|t| t.root.ends_with(suffix))
                .unwrap_or_else(|| panic!("missing target ending in {suffix}"))
        };

        let t_v2 = by_suffix("proj-v2/target");
        assert_eq!(t_v2.origin, TargetOrigin::VerifiedCargoTag);
        assert_eq!(t_v2.layout, TargetLayout::BuildDirV2);
        assert_eq!(t_v2.nested_target_roots.len(), 1);
        assert_eq!(t_v2.profiles[0].v2_units.len(), 1);
        match &t_v2.profiles[0].v2_units[0].metadata {
            UnitMetadata::Complete { targets, .. } => assert_eq!(targets.len(), 2),
            UnitMetadata::Incomplete { .. } => panic!("expected complete multi-json unit"),
        }
        assert_eq!(t_v2.profiles[0].incremental_dirs.len(), 1);
        assert!(t_v2.profiles[0].incremental_dirs[0].has_finalized());

        let t_nested = by_suffix("proj-v2/target/grpc-codegen");
        assert!(t_nested.parent_target.is_some());

        let t_v1 = by_suffix("proj-v1/target");
        assert_eq!(t_v1.layout, TargetLayout::LegacyV1);
        assert_eq!(t_v1.profiles[0].v1_units.len(), 1);
        assert_eq!(
            t_v1.profiles[0].v1_units[0]
                .v1_build_dir()
                .map(CompactString::as_str),
            Some("demo-0123456789abcdef")
        );
        assert_eq!(t_v1.profiles[0].v1_units[0].v1_dep_entry_count(), 2);

        let t_mixed = by_suffix("proj-mixed/target");
        assert_eq!(t_mixed.layout, TargetLayout::MixedV1V2);
        assert_eq!(t_mixed.profiles[0].v1_units.len(), 1);
        assert_eq!(t_mixed.profiles[0].v2_units.len(), 1);

        let t_art = by_suffix("proj-artifacts/gen-target");
        assert_eq!(t_art.origin, TargetOrigin::HeuristicNoTag);
        assert_eq!(t_art.layout, TargetLayout::ArtifactsOnly);
        assert!(!t_art.has_unverified_top_entries);

        let t_dirty = by_suffix("proj-sql-check/tool-target");
        assert_eq!(t_dirty.origin, TargetOrigin::HeuristicNoTag);
        assert!(t_dirty.has_unverified_top_entries);
    }

    #[test]
    fn mount_boundary_catches_bind_mounts_and_network_mounts() {
        let tmp = tempfile::tempdir().unwrap();
        let target = fs::canonicalize(tmp.path()).unwrap().join("target");
        fs::create_dir_all(&target).unwrap();
        let meta = fs::symlink_metadata(&target).unwrap();
        let dev = super::meta_dev(&meta);

        let bind_mounts = vec![MountEntry {
            source: CompactString::new("/somewhere"),
            mount_point: target.clone(),
            fstype: CompactString::new("nullfs"),
        }];
        assert!(crosses_mount_boundary(&target, dev, Some(&bind_mounts)));

        let sub_mount = vec![MountEntry {
            source: CompactString::new("/somewhere"),
            mount_point: target.join("build"),
            fstype: CompactString::new("apfs"),
        }];
        assert!(crosses_mount_boundary(&target, dev, Some(&sub_mount)));

        let nfs_parent = vec![MountEntry {
            source: CompactString::new("OrbStack:/OrbStack"),
            mount_point: target.parent().unwrap().to_path_buf(),
            fstype: CompactString::new("nfs"),
        }];
        assert!(crosses_mount_boundary(&target, dev, Some(&nfs_parent)));
    }

    #[cfg(unix)]
    #[test]
    fn hardlinks_are_deduplicated_and_symlinks_are_refused() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("repo/target");
        write_cargo_tag(&target);
        fs::create_dir_all(target.join("debug")).unwrap();
        let f1 = target.join("debug/bin_a");
        let f2 = target.join("debug/bin_b");
        fs::write(&f1, vec![7u8; 64 * 1024]).unwrap();
        fs::hard_link(&f1, &f2).unwrap();

        let link = tmp.path().join("link-target");
        symlink(&target, &link).unwrap();

        let platform = TestPlatform::new(1_800_000_000);
        let cfg = Config::default();

        let req_link = ScanRequest::with_default_volume(
            vec![ScanRoot {
                path: link,
                max_depth: 2,
                explicit: true,
            }],
            vec![],
            true,
            ScanDetail::Inventory,
        );
        let snap_link = scan(&platform, &cfg, &req_link).unwrap();
        assert_eq!(snap_link.targets.len(), 1);
        assert!(snap_link.targets[0].symlink_or_mount_boundary);

        let req_real = ScanRequest::with_default_volume(
            vec![ScanRoot {
                path: tmp.path().join("repo"),
                max_depth: 4,
                explicit: true,
            }],
            vec![],
            true,
            ScanDetail::Inventory,
        );
        let snap_real = scan(&platform, &cfg, &req_real).unwrap();
        assert_eq!(snap_real.targets.len(), 1);
        assert!(!snap_real.targets[0].symlink_or_mount_boundary);
        let single_file_bytes = super::meta_blocks(&fs::metadata(&f1).unwrap()) * 512;
        assert!(
            snap_real.targets[0].allocated_bytes < single_file_bytes * 2,
            "hardlinked files must not be double-counted: got {} vs single {}",
            snap_real.targets[0].allocated_bytes,
            single_file_bytes
        );
    }

    #[test]
    fn git_tracked_file_inside_target_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("tracked-repo");
        fs::create_dir_all(&repo).unwrap();
        let run = |args: &[&str]| {
            let st = std::process::Command::new("git")
                .args(args)
                .current_dir(&repo)
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .output()
                .unwrap();
            assert!(st.status.success(), "git {args:?} failed: {:?}", st);
        };
        run(&["init", "-b", "main"]);
        let target = repo.join("target");
        write_cargo_tag(&target);
        fs::create_dir_all(target.join("debug")).unwrap();
        fs::write(target.join("debug/tracked.txt"), b"important").unwrap();
        run(&["add", "target/debug/tracked.txt"]);
        run(&["commit", "-m", "track file inside target"]);

        let mut platform = TestPlatform::new(1_800_000_000);
        platform.run_real_git = true;
        let cfg = Config::default();
        let req = ScanRequest::with_default_volume(
            vec![ScanRoot {
                path: repo,
                max_depth: 4,
                explicit: true,
            }],
            vec![],
            true,
            ScanDetail::Inventory,
        );
        let snap = scan(&platform, &cfg, &req).unwrap();
        assert_eq!(snap.targets.len(), 1);
        match &snap.targets[0].git {
            GitDiscovery::Inspected(git) => assert!(git.has_tracked_files_in_target),
            other => panic!("expected inspected git, got {other:?}"),
        }
    }

    #[test]
    fn missing_worktree_dir_inspects_cleanly_for_r1_instead_of_failing_git_status() {
        struct MissingWorktreePlatform {
            now: u64,
            missing_wt: PathBuf,
            git_dir: PathBuf,
            common_dir: PathBuf,
        }

        impl Platform for MissingWorktreePlatform {
            fn euid(&self) -> Result<u32, AppError> {
                Ok(501)
            }
            fn now_unix(&self) -> u64 {
                self.now
            }
            fn disk_stats(&self, volume: &Path) -> Result<DiskStats, AppError> {
                Ok(DiskStats {
                    mount: volume.to_path_buf(),
                    total_bytes: 460 * GIB,
                    free_bytes: 100 * GIB,
                    local_snapshots: Some(vec![]),
                })
            }
            fn process_snapshot(&self) -> Result<ProcessSnapshot, AppError> {
                Ok(ProcessSnapshot::empty(self.now, 1))
            }
            fn mount_table(&self) -> Result<Vec<MountEntry>, AppError> {
                Ok(vec![MountEntry {
                    source: CompactString::new("/dev/disk3s5"),
                    mount_point: PathBuf::from("/"),
                    fstype: CompactString::new("apfs"),
                }])
            }
            fn run_git(&self, _cwd: &Path, args: &[&str]) -> Result<CommandOutput, AppError> {
                if args.first() == Some(&"rev-parse") {
                    let stdout = format!(
                        "{}\n{}\n{}\n",
                        self.missing_wt.display(),
                        self.git_dir.display(),
                        self.common_dir.display()
                    );
                    Ok(CommandOutput {
                        status_code: Some(0),
                        stdout: stdout.into_bytes(),
                        stderr: Vec::new(),
                    })
                } else {
                    panic!("must not invoke git {args:?} when worktree_dir_missing is true");
                }
            }
            fn try_lock_readonly(&self, _path: &Path) -> Result<LockProbe, AppError> {
                Ok(LockProbe::NotFound)
            }
            fn run_launchctl(&self, _args: &[&str]) -> Result<CommandOutput, AppError> {
                Err(AppError::CommandFailed {
                    program: "launchctl",
                    message: "unused".to_owned(),
                })
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let repo = base.join("ghost_repo");
        let target = repo.join("target");
        write_cargo_tag(&target);
        fs::create_dir_all(target.join("debug")).unwrap();
        fs::write(repo.join(".git"), b"gitdir: /nonexistent\n").unwrap();
        let common_dir = base.join("main/.git");
        let git_dir = common_dir.join("worktrees/ghost");
        fs::create_dir_all(&git_dir).unwrap();

        let platform = MissingWorktreePlatform {
            now: 2_000_000_000,
            missing_wt: base.join("deleted_worktree_root"),
            git_dir,
            common_dir,
        };
        let cfg = Config::default();
        let req = ScanRequest::with_default_volume(
            vec![ScanRoot {
                path: repo,
                max_depth: 4,
                explicit: true,
            }],
            vec![],
            true,
            ScanDetail::Inventory,
        );
        let snap = scan(&platform, &cfg, &req).unwrap();
        assert_eq!(snap.targets.len(), 1);
        match &snap.targets[0].git {
            GitDiscovery::Inspected(git) => {
                assert!(git.worktree_dir_missing);
                assert_eq!(
                    git.worktree_kind,
                    crate::model::WorktreeKind::LinkedWorktree
                );
            }
            other => panic!("expected Inspected with worktree_dir_missing=true, got {other:?}"),
        }
    }

    #[test]
    fn inventory_tracks_v2_fingerprint_mtime_budget_and_cached_sibling_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let proj = base.join("v2_app");
        let target = proj.join("target");
        write_cargo_tag(&target);
        let fp_dir = target.join("debug/build/v2_app/0123456789abcdef/fingerprint");
        fs::create_dir_all(&fp_dir).unwrap();
        let invoked = fp_dir.join("invoked.timestamp");
        fs::write(&invoked, b"").unwrap();
        fs::write(fp_dir.join("bin-v2_app.json"), r#"{"rustc":1,"deps":[]}"#).unwrap();

        // Advance ONLY `fingerprint/invoked.timestamp` (depth 5 inside profile) to a future timestamp
        // so Inventory mode MUST observe the exact same freshness as Full mode.
        let future_ts = std::time::SystemTime::now() + std::time::Duration::from_secs(7200);
        fs::OpenOptions::new()
            .write(true)
            .open(&invoked)
            .unwrap()
            .set_modified(future_ts)
            .unwrap();
        let expected_mtime = super::meta_mtime_unix(&fs::symlink_metadata(&invoked).unwrap());

        // Add sibling leftover staging next to `target/` to verify cached (`full_walk = false`) recovery.
        let sibling_staging = proj.join(".target.targetwarden-reap.99.1");
        fs::create_dir_all(&sibling_staging).unwrap();

        let platform = TestPlatform::new(expected_mtime + 60);
        let cfg = Config::default();

        let inv_req = ScanRequest::with_default_volume(
            vec![],
            vec![target.clone()],
            false,
            ScanDetail::Inventory,
        );
        let inv_snap = scan(&platform, &cfg, &inv_req).unwrap();
        assert_eq!(inv_snap.targets.len(), 1);
        assert_eq!(inv_snap.targets[0].last_activity_unix, expected_mtime);
        assert_eq!(inv_snap.targets[0].profiles[0].v2_unit_count, 1);
        assert!(
            inv_snap
                .leftover_staging
                .iter()
                .any(|s| s.staging_dir == sibling_staging),
            "cached scan must still discover sibling staging dirs for crash recovery"
        );

        let full_req =
            ScanRequest::with_default_volume(vec![], vec![target], false, ScanDetail::Full);
        let full_snap = scan(&platform, &cfg, &full_req).unwrap();
        assert_eq!(
            inv_snap.targets[0].last_activity_unix,
            full_snap.targets[0].last_activity_unix
        );

        // Tiny `max_entries` budget must trip `walk_partial = true`.
        let mut tight_cfg = Config::default();
        tight_cfg.discovery.max_entries = 1;
        let partial_req = ScanRequest::with_default_volume(
            vec![ScanRoot {
                path: base,
                max_depth: 6,
                explicit: true,
            }],
            vec![],
            true,
            ScanDetail::Inventory,
        );
        let partial_snap = scan(&platform, &tight_cfg, &partial_req).unwrap();
        assert!(partial_snap.walk_partial);
    }

    #[test]
    fn known_targets_with_parent_and_nested_child_does_not_double_count_or_drop_parent_link() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let parent = base.join("proj/target");
        let nested = parent.join("grpc-codegen");
        write_cargo_tag(&parent);
        write_cargo_tag(&nested);
        fs::create_dir_all(parent.join("debug/build/app/1111111111111111/fingerprint")).unwrap();
        fs::write(
            parent.join("debug/build/app/1111111111111111/out_blob"),
            vec![1u8; 64 * 1024],
        )
        .unwrap();
        fs::create_dir_all(nested.join("debug/build/proto/2222222222222222/fingerprint")).unwrap();
        fs::write(
            nested.join("debug/build/proto/2222222222222222/out_blob"),
            vec![2u8; 128 * 1024],
        )
        .unwrap();

        let platform = TestPlatform::new(1_800_000_000);
        let cfg = Config::default();

        // Reference full walk without cached known_targets
        let fresh_req = ScanRequest::with_default_volume(
            vec![ScanRoot {
                path: base.clone(),
                max_depth: 6,
                explicit: true,
            }],
            vec![],
            true,
            ScanDetail::Inventory,
        );
        let fresh_snap = scan(&platform, &cfg, &fresh_req).unwrap();
        assert_eq!(fresh_snap.targets.len(), 2);

        // Cached walk with BOTH parent and nested child in `known_targets` (normal state.json contents)
        for detail in [ScanDetail::Inventory, ScanDetail::Full] {
            let cached_req = ScanRequest::with_default_volume(
                vec![ScanRoot {
                    path: base.clone(),
                    max_depth: 6,
                    explicit: true,
                }],
                vec![nested.clone(), parent.clone()],
                true,
                detail,
            );
            let cached_snap = scan(&platform, &cfg, &cached_req).unwrap();
            assert_eq!(cached_snap.targets.len(), 2);
            let fresh_nested = fresh_snap
                .targets
                .iter()
                .find(|t| t.root == nested)
                .unwrap();
            let cached_nested = cached_snap
                .targets
                .iter()
                .find(|t| t.root == nested)
                .unwrap();
            assert_eq!(
                cached_nested.parent_target.as_deref(),
                Some(parent.as_path())
            );
            assert_eq!(
                cached_nested.allocated_bytes, fresh_nested.allocated_bytes,
                "nested target must not be double-counted when present in known_targets ({detail:?})"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_target_root_and_incremental_dir_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();

        // 1. Unreadable target_root (0o111: searchable so CACHEDIR.TAG opens, but read_dir fails EACCES)
        let ro_target = base.join("unreadable_proj/target");
        write_cargo_tag(&ro_target);
        fs::create_dir_all(ro_target.join("debug/build/demo/1111111111111111")).unwrap();

        // 2. Unreadable incremental crate directory inside a readable target
        let inc_target = base.join("inc_proj/target");
        write_cargo_tag(&inc_target);
        let locked_inc = inc_target.join("debug/incremental/demo-abc1234567890");
        fs::create_dir_all(locked_inc.join("s-1-aaa-final")).unwrap();

        fs::set_permissions(&ro_target, fs::Permissions::from_mode(0o111)).unwrap();
        fs::set_permissions(&locked_inc, fs::Permissions::from_mode(0o000)).unwrap();

        let platform = TestPlatform::new(1_800_000_000);
        let cfg = Config::default();
        let req = ScanRequest::with_default_volume(
            vec![],
            vec![ro_target.clone(), inc_target.clone()],
            false,
            ScanDetail::Full,
        );
        let snap = scan(&platform, &cfg, &req).unwrap();

        // Restore permissions before asserting so TempDir always cleans up!
        fs::set_permissions(&ro_target, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&locked_inc, fs::Permissions::from_mode(0o755)).unwrap();

        let t_ro = snap.targets.iter().find(|t| t.root == ro_target).unwrap();
        assert!(
            t_ro.has_unverified_top_entries,
            "unreadable target_root must fail closed as unverified/protected"
        );

        let t_inc = snap.targets.iter().find(|t| t.root == inc_target).unwrap();
        assert_eq!(t_inc.profiles[0].incremental_dirs.len(), 1);
        assert!(
            t_inc.profiles[0].incremental_dirs[0].any_locked,
            "unreadable incremental dir must fail closed as locked so R3 never prunes it"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_and_var_alias_target_paths_inside_git_repo_fail_closed_or_detect_tracked() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let tmp = tempfile::tempdir().unwrap();
        let repo = fs::canonicalize(tmp.path()).unwrap().join("git-edge");
        fs::create_dir_all(&repo).unwrap();
        let run = |args: &[&str]| {
            let st = std::process::Command::new("git")
                .args(args)
                .current_dir(&repo)
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .output()
                .unwrap();
            assert!(st.status.success(), "git {args:?} failed: {:?}", st);
        };
        run(&["init", "-b", "main"]);

        // 1. Tracked file detected even if known_targets uses `/var/...` alias on macOS
        let tracked_target = repo.join("target");
        write_cargo_tag(&tracked_target);
        fs::create_dir_all(tracked_target.join("debug")).unwrap();
        fs::write(tracked_target.join("debug/tracked.txt"), b"keep").unwrap();
        run(&["add", "target/debug/tracked.txt"]);
        run(&["commit", "-m", "track file"]);

        let alias_target = tracked_target
            .strip_prefix("/private")
            .map(|rest| Path::new("/").join(rest))
            .unwrap_or_else(|_| tracked_target.clone());

        let mut platform = TestPlatform::new(1_800_000_000);
        platform.run_real_git = true;
        let cfg = Config::default();
        let req = ScanRequest::with_default_volume(
            vec![],
            vec![alias_target],
            false,
            ScanDetail::Inventory,
        );
        let snap = scan(&platform, &cfg, &req).unwrap();
        assert_eq!(snap.targets.len(), 1);
        assert!(matches!(
            &snap.targets[0].git,
            GitDiscovery::Inspected(git) if git.has_tracked_files_in_target
        ));

        // 2. Non-UTF8 target path inside a Git repo fails closed (on filesystems allowing non-UTF8)
        let bad_name = OsString::from_vec(vec![b't', b'g', b't', 0xff]);
        let bad_target = repo.join(bad_name);
        if fs::create_dir_all(bad_target.join("debug")).is_ok() {
            write_cargo_tag(&bad_target);
            let bad_req = ScanRequest::with_default_volume(
                vec![],
                vec![bad_target],
                false,
                ScanDetail::Inventory,
            );
            let bad_snap = scan(&platform, &cfg, &bad_req).unwrap();
            assert_eq!(bad_snap.targets.len(), 1);
            assert!(matches!(bad_snap.targets[0].git, GitDiscovery::Failed(_)));
        }
    }

    #[cfg(unix)]
    #[test]
    fn dir_mtime_bumps_do_not_reset_activity_and_v1_orphans_are_discovered() {
        use rustix::fs::{AtFlags, Timespec, Timestamps, utimensat};

        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let target = base.join("proj/target");
        let debug = target.join("debug");
        write_cargo_tag(&target);

        let inc_root = debug.join("incremental");
        let inc_crate = inc_root.join("demo-abc1234567890");
        let inc_sess = inc_crate.join("s-1-aaa-final");
        let inc_lock = inc_crate.join("s-1-aaa.lock");
        fs::create_dir_all(&inc_sess).unwrap();
        fs::write(&inc_lock, b"").unwrap();
        fs::write(inc_sess.join("dep-graph.bin"), b"graph").unwrap();

        // V1 `.fingerprint/` with one live unit + orphaned `deps/` and `build/` without fingerprint
        let fp_live = debug.join(".fingerprint/live-1111111111111111");
        fs::create_dir_all(&fp_live).unwrap();
        fs::write(fp_live.join("lib-live.json"), r#"{"rustc":42,"deps":[]}"#).unwrap();
        fs::create_dir_all(debug.join("deps")).unwrap();
        fs::write(debug.join("deps/liblive-1111111111111111.rlib"), b"live").unwrap();
        fs::write(
            debug.join("deps/liborphan-aaaaaaaaaaaaaaaa.rlib"),
            b"orphan_rlib",
        )
        .unwrap();
        fs::create_dir_all(debug.join("build/orphan-bbbbbbbbbbbbbbbb/out")).unwrap();
        fs::write(
            debug.join("build/orphan-bbbbbbbbbbbbbbbb/out/gen.rs"),
            b"gen",
        )
        .unwrap();

        let old_ts = 1_700_000_000i64;
        let bumped_dir_ts = 1_799_000_000i64;
        let set_mtime = |p: &Path, sec: i64| {
            let ts = Timespec {
                tv_sec: sec,
                tv_nsec: 0,
            };
            utimensat(
                rustix::fs::CWD,
                p,
                &Timestamps {
                    last_access: ts,
                    last_modification: ts,
                },
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .unwrap();
        };

        // Backdate every file and dir inside `target/` to `old_ts`
        let mut all_paths: Vec<PathBuf> = walkdir::WalkDir::new(&target)
            .follow_links(false)
            .into_iter()
            .flatten()
            .map(|e| e.into_path())
            .collect();
        all_paths.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
        for p in &all_paths {
            set_mtime(p, old_ts);
        }

        // Now simulate R2/R3 staging/removal bumping directory mtimes (`target/`, `incremental/`, `<crate>/`)
        set_mtime(&inc_crate, bumped_dir_ts);
        set_mtime(&inc_root, bumped_dir_ts);
        set_mtime(&target, bumped_dir_ts);

        let platform = TestPlatform::new(1_800_000_000);
        let cfg = Config::default();

        for detail in [ScanDetail::Full, ScanDetail::Inventory] {
            let req = ScanRequest::with_default_volume(vec![], vec![target.clone()], false, detail);
            let snap = scan(&platform, &cfg, &req).unwrap();
            assert_eq!(snap.targets.len(), 1);
            let t = &snap.targets[0];
            assert_eq!(
                t.root_mtime_unix, bumped_dir_ts as u64,
                "root_mtime_unix must track target dir mtime ({detail:?})"
            );
            assert_eq!(
                t.last_activity_unix, old_ts as u64,
                "target dir / incremental dir mtime bumps must NOT reset last_activity_unix ({detail:?})"
            );
            let p = &t.profiles[0];
            assert_eq!(p.inc_root_mtime_unix, bumped_dir_ts as u64);
            assert_eq!(p.last_activity_unix, old_ts as u64);

            if detail == ScanDetail::Full {
                assert_eq!(p.incremental_dirs.len(), 1);
                assert_eq!(p.incremental_dirs[0].dir_mtime_unix, bumped_dir_ts as u64);
                assert_eq!(p.incremental_dirs[0].latest_mtime_unix, old_ts as u64);

                let orphan_count = p
                    .v1_units
                    .iter()
                    .filter(|u| {
                        matches!(
                            &u.id,
                            crate::model::BuildUnitId::V1 {
                                fingerprint_dir: None,
                                ..
                            }
                        )
                    })
                    .count();
                assert_eq!(
                    orphan_count, 2,
                    "expected both orphaned V1 deps and build units"
                );
            }
        }
    }

    #[test]
    fn git_op_markers_ignore_stale_rebase_head_but_detect_active_rebase_merge() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path();

        // Stale REBASE_HEAD alone must NOT trigger git_op_in_progress
        fs::write(git_dir.join("REBASE_HEAD"), b"0123456789abcdef\n").unwrap();
        assert!(!super::has_git_op_markers(git_dir));

        // Actual in-progress rebase directory MUST trigger git_op_in_progress
        fs::create_dir(git_dir.join("rebase-merge")).unwrap();
        assert!(super::has_git_op_markers(git_dir));
    }

    #[test]
    fn pruned_dir_name_tables_are_strictly_sorted_for_binary_search() {
        for table in [super::PRUNED_DIR_NAMES, super::REPO_INNER_PRUNED_DIR_NAMES] {
            assert!(!table.is_empty());
            for pair in table.windows(2) {
                assert!(
                    pair[0] < pair[1],
                    "pruned dir table out of order or duplicate: {:?} >= {:?}",
                    pair[0],
                    pair[1]
                );
            }
        }
    }

    #[test]
    fn parse_fingerprint_json_into_validates_and_rolls_back_dep_pool_on_error() {
        let mut pool = vec![0xdead_beef_u64];

        let valid = br#"{"rustc":12345,"features":"[]","declared_features":"[]","target":1,"profile":2,"path":3,"deps":[[1,"a",false,9001],[2,"b",true,9002]],"local":[],"rustflags":[],"rustdocflags":[],"config":0,"compile_kind":0}"#;
        let rustc = super::parse_fingerprint_json_into(valid, &mut pool).unwrap();
        assert_eq!(rustc, 12345);
        assert_eq!(pool, vec![0xdead_beef_u64, 9001, 9002]);

        // Every invalid/malformed case MUST fail closed (`None`) AND leave `pool` untouched!
        let saved_len = pool.len();
        let invalid_cases: &[&[u8]] = &[
            b"",
            b"{corrupt",
            // Missing `rustc`
            br#"{"deps":[[1,"a",false,9999]]}"#,
            // Duplicate `rustc`
            br#"{"rustc":1,"deps":[[1,"a",false,9999]],"rustc":2}"#,
            // Duplicate `deps`
            br#"{"rustc":1,"deps":[[1,"a",false,9999]],"deps":[]}"#,
            // Wrong dep tuple length (missing 4th element)
            br#"{"rustc":1,"deps":[[1,"a",9999]]}"#,
            // Wrong dep tuple length (extra 5th element)
            br#"{"rustc":1,"deps":[[1,"a",false,9999,123]]}"#,
            // Non-u64 dep fingerprint hash
            br#"{"rustc":1,"deps":[[1,"a",false,"not_a_num"]]}"#,
            // Partial valid dep followed by corrupt dep -> must roll back first dep too!
            br#"{"rustc":1,"deps":[[1,"a",false,7777],[2,"b",false,"bad"]]}"#,
            // Trailing garbage after valid object
            br#"{"rustc":1,"deps":[[1,"a",false,8888]]} trailing"#,
        ];

        for case in invalid_cases {
            assert!(
                super::parse_fingerprint_json_into(case, &mut pool).is_none(),
                "expected None for {:?}",
                String::from_utf8_lossy(case)
            );
            assert_eq!(
                pool.len(),
                saved_len,
                "dep pool leaked partial entries for {:?}",
                String::from_utf8_lossy(case)
            );
        }
    }

    #[test]
    fn is_valid_rustc_info_enforces_fingerprint_and_outputs_object() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".rustc_info.json");

        fs::write(
            &path,
            br#"{"rustc_fingerprint":123,"outputs":{"42":{"success":true}},"successes":{}}"#,
        )
        .unwrap();
        assert!(super::is_valid_rustc_info(&path));

        let invalid = [
            br#"{"rustc_fingerprint":null,"outputs":{}}"#.as_slice(),
            br#"{"outputs":{}}"#.as_slice(),
            br#"{"rustc_fingerprint":123,"outputs":[]}"#.as_slice(),
            br#"{"rustc_fingerprint":123,"outputs":123}"#.as_slice(),
            br#"{"rustc_fingerprint":123,"outputs":null}"#.as_slice(),
            br#"{"rustc_fingerprint":123}"#.as_slice(),
            br#"{not json"#.as_slice(),
        ];
        for body in invalid {
            fs::write(&path, body).unwrap();
            assert!(
                !super::is_valid_rustc_info(&path),
                "expected invalid rustc_info for {:?}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn parse_and_format_16_lower_hex_u64_edge_cases() {
        for (val, text) in [
            (0u64, "0000000000000000"),
            (0xau64, "000000000000000a"),
            (0x0123_4567_89ab_cdef_u64, "0123456789abcdef"),
            (u64::MAX, "ffffffffffffffff"),
        ] {
            assert_eq!(super::parse_16_lower_hex_u64(text), Some(val));
            assert_eq!(super::format_16_lower_hex(val).as_str(), text);
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
                super::parse_16_lower_hex_u64(bad).is_none(),
                "expected None for {bad:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn read_fd_bounded_handles_empty_exact_growth_and_oversize() {
        use rustix::fs::{Mode, OFlags, open};

        let tmp = tempfile::tempdir().unwrap();
        let mut buf = Vec::new();

        // 1. Empty file
        let empty_p = tmp.path().join("empty");
        fs::write(&empty_p, b"").unwrap();
        let fd = open(&empty_p, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
        assert_eq!(super::read_fd_bounded(&fd, 0, 1024, &mut buf), Some(0));

        // 2. Exact expected size (1-syscall fast path)
        let exact_p = tmp.path().join("exact");
        let payload = b"hello targetwarden fast path!";
        fs::write(&exact_p, payload).unwrap();
        let fd = open(&exact_p, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
        let n = super::read_fd_bounded(&fd, payload.len() as u64, 1024, &mut buf).unwrap();
        assert_eq!(&buf[..n], payload);

        // 3. File larger than `expected_size` hint (simulates concurrent file growth)
        let grew_p = tmp.path().join("grew");
        let big = vec![b'x'; 5000];
        fs::write(&grew_p, &big).unwrap();
        let fd = open(&grew_p, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
        let n = super::read_fd_bounded(&fd, 100, 8192, &mut buf).unwrap();
        assert_eq!(n, 5000);
        assert_eq!(&buf[..n], big.as_slice());

        // 4. Exceeds `max_bytes` (both when hint > max and when actual > max)
        let fd = open(&grew_p, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
        assert_eq!(super::read_fd_bounded(&fd, 5000, 4096, &mut buf), None);
        let fd = open(&grew_p, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
        assert_eq!(super::read_fd_bounded(&fd, 100, 4096, &mut buf), None);
    }

    #[cfg(unix)]
    #[test]
    fn shared_hardlink_set_ino_skip_matches_full_stat_accounting_exactly() {
        use std::os::unix::fs::MetadataExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("tree");
        let sub_a = root.join("a");
        let sub_b = root.join("b");
        fs::create_dir_all(&sub_a).unwrap();
        fs::create_dir_all(&sub_b).unwrap();

        // Create unique files and multi-linked files across sibling subdirs
        let shared1 = sub_a.join("shared1.rlib");
        let shared2 = sub_a.join("shared2.rlib");
        fs::write(&shared1, vec![0x11u8; 16 * 1024]).unwrap();
        fs::write(&shared2, vec![0x22u8; 24 * 1024]).unwrap();
        fs::write(sub_a.join("unique_a.o"), vec![0x33u8; 8 * 1024]).unwrap();
        fs::write(sub_b.join("unique_b.o"), vec![0x44u8; 12 * 1024]).unwrap();
        fs::hard_link(&shared1, sub_b.join("shared1_link1.rlib")).unwrap();
        fs::hard_link(&shared1, sub_b.join("shared1_link2.rlib")).unwrap();
        fs::hard_link(&shared2, sub_b.join("shared2_link1.rlib")).unwrap();

        let dev = fs::symlink_metadata(&root).unwrap().dev();
        let mut hl_no_skip = super::HardlinkSet::new();
        hl_no_skip.reset(dev, false);
        let mut hl_with_skip = super::HardlinkSet::new();
        hl_with_skip.reset(dev, true);

        let mut scratch = super::DirScratch::default();
        let res_no_skip = super::account_tree(
            &root,
            super::MtimePolicy::None,
            None,
            &mut hl_no_skip,
            &mut scratch,
        );
        let res_with_skip = super::account_tree(
            &root,
            super::MtimePolicy::None,
            None,
            &mut hl_with_skip,
            &mut scratch,
        );
        assert!(res_no_skip.bytes > 0);
        assert_eq!(res_with_skip.bytes, res_no_skip.bytes);

        // Verify `contains_primary` confirms the multi-linked inode was indexed,
        // and `reset()` clears all state for the next target.
        let shared1_ino = fs::symlink_metadata(&shared1).unwrap().ino();
        assert!(hl_with_skip.contains_primary(shared1_ino));
        hl_with_skip.reset(dev, true);
        assert!(!hl_with_skip.contains_primary(shared1_ino));
    }

    #[test]
    fn compact_profile_dep_fp_pool_preserves_reachable_v2_and_v1_spans_and_drops_unmatched() {
        use crate::model::{
            BuildUnit, BuildUnitId, ProfileDir, TargetLayout, UnitMetadata, UnitTargetAnchor,
            UnitTargetKind,
        };

        let anchor = |fp_hash: u64| {
            smallvec::smallvec![UnitTargetAnchor {
                target_kind: UnitTargetKind::Lib,
                target_name: CompactString::new("lib"),
                fingerprint_hash: Some(fp_hash),
            }]
        };
        fn unit_deps<'a>(unit: &BuildUnit, pool: &'a [u64]) -> &'a [u64] {
            match &unit.metadata {
                UnitMetadata::Complete {
                    dep_fp_start,
                    dep_fp_len,
                    ..
                } => &pool[*dep_fp_start as usize..(*dep_fp_start + *dep_fp_len) as usize],
                UnitMetadata::Incomplete { .. } => &[],
            }
        }

        let mut profile = ProfileDir {
            name: CompactString::new("debug"),
            rel_path: PathBuf::from("debug"),
            layout: TargetLayout::MixedV1V2,
            lock_files: smallvec::SmallVec::new(),
            locked_now: false,
            fingerprint_corrupt: false,
            v2_unit_count: 2,
            v1_unit_count: 2,
            incremental_dir_count: 0,
            profile_mtime_unix: 0,
            inc_root_mtime_unix: 0,
            allocated_bytes: 0,
            last_activity_unix: 0,
            // V2 anchors: 100, 200. V1 anchors: 300, 400. Unmatched: 777, 888, 999.
            // Interleaved spans: V2[0] (0..4), V1[0] (4..7), V2[1] (7..8), V1[1] (8..9)
            dep_fp_pool: vec![999, 200, 888, 300, 100, 400, 999, 777, 300],
            v2_units: vec![
                BuildUnit {
                    id: BuildUnitId::V2 {
                        pkg: CompactString::new("a"),
                        unit_hash: CompactString::new("0000000000000001"),
                    },
                    v1: None,
                    metadata: UnitMetadata::Complete {
                        rustc_hash: 1,
                        dep_fp_start: 0,
                        dep_fp_len: 4, // [999, 200, 888, 300] -> keeps [200] (300 is V1-only)
                        targets: anchor(100),
                        mtime_unix: 10,
                    },
                    allocated_bytes: 10,
                },
                BuildUnit {
                    id: BuildUnitId::V2 {
                        pkg: CompactString::new("b"),
                        unit_hash: CompactString::new("0000000000000002"),
                    },
                    v1: None,
                    metadata: UnitMetadata::Complete {
                        rustc_hash: 1,
                        dep_fp_start: 7,
                        dep_fp_len: 1, // [777] -> keeps []
                        targets: anchor(200),
                        mtime_unix: 10,
                    },
                    allocated_bytes: 10,
                },
            ],
            v1_units: vec![
                BuildUnit {
                    id: BuildUnitId::V1 {
                        fingerprint_dir: Some(CompactString::new("c-0000000000000003")),
                        unit_hash: CompactString::new("0000000000000003"),
                    },
                    v1: None,
                    metadata: UnitMetadata::Complete {
                        rustc_hash: 1,
                        dep_fp_start: 4,
                        dep_fp_len: 3, // [100, 400, 999] -> keeps [400] (100 is V2-only)
                        targets: anchor(300),
                        mtime_unix: 10,
                    },
                    allocated_bytes: 10,
                },
                BuildUnit {
                    id: BuildUnitId::V1 {
                        fingerprint_dir: Some(CompactString::new("d-0000000000000004")),
                        unit_hash: CompactString::new("0000000000000004"),
                    },
                    v1: None,
                    metadata: UnitMetadata::Complete {
                        rustc_hash: 1,
                        dep_fp_start: 8,
                        dep_fp_len: 1, // [300] -> keeps [300]
                        targets: anchor(400),
                        mtime_unix: 10,
                    },
                    allocated_bytes: 10,
                },
            ],
            incremental_dirs: Vec::new(),
        };

        super::compact_profile_dep_fp_pool(&mut profile);

        assert_eq!(profile.dep_fp_pool, vec![200, 400, 300]);
        assert_eq!(
            unit_deps(&profile.v2_units[0], &profile.dep_fp_pool),
            &[200]
        );
        assert_eq!(
            unit_deps(&profile.v2_units[1], &profile.dep_fp_pool),
            &[] as &[u64]
        );
        assert_eq!(
            unit_deps(&profile.v1_units[0], &profile.dep_fp_pool),
            &[400]
        );
        assert_eq!(
            unit_deps(&profile.v1_units[1], &profile.dep_fp_pool),
            &[300]
        );
    }

    #[cfg(unix)]
    #[test]
    fn inventory_and_full_agree_on_symlinks_and_missing_mounts_disables_ino_skip() {
        use std::os::unix::fs::symlink;

        struct NoMountsPlatform {
            now: u64,
        }
        impl Platform for NoMountsPlatform {
            fn euid(&self) -> Result<u32, AppError> {
                Ok(501)
            }
            fn now_unix(&self) -> u64 {
                self.now
            }
            fn disk_stats(&self, volume: &Path) -> Result<DiskStats, AppError> {
                Ok(DiskStats {
                    mount: volume.to_path_buf(),
                    total_bytes: 460 * GIB,
                    free_bytes: 100 * GIB,
                    local_snapshots: Some(vec![]),
                })
            }
            fn process_snapshot(&self) -> Result<ProcessSnapshot, AppError> {
                Ok(ProcessSnapshot::empty(self.now, 1))
            }
            fn mount_table(&self) -> Result<Vec<MountEntry>, AppError> {
                Err(AppError::CommandFailed {
                    program: "mount",
                    message: "simulated unavailable mount table".to_owned(),
                })
            }
            fn run_git(&self, _cwd: &Path, _args: &[&str]) -> Result<CommandOutput, AppError> {
                Err(AppError::CommandFailed {
                    program: "git",
                    message: "disabled".to_owned(),
                })
            }
            fn try_lock_readonly(&self, _path: &Path) -> Result<LockProbe, AppError> {
                Ok(LockProbe::NotFound)
            }
            fn run_launchctl(&self, _args: &[&str]) -> Result<CommandOutput, AppError> {
                Err(AppError::CommandFailed {
                    program: "launchctl",
                    message: "disabled".to_owned(),
                })
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let outside = base.join("outside.bin");
        fs::write(&outside, vec![0xaa; 32 * 1024]).unwrap();

        let target = base.join("proj/target");
        write_cargo_tag(&target);
        let debug = target.join("debug");
        let fp = debug.join(".fingerprint/demo-0123456789abcdef");
        let build = debug.join("build/demo/0123456789abcdef/fingerprint");
        let inc = debug.join("incremental/demo-abc12345/s-1-final");
        let deps = debug.join("deps");
        fs::create_dir_all(&fp).unwrap();
        fs::create_dir_all(&build).unwrap();
        fs::create_dir_all(&inc).unwrap();
        fs::create_dir_all(&deps).unwrap();
        fs::write(fp.join("lib-demo.json"), r#"{"rustc":1,"deps":[]}"#).unwrap();
        fs::write(build.join("lib-demo.json"), r#"{"rustc":1,"deps":[]}"#).unwrap();
        let dep1 = deps.join("libdemo-0123456789abcdef.rlib");
        fs::write(&dep1, vec![0x11; 16 * 1024]).unwrap();
        fs::hard_link(&dep1, deps.join("libdemo_alias-0123456789abcdef.rlib")).unwrap();

        // Symlinks inside `.fingerprint/`, `build/`, and `incremental/` must be skipped
        // identically by BOTH `Inventory` and `Full` modes.
        symlink(&outside, debug.join(".fingerprint/link_outside")).unwrap();
        symlink(&outside, debug.join("build/link_outside")).unwrap();
        symlink(&outside, debug.join("incremental/link_outside")).unwrap();

        let cfg = Config::default();
        let platform = TestPlatform::new(1_800_000_000);
        let inv_snap = scan(
            &platform,
            &cfg,
            &ScanRequest::with_default_volume(
                vec![],
                vec![target.clone()],
                false,
                ScanDetail::Inventory,
            ),
        )
        .unwrap();
        let full_snap = scan(
            &platform,
            &cfg,
            &ScanRequest::with_default_volume(
                vec![],
                vec![target.clone()],
                false,
                ScanDetail::Full,
            ),
        )
        .unwrap();
        assert_eq!(
            inv_snap.targets[0].allocated_bytes, full_snap.targets[0].allocated_bytes,
            "Inventory and Full must report identical allocated_bytes with symlinks and hardlinks"
        );

        // When mount table is unavailable (`mounts = None`), hardlink accounting still works
        // cleanly without enabling `d_ino` skipping and fails closed (`mount_table_available = false`).
        let no_mounts = NoMountsPlatform { now: 1_800_000_000 };
        let no_mounts_snap = scan(
            &no_mounts,
            &cfg,
            &ScanRequest::with_default_volume(vec![], vec![target], false, ScanDetail::Full),
        )
        .unwrap();
        assert!(!no_mounts_snap.mount_table_available);
        assert_eq!(
            no_mounts_snap.targets[0].allocated_bytes,
            full_snap.targets[0].allocated_bytes
        );
    }

    #[test]
    fn inventory_cache_hits_when_stamp_matches_invalidates_on_mutation_and_bypasses_in_full_mode() {
        use std::collections::HashMap;

        use crate::model::{CachedProfileInventory, CachedTargetInventory};

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let debug = target.join("debug");
        let deps = debug.join("deps");
        let v2_build_pkg = debug.join("build/mycrate");
        let v2_build_unit = v2_build_pkg.join("0123456789abcdef");
        let inc_crate = debug.join("incremental/mycrate-1abc");
        let inc_sess = inc_crate.join("s-1111111111-aaaa");
        let doc = target.join("doc");
        fs::create_dir_all(&deps).unwrap();
        fs::create_dir_all(v2_build_unit.join("out")).unwrap();
        fs::create_dir_all(v2_build_unit.join("fingerprint")).unwrap();
        fs::create_dir_all(&inc_sess).unwrap();
        fs::create_dir_all(&doc).unwrap();
        fs::write(
            target.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n# created by cargo\n",
        )
        .unwrap();
        fs::write(deps.join("libfoo-0123456789abcdef.rlib"), vec![b'a'; 8192]).unwrap();
        fs::write(v2_build_unit.join("out/libmycrate.rlib"), vec![b'f'; 4096]).unwrap();
        fs::write(
            v2_build_unit.join("fingerprint/invoked.timestamp"),
            vec![b't'; 64],
        )
        .unwrap();
        fs::write(inc_sess.join("dep-graph.bin"), vec![b'b'; 4096]).unwrap();
        fs::write(doc.join("search-index.js"), vec![b'c'; 2048]).unwrap();

        let cfg = Config::default();
        // Use a timestamp far after file mtimes so target is not cooling.
        let platform = TestPlatform::new(2_500_000_000);

        let first = scan(
            &platform,
            &cfg,
            &ScanRequest::with_default_volume(
                vec![],
                vec![target.clone()],
                false,
                ScanDetail::Inventory,
            ),
        )
        .unwrap();
        assert_eq!(first.targets.len(), 1);
        let t0 = &first.targets[0];
        assert_ne!(t0.inventory_stamp, 0);
        assert_eq!(t0.inventory_computed_at_unix, 2_500_000_000);
        let real_bytes = t0.allocated_bytes;
        assert!(real_bytes > 0);

        // Build a cached inventory with a sentinel byte count and matching stamp to prove
        // `ScanDetail::Inventory` actually hits the cache without re-walking, and preserves
        // the original `computed_at_unix` even when scanned at a later timestamp.
        let sentinel_bytes = real_bytes + 123_456;
        let mut cache = HashMap::new();
        cache.insert(
            t0.root.clone(),
            CachedTargetInventory {
                stamp: t0.inventory_stamp,
                computed_at_unix: 2_500_000_000,
                allocated_bytes: sentinel_bytes,
                last_activity_unix: t0.last_activity_unix,
                has_doc_dir: t0.doc_dir.is_some(),
                doc_allocated_bytes: 99_999,
                doc_last_activity_unix: t0.last_activity_unix,
                profiles: t0
                    .profiles
                    .iter()
                    .map(|p| CachedProfileInventory {
                        rel_path: p.rel_path.clone(),
                        layout: p.layout,
                        allocated_bytes: sentinel_bytes,
                        last_activity_unix: p.last_activity_unix,
                        v2_unit_count: 7,
                        v1_unit_count: 3,
                        incremental_dir_count: 2,
                    })
                    .collect(),
            },
        );

        let later_platform = TestPlatform::new(2_500_000_600);
        let cached_hit = scan(
            &later_platform,
            &cfg,
            &ScanRequest::with_default_volume(
                vec![],
                vec![target.clone()],
                false,
                ScanDetail::Inventory,
            )
            .with_inventory_cache(cache.clone()),
        )
        .unwrap();
        assert_eq!(cached_hit.targets[0].allocated_bytes, sentinel_bytes);
        assert_eq!(
            cached_hit.targets[0].inventory_computed_at_unix,
            2_500_000_000
        );
        assert_eq!(cached_hit.targets[0].profiles[0].v2_unit_count, 7);
        assert_eq!(
            cached_hit.targets[0]
                .doc_dir
                .as_ref()
                .unwrap()
                .allocated_bytes,
            99_999
        );

        // `ScanDetail::Full` on an eligible (non-blocked, non-cooling) target MUST bypass the cache
        // and update `inventory_computed_at_unix` to the fresh scan timestamp.
        let full_bypass = scan(
            &later_platform,
            &cfg,
            &ScanRequest::with_default_volume(
                vec![],
                vec![target.clone()],
                false,
                ScanDetail::Full,
            )
            .with_inventory_cache(cache.clone()),
        )
        .unwrap();
        assert_eq!(full_bypass.targets[0].allocated_bytes, real_bytes);
        assert_eq!(
            full_bypass.targets[0].inventory_computed_at_unix,
            2_500_000_600
        );
        assert_eq!(full_bypass.targets[0].profiles[0].incremental_dirs.len(), 1);

        // Mutating Cargo v2 `build/<pkg>/` by creating a new unit hash dir MUST change the stamp
        // even though `build/`'s own directory mtime is untouched.
        let v2_new_unit = v2_build_pkg.join("fedcba9876543210");
        fs::create_dir_all(v2_new_unit.join("out")).unwrap();
        fs::create_dir_all(v2_new_unit.join("fingerprint")).unwrap();
        fs::write(v2_new_unit.join("out/libmycrate.rlib"), vec![b'g'; 8192]).unwrap();

        let after_v2_mutation = scan(
            &later_platform,
            &cfg,
            &ScanRequest::with_default_volume(
                vec![],
                vec![target.clone()],
                false,
                ScanDetail::Inventory,
            )
            .with_inventory_cache(cache.clone()),
        )
        .unwrap();
        assert_ne!(
            after_v2_mutation.targets[0].inventory_stamp,
            t0.inventory_stamp
        );
        assert_ne!(after_v2_mutation.targets[0].allocated_bytes, sentinel_bytes);
        assert!(after_v2_mutation.targets[0].allocated_bytes > real_bytes);
        assert_eq!(
            after_v2_mutation.targets[0].inventory_computed_at_unix,
            2_500_000_600
        );

        // Mutating `incremental/<crate>/` by creating a new session dir MUST also change the stamp.
        let new_sess = inc_crate.join("s-2222222222-bbbb");
        fs::create_dir_all(&new_sess).unwrap();
        fs::write(new_sess.join("dep-graph.bin"), vec![b'd'; 16_384]).unwrap();

        let after_mutation = scan(
            &later_platform,
            &cfg,
            &ScanRequest::with_default_volume(vec![], vec![target], false, ScanDetail::Inventory)
                .with_inventory_cache(cache),
        )
        .unwrap();
        assert_ne!(
            after_mutation.targets[0].inventory_stamp,
            after_v2_mutation.targets[0].inventory_stamp
        );
        assert!(
            after_mutation.targets[0].allocated_bytes
                > after_v2_mutation.targets[0].allocated_bytes
        );
    }
}
