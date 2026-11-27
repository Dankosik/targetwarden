//! Imperative Shell (Layer 5): budgeted root traversal (`max_depth`, `max_entries`,
//! non-Rust `.git` cutoff), `CACHEDIR.TAG` / `HeuristicNoTag` verification,
//! 4-layout detection, `fingerprint/*.json` reading, local Git checks, and `st_blocks` accounting.
//!
//! Allowed dependencies: `error`, `model`, `config`, `platform`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use compact_str::CompactString;
use serde::Deserialize;
use smallvec::SmallVec;
use walkdir::WalkDir;

use crate::config::Config;
use crate::error::AppError;
use crate::model::{
    BuildUnit, BuildUnitId, CargoTarget, DocDirInfo, GitDiscovery, GitInspection, IncrementalDir,
    IncrementalSession, LeftoverStaging, MountEntry, ProfileDir, ScanSnapshot, SessionState,
    TargetLayout, TargetOrigin, UnitMetadata, UnitTargetAnchor, UnitTargetKind, WorktreeKind,
};
use crate::platform::{DEFAULT_VOLUME_MOUNT, LockProbe, Platform};

const CACHEDIR_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";
const MAX_CACHEDIR_TAG_BYTES: u64 = 4 * 1024;
const MAX_RUSTC_INFO_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FINGERPRINT_JSON_BYTES: u64 = 2 * 1024 * 1024;
const MAX_COMPANION_HASH_BYTES: u64 = 64;
const STAGING_PREFIX: &str = ".targetwarden-reap.";
const SIBLING_STAGING_MARKER: &str = ".targetwarden-reap.";
const PIN_MARKER_FILE: &str = ".targetwarden-pin";
const MAX_INSPECT_WORKERS: usize = 2;

const PRUNED_DIR_NAMES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".ruff_cache",
    ".pytest_cache",
    ".next",
    ".nuxt",
    ".turbo",
    ".cache",
    "Pods",
    ".gradle",
    ".codegraph",
    "dist",
    "Library",
    ".Trash",
];

/// Non-target subdirectories pruned only once inside a `.git` repository (never at scan root,
/// so default roots such as `~/src` remain scanned normally).
const REPO_INNER_PRUNED_DIR_NAMES: &[&str] = &[
    "src",
    "docs",
    "migrations",
    "scripts",
    "specs",
    "plans",
    "evals",
    "assets",
    "static",
    "public",
    "templates",
    "charts",
    "deploy",
    "infra",
    "k8s",
    "helm",
    "proto",
    "openapi",
    "fixtures",
    "testdata",
    ".agents",
    ".github",
    ".vscode",
    ".claude",
    ".codex",
    ".cursor",
    ".idea",
    ".local",
    ".beads",
];

/// Controls how deeply target internals are parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScanDetail {
    /// Fast read-only inventory (`status` / `scan`): counts units and incremental dirs without
    /// opening/parsing thousands of `fingerprint/*.json` files or `flock`ing `s-*.lock`.
    Inventory,
    /// Full sweep metadata (`reclaim` / `watch`): reads every `fingerprint/*.json`, companion
    /// hash, `deps/` match, and `incremental/*/s-*.lock` status.
    #[allow(dead_code)]
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
        }
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

    // Overlap independent OS probes (`statvfs`+`tmutil`, `lsof`, `/sbin/mount`) with the
    // outer directory walk via synchronous scoped threads.
    let (disk_res, processes, mounts, walk_result) = std::thread::scope(|scope| {
        let disk_handle = scope.spawn(|| platform.disk_stats(&request.volume_mount));
        let proc_handle = scope.spawn(|| platform.process_snapshot().ok());
        let mount_handle = scope.spawn(|| platform.mount_table().ok());
        let walk_result = discover_candidates(config, request);
        (
            disk_handle.join().expect("disk_stats thread panicked"),
            proc_handle
                .join()
                .expect("process_snapshot thread panicked"),
            mount_handle.join().expect("mount_table thread panicked"),
            walk_result,
        )
    });

    let disk = disk_res?;
    let mount_table_available = mounts.is_some();

    let mut targets = inspect_candidates_bounded(
        platform,
        mounts.as_deref(),
        request.detail,
        &walk_result.candidates,
    );
    let mut leftover_staging = walk_result.leftover_staging;
    let mut seen_staging: HashSet<(u64, u64)> = walk_result.seen_staging;

    // Merge staging dirs found inside targets and deduplicate targets by (dev, ino).
    let mut final_targets = Vec::with_capacity(targets.len());
    let mut seen_target_ids: HashSet<(u64, u64)> = HashSet::new();
    for batch in targets.drain(..) {
        for t in batch.targets {
            if seen_target_ids.insert((t.dev_id, t.ino)) {
                final_targets.push(t);
            }
        }
        for (staging, ino) in batch.leftover_staging {
            if seen_staging.insert((staging.expected_dev, ino)) {
                leftover_staging.push(staging);
            }
        }
    }
    final_targets.sort_by(|a, b| a.root.cmp(&b.root));
    leftover_staging.sort_by(|a, b| a.staging_dir.cmp(&b.staging_dir));

    Ok(ScanSnapshot {
        captured_at_unix,
        disk,
        processes,
        mount_table_available,
        targets: final_targets,
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

fn discover_candidates(config: &Config, request: &ScanRequest) -> WalkResult {
    let mut visited_roots: HashSet<(u64, u64)> = HashSet::new();
    let mut seen_candidates: HashSet<(u64, u64)> = HashSet::new();
    let mut candidates: Vec<DiscoveredCandidate> = Vec::new();
    let mut leftover_staging: Vec<LeftoverStaging> = Vec::new();
    let mut seen_staging: HashSet<(u64, u64)> = HashSet::new();
    let mut scanned_roots: Vec<PathBuf> = Vec::new();
    let mut walk_partial = false;

    let deadline = Instant::now() + Duration::from_secs(config.discovery.walk_timeout_secs);
    let mut total_entries: usize = 0;

    if request.full_walk {
        for root in &request.roots {
            if walk_partial {
                break;
            }
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
                        &mut seen_candidates,
                        &mut candidates,
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
            if !visited_roots.insert((meta_dev(&canon_meta), meta_ino(&canon_meta))) {
                continue;
            }
            scanned_roots.push(canon_root.clone());

            walk_single_root(
                &canon_root,
                root.max_depth,
                config,
                deadline,
                &mut total_entries,
                &mut walk_partial,
                &mut seen_candidates,
                &mut candidates,
                &mut seen_staging,
                &mut leftover_staging,
            );
        }
    }

    for known in &request.known_targets {
        let Ok(lmeta) = fs::symlink_metadata(known) else {
            continue;
        };
        if lmeta.file_type().is_symlink() {
            if let Ok(meta) = fs::metadata(known)
                && meta.is_dir()
                && let Some(origin) = detect_target_origin(known)
            {
                push_candidate(&mut seen_candidates, &mut candidates, known, origin, true);
            }
            continue;
        }
        if !lmeta.is_dir() {
            continue;
        }
        if let Some(origin) = detect_target_origin(known) {
            push_candidate(&mut seen_candidates, &mut candidates, known, origin, false);
        }
    }

    WalkResult {
        candidates,
        leftover_staging,
        seen_staging,
        scanned_roots,
        walk_partial,
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
        && seen_candidates.insert((meta_dev(&meta), meta_ino(&meta)))
    {
        candidates.push(DiscoveredCandidate {
            path: path.to_path_buf(),
            origin,
            forced_boundary_violation,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_single_root(
    root: &Path,
    max_depth: usize,
    config: &Config,
    deadline: Instant,
    total_entries: &mut usize,
    walk_partial: &mut bool,
    seen_candidates: &mut HashSet<(u64, u64)>,
    candidates: &mut Vec<DiscoveredCandidate>,
    seen_staging: &mut HashSet<(u64, u64)>,
    leftover_staging: &mut Vec<LeftoverStaging>,
) {
    let mut it = WalkDir::new(root)
        .max_depth(max_depth)
        .follow_links(false)
        .max_open(config.discovery.max_open_dirs)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let ft = entry.file_type();
            if ft.is_symlink() || !ft.is_dir() {
                return false;
            }
            entry
                .file_name()
                .to_str()
                .is_none_or(|name| !PRUNED_DIR_NAMES.contains(&name))
        });

    // Stack of active Git repo depth caps: (repo_entry_depth, max_allowed_depth)
    let mut repo_caps: Vec<(usize, usize)> = Vec::new();

    while let Some(next_entry) = it.next() {
        *total_entries = total_entries.saturating_add(1);
        if *total_entries > config.discovery.max_entries
            || ((*total_entries & 0xFF) == 0 && Instant::now() >= deadline)
        {
            *walk_partial = true;
            break;
        }

        let Ok(entry) = next_entry else {
            continue;
        };
        let depth = entry.depth();
        while repo_caps
            .last()
            .is_some_and(|&(repo_depth, _)| depth <= repo_depth)
        {
            repo_caps.pop();
        }

        let path = entry.path();
        if depth > 0
            && let Some(name) = entry.file_name().to_str()
        {
            if is_staging_dir_name(name) {
                if let Ok(meta) = fs::symlink_metadata(path) {
                    let dev = meta_dev(&meta);
                    let ino = meta_ino(&meta);
                    if seen_staging.insert((dev, ino)) {
                        leftover_staging.push(LeftoverStaging {
                            staging_dir: path.to_path_buf(),
                            expected_dev: dev,
                        });
                    }
                }
                it.skip_current_dir();
                continue;
            }
            if !repo_caps.is_empty() && REPO_INNER_PRUNED_DIR_NAMES.contains(&name) {
                it.skip_current_dir();
                continue;
            }
        }

        if let Some(origin) = detect_target_origin(path) {
            if let Ok(meta) = fs::symlink_metadata(path)
                && seen_candidates.insert((meta_dev(&meta), meta_ino(&meta)))
            {
                candidates.push(DiscoveredCandidate {
                    path: path.to_path_buf(),
                    origin,
                    forced_boundary_violation: false,
                });
            }
            it.skip_current_dir();
            continue;
        }

        if let Some(&(_, cap_depth)) = repo_caps.last()
            && depth >= cap_depth
        {
            it.skip_current_dir();
            continue;
        }

        // Entering a `.git` repository (including explicit scan roots at depth 0):
        // - Rust repo (`Cargo.toml` at depth 0): target dirs live at depth +1 or +2 (`target/`,
        //   `<subcrate>/target/`), never deep inside source trees.
        // - Non-Rust `.git` repo (no `Cargo.toml`/`CACHEDIR.TAG`/`.rustc_info.json` at depth 0–1):
        //   cap remaining descent to `+2` per spec Section 4.1.
        if path.join(".git").exists() {
            let cap = if has_direct_rust_marker(path) {
                depth.saturating_add(2)
            } else if !has_rust_marker_at_depth_1(path) {
                depth.saturating_add(config.discovery.non_rust_git_extra_depth)
            } else {
                depth.saturating_add(3)
            };
            repo_caps.push((depth, cap));
        }
    }
}

struct WorkerOutput {
    targets: Vec<CargoTarget>,
    leftover_staging: Vec<(LeftoverStaging, u64)>,
}

fn inspect_candidates_bounded<P: Platform + Sync>(
    platform: &P,
    mounts: Option<&[MountEntry]>,
    detail: ScanDetail,
    candidates: &[DiscoveredCandidate],
) -> Vec<WorkerOutput> {
    if candidates.is_empty() {
        return Vec::new();
    }
    if candidates.len() == 1 {
        let mut ctx = WorkerContext::new(platform, mounts, detail);
        ctx.inspect_target(
            &candidates[0].path,
            candidates[0].origin,
            None,
            candidates[0].forced_boundary_violation,
        );
        return vec![WorkerOutput {
            targets: ctx.targets,
            leftover_staging: ctx.leftover_staging,
        }];
    }

    let worker_count = candidates.len().min(MAX_INSPECT_WORKERS);
    let next_idx = AtomicUsize::new(0);

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let next_ref = &next_idx;
            handles.push(scope.spawn(move || {
                let mut ctx = WorkerContext::new(platform, mounts, detail);
                loop {
                    let idx = next_ref.fetch_add(1, Ordering::Relaxed);
                    let Some(cand) = candidates.get(idx) else {
                        break;
                    };
                    ctx.inspect_target(
                        &cand.path,
                        cand.origin,
                        None,
                        cand.forced_boundary_violation,
                    );
                }
                WorkerOutput {
                    targets: ctx.targets,
                    leftover_staging: ctx.leftover_staging,
                }
            }));
        }
        handles
            .into_iter()
            .map(|h| h.join().expect("target inspection worker panicked"))
            .collect()
    })
}

fn has_rust_marker_at_depth_1(dir: &Path) -> bool {
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
        if entry.file_name().to_str().is_some_and(|name| {
            PRUNED_DIR_NAMES.contains(&name) || REPO_INNER_PRUNED_DIR_NAMES.contains(&name)
        }) {
            continue;
        }
        if has_direct_rust_marker(&entry.path()) {
            return true;
        }
    }
    false
}

fn has_direct_rust_marker(dir: &Path) -> bool {
    dir.join("Cargo.toml").exists()
        || dir.join("CACHEDIR.TAG").exists()
        || dir.join(".rustc_info.json").exists()
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
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let mut buf = Vec::new();
    if file
        .take(MAX_CACHEDIR_TAG_BYTES + 1)
        .read_to_end(&mut buf)
        .is_err()
    {
        return false;
    }
    if buf.len() as u64 > MAX_CACHEDIR_TAG_BYTES || !buf.starts_with(CACHEDIR_SIGNATURE) {
        return false;
    }
    let rest = &buf[CACHEDIR_SIGNATURE.len()..];
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

#[derive(Deserialize)]
struct MinimalRustcInfo {
    rustc_fingerprint: serde_json::Value,
    outputs: serde_json::Value,
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
    match serde_json::from_slice::<MinimalRustcInfo>(&buf) {
        Ok(info) => !info.rustc_fingerprint.is_null() && info.outputs.is_object(),
        Err(_) => false,
    }
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
    PROFILE_MARKERS.iter().any(|marker| {
        fs::symlink_metadata(dir.join(marker)).is_ok_and(|m| !m.file_type().is_symlink())
    })
}

struct WorkerContext<'a, P: Platform> {
    platform: &'a P,
    mounts: Option<&'a [MountEntry]>,
    detail: ScanDetail,
    visited_targets: HashSet<(u64, u64)>,
    targets: Vec<CargoTarget>,
    leftover_staging: Vec<(LeftoverStaging, u64)>,
    git_repo_cache: HashMap<PathBuf, Result<RepoGitInfo, CompactString>>,
}

impl<'a, P: Platform> WorkerContext<'a, P> {
    fn new(platform: &'a P, mounts: Option<&'a [MountEntry]>, detail: ScanDetail) -> Self {
        Self {
            platform,
            mounts,
            detail,
            visited_targets: HashSet::new(),
            targets: Vec::new(),
            leftover_staging: Vec::new(),
            git_repo_cache: HashMap::new(),
        }
    }

    fn inspect_target(
        &mut self,
        target_root: &Path,
        origin: TargetOrigin,
        parent_target: Option<PathBuf>,
        forced_boundary_violation: bool,
    ) {
        let Ok(lmeta) = fs::symlink_metadata(target_root) else {
            return;
        };
        let dev_id = meta_dev(&lmeta);
        let ino = meta_ino(&lmeta);
        if !self.visited_targets.insert((dev_id, ino)) {
            return;
        }

        let symlink_or_mount_boundary = forced_boundary_violation
            || lmeta.file_type().is_symlink()
            || has_symlink_boundary(target_root)
            || crosses_mount_boundary(target_root, dev_id, self.mounts);

        let mut seen_hardlinks: HashSet<(u64, u64)> = HashSet::new();
        let mut profiles: Vec<ProfileDir> = Vec::new();
        let mut doc_dir: Option<DocDirInfo> = None;
        let mut nested_target_roots: Vec<PathBuf> = Vec::new();
        let mut nested_to_inspect: Vec<(PathBuf, TargetOrigin)> = Vec::new();
        let mut has_unverified_top_entries = false;
        let mut has_pin_marker = fs::symlink_metadata(target_root.join(PIN_MARKER_FILE)).is_ok();
        let mut allocated_bytes: u64 = 0;
        let mut last_activity_unix: u64 = 0;

        let legacy_root_lock = target_root.join(".cargo-lock");
        let has_legacy_root_lock =
            fs::symlink_metadata(&legacy_root_lock).is_ok_and(|m| m.file_type().is_file());

        let entries: Vec<_> = match fs::read_dir(target_root) {
            Ok(rd) => rd.flatten().collect(),
            Err(_) => Vec::new(),
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
                self.leftover_staging.push((
                    LeftoverStaging {
                        staging_dir: entry_path,
                        expected_dev: meta_dev(&emeta),
                    },
                    meta_ino(&emeta),
                ));
                continue;
            }

            if name == PIN_MARKER_FILE {
                has_pin_marker = true;
                continue;
            }

            if name == ".rustc_info.json" || name == ".rustdoc_fingerprint.json" {
                last_activity_unix = last_activity_unix.max(meta_mtime_unix(&emeta));
                allocated_bytes = allocated_bytes
                    .saturating_add(entry_allocated_bytes(&emeta, &mut seen_hardlinks));
                continue;
            }

            if name == "CACHEDIR.TAG" || name == ".cargo-lock" {
                allocated_bytes = allocated_bytes
                    .saturating_add(entry_allocated_bytes(&emeta, &mut seen_hardlinks));
                continue;
            }

            if ft.is_dir() && !ft.is_symlink() {
                if name == "doc" {
                    let info = inspect_doc_dir(&entry_path, self.platform, &mut seen_hardlinks);
                    last_activity_unix = last_activity_unix.max(info.last_activity_unix);
                    allocated_bytes = allocated_bytes.saturating_add(info.allocated_bytes);
                    doc_dir = Some(info);
                    continue;
                }
                if name == "tmp" || name == "package" {
                    let bytes = sum_tree_bytes(&entry_path, &mut seen_hardlinks);
                    allocated_bytes = allocated_bytes.saturating_add(bytes);
                    continue;
                }
                if let Some(nested_origin) = detect_target_origin(&entry_path) {
                    nested_target_roots.push(entry_path.clone());
                    nested_to_inspect.push((entry_path, nested_origin));
                    continue;
                }
                if is_profile_dir(&entry_path) {
                    let profile = inspect_profile_dir(
                        Path::new(&name),
                        &entry_path,
                        has_legacy_root_lock.then_some(legacy_root_lock.as_path()),
                        self.platform,
                        self.detail,
                        &mut seen_hardlinks,
                    );
                    last_activity_unix = last_activity_unix.max(profile.last_activity_unix);
                    allocated_bytes = allocated_bytes.saturating_add(profile.allocated_bytes);
                    profiles.push(profile);
                    continue;
                }
                // Check `<target-triple>/<profile>/` one level deeper.
                let triple_profiles = find_triple_profiles(&entry_path);
                if !triple_profiles.is_empty() {
                    for sub_name in triple_profiles {
                        let rel = PathBuf::from(&name).join(&sub_name);
                        let full = entry_path.join(&sub_name);
                        let profile = inspect_profile_dir(
                            &rel,
                            &full,
                            has_legacy_root_lock.then_some(legacy_root_lock.as_path()),
                            self.platform,
                            self.detail,
                            &mut seen_hardlinks,
                        );
                        last_activity_unix = last_activity_unix.max(profile.last_activity_unix);
                        allocated_bytes = allocated_bytes.saturating_add(profile.allocated_bytes);
                        profiles.push(profile);
                    }
                    continue;
                }
            }

            // Unknown top-level entry.
            if origin == TargetOrigin::HeuristicNoTag {
                has_unverified_top_entries = true;
            }
            if ft.is_dir() && !ft.is_symlink() {
                allocated_bytes = allocated_bytes
                    .saturating_add(sum_tree_bytes(&entry_path, &mut seen_hardlinks));
            } else {
                allocated_bytes = allocated_bytes
                    .saturating_add(entry_allocated_bytes(&emeta, &mut seen_hardlinks));
            }
        }

        if last_activity_unix == 0 {
            last_activity_unix = meta_mtime_unix(&lmeta);
        }

        profiles.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        nested_target_roots.sort();

        let layout = classify_target_layout(&profiles);
        let git = inspect_git_for_target(target_root, self.platform, &mut self.git_repo_cache);
        let worktree_kind = match &git {
            GitDiscovery::Inspected(info) => info.worktree_kind,
            GitDiscovery::NotInGitRepo | GitDiscovery::Failed(_) => WorktreeKind::NonGit,
        };
        let project_dir = match &git {
            GitDiscovery::Inspected(info) => Some(info.worktree_root.clone()),
            GitDiscovery::NotInGitRepo | GitDiscovery::Failed(_) => {
                infer_non_git_project_dir(target_root)
            }
        };
        if let Some(proj) = &project_dir
            && fs::symlink_metadata(proj.join(PIN_MARKER_FILE)).is_ok()
        {
            has_pin_marker = true;
        }

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
            allocated_bytes,
            last_activity_unix,
        });

        for (nested_path, nested_origin) in nested_to_inspect {
            self.inspect_target(
                &nested_path,
                nested_origin,
                Some(target_root.to_path_buf()),
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

fn inspect_doc_dir(
    doc_path: &Path,
    platform: &impl Platform,
    seen_hardlinks: &mut HashSet<(u64, u64)>,
) -> DocDirInfo {
    let lock_candidate = doc_path.join(".lock");
    let (lock_file, locked_now) =
        if fs::symlink_metadata(&lock_candidate).is_ok_and(|m| m.file_type().is_file()) {
            let locked = match platform.try_lock_readonly(&lock_candidate) {
                Ok(LockProbe::Acquired(_)) | Ok(LockProbe::NotFound) => false,
                Ok(LockProbe::Contested) | Err(_) => true,
            };
            (Some(lock_candidate), locked)
        } else {
            (None, false)
        };

    let (allocated_bytes, last_activity_unix) =
        sum_tree_bytes_and_mtime(doc_path, 2, seen_hardlinks);

    DocDirInfo {
        path: doc_path.to_path_buf(),
        lock_file,
        locked_now,
        last_activity_unix,
        allocated_bytes,
    }
}

fn inspect_profile_dir(
    rel_path: &Path,
    profile_path: &Path,
    legacy_root_lock: Option<&Path>,
    platform: &impl Platform,
    detail: ScanDetail,
    seen_hardlinks: &mut HashSet<(u64, u64)>,
) -> ProfileDir {
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
            Ok(LockProbe::Acquired(_)) | Ok(LockProbe::NotFound) => {}
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
    let has_inc_dir = fs::symlink_metadata(&inc_root).is_ok_and(|m| m.file_type().is_dir());

    if detail == ScanDetail::Inventory {
        return inspect_profile_inventory(
            rel_path,
            profile_path,
            lock_files,
            locked_now,
            has_v1_fp_dir,
            has_v1_deps_dir,
            has_build_dir,
            has_inc_dir,
            seen_hardlinks,
        );
    }

    let mut fingerprint_corrupt = false;
    let mut v1_units: Vec<BuildUnit> = Vec::new();
    let mut v2_units: Vec<BuildUnit> = Vec::new();
    let mut incremental_dirs: Vec<IncrementalDir> = Vec::new();
    let mut allocated_bytes: u64 = 0;
    let mut last_activity_unix: u64 = 0;

    let mut v1_fp_index_by_name: HashMap<CompactString, usize> = HashMap::new();
    let mut v1_hash_to_indices: HashMap<CompactString, SmallVec<[usize; 2]>> = HashMap::new();

    // 1. V1 `.fingerprint/<pkg>-<16hex>/`
    if has_v1_fp_dir && let Ok(entries) = fs::read_dir(&fp_root) {
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            let entry_path = entry.path();
            if !ft.is_dir() || ft.is_symlink() {
                if let Ok(meta) = fs::symlink_metadata(&entry_path) {
                    allocated_bytes = allocated_bytes
                        .saturating_add(entry_allocated_bytes(&meta, seen_hardlinks));
                }
                continue;
            }
            let Some(dir_name) = entry.file_name().to_str().map(CompactString::from) else {
                fingerprint_corrupt = true;
                continue;
            };
            let Some((pkg_group, unit_hash)) = split_pkg_and_16hex(&dir_name) else {
                allocated_bytes =
                    allocated_bytes.saturating_add(sum_tree_bytes(&entry_path, seen_hardlinks));
                continue;
            };
            let parsed = parse_fingerprint_dir(&entry_path, seen_hardlinks);
            if parsed.corrupt {
                fingerprint_corrupt = true;
            }
            let unit_mtime = unit_metadata_mtime(&parsed.metadata);
            last_activity_unix = last_activity_unix.max(unit_mtime);
            allocated_bytes = allocated_bytes.saturating_add(parsed.allocated_bytes);

            let idx = v1_units.len();
            v1_fp_index_by_name.insert(dir_name.clone(), idx);
            v1_hash_to_indices
                .entry(unit_hash.clone())
                .or_default()
                .push(idx);
            v1_units.push(BuildUnit {
                id: BuildUnitId::V1 {
                    fingerprint_dir: dir_name,
                    unit_hash,
                },
                pkg_group,
                metadata: parsed.metadata,
                v1_build_dir: None,
                v1_dep_entries: Vec::new(),
                allocated_bytes: parsed.allocated_bytes,
            });
        }
    }

    // 2. V1 `deps/` (match files and `.dSYM` directories to unique V1 unit_hash)
    if has_v1_deps_dir && let Ok(entries) = fs::read_dir(&deps_root) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let Ok(emeta) = fs::symlink_metadata(&entry_path) else {
                continue;
            };
            let bytes = if emeta.file_type().is_dir() && !emeta.file_type().is_symlink() {
                sum_tree_bytes(&entry_path, seen_hardlinks)
            } else {
                entry_allocated_bytes(&emeta, seen_hardlinks)
            };
            allocated_bytes = allocated_bytes.saturating_add(bytes);

            if let Some(name) = entry.file_name().to_str()
                && let Some(hash) = extract_16hex_from_dep_name(name)
                && let Some(indices) = v1_hash_to_indices.get(hash)
                && indices.len() == 1
            {
                let unit = &mut v1_units[indices[0]];
                unit.v1_dep_entries.push(CompactString::from(name));
                unit.allocated_bytes = unit.allocated_bytes.saturating_add(bytes);
            }
        }
    }

    // 3. `build/` (handles V1 `build/<pkg>-<16hex>/`, V2 `build/<pkg>/<16hex>/`, and MixedV1V2)
    if has_build_dir && let Ok(entries) = fs::read_dir(&build_root) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if !ft.is_dir() || ft.is_symlink() {
                if let Ok(meta) = fs::symlink_metadata(&entry_path) {
                    allocated_bytes = allocated_bytes
                        .saturating_add(entry_allocated_bytes(&meta, seen_hardlinks));
                }
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(CompactString::from) else {
                continue;
            };

            if let Some(&v1_idx) = v1_fp_index_by_name.get(&name) {
                let bytes = sum_tree_bytes(&entry_path, seen_hardlinks);
                allocated_bytes = allocated_bytes.saturating_add(bytes);
                let unit = &mut v1_units[v1_idx];
                unit.v1_build_dir = Some(name);
                unit.allocated_bytes = unit.allocated_bytes.saturating_add(bytes);
                continue;
            }

            let mut found_v2_child = false;
            if let Ok(children) = fs::read_dir(&entry_path) {
                for child in children.flatten() {
                    let child_path = child.path();
                    let Ok(cft) = child.file_type() else {
                        continue;
                    };
                    if !cft.is_dir() || cft.is_symlink() {
                        continue;
                    }
                    let child_os = child.file_name();
                    let Some(child_name) = child_os.to_str() else {
                        continue;
                    };
                    if !is_16_lower_hex(child_name) {
                        continue;
                    }
                    found_v2_child = true;

                    let unit_hash = CompactString::from(child_name);
                    let fp_sub = child_path.join("fingerprint");
                    let parsed =
                        if fs::symlink_metadata(&fp_sub).is_ok_and(|m| m.file_type().is_dir()) {
                            parse_fingerprint_dir(&fp_sub, seen_hardlinks)
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
                        fingerprint_corrupt = true;
                    }

                    let other_bytes =
                        sum_tree_bytes_excluding_child(&child_path, "fingerprint", seen_hardlinks);
                    let unit_bytes = parsed.allocated_bytes.saturating_add(other_bytes);
                    let unit_mtime = unit_metadata_mtime(&parsed.metadata);
                    last_activity_unix = last_activity_unix.max(unit_mtime);
                    allocated_bytes = allocated_bytes.saturating_add(unit_bytes);

                    v2_units.push(BuildUnit {
                        id: BuildUnitId::V2 {
                            pkg: name.clone(),
                            unit_hash,
                        },
                        pkg_group: name.clone(),
                        metadata: parsed.metadata,
                        v1_build_dir: None,
                        v1_dep_entries: Vec::new(),
                        allocated_bytes: unit_bytes,
                    });
                }
            }

            if !found_v2_child {
                allocated_bytes =
                    allocated_bytes.saturating_add(sum_tree_bytes(&entry_path, seen_hardlinks));
            }
        }
    }

    // 4. `incremental/`
    if has_inc_dir && let Ok(entries) = fs::read_dir(&inc_root) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if !ft.is_dir() || ft.is_symlink() {
                if let Ok(meta) = fs::symlink_metadata(&entry_path) {
                    allocated_bytes = allocated_bytes
                        .saturating_add(entry_allocated_bytes(&meta, seen_hardlinks));
                }
                continue;
            }
            let Some(dir_name) = entry.file_name().to_str().map(CompactString::from) else {
                continue;
            };
            let inc_dir = inspect_incremental_dir(&entry_path, dir_name, platform, seen_hardlinks);
            last_activity_unix = last_activity_unix.max(inc_dir.latest_mtime_unix);
            allocated_bytes = allocated_bytes.saturating_add(inc_dir.allocated_bytes);
            incremental_dirs.push(inc_dir);
        }
    }

    // 5. Top-level profile entries (excluding already-accounted subdirs)
    if let Ok(entries) = fs::read_dir(profile_path) {
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if matches!(
                name.as_str(),
                ".fingerprint" | "deps" | "build" | "incremental"
            ) {
                continue;
            }
            let entry_path = entry.path();
            let Ok(emeta) = fs::symlink_metadata(&entry_path) else {
                continue;
            };
            last_activity_unix = last_activity_unix.max(meta_mtime_unix(&emeta));
            if emeta.file_type().is_dir() && !emeta.file_type().is_symlink() {
                allocated_bytes =
                    allocated_bytes.saturating_add(sum_tree_bytes(&entry_path, seen_hardlinks));
            } else {
                allocated_bytes =
                    allocated_bytes.saturating_add(entry_allocated_bytes(&emeta, seen_hardlinks));
            }
        }
    }

    let has_v2 = !v2_units.is_empty();
    let has_v1 = !v1_units.is_empty() || has_v1_fp_dir || has_v1_deps_dir;
    let layout = classify_profile_layout(has_v2, has_v1, has_build_dir, has_inc_dir);

    ProfileDir {
        name: CompactString::from(rel_path.to_string_lossy().as_ref()),
        rel_path: rel_path.to_path_buf(),
        layout,
        lock_files,
        locked_now,
        fingerprint_corrupt,
        v2_unit_count: v2_units.len(),
        v1_unit_count: v1_units.len(),
        incremental_dir_count: incremental_dirs.len(),
        v2_units,
        v1_units,
        incremental_dirs,
        allocated_bytes,
        last_activity_unix,
    }
}

#[allow(clippy::too_many_arguments)]
fn inspect_profile_inventory(
    rel_path: &Path,
    profile_path: &Path,
    lock_files: SmallVec<[PathBuf; 4]>,
    locked_now: bool,
    has_v1_fp_dir: bool,
    has_v1_deps_dir: bool,
    has_build_dir: bool,
    has_inc_dir: bool,
    seen_hardlinks: &mut HashSet<(u64, u64)>,
) -> ProfileDir {
    let mut v1_fp_names: HashSet<CompactString> = HashSet::new();
    let mut v1_unit_count = 0usize;
    let mut v2_unit_count = 0usize;
    let mut incremental_dir_count = 0usize;

    if has_v1_fp_dir && let Ok(entries) = fs::read_dir(profile_path.join(".fingerprint")) {
        for entry in entries.flatten() {
            if entry
                .file_type()
                .is_ok_and(|ft| ft.is_dir() && !ft.is_symlink())
                && let Some(name) = entry.file_name().to_str()
                && split_pkg_and_16hex(name).is_some()
            {
                v1_unit_count += 1;
                v1_fp_names.insert(CompactString::from(name));
            }
        }
    }

    if has_build_dir && let Ok(entries) = fs::read_dir(profile_path.join("build")) {
        for entry in entries.flatten() {
            if !entry
                .file_type()
                .is_ok_and(|ft| ft.is_dir() && !ft.is_symlink())
            {
                continue;
            }
            let os_name = entry.file_name();
            if let Some(name) = os_name.to_str()
                && v1_fp_names.contains(name)
            {
                continue;
            }
            if let Ok(children) = fs::read_dir(entry.path()) {
                for child in children.flatten() {
                    if child
                        .file_type()
                        .is_ok_and(|ft| ft.is_dir() && !ft.is_symlink())
                        && child.file_name().to_str().is_some_and(is_16_lower_hex)
                    {
                        v2_unit_count += 1;
                    }
                }
            }
        }
    }

    if has_inc_dir && let Ok(entries) = fs::read_dir(profile_path.join("incremental")) {
        for entry in entries.flatten() {
            if entry
                .file_type()
                .is_ok_and(|ft| ft.is_dir() && !ft.is_symlink())
            {
                incremental_dir_count += 1;
            }
        }
    }

    let (allocated_bytes, last_activity_unix) =
        sum_tree_bytes_and_mtime(profile_path, 3, seen_hardlinks);

    let has_v2 = v2_unit_count > 0;
    let has_v1 = v1_unit_count > 0 || has_v1_fp_dir || has_v1_deps_dir;
    let layout = classify_profile_layout(has_v2, has_v1, has_build_dir, has_inc_dir);

    ProfileDir {
        name: CompactString::from(rel_path.to_string_lossy().as_ref()),
        rel_path: rel_path.to_path_buf(),
        layout,
        lock_files,
        locked_now,
        fingerprint_corrupt: false,
        v2_unit_count,
        v1_unit_count,
        incremental_dir_count,
        v2_units: Vec::new(),
        v1_units: Vec::new(),
        incremental_dirs: Vec::new(),
        allocated_bytes,
        last_activity_unix,
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

#[derive(Deserialize)]
struct RawFingerprintJson {
    rustc: u64,
    #[serde(default)]
    deps: Vec<(
        serde::de::IgnoredAny,
        serde::de::IgnoredAny,
        serde::de::IgnoredAny,
        u64,
    )>,
}

fn parse_fingerprint_dir(
    fp_dir: &Path,
    seen_hardlinks: &mut HashSet<(u64, u64)>,
) -> ParsedFingerprintDir {
    let mut allocated_bytes: u64 = 0;
    let mut max_mtime: u64 = fs::symlink_metadata(fp_dir)
        .map(|m| meta_mtime_unix(&m))
        .unwrap_or(0);
    let mut corrupt = false;
    let mut targets: SmallVec<[UnitTargetAnchor; 2]> = SmallVec::new();
    let mut dep_fp_hashes: SmallVec<[u64; 8]> = SmallVec::new();
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
        allocated_bytes =
            allocated_bytes.saturating_add(entry_allocated_bytes(&meta, seen_hardlinks));

        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
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
        let Ok(bytes) = fs::read(&entry_path) else {
            corrupt = true;
            continue;
        };
        let Ok(parsed) = serde_json::from_slice::<RawFingerprintJson>(&bytes) else {
            corrupt = true;
            continue;
        };

        rustc_hash = Some(parsed.rustc);
        for (_, _, _, dep_hash) in parsed.deps {
            if !dep_fp_hashes.contains(&dep_hash) {
                dep_fp_hashes.push(dep_hash);
            }
        }

        let (target_kind, target_name) = parse_fingerprint_target_stem(stem);
        let companion_path = fp_dir.join(stem);
        let fingerprint_hash = read_companion_fingerprint_hash(&companion_path);
        targets.push(UnitTargetAnchor {
            target_kind,
            target_name,
            fingerprint_hash,
        });
    }

    let metadata = match rustc_hash {
        Some(rustc) if !targets.is_empty() => UnitMetadata::Complete {
            targets,
            rustc_hash: rustc,
            dep_fp_hashes,
            mtime_unix: max_mtime,
        },
        _ => UnitMetadata::Incomplete {
            mtime_unix: max_mtime,
        },
    };

    ParsedFingerprintDir {
        metadata,
        allocated_bytes,
        corrupt,
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

fn read_companion_fingerprint_hash(path: &Path) -> Option<u64> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > MAX_COMPANION_HASH_BYTES {
        return None;
    }
    let raw = fs::read(path).ok()?;
    decode_le_u64_hex(&raw)
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

fn inspect_incremental_dir(
    dir_path: &Path,
    dir_name: CompactString,
    platform: &impl Platform,
    seen_hardlinks: &mut HashSet<(u64, u64)>,
) -> IncrementalDir {
    let crate_name = extract_incremental_crate_name(&dir_name);
    let mut sessions: Vec<IncrementalSession> = Vec::new();
    let mut lock_status: HashMap<CompactString, bool> = HashMap::new();
    let mut lock_mtimes: HashMap<CompactString, u64> = HashMap::new();
    let mut allocated_bytes: u64 = 0;
    let mut latest_mtime_unix: u64 = fs::symlink_metadata(dir_path)
        .map(|m| meta_mtime_unix(&m))
        .unwrap_or(0);

    let entries: Vec<_> = match fs::read_dir(dir_path) {
        Ok(rd) => rd.flatten().collect(),
        Err(_) => Vec::new(),
    };

    for entry in &entries {
        let entry_path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&entry_path) else {
            continue;
        };
        let Some(name) = entry.file_name().to_str().map(CompactString::from) else {
            continue;
        };
        if meta.file_type().is_file() && name.starts_with("s-") && name.ends_with(".lock") {
            let locked = match platform.try_lock_readonly(&entry_path) {
                Ok(LockProbe::Acquired(_)) | Ok(LockProbe::NotFound) => false,
                Ok(LockProbe::Contested) | Err(_) => true,
            };
            let mtime = meta_mtime_unix(&meta);
            latest_mtime_unix = latest_mtime_unix.max(mtime);
            allocated_bytes =
                allocated_bytes.saturating_add(entry_allocated_bytes(&meta, seen_hardlinks));
            lock_status.insert(name.clone(), locked);
            lock_mtimes.insert(name, mtime);
        }
    }

    let mut any_locked = lock_status.values().any(|&locked| locked);

    for entry in entries {
        let entry_path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&entry_path) else {
            continue;
        };
        let Some(name) = entry.file_name().to_str().map(CompactString::from) else {
            continue;
        };
        if meta.file_type().is_file() && name.starts_with("s-") && name.ends_with(".lock") {
            continue;
        }
        if !meta.file_type().is_dir() || meta.file_type().is_symlink() || !name.starts_with("s-") {
            if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
                allocated_bytes =
                    allocated_bytes.saturating_add(sum_tree_bytes(&entry_path, seen_hardlinks));
            } else {
                allocated_bytes =
                    allocated_bytes.saturating_add(entry_allocated_bytes(&meta, seen_hardlinks));
            }
            continue;
        }

        let (state, lock_file) = classify_incremental_session(&name, &lock_status);
        let locked = lock_file
            .as_ref()
            .and_then(|lf| lock_status.get(lf).copied())
            .unwrap_or(false);
        if locked {
            any_locked = true;
        }

        let (sess_bytes, mut sess_mtime) = sum_tree_bytes_and_mtime(&entry_path, 1, seen_hardlinks);
        if let Some(lf) = &lock_file
            && let Some(&lm) = lock_mtimes.get(lf)
        {
            sess_mtime = sess_mtime.max(lm);
        }
        latest_mtime_unix = latest_mtime_unix.max(sess_mtime);
        allocated_bytes = allocated_bytes.saturating_add(sess_bytes);

        sessions.push(IncrementalSession {
            dir_name: name,
            lock_file,
            state,
            locked,
            mtime_unix: sess_mtime,
            allocated_bytes: sess_bytes,
        });
    }

    IncrementalDir {
        dir_name,
        crate_name,
        sessions,
        any_locked,
        latest_mtime_unix,
        allocated_bytes,
    }
}

fn classify_incremental_session(
    session_dir_name: &str,
    known_locks: &HashMap<CompactString, bool>,
) -> (SessionState, Option<CompactString>) {
    let state = if session_dir_name.ends_with("-working") {
        SessionState::Working
    } else {
        SessionState::Finalized
    };
    let lock_candidate = session_dir_name
        .rsplit_once('-')
        .map(|(prefix, _)| CompactString::from(format!("{prefix}.lock")))
        .filter(|candidate| known_locks.contains_key(candidate));
    (state, lock_candidate)
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

fn is_16_lower_hex(s: &str) -> bool {
    s.len() == 16
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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

fn inspect_git_for_target(
    target_root: &Path,
    platform: &impl Platform,
    cache: &mut HashMap<PathBuf, Result<RepoGitInfo, CompactString>>,
) -> GitDiscovery {
    let Some(repo_anchor) = find_git_ancestor(target_root) else {
        return GitDiscovery::NotInGitRepo;
    };

    let repo_info = match cache.get(&repo_anchor) {
        Some(cached) => cached.clone(),
        None => {
            let computed = inspect_repo_git(&repo_anchor, platform);
            cache.insert(repo_anchor.clone(), computed.clone());
            computed
        }
    };

    let info = match repo_info {
        Ok(info) => info,
        Err(reason) => return GitDiscovery::Failed(reason),
    };

    let has_tracked_files_in_target =
        if let Ok(rel_target) = target_root.strip_prefix(&info.worktree_root) {
            let rel_str = rel_target.to_string_lossy();
            match platform.run_git(&info.worktree_root, &["ls-files", "-z", "--", &rel_str]) {
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
) -> Result<RepoGitInfo, CompactString> {
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
    let git_op_in_progress = has_git_op_markers(&git_dir) || has_git_op_markers(&repo_common_dir);
    let worktree_locked =
        worktree_kind == WorktreeKind::LinkedWorktree && git_dir.join("locked").exists();

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
    let is_dirty = !status.stdout.is_empty();

    let branch_merged_into_default = if worktree_kind == WorktreeKind::LinkedWorktree
        && !is_dirty
        && !worktree_locked
        && !git_op_in_progress
    {
        check_branch_merged_locally(&worktree_root, platform)
    } else {
        None
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
    const MARKERS: &[&str] = &[
        "index.lock",
        "MERGE_HEAD",
        "REBASE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
        "rebase-merge",
        "rebase-apply",
    ];
    MARKERS.iter().any(|marker| git_dir.join(marker).exists())
}

fn check_branch_merged_locally(worktree_root: &Path, platform: &impl Platform) -> Option<bool> {
    let default_ref = resolve_local_default_ref(worktree_root, platform)?;
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

fn has_symlink_boundary(path: &Path) -> bool {
    let Ok(canon) = fs::canonicalize(path) else {
        return true;
    };
    let normalized = normalize_macos_system_symlinks(path);
    canon != normalized
}

fn normalize_macos_system_symlinks(path: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Ok(rest) = path.strip_prefix("/var") {
            return Path::new("/private/var").join(rest);
        }
        if let Ok(rest) = path.strip_prefix("/tmp") {
            return Path::new("/private/tmp").join(rest);
        }
        if let Ok(rest) = path.strip_prefix("/etc") {
            return Path::new("/private/etc").join(rest);
        }
    }
    path.to_path_buf()
}

pub(crate) fn crosses_mount_boundary(
    target_root: &Path,
    target_dev: u64,
    mounts: Option<&[MountEntry]>,
) -> bool {
    if let Some(parent) = target_root.parent() {
        let Ok(parent_meta) = fs::symlink_metadata(parent) else {
            return true;
        };
        if meta_dev(&parent_meta) != target_dev {
            return true;
        }
    }

    let Some(entries) = mounts else {
        return false;
    };

    let norm_target = normalize_mount_path(target_root);
    for entry in entries {
        let mp = entry.mount_point.as_path();
        if mp == Path::new("/") || mp == Path::new(DEFAULT_VOLUME_MOUNT) {
            continue;
        }
        let norm_mp = normalize_mount_path(mp);
        if norm_mp == Path::new("/") {
            continue;
        }
        if norm_mp == norm_target || norm_mp.starts_with(&norm_target) {
            return true;
        }
        if norm_target.starts_with(&norm_mp) && is_non_local_fstype(&entry.fstype) {
            return true;
        }
    }
    false
}

fn normalize_mount_path(path: &Path) -> PathBuf {
    let stripped = if let Ok(rest) = path.strip_prefix(DEFAULT_VOLUME_MOUNT) {
        if rest.as_os_str().is_empty() {
            PathBuf::from("/")
        } else {
            Path::new("/").join(rest)
        }
    } else {
        path.to_path_buf()
    };
    normalize_macos_system_symlinks(&stripped)
}

fn is_non_local_fstype(fstype: &str) -> bool {
    let lower = fstype.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "nfs"
            | "smbfs"
            | "afpfs"
            | "webdav"
            | "autofs"
            | "devfs"
            | "nullfs"
            | "macfuse"
            | "osxfuse"
    ) || lower.starts_with("fuse")
}

/// Fast fd-anchored `st_blocks * 512` tree sum with hardlink deduplication.
fn sum_tree_bytes(root: &Path, seen_hardlinks: &mut HashSet<(u64, u64)>) -> u64 {
    sum_tree_bytes_and_mtime(root, 0, seen_hardlinks).0
}

fn sum_tree_bytes_excluding_child(
    root: &Path,
    exclude_child: &str,
    seen_hardlinks: &mut HashSet<(u64, u64)>,
) -> u64 {
    #[cfg(unix)]
    {
        sum_tree_unix(root, 0, Some(exclude_child.as_bytes()), seen_hardlinks).0
    }
    #[cfg(not(unix))]
    {
        let mut total: u64 = 0;
        let mut it = WalkDir::new(root).follow_links(false).into_iter();
        while let Some(next) = it.next() {
            let Ok(entry) = next else { continue };
            if entry.depth() == 1 && entry.file_name().to_str() == Some(exclude_child) {
                it.skip_current_dir();
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                total = total.saturating_add(entry_allocated_bytes(&meta, seen_hardlinks));
            }
        }
        total
    }
}

fn sum_tree_bytes_and_mtime(
    root: &Path,
    mtime_max_depth: usize,
    seen_hardlinks: &mut HashSet<(u64, u64)>,
) -> (u64, u64) {
    #[cfg(unix)]
    {
        sum_tree_unix(root, mtime_max_depth, None, seen_hardlinks)
    }
    #[cfg(not(unix))]
    {
        let mut total: u64 = 0;
        let mut max_mtime: u64 = 0;
        for entry in WalkDir::new(root).follow_links(false).into_iter().flatten() {
            if let Ok(meta) = entry.metadata() {
                total = total.saturating_add(entry_allocated_bytes(&meta, seen_hardlinks));
                if entry.depth() <= mtime_max_depth {
                    max_mtime = max_mtime.max(meta_mtime_unix(&meta));
                }
            }
        }
        (total, max_mtime)
    }
}

#[cfg(unix)]
fn sum_tree_unix(
    root: &Path,
    mtime_max_depth: usize,
    exclude_top_child: Option<&[u8]>,
    seen_hardlinks: &mut HashSet<(u64, u64)>,
) -> (u64, u64) {
    use rustix::fs::{Mode, OFlags, fstat, open};

    let Ok(fd) = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return (0, 0);
    };

    let mut total: u64 = 0;
    let mut max_mtime: u64 = 0;
    if let Ok(st) = fstat(&fd) {
        total = total.saturating_add(stat_blocks_bytes(&st, true, seen_hardlinks));
        max_mtime = max_mtime.max(u64::try_from(st.st_mtime).unwrap_or(0));
    }
    sum_dir_fd_recursive(
        fd,
        1,
        mtime_max_depth,
        exclude_top_child,
        seen_hardlinks,
        &mut total,
        &mut max_mtime,
    );
    (total, max_mtime)
}

#[cfg(unix)]
fn sum_dir_fd_recursive(
    dir_fd: std::os::fd::OwnedFd,
    depth: usize,
    mtime_max_depth: usize,
    exclude_top_child: Option<&[u8]>,
    seen_hardlinks: &mut HashSet<(u64, u64)>,
    total: &mut u64,
    max_mtime: &mut u64,
) {
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, statat};

    const MAX_ACCOUNT_DEPTH: usize = 64;
    if depth > MAX_ACCOUNT_DEPTH {
        return;
    }

    let Ok(mut dir) = Dir::read_from(&dir_fd) else {
        return;
    };

    let mut child_dirs: Vec<std::ffi::CString> = Vec::new();
    for entry_res in dir.by_ref() {
        let Ok(entry) = entry_res else {
            continue;
        };
        let name = entry.file_name();
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if depth == 1 && exclude_top_child.is_some_and(|ex| ex == bytes) {
            continue;
        }

        let ft = entry.file_type();
        if ft == FileType::Symlink {
            continue;
        }

        let Ok(st) = statat(&dir_fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        let is_dir = (st.st_mode & rustix::fs::FileType::Directory.as_raw_mode())
            == rustix::fs::FileType::Directory.as_raw_mode()
            && ft != FileType::RegularFile;
        *total = total.saturating_add(stat_blocks_bytes(&st, is_dir, seen_hardlinks));
        if depth <= mtime_max_depth {
            *max_mtime = (*max_mtime).max(u64::try_from(st.st_mtime).unwrap_or(0));
        }

        if ft == FileType::Directory || (ft == FileType::Unknown && is_dir) {
            child_dirs.push(name.to_owned());
        }
    }

    drop(dir);

    for child_name in child_dirs {
        if let Ok(child_fd) = openat(
            &dir_fd,
            child_name.as_c_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            sum_dir_fd_recursive(
                child_fd,
                depth + 1,
                mtime_max_depth,
                None,
                seen_hardlinks,
                total,
                max_mtime,
            );
        }
    }
}

#[cfg(unix)]
fn stat_blocks_bytes(
    st: &rustix::fs::Stat,
    is_dir: bool,
    seen_hardlinks: &mut HashSet<(u64, u64)>,
) -> u64 {
    let blocks = u64::try_from(st.st_blocks).unwrap_or(0);
    let bytes = blocks.saturating_mul(512);
    let nlink = u64::from(st.st_nlink);
    if !is_dir && nlink > 1 {
        let dev = u64::try_from(st.st_dev).unwrap_or(0);
        #[allow(clippy::unnecessary_cast)]
        let ino = st.st_ino as u64;
        if !seen_hardlinks.insert((dev, ino)) {
            return 0;
        }
    }
    bytes
}

fn entry_allocated_bytes(meta: &fs::Metadata, seen_hardlinks: &mut HashSet<(u64, u64)>) -> u64 {
    let bytes = meta_blocks(meta).saturating_mul(512);
    if !meta.is_dir()
        && meta_nlink(meta) > 1
        && !seen_hardlinks.insert((meta_dev(meta), meta_ino(meta)))
    {
        return 0;
    }
    bytes
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use compact_str::CompactString;

    use super::{
        ScanDetail, ScanRequest, ScanRoot, crosses_mount_boundary, decode_le_u64_hex,
        extract_16hex_from_dep_name, extract_incremental_crate_name, parse_fingerprint_target_stem,
        scan,
    };
    use crate::config::Config;
    use crate::error::AppError;
    use crate::model::{
        DiskStats, GIB, GitDiscovery, MountEntry, ProcessSnapshot, TargetLayout, TargetOrigin,
        UnitMetadata, UnitTargetKind,
    };
    use crate::platform::{CommandOutput, LockProbe, Platform};

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
            Ok(ProcessSnapshot {
                captured_at_unix: self.now,
                self_pid: 1,
                processes: vec![],
            })
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
            t_v1.profiles[0].v1_units[0].v1_build_dir.as_deref(),
            Some("demo-0123456789abcdef")
        );
        assert_eq!(t_v1.profiles[0].v1_units[0].v1_dep_entries.len(), 2);

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
}
