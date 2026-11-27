//! Imperative Shell (Layer 5): budgeted root traversal (`max_depth`, `max_entries`,
//! non-Rust `.git` cutoff), `CACHEDIR.TAG` / `HeuristicNoTag` verification,
//! 4-layout detection, `fingerprint/*.json` reading, local Git checks, and `st_blocks` accounting.
//!
//! Allowed dependencies: `error`, `model`, `config`, `platform`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use compact_str::CompactString;
use serde::Deserialize;
use smallvec::SmallVec;
#[cfg(not(unix))]
use walkdir::WalkDir;

use crate::config::Config;
use crate::error::AppError;
use crate::model::{
    BuildUnit, BuildUnitId, CargoTarget, DocDirInfo, GitDiscovery, GitInspection, IncrementalDir,
    IncrementalSession, LeftoverStaging, MountEntry, ProfileDir, ScanSnapshot, SessionState,
    TargetLayout, TargetOrigin, UnitMetadata, UnitTargetAnchor, UnitTargetKind, WorktreeKind,
};
use crate::platform::{
    DEFAULT_VOLUME_MOUNT, LockProbe, Platform, crosses_mount_boundary, has_symlink_boundary,
};

const CACHEDIR_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";
const MAX_CACHEDIR_TAG_BYTES: u64 = 4 * 1024;
const MAX_RUSTC_INFO_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FINGERPRINT_JSON_BYTES: u64 = 2 * 1024 * 1024;
const MAX_COMPANION_HASH_BYTES: u64 = 64;
const STAGING_PREFIX: &str = ".targetwarden-reap.";
const SIBLING_STAGING_MARKER: &str = ".targetwarden-reap.";
const PIN_MARKER_FILE: &str = ".targetwarden-pin";
const MAX_SCAN_WORKERS: usize = 8;

fn bounded_worker_count() -> usize {
    std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .clamp(2, MAX_SCAN_WORKERS)
}

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
    "cmd",
    "internal",
    "pkg",
    "api",
    "env",
    "design",
    "research",
    "research_notes",
    "roadmap",
    "quality",
    "contracts",
    "compose",
    "observability",
    "envoy",
    "ansible",
    "postgres",
    "plugins",
    "patches",
    "licenses",
    "brands",
    "campaigns",
    "studio",
    "clients",
    "inbox",
    "archive",
    "_bmad",
    "_bmad-output",
    ".agents",
    ".github",
    ".vscode",
    ".claude",
    ".codex",
    ".cursor",
    ".cursor-plugin",
    ".idea",
    ".local",
    ".beads",
    ".qwen",
    ".grok",
    ".gemini",
    ".kilo",
    ".opencode",
    ".railway",
    ".githooks",
    ".mise",
    ".config",
    ".cargo",
    ".sqlx",
    ".ci",
    ".cloud",
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
    // parallel outer directory walk via synchronous scoped threads.
    let (disk_res, proc_res, mount_res, walk_result) = std::thread::scope(|scope| {
        let disk_handle = scope.spawn(|| platform.disk_stats(&request.volume_mount));
        let proc_handle = scope.spawn(|| platform.process_snapshot());
        let mount_handle = scope.spawn(|| platform.mount_table());
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
    let (processes, process_snapshot_error) = match proc_res {
        Ok(snapshot) => (Some(snapshot), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let (mounts, mount_table_error) = match mount_res {
        Ok(table) => (Some(table), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let mount_table_available = mounts.is_some();

    let mut batches = inspect_candidates_bounded(
        platform,
        mounts.as_deref(),
        request.detail,
        &walk_result.candidates,
    );
    let mut leftover_staging = walk_result.leftover_staging;
    let mut seen_staging: HashSet<(u64, u64)> = walk_result.seen_staging;

    // Merge staging dirs found inside targets, deduplicate targets by (dev, ino), and collect
    // any deferred Inventory accounting chunks for load-balanced parallel execution.
    let mut final_targets: Vec<CargoTarget> = Vec::new();
    let mut target_hardlinks: Vec<HashSet<(u64, u64)>> = Vec::new();
    let mut target_idx_by_id: HashMap<(u64, u64), usize> = HashMap::new();
    let mut deferred_chunks: Vec<AccountChunk> = Vec::new();

    for batch in batches.drain(..) {
        for (target, hardlinks) in batch.targets {
            let key = (target.dev_id, target.ino);
            if let std::collections::hash_map::Entry::Vacant(slot) = target_idx_by_id.entry(key) {
                slot.insert(final_targets.len());
                final_targets.push(target);
                target_hardlinks.push(hardlinks);
            }
        }
        for (staging, ino) in batch.leftover_staging {
            if seen_staging.insert((staging.expected_dev, ino)) {
                leftover_staging.push(staging);
            }
        }
        deferred_chunks.extend(batch.account_chunks);
    }

    if !deferred_chunks.is_empty() {
        apply_deferred_accounting(
            &deferred_chunks,
            &target_idx_by_id,
            &mut final_targets,
            &mut target_hardlinks,
        );
    }

    final_targets.sort_by(|a, b| a.root.cmp(&b.root));
    leftover_staging.sort_by(|a, b| a.staging_dir.cmp(&b.staging_dir));

    Ok(ScanSnapshot {
        captured_at_unix,
        disk,
        processes,
        process_snapshot_error,
        mount_table_available,
        mount_table_error,
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

#[derive(Clone, Debug)]
struct WalkTask {
    path: PathBuf,
    depth: usize,
    max_depth: usize,
    repo_cap: Option<usize>,
}

#[derive(Default)]
struct WalkBatch {
    candidates: Vec<(DiscoveredCandidate, u64, u64)>,
    leftover_staging: Vec<(LeftoverStaging, u64)>,
}

fn discover_candidates(config: &Config, request: &ScanRequest) -> WalkResult {
    let mut visited_roots: HashSet<(u64, u64)> = HashSet::new();
    let mut seen_candidates: HashSet<(u64, u64)> = HashSet::new();
    let mut candidates: Vec<DiscoveredCandidate> = Vec::new();
    let mut leftover_staging: Vec<LeftoverStaging> = Vec::new();
    let mut seen_staging: HashSet<(u64, u64)> = HashSet::new();
    let mut scanned_roots: Vec<PathBuf> = Vec::new();

    let deadline = Instant::now() + Duration::from_secs(config.discovery.walk_timeout_secs);
    let total_entries = AtomicUsize::new(0);
    let walk_partial = AtomicBool::new(false);

    if request.full_walk {
        let mut seed_tasks: Vec<WalkTask> = Vec::new();
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
            seed_tasks.push(WalkTask {
                path: canon_root,
                depth: 0,
                max_depth: root.max_depth,
                repo_cap: None,
            });
        }

        // Expand top 1-2 directory levels into independent subtrees so workers share I/O evenly
        // (e.g., ~/Projects/{org-a/*, org-b/*, oss/*}) while holding <= 1 FD per worker.
        let worker_count = bounded_worker_count();
        let mut seed_out = WalkBatch::default();
        let mut frontier = seed_tasks;
        for _ in 0..2 {
            if frontier.is_empty()
                || frontier.len() >= worker_count * 4
                || walk_partial.load(Ordering::Relaxed)
            {
                break;
            }
            let mut next_frontier = Vec::new();
            for task in frontier {
                visit_walk_dir(
                    &task,
                    config,
                    deadline,
                    &total_entries,
                    &walk_partial,
                    &mut seed_out,
                    |child| next_frontier.push(child),
                );
            }
            frontier = next_frontier;
        }
        merge_walk_batch(
            seed_out,
            &mut seen_candidates,
            &mut candidates,
            &mut seen_staging,
            &mut leftover_staging,
        );

        if !frontier.is_empty() && !walk_partial.load(Ordering::Relaxed) {
            let active_workers = frontier.len().min(worker_count);
            let next_idx = AtomicUsize::new(0);
            let worker_batches: Vec<WalkBatch> = std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(active_workers);
                for _ in 0..active_workers {
                    let next_ref = &next_idx;
                    let frontier_ref = &frontier;
                    let total_ref = &total_entries;
                    let partial_ref = &walk_partial;
                    handles.push(scope.spawn(move || {
                        let mut batch = WalkBatch::default();
                        let mut stack: Vec<WalkTask> = Vec::with_capacity(32);
                        loop {
                            if partial_ref.load(Ordering::Relaxed) {
                                break;
                            }
                            let idx = next_ref.fetch_add(1, Ordering::Relaxed);
                            let Some(seed) = frontier_ref.get(idx) else {
                                break;
                            };
                            stack.push(seed.clone());
                            while let Some(task) = stack.pop() {
                                if partial_ref.load(Ordering::Relaxed) {
                                    break;
                                }
                                visit_walk_dir(
                                    &task,
                                    config,
                                    deadline,
                                    total_ref,
                                    partial_ref,
                                    &mut batch,
                                    |child| stack.push(child),
                                );
                            }
                        }
                        batch
                    }));
                }
                handles
                    .into_iter()
                    .map(|h| h.join().expect("discovery walk worker panicked"))
                    .collect()
            });

            for batch in worker_batches {
                merge_walk_batch(
                    batch,
                    &mut seen_candidates,
                    &mut candidates,
                    &mut seen_staging,
                    &mut leftover_staging,
                );
            }
        }
    }

    let mut checked_known_parents: HashSet<PathBuf> = HashSet::new();
    for known in &request.known_targets {
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
                    let dev = meta_dev(&meta);
                    let ino = meta_ino(&meta);
                    if seen_staging.insert((dev, ino)) {
                        leftover_staging.push(LeftoverStaging {
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

    candidates.sort_by(|a, b| a.path.cmp(&b.path));

    WalkResult {
        candidates,
        leftover_staging,
        seen_staging,
        scanned_roots,
        walk_partial: walk_partial.load(Ordering::Relaxed),
    }
}

fn merge_walk_batch(
    batch: WalkBatch,
    seen_candidates: &mut HashSet<(u64, u64)>,
    candidates: &mut Vec<DiscoveredCandidate>,
    seen_staging: &mut HashSet<(u64, u64)>,
    leftover_staging: &mut Vec<LeftoverStaging>,
) {
    for (cand, dev, ino) in batch.candidates {
        if seen_candidates.insert((dev, ino)) {
            candidates.push(cand);
        }
    }
    for (staging, ino) in batch.leftover_staging {
        if seen_staging.insert((staging.expected_dev, ino)) {
            leftover_staging.push(staging);
        }
    }
}

fn consume_walk_budget(
    config: &Config,
    deadline: Instant,
    total_entries: &AtomicUsize,
    walk_partial: &AtomicBool,
) -> bool {
    let count = total_entries.fetch_add(1, Ordering::Relaxed) + 1;
    if count > config.discovery.max_entries || ((count & 0xFF) == 0 && Instant::now() >= deadline) {
        walk_partial.store(true, Ordering::Relaxed);
        return false;
    }
    true
}

fn record_walk_candidate(batch: &mut WalkBatch, path: PathBuf, origin: TargetOrigin) {
    if let Ok(meta) = fs::symlink_metadata(&path) {
        batch.candidates.push((
            DiscoveredCandidate {
                path,
                origin,
                forced_boundary_violation: false,
            },
            meta_dev(&meta),
            meta_ino(&meta),
        ));
    }
}

fn visit_walk_dir<F>(
    task: &WalkTask,
    config: &Config,
    deadline: Instant,
    total_entries: &AtomicUsize,
    walk_partial: &AtomicBool,
    batch: &mut WalkBatch,
    mut push_child: F,
) where
    F: FnMut(WalkTask),
{
    if !consume_walk_budget(config, deadline, total_entries, walk_partial) {
        return;
    }

    let Ok(rd) = fs::read_dir(&task.path) else {
        return;
    };

    let mut has_cachedir_tag = false;
    let mut has_rustc_info = false;
    let mut has_git = false;
    let mut has_cargo_toml = false;
    let mut child_dirs: Vec<(PathBuf, Option<String>)> = Vec::new();

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
                    batch.leftover_staging.push((
                        LeftoverStaging {
                            staging_dir: staging_path,
                            expected_dev: meta_dev(&meta),
                        },
                        meta_ino(&meta),
                    ));
                }
                continue;
            }
            if PRUNED_DIR_NAMES.contains(&name) {
                continue;
            }
            child_dirs.push((entry.path(), Some(name.to_owned())));
        } else {
            child_dirs.push((entry.path(), None));
        }
    }

    if has_cachedir_tag {
        let tag_path = task.path.join("CACHEDIR.TAG");
        if fs::symlink_metadata(&tag_path)
            .is_ok_and(|m| m.file_type().is_file() && m.len() <= MAX_CACHEDIR_TAG_BYTES)
            && is_verified_cargo_cachedir_tag(&tag_path)
        {
            record_walk_candidate(batch, task.path.clone(), TargetOrigin::VerifiedCargoTag);
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
            record_walk_candidate(batch, task.path.clone(), TargetOrigin::HeuristicNoTag);
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
                    .saturating_add(config.discovery.non_rust_git_extra_depth),
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

    for (child_path, child_name) in child_dirs {
        if next_cap.is_some()
            && child_name
                .as_deref()
                .is_some_and(|name| REPO_INNER_PRUNED_DIR_NAMES.contains(&name))
        {
            continue;
        }
        if is_leaf {
            if !consume_walk_budget(config, deadline, total_entries, walk_partial) {
                return;
            }
            if let Some(origin) = detect_target_origin(&child_path) {
                record_walk_candidate(batch, child_path, origin);
            }
        } else {
            push_child(WalkTask {
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
        && seen_candidates.insert((meta_dev(&meta), meta_ino(&meta)))
    {
        candidates.push(DiscoveredCandidate {
            path: path.to_path_buf(),
            origin,
            forced_boundary_violation,
        });
    }
}

#[derive(Clone, Copy, Debug)]
enum MtimePolicy {
    None,
    UpToDepth(usize),
    V2PkgDir,
    V2UnitFingerprint { unit_depth: usize },
}

#[derive(Clone, Debug)]
enum AccountDest {
    TargetOnly,
    DocDir,
    Profile(PathBuf),
}

#[derive(Clone, Debug)]
struct AccountChunk {
    target_key: (u64, u64),
    dest: AccountDest,
    path: PathBuf,
    mtime_policy: MtimePolicy,
}

#[derive(Default)]
struct TreeAccounting {
    nlink1_bytes: u64,
    multi_link: Vec<(u64, u64, u64)>,
    max_mtime: u64,
}

struct WorkerOutput {
    targets: Vec<(CargoTarget, HashSet<(u64, u64)>)>,
    leftover_staging: Vec<(LeftoverStaging, u64)>,
    account_chunks: Vec<AccountChunk>,
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
            account_chunks: ctx.account_chunks,
        }];
    }

    let worker_count = candidates.len().min(bounded_worker_count());
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
                    account_chunks: ctx.account_chunks,
                }
            }));
        }
        handles
            .into_iter()
            .map(|h| h.join().expect("target inspection worker panicked"))
            .collect()
    })
}

fn apply_deferred_accounting(
    chunks: &[AccountChunk],
    target_idx_by_id: &HashMap<(u64, u64), usize>,
    targets: &mut [CargoTarget],
    target_hardlinks: &mut [HashSet<(u64, u64)>],
) {
    let worker_count = chunks.len().min(bounded_worker_count());
    let next_idx = AtomicUsize::new(0);

    let results: Vec<Vec<(usize, TreeAccounting)>> = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let next_ref = &next_idx;
            handles.push(scope.spawn(move || {
                let mut local = Vec::new();
                loop {
                    let idx = next_ref.fetch_add(1, Ordering::Relaxed);
                    let Some(chunk) = chunks.get(idx) else {
                        break;
                    };
                    let acct = account_tree(&chunk.path, chunk.mtime_policy, None);
                    local.push((idx, acct));
                }
                local
            }));
        }
        handles
            .into_iter()
            .map(|h| h.join().expect("accounting worker panicked"))
            .collect()
    });

    for worker_res in results {
        for (chunk_idx, acct) in worker_res {
            let chunk = &chunks[chunk_idx];
            let Some(&tidx) = target_idx_by_id.get(&chunk.target_key) else {
                continue;
            };
            let seen_hardlinks = &mut target_hardlinks[tidx];
            let mut bytes = acct.nlink1_bytes;
            for (dev, ino, file_bytes) in acct.multi_link {
                if seen_hardlinks.insert((dev, ino)) {
                    bytes = bytes.saturating_add(file_bytes);
                }
            }

            let target = &mut targets[tidx];
            target.allocated_bytes = target.allocated_bytes.saturating_add(bytes);
            if acct.max_mtime > 0 {
                target.last_activity_unix = target.last_activity_unix.max(acct.max_mtime);
            }
            match &chunk.dest {
                AccountDest::TargetOnly => {}
                AccountDest::DocDir => {
                    if let Some(doc) = &mut target.doc_dir {
                        doc.allocated_bytes = doc.allocated_bytes.saturating_add(bytes);
                        if acct.max_mtime > 0 {
                            doc.last_activity_unix = doc.last_activity_unix.max(acct.max_mtime);
                        }
                    }
                }
                AccountDest::Profile(rel_path) => {
                    if let Some(profile) =
                        target.profiles.iter_mut().find(|p| p.rel_path == *rel_path)
                    {
                        profile.allocated_bytes = profile.allocated_bytes.saturating_add(bytes);
                        if acct.max_mtime > 0 {
                            profile.last_activity_unix =
                                profile.last_activity_unix.max(acct.max_mtime);
                        }
                    }
                }
            }
        }
    }
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
    targets: Vec<(CargoTarget, HashSet<(u64, u64)>)>,
    leftover_staging: Vec<(LeftoverStaging, u64)>,
    account_chunks: Vec<AccountChunk>,
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
            account_chunks: Vec::new(),
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
        let target_key = (dev_id, ino);
        if !self.visited_targets.insert(target_key) {
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
                    let info = inspect_doc_dir(
                        &entry_path,
                        self.platform,
                        self.detail,
                        target_key,
                        &mut seen_hardlinks,
                        &mut self.account_chunks,
                    );
                    last_activity_unix = last_activity_unix.max(info.last_activity_unix);
                    allocated_bytes = allocated_bytes.saturating_add(info.allocated_bytes);
                    doc_dir = Some(info);
                    continue;
                }
                if name == "tmp" || name == "package" {
                    if self.detail == ScanDetail::Inventory {
                        self.account_chunks.push(AccountChunk {
                            target_key,
                            dest: AccountDest::TargetOnly,
                            path: entry_path,
                            mtime_policy: MtimePolicy::None,
                        });
                    } else {
                        let bytes = sum_tree_bytes(&entry_path, &mut seen_hardlinks);
                        allocated_bytes = allocated_bytes.saturating_add(bytes);
                    }
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
                        target_key,
                        &mut seen_hardlinks,
                        &mut self.account_chunks,
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
                            target_key,
                            &mut seen_hardlinks,
                            &mut self.account_chunks,
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
                if self.detail == ScanDetail::Inventory {
                    self.account_chunks.push(AccountChunk {
                        target_key,
                        dest: AccountDest::TargetOnly,
                        path: entry_path,
                        mtime_policy: MtimePolicy::None,
                    });
                } else {
                    allocated_bytes = allocated_bytes
                        .saturating_add(sum_tree_bytes(&entry_path, &mut seen_hardlinks));
                }
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

        self.targets.push((
            CargoTarget {
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
                allocated_bytes,
                last_activity_unix,
            },
            seen_hardlinks,
        ));

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
    detail: ScanDetail,
    target_key: (u64, u64),
    seen_hardlinks: &mut HashSet<(u64, u64)>,
    account_chunks: &mut Vec<AccountChunk>,
) -> DocDirInfo {
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

    let (allocated_bytes, last_activity_unix) = if detail == ScanDetail::Inventory {
        account_chunks.push(AccountChunk {
            target_key,
            dest: AccountDest::DocDir,
            path: doc_path.to_path_buf(),
            mtime_policy: MtimePolicy::UpToDepth(2),
        });
        let mtime = fs::symlink_metadata(doc_path)
            .map(|m| meta_mtime_unix(&m))
            .unwrap_or(0);
        (0, mtime)
    } else {
        sum_tree_bytes_and_mtime(doc_path, 2, seen_hardlinks)
    };

    DocDirInfo {
        path: doc_path.to_path_buf(),
        lock_file,
        locked_now,
        last_activity_unix,
        allocated_bytes,
    }
}

#[allow(clippy::too_many_arguments)]
fn inspect_profile_dir(
    rel_path: &Path,
    profile_path: &Path,
    legacy_root_lock: Option<&Path>,
    platform: &impl Platform,
    detail: ScanDetail,
    target_key: (u64, u64),
    seen_hardlinks: &mut HashSet<(u64, u64)>,
    account_chunks: &mut Vec<AccountChunk>,
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
            target_key,
            seen_hardlinks,
            account_chunks,
        );
    }

    let mut fingerprint_corrupt = false;
    let mut v1_units: Vec<BuildUnit> = Vec::new();
    let mut v2_units: Vec<BuildUnit> = Vec::new();
    let mut incremental_dirs: Vec<IncrementalDir> = Vec::new();
    let mut allocated_bytes: u64 = 0;
    let mut last_activity_unix: u64 = fs::symlink_metadata(profile_path)
        .map(|m| meta_mtime_unix(&m))
        .unwrap_or(0);

    let mut v1_fp_index_by_name: HashMap<CompactString, usize> = HashMap::new();
    let mut v1_hash_to_indices: HashMap<CompactString, SmallVec<[usize; 2]>> = HashMap::new();

    // 1. V1 `.fingerprint/<pkg>-<16hex>/`
    if has_v1_fp_dir {
        match fs::read_dir(&fp_root) {
            Ok(entries) => {
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
                        allocated_bytes = allocated_bytes
                            .saturating_add(sum_tree_bytes(&entry_path, seen_hardlinks));
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
            Err(_) => {
                fingerprint_corrupt = true;
            }
        }
    }

    // 2. V1 `deps/` (match files and `.dSYM` directories to unique V1 unit_hash)
    if has_v1_deps_dir {
        match fs::read_dir(&deps_root) {
            Ok(entries) => {
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
            Err(_) => {
                fingerprint_corrupt = true;
            }
        }
    }

    // 3. `build/` (handles V1 `build/<pkg>-<16hex>/`, V2 `build/<pkg>/<16hex>/`, and MixedV1V2)
    if has_build_dir {
        match fs::read_dir(&build_root) {
            Ok(entries) => {
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
                            let parsed = if fs::symlink_metadata(&fp_sub)
                                .is_ok_and(|m| m.file_type().is_dir())
                            {
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

                            let other_bytes = sum_tree_bytes_excluding_child(
                                &child_path,
                                "fingerprint",
                                seen_hardlinks,
                            );
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
                        allocated_bytes = allocated_bytes
                            .saturating_add(sum_tree_bytes(&entry_path, seen_hardlinks));
                    }
                }
            }
            Err(_) => {
                fingerprint_corrupt = true;
            }
        }
    }

    // 4. `incremental/`
    if has_inc_dir {
        if let Ok(inc_meta) = fs::symlink_metadata(&inc_root) {
            last_activity_unix = last_activity_unix.max(meta_mtime_unix(&inc_meta));
        }
        if let Ok(entries) = fs::read_dir(&inc_root) {
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
                let inc_dir =
                    inspect_incremental_dir(&entry_path, dir_name, platform, seen_hardlinks);
                last_activity_unix = last_activity_unix.max(inc_dir.latest_mtime_unix);
                allocated_bytes = allocated_bytes.saturating_add(inc_dir.allocated_bytes);
                incremental_dirs.push(inc_dir);
            }
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
    target_key: (u64, u64),
    seen_hardlinks: &mut HashSet<(u64, u64)>,
    account_chunks: &mut Vec<AccountChunk>,
) -> ProfileDir {
    let dest = AccountDest::Profile(rel_path.to_path_buf());
    let mut v1_fp_names: HashSet<CompactString> = HashSet::new();
    let mut v1_unit_count = 0usize;
    let mut v2_unit_count = 0usize;
    let mut incremental_dir_count = 0usize;
    let mut allocated_bytes: u64 = 0;
    let mut last_activity_unix: u64 = fs::symlink_metadata(profile_path)
        .map(|m| meta_mtime_unix(&m))
        .unwrap_or(0);

    // 1. `.fingerprint/` (V1): single pass for counting + deferred byte/mtime accounting.
    if has_v1_fp_dir && let Ok(entries) = fs::read_dir(profile_path.join(".fingerprint")) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
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
                    v1_unit_count += 1;
                    v1_fp_names.insert(CompactString::from(name));
                }
                account_chunks.push(AccountChunk {
                    target_key,
                    dest: dest.clone(),
                    path: entry_path,
                    mtime_policy: MtimePolicy::UpToDepth(1),
                });
            } else if let Ok(meta) = fs::symlink_metadata(&entry_path) {
                allocated_bytes =
                    allocated_bytes.saturating_add(entry_allocated_bytes(&meta, seen_hardlinks));
            }
        }
    }

    // 2. `deps/` (V1)
    if has_v1_deps_dir {
        account_chunks.push(AccountChunk {
            target_key,
            dest: dest.clone(),
            path: profile_path.join("deps"),
            mtime_policy: MtimePolicy::None,
        });
    }

    // 3. `build/`: single pass for counting V2 units + fine-grained parallel byte/mtime chunks.
    if has_build_dir && let Ok(entries) = fs::read_dir(profile_path.join("build")) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            if !ft.is_dir() {
                if let Ok(meta) = fs::symlink_metadata(&entry_path) {
                    allocated_bytes = allocated_bytes
                        .saturating_add(entry_allocated_bytes(&meta, seen_hardlinks));
                }
                continue;
            }
            let os_name = entry.file_name();
            if let Some(name) = os_name.to_str()
                && v1_fp_names.contains(name)
            {
                account_chunks.push(AccountChunk {
                    target_key,
                    dest: dest.clone(),
                    path: entry_path,
                    mtime_policy: MtimePolicy::None,
                });
                continue;
            }
            let mut found_v2_child = false;
            if let Ok(children) = fs::read_dir(&entry_path) {
                for child in children.flatten() {
                    if child
                        .file_type()
                        .is_ok_and(|cft| cft.is_dir() && !cft.is_symlink())
                        && child.file_name().to_str().is_some_and(is_16_lower_hex)
                    {
                        found_v2_child = true;
                        v2_unit_count += 1;
                    }
                }
            }
            account_chunks.push(AccountChunk {
                target_key,
                dest: dest.clone(),
                path: entry_path,
                mtime_policy: if found_v2_child {
                    MtimePolicy::V2PkgDir
                } else {
                    MtimePolicy::None
                },
            });
        }
    }

    // 4. `incremental/`: single pass for counting + parallel chunks with `s-*.lock`/`s-*` mtime.
    if has_inc_dir {
        let inc_root = profile_path.join("incremental");
        if let Ok(inc_meta) = fs::symlink_metadata(&inc_root) {
            last_activity_unix = last_activity_unix.max(meta_mtime_unix(&inc_meta));
        }
        if let Ok(entries) = fs::read_dir(&inc_root) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                let Ok(ft) = entry.file_type() else {
                    continue;
                };
                if ft.is_symlink() {
                    continue;
                }
                if ft.is_dir() {
                    incremental_dir_count += 1;
                    account_chunks.push(AccountChunk {
                        target_key,
                        dest: dest.clone(),
                        path: entry_path,
                        mtime_policy: MtimePolicy::UpToDepth(2),
                    });
                } else if let Ok(meta) = fs::symlink_metadata(&entry_path) {
                    allocated_bytes = allocated_bytes
                        .saturating_add(entry_allocated_bytes(&meta, seen_hardlinks));
                }
            }
        }
    }

    // 5. Top-level profile files and auxiliary dirs (e.g. binaries, examples/).
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
                account_chunks.push(AccountChunk {
                    target_key,
                    dest: dest.clone(),
                    path: entry_path,
                    mtime_policy: MtimePolicy::None,
                });
            } else {
                allocated_bytes =
                    allocated_bytes.saturating_add(entry_allocated_bytes(&emeta, seen_hardlinks));
            }
        }
    }

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

    let has_tracked_files_in_target = if !info.worktree_dir_missing
        && let Ok(rel_target) = target_root.strip_prefix(&info.worktree_root)
    {
        let Some(rel_str) = rel_target.to_str() else {
            return GitDiscovery::Failed(CompactString::new(
                "non-utf8 target path inside git worktree",
            ));
        };
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

/// Fast fd-anchored `st_blocks * 512` tree sum with hardlink deduplication.
fn sum_tree_bytes(root: &Path, seen_hardlinks: &mut HashSet<(u64, u64)>) -> u64 {
    merge_accounting(account_tree(root, MtimePolicy::None, None), seen_hardlinks).0
}

fn sum_tree_bytes_excluding_child(
    root: &Path,
    exclude_child: &str,
    seen_hardlinks: &mut HashSet<(u64, u64)>,
) -> u64 {
    merge_accounting(
        account_tree(root, MtimePolicy::None, Some(exclude_child.as_bytes())),
        seen_hardlinks,
    )
    .0
}

fn sum_tree_bytes_and_mtime(
    root: &Path,
    mtime_max_depth: usize,
    seen_hardlinks: &mut HashSet<(u64, u64)>,
) -> (u64, u64) {
    merge_accounting(
        account_tree(root, MtimePolicy::UpToDepth(mtime_max_depth), None),
        seen_hardlinks,
    )
}

fn merge_accounting(acct: TreeAccounting, seen_hardlinks: &mut HashSet<(u64, u64)>) -> (u64, u64) {
    let mut total = acct.nlink1_bytes;
    for (dev, ino, bytes) in acct.multi_link {
        if seen_hardlinks.insert((dev, ino)) {
            total = total.saturating_add(bytes);
        }
    }
    (total, acct.max_mtime)
}

fn account_tree(
    root: &Path,
    mtime_policy: MtimePolicy,
    exclude_top_child: Option<&[u8]>,
) -> TreeAccounting {
    #[cfg(unix)]
    {
        account_tree_unix(root, mtime_policy, exclude_top_child)
    }
    #[cfg(not(unix))]
    {
        let mut out = TreeAccounting::default();
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
            if let Ok(meta) = entry.metadata() {
                let bytes = meta_blocks(&meta).saturating_mul(512);
                if !meta.is_dir() && meta_nlink(&meta) > 1 {
                    out.multi_link
                        .push((meta_dev(&meta), meta_ino(&meta), bytes));
                } else {
                    out.nlink1_bytes = out.nlink1_bytes.saturating_add(bytes);
                }
                let track_mtime = match mtime_policy {
                    MtimePolicy::None => false,
                    MtimePolicy::UpToDepth(max_d) => entry.depth() <= max_d,
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
fn account_tree_unix(
    root: &Path,
    mtime_policy: MtimePolicy,
    exclude_top_child: Option<&[u8]>,
) -> TreeAccounting {
    use rustix::fs::{Mode, OFlags, open};

    let mut out = TreeAccounting::default();
    let Ok(fd) = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return out;
    };

    sum_dir_fd_recursive(fd, 0, mtime_policy, exclude_top_child, &mut out);
    out
}

#[cfg(unix)]
fn sum_dir_fd_recursive(
    dir_fd: std::os::fd::OwnedFd,
    depth: usize,
    mtime_policy: MtimePolicy,
    exclude_top_child: Option<&[u8]>,
    out: &mut TreeAccounting,
) {
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, statat};

    const MAX_ACCOUNT_DEPTH: usize = 64;
    if depth > MAX_ACCOUNT_DEPTH {
        return;
    }

    let Ok(mut dir) = Dir::new(dir_fd) else {
        return;
    };

    let stat_self_dir = match mtime_policy {
        MtimePolicy::None | MtimePolicy::V2PkgDir => false,
        MtimePolicy::UpToDepth(max_d) => depth <= max_d,
        MtimePolicy::V2UnitFingerprint { unit_depth } => depth == unit_depth,
    };
    if stat_self_dir && let Ok(st) = dir.stat() {
        record_stat_blocks(&st, true, out);
        out.max_mtime = out.max_mtime.max(u64::try_from(st.st_mtime).unwrap_or(0));
    }

    let track_child_file_mtime = match mtime_policy {
        MtimePolicy::None | MtimePolicy::V2PkgDir | MtimePolicy::V2UnitFingerprint { .. } => false,
        MtimePolicy::UpToDepth(max_d) => depth < max_d,
    };

    let mut child_dirs: Vec<std::ffi::CString> = Vec::new();
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
            child_dirs.push(name.to_owned());
            continue;
        }

        let Ok(fd) = dir.fd() else {
            break;
        };
        let Ok(st) = statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
            child_dirs.push(name.to_owned());
            continue;
        }
        record_stat_blocks(&st, false, out);
        if track_child_file_mtime {
            out.max_mtime = out.max_mtime.max(u64::try_from(st.st_mtime).unwrap_or(0));
        }
    }

    for child_name in child_dirs {
        let Ok(fd) = dir.fd() else {
            break;
        };
        let child_policy = match mtime_policy {
            MtimePolicy::None => MtimePolicy::None,
            MtimePolicy::UpToDepth(max_d) => {
                if depth < max_d {
                    MtimePolicy::UpToDepth(max_d)
                } else {
                    MtimePolicy::None
                }
            }
            MtimePolicy::V2PkgDir => {
                if depth == 0
                    && std::str::from_utf8(child_name.to_bytes()).is_ok_and(is_16_lower_hex)
                {
                    MtimePolicy::V2UnitFingerprint { unit_depth: 1 }
                } else {
                    MtimePolicy::None
                }
            }
            MtimePolicy::V2UnitFingerprint { unit_depth } => {
                if depth == unit_depth && child_name.to_bytes() == b"fingerprint" {
                    MtimePolicy::UpToDepth(depth + 2)
                } else {
                    MtimePolicy::None
                }
            }
        };
        if let Ok(child_fd) = openat(
            fd,
            child_name.as_c_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            sum_dir_fd_recursive(child_fd, depth + 1, child_policy, None, out);
        }
    }
}

#[cfg(unix)]
fn record_stat_blocks(st: &rustix::fs::Stat, is_dir: bool, out: &mut TreeAccounting) {
    let blocks = u64::try_from(st.st_blocks).unwrap_or(0);
    let bytes = blocks.saturating_mul(512);
    let nlink = u64::from(st.st_nlink);
    if !is_dir && nlink > 1 {
        let dev = u64::try_from(st.st_dev).unwrap_or(0);
        #[allow(clippy::unnecessary_cast)]
        let ino = st.st_ino as u64;
        out.multi_link.push((dev, ino, bytes));
    } else {
        out.nlink1_bytes = out.nlink1_bytes.saturating_add(bytes);
    }
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
        ScanDetail, ScanRequest, ScanRoot, decode_le_u64_hex, extract_16hex_from_dep_name,
        extract_incremental_crate_name, parse_fingerprint_target_stem, scan,
    };
    use crate::config::Config;
    use crate::error::AppError;
    use crate::model::{
        DiskStats, GIB, GitDiscovery, MountEntry, ProcessSnapshot, TargetLayout, TargetOrigin,
        UnitMetadata, UnitTargetKind,
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
                Ok(ProcessSnapshot {
                    captured_at_unix: self.now,
                    self_pid: 1,
                    processes: vec![],
                })
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
}
