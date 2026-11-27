//! Imperative Shell (Layer 5): TOCTOU-safe executor (sorted `try_lock_readonly`,
//! post-lock revalidation, V1 `.fingerprint/`-first staging rename, immediate unlock,
//! `rustix` fd-anchored `remove_tree_safe`, and dual staging crash recovery).
//!
//! Allowed dependencies: `error`, `model`, `platform`.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use compact_str::CompactString;

use crate::error::AppError;
use crate::model::{
    ActionOutcome, ActionReceipt, DiskPressure, EvictRule, IncrementalRemoval, ProcessSnapshot,
    ReclaimAction, ReclaimHoldState, ReclaimPlan, SweepOps, V1UnitRemoval, V2UnitRemoval,
};
use crate::platform::{
    DEFAULT_VOLUME_MOUNT, LockProbe, Platform, crosses_mount_boundary, has_symlink_boundary,
};

static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);
const STAGING_MARKER: &str = ".targetwarden-reap.";
const PIN_MARKER_FILE: &str = ".targetwarden-pin";

#[derive(Clone, Debug)]
pub(crate) struct ExecutionOutcome {
    pub receipts: Vec<ActionReceipt>,
    pub triggered_hold: Option<ReclaimHoldState>,
}

/// Execute all actions in a `ReclaimPlan`, honoring `dry_run`, optional cooperative stop flag,
/// live `statvfs` headroom stop for `R5`, and APFS `ReclaimHoldState` circuit breaker.
pub(crate) fn execute_plan<F>(
    plan: &ReclaimPlan,
    platform: &impl Platform,
    dry_run: bool,
    r5_target_free_bytes: Option<u64>,
    should_trip_hold: F,
    stop_flag: Option<&AtomicBool>,
) -> ExecutionOutcome
where
    F: Fn(u64, u64) -> bool,
{
    let mut receipts = Vec::with_capacity(plan.actions.len());
    let mut r5_reclaimed_allocated: u64 = 0;
    let mut r5_free_before_first: Option<u64> = None;
    let mut r5_halted = false;
    let mut triggered_hold: Option<ReclaimHoldState> = None;

    for action in &plan.actions {
        if stop_flag.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            break;
        }
        let is_r5 = matches!(
            action,
            ReclaimAction::EvictTarget {
                rule: EvictRule::R5PressureLru,
                ..
            }
        );
        if is_r5 && !dry_run {
            if r5_halted || triggered_hold.is_some() {
                continue;
            }
            if let Some(target_free) = r5_target_free_bytes
                && let Some(free_now) = current_free_bytes_opt(platform)
            {
                if free_now >= target_free {
                    r5_halted = true;
                    continue;
                }
                r5_free_before_first.get_or_insert(free_now);
            }
        }

        let receipt = execute_action_with_disk_free(
            action,
            platform,
            plan.pressure,
            dry_run,
            Some(plan.disk.free_bytes),
        );

        if is_r5 && !dry_run && matches!(receipt.outcome, ActionOutcome::Applied) {
            r5_reclaimed_allocated = r5_reclaimed_allocated.saturating_add(receipt.allocated_bytes);
            let baseline = *r5_free_before_first.get_or_insert(receipt.free_before_bytes);
            if let Some(free_now) = current_free_bytes_opt(platform) {
                let observed_gain = free_now.saturating_sub(baseline);
                if should_trip_hold(r5_reclaimed_allocated, observed_gain) {
                    let snapshots_at_detection = current_disk_stats(platform)
                        .and_then(|d| d.local_snapshots)
                        .unwrap_or_default();
                    triggered_hold = Some(ReclaimHoldState {
                        detected_at_unix: platform.now_unix(),
                        reclaimed_allocated_bytes: r5_reclaimed_allocated,
                        observed_free_gain_bytes: observed_gain,
                        free_bytes_at_detection: free_now,
                        pressure_at_detection: plan.pressure,
                        snapshots_at_detection,
                    });
                    r5_halted = true;
                } else if r5_target_free_bytes.is_some_and(|target_free| free_now >= target_free) {
                    r5_halted = true;
                }
            }
        }

        receipts.push(receipt);
    }

    ExecutionOutcome {
        receipts,
        triggered_hold,
    }
}

/// Execute one `ReclaimAction` under the full TOCTOU-safe protocol.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn execute_action(
    action: &ReclaimAction,
    platform: &impl Platform,
    pressure: DiskPressure,
    dry_run: bool,
) -> ActionReceipt {
    execute_action_with_disk_free(action, platform, pressure, dry_run, None)
}

fn execute_action_with_disk_free(
    action: &ReclaimAction,
    platform: &impl Platform,
    pressure: DiskPressure,
    dry_run: bool,
    known_free_bytes: Option<u64>,
) -> ActionReceipt {
    let started = Instant::now();
    let ts_unix = platform.now_unix();
    let rule = action.rule_id();
    let target_root = action.target_root().to_path_buf();
    let profile_rel = action.profile_rel().map(Path::to_path_buf);
    let reason = action.reason();
    let planned_bytes = action.estimated_allocated_bytes();
    let planned_units = action.unit_count();

    if dry_run {
        let free_now = known_free_bytes.unwrap_or_else(|| current_free_bytes(platform));
        return ActionReceipt {
            ts_unix,
            rule,
            target_root,
            profile_rel,
            outcome: ActionOutcome::DryRun,
            units_removed: planned_units,
            allocated_bytes: planned_bytes,
            free_before_bytes: free_now,
            free_after_bytes: free_now,
            duration_ms: 0,
            pressure,
            reason,
        };
    }

    let free_before_bytes = current_free_bytes(platform);
    let (outcome, units_removed, allocated_bytes) = match action {
        ReclaimAction::ReapLeftoverStaging {
            staging_dir,
            expected_dev,
        } => execute_reap_staging(staging_dir, *expected_dev, platform),
        ReclaimAction::SweepBuildUnits {
            target_root,
            target_dev,
            target_ino,
            expected_activity_unix,
            expected_target_activity_unix,
            worktree_root,
            profile_rel,
            profile_locks,
            ops,
            estimated_allocated_bytes,
        } => execute_sweep_build_units(
            target_root,
            *target_dev,
            *target_ino,
            *expected_activity_unix,
            *expected_target_activity_unix,
            worktree_root.as_deref(),
            profile_rel,
            profile_locks,
            ops,
            *estimated_allocated_bytes,
            platform,
        ),
        ReclaimAction::RemoveDoc {
            target_root,
            target_dev,
            target_ino,
            expected_doc_mtime_unix,
            worktree_root,
            locks,
            estimated_allocated_bytes,
        } => execute_remove_doc(
            target_root,
            *target_dev,
            *target_ino,
            *expected_doc_mtime_unix,
            worktree_root.as_deref(),
            locks,
            *estimated_allocated_bytes,
            platform,
        ),
        ReclaimAction::PruneIncremental {
            target_root,
            target_dev,
            target_ino,
            expected_activity_unix,
            expected_target_activity_unix,
            worktree_root,
            profile_rel,
            profile_locks,
            removals,
            estimated_allocated_bytes,
        } => execute_prune_incremental(
            target_root,
            *target_dev,
            *target_ino,
            *expected_activity_unix,
            *expected_target_activity_unix,
            worktree_root.as_deref(),
            profile_rel,
            profile_locks,
            removals,
            *estimated_allocated_bytes,
            platform,
        ),
        ReclaimAction::EvictTarget {
            target_root,
            target_dev,
            target_ino,
            expected_activity_unix,
            worktree_root,
            all_locks,
            estimated_allocated_bytes,
            ..
        } => execute_evict_target(
            target_root,
            *target_dev,
            *target_ino,
            *expected_activity_unix,
            worktree_root.as_deref(),
            all_locks,
            *estimated_allocated_bytes,
            platform,
        ),
    };

    let free_after_bytes = current_free_bytes(platform);
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    ActionReceipt {
        ts_unix,
        rule,
        target_root,
        profile_rel,
        outcome,
        units_removed,
        allocated_bytes,
        free_before_bytes,
        free_after_bytes,
        duration_ms,
        pressure,
        reason,
    }
}

fn default_volume_path() -> &'static Path {
    if Path::new(DEFAULT_VOLUME_MOUNT).exists() {
        Path::new(DEFAULT_VOLUME_MOUNT)
    } else {
        Path::new("/")
    }
}

fn current_disk_stats(platform: &impl Platform) -> Option<crate::model::DiskStats> {
    platform.disk_stats(default_volume_path()).ok()
}

fn current_free_bytes_opt(platform: &impl Platform) -> Option<u64> {
    platform.free_bytes(default_volume_path()).ok()
}

fn current_free_bytes(platform: &impl Platform) -> u64 {
    current_free_bytes_opt(platform).unwrap_or(0)
}

fn execute_reap_staging(
    staging_dir: &Path,
    expected_dev: u64,
    platform: &impl Platform,
) -> (ActionOutcome, u32, u64) {
    let Some(name) = staging_dir.file_name().and_then(|n| n.to_str()) else {
        return (
            ActionOutcome::Failed {
                error: CompactString::new("invalid staging directory path"),
            },
            0,
            0,
        );
    };
    if !is_staging_dir_name(name) {
        return (
            ActionOutcome::Failed {
                error: CompactString::new("refusing to reap non-staging directory name"),
            },
            0,
            0,
        );
    }

    let meta = match fs::symlink_metadata(staging_dir) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (
                ActionOutcome::SkippedRevalidateChanged {
                    reason: CompactString::new("staging_already_removed"),
                },
                0,
                0,
            );
        }
        Err(error) => {
            return (
                ActionOutcome::Failed {
                    error: CompactString::from(format!("lstat staging failed: {error}")),
                },
                0,
                0,
            );
        }
    };
    if meta.file_type().is_symlink()
        || !meta.file_type().is_dir()
        || meta_dev(&meta) != expected_dev
    {
        return (
            ActionOutcome::SkippedRevalidateChanged {
                reason: CompactString::new("staging_identity_changed"),
            },
            0,
            0,
        );
    }

    let Ok(proc_snap) = platform.process_snapshot() else {
        return (
            ActionOutcome::SkippedRevalidateChanged {
                reason: CompactString::new("lsof_unavailable"),
            },
            0,
            0,
        );
    };
    if any_process_in_dir(&proc_snap, staging_dir) {
        return (
            ActionOutcome::SkippedContested {
                reason: CompactString::new("staging_in_use"),
            },
            0,
            0,
        );
    }

    match remove_tree_safe(staging_dir, expected_dev) {
        Ok(()) => (ActionOutcome::Applied, 1, 0),
        Err(error) => (
            ActionOutcome::Failed {
                error: CompactString::from(error.to_string()),
            },
            0,
            0,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_sweep_build_units(
    target_root: &Path,
    target_dev: u64,
    target_ino: u64,
    expected_activity_unix: u64,
    expected_target_activity_unix: u64,
    worktree_root: Option<&Path>,
    profile_rel: &Path,
    profile_locks: &[PathBuf],
    ops: &SweepOps,
    estimated_allocated_bytes: u64,
    platform: &impl Platform,
) -> (ActionOutcome, u32, u64) {
    let held_locks = match acquire_sorted_locks(profile_locks, platform) {
        Ok(locks) => locks,
        Err(outcome) => return (outcome, 0, 0),
    };

    let profile_dir = target_root.join(profile_rel);
    if let Err(outcome) = revalidate_target_under_lock(
        target_root,
        target_dev,
        target_ino,
        &profile_dir,
        expected_activity_unix,
        Some(expected_target_activity_unix),
        worktree_root,
        platform,
        |proc_snap| {
            has_blocking_process_for_sweep(proc_snap, target_root, worktree_root, &profile_dir, ops)
        },
    ) {
        release_locks(held_locks);
        return (outcome, 0, 0);
    }

    let staging_dir = match create_internal_staging_dir(target_root, target_dev) {
        Ok(dir) => dir,
        Err(error) => {
            release_locks(held_locks);
            return (
                ActionOutcome::Failed {
                    error: CompactString::from(error.to_string()),
                },
                0,
                0,
            );
        }
    };

    let (moved_units, move_error) = stage_sweep_ops(&profile_dir, &staging_dir, ops);

    // Explicitly unlock and drop Cargo locks immediately after staging renames (< 15 ms).
    release_locks(held_locks);

    if let Err(rm_err) = remove_tree_safe(&staging_dir, target_dev) {
        return (
            ActionOutcome::Failed {
                error: CompactString::from(format!("safe remove of staging failed: {rm_err}")),
            },
            moved_units,
            0,
        );
    }

    if let Some(err) = move_error {
        return (
            ActionOutcome::Failed {
                error: CompactString::from(err),
            },
            moved_units,
            0,
        );
    }
    if moved_units == 0 {
        return (
            ActionOutcome::SkippedRevalidateChanged {
                reason: CompactString::new("units_already_absent"),
            },
            0,
            0,
        );
    }
    (
        ActionOutcome::Applied,
        moved_units,
        estimated_allocated_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_remove_doc(
    target_root: &Path,
    target_dev: u64,
    target_ino: u64,
    expected_doc_mtime_unix: u64,
    worktree_root: Option<&Path>,
    locks: &[PathBuf],
    estimated_allocated_bytes: u64,
    platform: &impl Platform,
) -> (ActionOutcome, u32, u64) {
    let held_locks = match acquire_sorted_locks(locks, platform) {
        Ok(locks) => locks,
        Err(outcome) => return (outcome, 0, 0),
    };

    let doc_dir = target_root.join("doc");
    if let Err(outcome) = revalidate_target_under_lock(
        target_root,
        target_dev,
        target_ino,
        &doc_dir,
        expected_doc_mtime_unix,
        None,
        worktree_root,
        platform,
        |proc_snap| {
            has_hard_blocked_process_for_target(proc_snap, target_root, worktree_root, &doc_dir)
        },
    ) {
        release_locks(held_locks);
        return (outcome, 0, 0);
    }
    if let Ok(lock_meta) = fs::symlink_metadata(doc_dir.join(".lock"))
        && meta_mtime_unix(&lock_meta) > expected_doc_mtime_unix
    {
        release_locks(held_locks);
        return (
            ActionOutcome::SkippedRevalidateChanged {
                reason: CompactString::new("doc_lock_mtime_advanced"),
            },
            0,
            0,
        );
    }

    let staging_dir = match create_internal_staging_dir(target_root, target_dev) {
        Ok(dir) => dir,
        Err(error) => {
            release_locks(held_locks);
            return (
                ActionOutcome::Failed {
                    error: CompactString::from(error.to_string()),
                },
                0,
                0,
            );
        }
    };

    let moved = rename_entry_atomic(target_root, "doc", &staging_dir, "doc");

    release_locks(held_locks);

    let rm_res = remove_tree_safe(&staging_dir, target_dev);
    if let Err(error) = moved {
        return (
            ActionOutcome::Failed {
                error: CompactString::from(format!("rename target/doc failed: {error}")),
            },
            0,
            0,
        );
    }
    if let Err(rm_err) = rm_res {
        return (
            ActionOutcome::Failed {
                error: CompactString::from(format!("safe remove of doc staging failed: {rm_err}")),
            },
            0,
            0,
        );
    }
    if moved.unwrap_or(false) {
        (ActionOutcome::Applied, 1, estimated_allocated_bytes)
    } else {
        (
            ActionOutcome::SkippedRevalidateChanged {
                reason: CompactString::new("doc_dir_already_absent"),
            },
            0,
            0,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_prune_incremental(
    target_root: &Path,
    target_dev: u64,
    target_ino: u64,
    expected_activity_unix: u64,
    expected_target_activity_unix: u64,
    worktree_root: Option<&Path>,
    profile_rel: &Path,
    profile_locks: &[PathBuf],
    removals: &[IncrementalRemoval],
    estimated_allocated_bytes: u64,
    platform: &impl Platform,
) -> (ActionOutcome, u32, u64) {
    let profile_dir = target_root.join(profile_rel);
    let inc_root = profile_dir.join("incremental");

    // Collect both profile locks AND all relevant `s-*.lock` files for sorted non-blocking acquisition.
    let mut all_locks: Vec<PathBuf> = profile_locks.to_vec();
    for removal in removals {
        match removal {
            IncrementalRemoval::WholeCrateDir { dir_name, .. } => {
                let crate_path = inc_root.join(dir_name.as_str());
                if let Ok(entries) = fs::read_dir(&crate_path) {
                    for entry in entries.flatten() {
                        if let Some(name) = entry.file_name().to_str()
                            && name.starts_with("s-")
                            && name.ends_with(".lock")
                        {
                            all_locks.push(entry.path());
                        }
                    }
                }
            }
            IncrementalRemoval::SingleSession {
                crate_dir,
                lock_file: Some(lf),
                ..
            } => {
                all_locks.push(inc_root.join(crate_dir.as_str()).join(lf.as_str()));
            }
            IncrementalRemoval::SingleSession {
                lock_file: None, ..
            } => {}
        }
    }

    let held_locks = match acquire_sorted_locks(&all_locks, platform) {
        Ok(locks) => locks,
        Err(outcome) => return (outcome, 0, 0),
    };

    if let Err(outcome) = revalidate_target_under_lock(
        target_root,
        target_dev,
        target_ino,
        &inc_root,
        expected_activity_unix,
        Some(expected_target_activity_unix),
        worktree_root,
        platform,
        |proc_snap| {
            has_hard_blocked_process_for_target(proc_snap, target_root, worktree_root, &inc_root)
        },
    ) {
        release_locks(held_locks);
        return (outcome, 0, 0);
    }

    let staging_dir = match create_internal_staging_dir(target_root, target_dev) {
        Ok(dir) => dir,
        Err(error) => {
            release_locks(held_locks);
            return (
                ActionOutcome::Failed {
                    error: CompactString::from(error.to_string()),
                },
                0,
                0,
            );
        }
    };

    let mut moved_count: u32 = 0;
    let mut move_error: Option<String> = None;

    for (idx, removal) in removals.iter().enumerate() {
        match removal {
            IncrementalRemoval::WholeCrateDir { dir_name, .. } => {
                let dst = format!("inc_crate_{idx}");
                match rename_entry_atomic(&inc_root, dir_name.as_str(), &staging_dir, &dst) {
                    Ok(true) => moved_count = moved_count.saturating_add(1),
                    Ok(false) => {}
                    Err(error) => {
                        move_error = Some(format!("rename incremental/{dir_name}: {error}"));
                        break;
                    }
                }
            }
            IncrementalRemoval::SingleSession {
                crate_dir,
                session_dir,
                lock_file,
                ..
            } => {
                let crate_path = inc_root.join(crate_dir.as_str());
                let dst = format!("inc_sess_{idx}");
                match rename_entry_atomic(&crate_path, session_dir.as_str(), &staging_dir, &dst) {
                    Ok(true) => {
                        moved_count = moved_count.saturating_add(1);
                        if let Some(lf) = lock_file {
                            let lock_dst = format!("inc_lock_{idx}");
                            let _ = rename_entry_atomic(
                                &crate_path,
                                lf.as_str(),
                                &staging_dir,
                                &lock_dst,
                            );
                        }
                    }
                    Ok(false) => {}
                    Err(error) => {
                        move_error = Some(format!(
                            "rename incremental/{crate_dir}/{session_dir}: {error}"
                        ));
                        break;
                    }
                }
            }
        }
    }

    release_locks(held_locks);

    if let Err(rm_err) = remove_tree_safe(&staging_dir, target_dev) {
        return (
            ActionOutcome::Failed {
                error: CompactString::from(format!(
                    "safe remove of incremental staging failed: {rm_err}"
                )),
            },
            moved_count,
            0,
        );
    }

    if let Some(err) = move_error {
        return (
            ActionOutcome::Failed {
                error: CompactString::from(err),
            },
            moved_count,
            0,
        );
    }
    if moved_count == 0 {
        return (
            ActionOutcome::SkippedRevalidateChanged {
                reason: CompactString::new("incremental_entries_already_absent"),
            },
            0,
            0,
        );
    }
    (
        ActionOutcome::Applied,
        moved_count,
        estimated_allocated_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_evict_target(
    target_root: &Path,
    target_dev: u64,
    target_ino: u64,
    expected_activity_unix: u64,
    worktree_root: Option<&Path>,
    all_locks: &[PathBuf],
    estimated_allocated_bytes: u64,
    platform: &impl Platform,
) -> (ActionOutcome, u32, u64) {
    let Some(parent_dir) = target_root.parent() else {
        return (
            ActionOutcome::Failed {
                error: CompactString::new("refusing to evict filesystem root"),
            },
            0,
            0,
        );
    };
    let Some(leaf_name) = target_root.file_name().and_then(|n| n.to_str()) else {
        return (
            ActionOutcome::Failed {
                error: CompactString::new("target directory name is not valid UTF-8"),
            },
            0,
            0,
        );
    };

    let held_locks = match acquire_sorted_locks(all_locks, platform) {
        Ok(locks) => locks,
        Err(outcome) => return (outcome, 0, 0),
    };

    if let Err(outcome) = revalidate_target_under_lock(
        target_root,
        target_dev,
        target_ino,
        target_root,
        expected_activity_unix,
        Some(expected_activity_unix),
        worktree_root,
        platform,
        |proc_snap| has_any_process_for_eviction(proc_snap, target_root, worktree_root),
    ) {
        release_locks(held_locks);
        return (outcome, 0, 0);
    }

    // Atomic sibling staging rename on same APFS volume: `<parent>/<name>` -> `<parent>/.<name>.targetwarden-reap.<pid>.<seq>`
    let pid = std::process::id();
    let mut staged_path: Option<PathBuf> = None;
    let mut rename_error: Option<String> = None;
    for _ in 0..32 {
        let seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
        let staging_name = format!(".{leaf_name}.targetwarden-reap.{pid}.{seq}");
        let candidate = parent_dir.join(&staging_name);
        if fs::symlink_metadata(&candidate).is_ok() {
            continue;
        }
        match rename_entry_atomic(parent_dir, leaf_name, parent_dir, &staging_name) {
            Ok(true) => {
                staged_path = Some(candidate);
                break;
            }
            Ok(false) => {
                release_locks(held_locks);
                return (
                    ActionOutcome::SkippedRevalidateChanged {
                        reason: CompactString::new("target_already_absent"),
                    },
                    0,
                    0,
                );
            }
            Err(error) => {
                rename_error = Some(format!("sibling staging rename failed: {error}"));
                break;
            }
        }
    }

    // Release all parent + nested locks immediately after the atomic rename.
    release_locks(held_locks);

    if let Some(error) = rename_error {
        return (
            ActionOutcome::Failed {
                error: CompactString::from(error),
            },
            0,
            0,
        );
    }

    let Some(sibling_staging) = staged_path else {
        return (
            ActionOutcome::Failed {
                error: CompactString::new("exhausted unique sibling staging names"),
            },
            0,
            0,
        );
    };

    match remove_tree_safe(&sibling_staging, target_dev) {
        Ok(()) => (ActionOutcome::Applied, 1, estimated_allocated_bytes),
        Err(error) => (
            ActionOutcome::Failed {
                error: CompactString::from(format!(
                    "safe remove of evicted target failed: {error}"
                )),
            },
            0,
            0,
        ),
    }
}

fn has_any_process_for_eviction(
    proc_snap: &ProcessSnapshot,
    target_root: &Path,
    worktree_root: Option<&Path>,
) -> Option<CompactString> {
    for proc_entry in &proc_snap.processes {
        if proc_snap.self_pid != 0 && proc_entry.pid == proc_snap.self_pid {
            continue;
        }
        if proc_entry
            .cwd
            .as_deref()
            .is_some_and(|cwd| cwd.starts_with(target_root))
            || proc_entry
                .open_paths
                .iter()
                .any(|open| open.starts_with(target_root))
        {
            return Some(CompactString::from(format!(
                "process_in_target:{}",
                proc_entry.comm
            )));
        }
        if let Some(wt) = worktree_root
            && (proc_entry
                .cwd
                .as_deref()
                .is_some_and(|cwd| cwd.starts_with(wt))
                || proc_entry
                    .open_paths
                    .iter()
                    .any(|open| open.starts_with(wt)))
        {
            return Some(CompactString::from(format!(
                "process_in_worktree:{}",
                proc_entry.comm
            )));
        }
    }
    None
}

fn release_locks(held: Vec<File>) {
    for file in &held {
        let _ = file.unlock();
    }
    drop(held);
}

fn acquire_sorted_locks(
    lock_paths: &[PathBuf],
    platform: &impl Platform,
) -> Result<Vec<File>, ActionOutcome> {
    let mut sorted: Vec<&Path> = lock_paths.iter().map(PathBuf::as_path).collect();
    sorted.sort();
    sorted.dedup();

    let mut held = Vec::with_capacity(sorted.len());
    for lock_path in sorted {
        match platform.try_lock_readonly(lock_path) {
            Ok(LockProbe::Acquired(file)) => held.push(file),
            Ok(LockProbe::NotFound) => {}
            Ok(LockProbe::Contested) => {
                release_locks(held);
                return Err(ActionOutcome::SkippedContested {
                    reason: CompactString::from(format!(
                        "lock_busy:{}",
                        lock_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("lock")
                    )),
                });
            }
            Err(error) => {
                release_locks(held);
                return Err(ActionOutcome::SkippedContested {
                    reason: CompactString::from(format!("lock_probe_error:{error}")),
                });
            }
        }
    }
    Ok(held)
}

#[allow(clippy::too_many_arguments)]
fn revalidate_target_under_lock<F>(
    target_root: &Path,
    expected_dev: u64,
    expected_ino: u64,
    activity_dir: &Path,
    expected_mtime_unix: u64,
    expected_target_mtime_unix: Option<u64>,
    worktree_root: Option<&Path>,
    platform: &impl Platform,
    proc_blocked: F,
) -> Result<(), ActionOutcome>
where
    F: FnOnce(&ProcessSnapshot) -> Option<CompactString>,
{
    let meta =
        fs::symlink_metadata(target_root).map_err(|_| ActionOutcome::SkippedRevalidateChanged {
            reason: CompactString::new("target_missing"),
        })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(ActionOutcome::SkippedRevalidateChanged {
            reason: CompactString::new("target_is_symlink_or_not_dir"),
        });
    }
    if meta_dev(&meta) != expected_dev || meta_ino(&meta) != expected_ino {
        return Err(ActionOutcome::SkippedRevalidateChanged {
            reason: CompactString::new("target_inode_changed"),
        });
    }
    if has_symlink_boundary(target_root) {
        return Err(ActionOutcome::SkippedRevalidateChanged {
            reason: CompactString::new("symlink_boundary_detected"),
        });
    }

    // Revalidate pin marker wasn't created after scan (TOCTOU fail-closed)
    if fs::symlink_metadata(target_root.join(PIN_MARKER_FILE)).is_ok()
        || worktree_root.is_some_and(|wt| fs::symlink_metadata(wt.join(PIN_MARKER_FILE)).is_ok())
    {
        return Err(ActionOutcome::SkippedRevalidateChanged {
            reason: CompactString::new("pin_marker_appeared"),
        });
    }

    // Revalidate mount table using single-owner boundary validator (fail-closed)
    let mounts = platform
        .mount_table()
        .map_err(|_| ActionOutcome::SkippedRevalidateChanged {
            reason: CompactString::new("mount_table_unavailable"),
        })?;
    if crosses_mount_boundary(target_root, expected_dev, Some(&mounts)) {
        return Err(ActionOutcome::SkippedRevalidateChanged {
            reason: CompactString::new("mount_boundary_detected"),
        });
    }

    // Revalidate mtime did not advance on the activity dir (and `.rustc_info.json` vs target mtime)
    if let Ok(act_meta) = fs::symlink_metadata(activity_dir)
        && meta_mtime_unix(&act_meta) > expected_mtime_unix
    {
        return Err(ActionOutcome::SkippedRevalidateChanged {
            reason: CompactString::new("mtime_advanced"),
        });
    }
    if let Some(target_mtime) = expected_target_mtime_unix
        && let Ok(ri_meta) = fs::symlink_metadata(target_root.join(".rustc_info.json"))
        && meta_mtime_unix(&ri_meta) > target_mtime
    {
        return Err(ActionOutcome::SkippedRevalidateChanged {
            reason: CompactString::new("rustc_info_mtime_advanced"),
        });
    }

    // Fresh post-lock `lsof` snapshot (fail-closed)
    let proc_snap =
        platform
            .process_snapshot()
            .map_err(|_| ActionOutcome::SkippedRevalidateChanged {
                reason: CompactString::new("lsof_unavailable"),
            })?;
    if let Some(reason) = proc_blocked(&proc_snap) {
        return Err(ActionOutcome::SkippedRevalidateChanged { reason });
    }

    Ok(())
}

fn has_blocking_process_for_sweep(
    proc_snap: &ProcessSnapshot,
    target_root: &Path,
    worktree_root: Option<&Path>,
    profile_dir: &Path,
    ops: &SweepOps,
) -> Option<CompactString> {
    for proc_entry in &proc_snap.processes {
        if proc_snap.self_pid != 0 && proc_entry.pid == proc_snap.self_pid {
            continue;
        }
        let is_pm_srv = proc_entry.is_rust_analyzer_proc_macro_srv();
        if proc_entry
            .cwd
            .as_deref()
            .is_some_and(|cwd| cwd.starts_with(target_root))
        {
            return Some(CompactString::from(format!(
                "process_cwd_in_target:{}",
                proc_entry.comm
            )));
        }
        for open in &proc_entry.open_paths {
            if !open.starts_with(target_root) {
                continue;
            }
            if is_pm_srv && open.extension().and_then(|e| e.to_str()) == Some("dylib") {
                if path_hits_swept_unit(open, profile_dir, ops) {
                    return Some(CompactString::new("proc_macro_dylib_open_in_swept_unit"));
                }
                continue;
            }
            return Some(CompactString::from(format!(
                "process_open_in_target:{}",
                proc_entry.comm
            )));
        }
        if let Some(wt) = worktree_root
            && proc_entry.is_active_compiler_or_tool()
            && (proc_entry
                .cwd
                .as_deref()
                .is_some_and(|cwd| cwd.starts_with(wt))
                || proc_entry
                    .open_paths
                    .iter()
                    .any(|open| open.starts_with(wt)))
        {
            return Some(CompactString::from(format!(
                "compiler_in_worktree:{}",
                proc_entry.comm
            )));
        }
    }
    None
}

fn has_hard_blocked_process_for_target(
    proc_snap: &ProcessSnapshot,
    target_root: &Path,
    worktree_root: Option<&Path>,
    action_dir: &Path,
) -> Option<CompactString> {
    for proc_entry in &proc_snap.processes {
        if proc_snap.self_pid != 0 && proc_entry.pid == proc_snap.self_pid {
            continue;
        }
        let is_pm_srv = proc_entry.is_rust_analyzer_proc_macro_srv();
        if proc_entry
            .cwd
            .as_deref()
            .is_some_and(|cwd| cwd.starts_with(target_root) || cwd.starts_with(action_dir))
        {
            return Some(CompactString::from(format!(
                "process_cwd_in_target:{}",
                proc_entry.comm
            )));
        }
        for open in &proc_entry.open_paths {
            if open.starts_with(action_dir) {
                return Some(CompactString::from(format!(
                    "process_open_in_dir:{}",
                    proc_entry.comm
                )));
            }
            if open.starts_with(target_root) {
                if is_pm_srv && open.extension().and_then(|e| e.to_str()) == Some("dylib") {
                    continue;
                }
                return Some(CompactString::from(format!(
                    "process_open_in_target:{}",
                    proc_entry.comm
                )));
            }
        }
        if let Some(wt) = worktree_root
            && proc_entry.is_active_compiler_or_tool()
            && (proc_entry
                .cwd
                .as_deref()
                .is_some_and(|cwd| cwd.starts_with(wt))
                || proc_entry
                    .open_paths
                    .iter()
                    .any(|open| open.starts_with(wt)))
        {
            return Some(CompactString::from(format!(
                "compiler_in_worktree:{}",
                proc_entry.comm
            )));
        }
    }
    None
}

fn path_hits_swept_unit(path: &Path, profile_dir: &Path, ops: &SweepOps) -> bool {
    let check_v2 = |v2: &[V2UnitRemoval]| {
        v2.iter().any(|u| {
            let unit_dir = profile_dir
                .join("build")
                .join(u.pkg.as_str())
                .join(u.unit_hash.as_str());
            path.starts_with(&unit_dir)
        })
    };
    let check_v1 = |v1: &[V1UnitRemoval]| {
        let deps_dir = profile_dir.join("deps");
        v1.iter().any(|u| {
            let fp_dir = profile_dir
                .join(".fingerprint")
                .join(u.fingerprint_dir.as_str());
            let build_hit = u
                .build_dir
                .as_deref()
                .is_some_and(|b| path.starts_with(profile_dir.join("build").join(b)));
            let dep_hit = u
                .dep_entries
                .iter()
                .any(|d| path.starts_with(deps_dir.join(d.as_str())));
            path.starts_with(&fp_dir) || build_hit || dep_hit
        })
    };
    match ops {
        SweepOps::V2(v2) => check_v2(v2),
        SweepOps::V1(v1) => check_v1(v1),
        SweepOps::Mixed { v2, v1 } => check_v2(v2) || check_v1(v1),
    }
}

fn any_process_in_dir(proc_snap: &ProcessSnapshot, dir: &Path) -> bool {
    proc_snap.processes.iter().any(|proc_entry| {
        if proc_snap.self_pid != 0 && proc_entry.pid == proc_snap.self_pid {
            return false;
        }
        proc_entry
            .cwd
            .as_deref()
            .is_some_and(|cwd| cwd.starts_with(dir))
            || proc_entry
                .open_paths
                .iter()
                .any(|open| open.starts_with(dir))
    })
}

fn stage_sweep_ops(
    profile_dir: &Path,
    staging_dir: &Path,
    ops: &SweepOps,
) -> (u32, Option<String>) {
    let mut moved: u32 = 0;
    let mut first_error: Option<String> = None;

    match ops {
        SweepOps::V2(v2) => {
            stage_v2_units(profile_dir, staging_dir, v2, &mut moved, &mut first_error);
        }
        SweepOps::V1(v1) => {
            stage_v1_units(profile_dir, staging_dir, v1, &mut moved, &mut first_error);
        }
        SweepOps::Mixed { v2, v1 } => {
            stage_v2_units(profile_dir, staging_dir, v2, &mut moved, &mut first_error);
            if first_error.is_none() {
                stage_v1_units(profile_dir, staging_dir, v1, &mut moved, &mut first_error);
            }
        }
    }

    (moved, first_error)
}

fn stage_v2_units(
    profile_dir: &Path,
    staging_dir: &Path,
    units: &[V2UnitRemoval],
    moved: &mut u32,
    first_error: &mut Option<String>,
) {
    let build_root = profile_dir.join("build");
    for (idx, unit) in units.iter().enumerate() {
        let pkg_dir = build_root.join(unit.pkg.as_str());
        let dst = format!("v2_{idx}_{}", unit.unit_hash);
        match rename_entry_atomic(&pkg_dir, unit.unit_hash.as_str(), staging_dir, &dst) {
            Ok(true) => *moved = moved.saturating_add(1),
            Ok(false) => {}
            Err(error) => {
                *first_error = Some(format!(
                    "rename V2 build/{}/{}: {error}",
                    unit.pkg, unit.unit_hash
                ));
                break;
            }
        }
    }
}

fn stage_v1_units(
    profile_dir: &Path,
    staging_dir: &Path,
    units: &[V1UnitRemoval],
    moved: &mut u32,
    first_error: &mut Option<String>,
) {
    let fp_root = profile_dir.join(".fingerprint");
    let build_root = profile_dir.join("build");
    let deps_root = profile_dir.join("deps");
    for (idx, unit) in units.iter().enumerate() {
        // Crash-consistency invariant (Section 4.3): rename `.fingerprint/<dir>` FIRST so
        // Cargo treats the unit as absent even if power is lost before `deps/` finishes.
        let fp_dst = format!("v1_fp_{idx}");
        match rename_entry_atomic(
            &fp_root,
            unit.fingerprint_dir.as_str(),
            staging_dir,
            &fp_dst,
        ) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                *first_error = Some(format!(
                    "rename V1 .fingerprint/{}: {error}",
                    unit.fingerprint_dir
                ));
                break;
            }
        }

        if let Some(build_dir) = &unit.build_dir {
            let build_dst = format!("v1_build_{idx}");
            if let Err(error) =
                rename_entry_atomic(&build_root, build_dir.as_str(), staging_dir, &build_dst)
            {
                *first_error = Some(format!("rename V1 build/{build_dir}: {error}"));
                break;
            }
        }

        for (dep_idx, dep_entry) in unit.dep_entries.iter().enumerate() {
            let dep_dst = format!("v1_dep_{idx}_{dep_idx}");
            if let Err(error) =
                rename_entry_atomic(&deps_root, dep_entry.as_str(), staging_dir, &dep_dst)
            {
                *first_error = Some(format!("rename V1 deps/{dep_entry}: {error}"));
                break;
            }
        }
        if first_error.is_some() {
            break;
        }
        *moved = moved.saturating_add(1);
    }
}

fn create_internal_staging_dir(target_root: &Path, expected_dev: u64) -> Result<PathBuf, AppError> {
    let pid = std::process::id();
    for _ in 0..32 {
        let seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
        let name = format!(".targetwarden-reap.{pid}.{seq}");
        let candidate = target_root.join(&name);
        match fs::create_dir(&candidate) {
            Ok(()) => {
                let meta =
                    fs::symlink_metadata(&candidate).map_err(|error| AppError::InvalidPath {
                        path: candidate.clone(),
                        message: format!("cannot stat new staging dir: {error}"),
                    })?;
                if meta_dev(&meta) != expected_dev {
                    return Err(AppError::InvalidPath {
                        path: candidate,
                        message: "staging directory created on unexpected device".to_owned(),
                    });
                }
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(AppError::InvalidPath {
                    path: candidate,
                    message: format!("cannot create staging directory: {error}"),
                });
            }
        }
    }
    Err(AppError::InvalidPath {
        path: target_root.to_path_buf(),
        message: "exhausted unique staging directory attempts".to_owned(),
    })
}

/// Atomically rename `src_parent/src_name` to `dst_parent/dst_name` via `rustix::fs::renameat`
/// (opening both parent directories with `O_NOFOLLOW | O_DIRECTORY`).
/// Returns `Ok(true)` if moved, `Ok(false)` if source did not exist (`ENOENT`).
fn rename_entry_atomic(
    src_parent: &Path,
    src_name: &str,
    dst_parent: &Path,
    dst_name: &str,
) -> std::io::Result<bool> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open, renameat};
        use rustix::io::Errno;

        let src_dir_fd = match open(
            src_parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(false),
            Err(error) => return Err(std::io::Error::from(error)),
        };
        let dst_dir_fd = open(
            dst_parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;

        match renameat(&src_dir_fd, src_name, &dst_dir_fd, dst_name) {
            Ok(()) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(error) => Err(std::io::Error::from(error)),
        }
    }
    #[cfg(not(unix))]
    {
        let src = src_parent.join(src_name);
        if !src.exists() {
            return Ok(false);
        }
        fs::rename(src, dst_parent.join(dst_name))?;
        Ok(true)
    }
}

/// FD-anchored safe directory tree removal (`rustix::fs`):
/// `openat(O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` -> `fstat.st_dev == expected_dev`
/// -> bounded depth-64 `Dir` + `statat(SYMLINK_NOFOLLOW)` -> `unlinkat(REMOVEDIR)` / `unlinkat(empty)`.
/// Never follows symlinks and never crosses device boundaries.
pub(crate) fn remove_tree_safe(root: &Path, expected_dev: u64) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        use rustix::fs::{AtFlags, Mode, OFlags, fstat, open, openat, unlinkat};
        use rustix::io::Errno;

        let parent = root.parent().ok_or_else(|| AppError::InvalidPath {
            path: root.to_path_buf(),
            message: "refusing to remove filesystem root".to_owned(),
        })?;
        let leaf_name = root.file_name().ok_or_else(|| AppError::InvalidPath {
            path: root.to_path_buf(),
            message: "missing leaf directory name".to_owned(),
        })?;

        let parent_fd = open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| AppError::InvalidPath {
            path: parent.to_path_buf(),
            message: format!("cannot open parent safely: {error}"),
        })?;

        let root_fd = match openat(
            &parent_fd,
            leaf_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(()),
            Err(error) => {
                return Err(AppError::InvalidPath {
                    path: root.to_path_buf(),
                    message: format!("refused safe open (symlink or inaccessible): {error}"),
                });
            }
        };

        let st = fstat(&root_fd).map_err(|error| AppError::InvalidPath {
            path: root.to_path_buf(),
            message: format!("fstat failed: {error}"),
        })?;
        if u64::try_from(st.st_dev).unwrap_or(u64::MAX) != expected_dev {
            return Err(AppError::InvalidPath {
                path: root.to_path_buf(),
                message: "device mismatch during safe remove (mount boundary)".to_owned(),
            });
        }

        clear_dir_fd_recursive(&root_fd, expected_dev, 0, root)?;
        drop(root_fd);

        match unlinkat(&parent_fd, leaf_name, AtFlags::REMOVEDIR) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(error) => Err(AppError::InvalidPath {
                path: root.to_path_buf(),
                message: format!("unlinkat REMOVEDIR failed: {error}"),
            }),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (root, expected_dev);
        Err(AppError::UnsupportedPlatform)
    }
}

#[cfg(unix)]
fn clear_dir_fd_recursive(
    dir_fd: &std::os::fd::OwnedFd,
    expected_dev: u64,
    depth: usize,
    diag_root: &Path,
) -> Result<(), AppError> {
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, fstat, openat, statat, unlinkat};
    use rustix::io::Errno;

    const MAX_REMOVE_DEPTH: usize = 64;
    if depth >= MAX_REMOVE_DEPTH {
        return Err(AppError::InvalidPath {
            path: diag_root.to_path_buf(),
            message: "safe remove exceeded depth bound (64)".to_owned(),
        });
    }

    let mut dir = Dir::read_from(dir_fd).map_err(|error| AppError::InvalidPath {
        path: diag_root.to_path_buf(),
        message: format!("Dir::read_from failed: {error}"),
    })?;

    let mut entries: Vec<(std::ffi::CString, bool)> = Vec::new();
    for entry_res in dir.by_ref() {
        let entry = entry_res.map_err(|error| AppError::InvalidPath {
            path: diag_root.to_path_buf(),
            message: format!("directory entry read failed: {error}"),
        })?;
        let name = entry.file_name();
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let st = match statat(dir_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(Errno::NOENT) => continue,
            Err(error) => {
                return Err(AppError::InvalidPath {
                    path: diag_root.to_path_buf(),
                    message: format!("statat failed during safe remove: {error}"),
                });
            }
        };
        let is_dir = FileType::from_raw_mode(st.st_mode) == FileType::Directory;
        if is_dir && u64::try_from(st.st_dev).unwrap_or(u64::MAX) != expected_dev {
            return Err(AppError::InvalidPath {
                path: diag_root.to_path_buf(),
                message: "encountered mount point inside staging tree".to_owned(),
            });
        }
        entries.push((name.to_owned(), is_dir));
    }
    drop(dir);

    for (name, is_dir) in entries {
        if is_dir {
            let child_fd = match openat(
                dir_fd,
                name.as_c_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => continue,
                Err(error) => {
                    return Err(AppError::InvalidPath {
                        path: diag_root.to_path_buf(),
                        message: format!("safe openat child directory failed: {error}"),
                    });
                }
            };
            let cst = fstat(&child_fd).map_err(|error| AppError::InvalidPath {
                path: diag_root.to_path_buf(),
                message: format!("fstat child directory failed: {error}"),
            })?;
            if u64::try_from(cst.st_dev).unwrap_or(u64::MAX) != expected_dev {
                return Err(AppError::InvalidPath {
                    path: diag_root.to_path_buf(),
                    message: "child directory crossed device boundary".to_owned(),
                });
            }
            clear_dir_fd_recursive(&child_fd, expected_dev, depth + 1, diag_root)?;
            drop(child_fd);
            match unlinkat(dir_fd, name.as_c_str(), AtFlags::REMOVEDIR) {
                Ok(()) | Err(Errno::NOENT) => {}
                Err(error) => {
                    return Err(AppError::InvalidPath {
                        path: diag_root.to_path_buf(),
                        message: format!("unlinkat child dir failed: {error}"),
                    });
                }
            }
        } else {
            // Regular files, symlinks (unlinked directly, NEVER followed), fifos, sockets
            match unlinkat(dir_fd, name.as_c_str(), AtFlags::empty()) {
                Ok(()) | Err(Errno::NOENT) => {}
                Err(error) => {
                    return Err(AppError::InvalidPath {
                        path: diag_root.to_path_buf(),
                        message: format!("unlinkat entry failed: {error}"),
                    });
                }
            }
        }
    }

    Ok(())
}

fn is_staging_dir_name(name: &str) -> bool {
    name.starts_with(STAGING_MARKER) || (name.starts_with('.') && name.contains(STAGING_MARKER))
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
    use smallvec::SmallVec;

    use super::{execute_action, meta_dev, meta_ino, meta_mtime_unix, remove_tree_safe};
    use crate::error::AppError;
    use crate::model::{
        ActionOutcome, DiskPressure, DiskStats, GIB, IncrementalRemoval, MountEntry,
        ProcessSnapshot, ReclaimAction, SweepOps, SweepUnitReason, V1UnitRemoval, V2UnitRemoval,
    };
    use crate::platform::{CommandOutput, LockProbe, Platform};

    struct RealLockTestPlatform {
        now: u64,
    }

    impl Platform for RealLockTestPlatform {
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
                self_pid: std::process::id(),
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
        fn run_git(&self, _cwd: &Path, _args: &[&str]) -> Result<CommandOutput, AppError> {
            Err(AppError::CommandFailed {
                program: "git",
                message: "unused".to_owned(),
            })
        }
        fn try_lock_readonly(&self, path: &Path) -> Result<LockProbe, AppError> {
            use std::fs::TryLockError;
            match fs::File::open(path) {
                Ok(file) => match file.try_lock() {
                    Ok(()) => Ok(LockProbe::Acquired(file)),
                    Err(TryLockError::WouldBlock) => Ok(LockProbe::Contested),
                    Err(TryLockError::Error(source)) => Err(AppError::LockProbe {
                        path: path.to_path_buf(),
                        source,
                    }),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(LockProbe::NotFound),
                Err(source) => Err(AppError::LockProbe {
                    path: path.to_path_buf(),
                    source,
                }),
            }
        }
        fn run_launchctl(&self, _args: &[&str]) -> Result<CommandOutput, AppError> {
            Err(AppError::CommandFailed {
                program: "launchctl",
                message: "unused".to_owned(),
            })
        }
    }

    #[cfg(unix)]
    #[test]
    fn remove_tree_safe_unlinks_symlink_without_touching_symlink_target() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside_secret");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep.rs"), b"precious source").unwrap();

        let staging = tmp.path().join(".targetwarden-reap.1.1");
        fs::create_dir_all(staging.join("nested")).unwrap();
        symlink(&outside, staging.join("nested/evil_link")).unwrap();
        fs::write(staging.join("nested/junk.o"), b"obj").unwrap();

        let dev = meta_dev(&fs::symlink_metadata(&staging).unwrap());
        remove_tree_safe(&staging, dev).unwrap();

        assert!(!staging.exists());
        assert!(outside.join("keep.rs").exists());
        assert_eq!(
            fs::read(outside.join("keep.rs")).unwrap(),
            b"precious source"
        );

        // Refuses symlink at root itself
        let root_link = tmp.path().join("root_symlink");
        symlink(&outside, &root_link).unwrap();
        assert!(remove_tree_safe(&root_link, dev).is_err());
        assert!(outside.join("keep.rs").exists());
    }

    #[cfg(unix)]
    #[test]
    fn live_flock_competitors_abort_build_doc_and_incremental_actions_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap().join("target");
        let debug = root.join("debug");
        fs::create_dir_all(debug.join("build/demo/0123456789abcdef")).unwrap();
        fs::create_dir_all(root.join("doc")).unwrap();
        fs::create_dir_all(debug.join("incremental/app-abc1234567890/s-1-a-final")).unwrap();

        let build_lock = debug.join(".cargo-build-lock");
        let doc_lock = root.join("doc/.lock");
        let inc_lock = debug.join("incremental/app-abc1234567890/s-1-a.lock");
        fs::write(&build_lock, b"").unwrap();
        fs::write(&doc_lock, b"").unwrap();
        fs::write(&inc_lock, b"").unwrap();

        let tmeta = fs::symlink_metadata(&root).unwrap();
        let dev = meta_dev(&tmeta);
        let ino = meta_ino(&tmeta);
        let future_mtime = meta_mtime_unix(&tmeta) + 1000;
        let platform = RealLockTestPlatform { now: future_mtime };

        // 1. Live lock on `.cargo-build-lock` blocks SweepBuildUnits
        let build_holder = fs::File::open(&build_lock).unwrap();
        build_holder.try_lock().unwrap();
        let mut plocks = SmallVec::new();
        plocks.push(build_lock);
        let sweep_action = ReclaimAction::SweepBuildUnits {
            target_root: root.clone(),
            target_dev: dev,
            target_ino: ino,
            expected_activity_unix: future_mtime,
            expected_target_activity_unix: future_mtime,
            worktree_root: None,
            profile_rel: PathBuf::from("debug"),
            profile_locks: plocks.clone(),
            ops: SweepOps::V2(vec![V2UnitRemoval {
                pkg: CompactString::new("demo"),
                unit_hash: CompactString::new("0123456789abcdef"),
                allocated_bytes: 100,
                reason: SweepUnitReason::UnreachableDuplicate,
            }]),
            estimated_allocated_bytes: 100,
        };
        let r1 = execute_action(&sweep_action, &platform, DiskPressure::Calm, false);
        assert!(matches!(r1.outcome, ActionOutcome::SkippedContested { .. }));
        assert!(debug.join("build/demo/0123456789abcdef").exists());
        build_holder.unlock().unwrap();
        drop(build_holder);

        // Once unlocked, sweep applies cleanly!
        let r1_ok = execute_action(&sweep_action, &platform, DiskPressure::Calm, false);
        assert_eq!(r1_ok.outcome, ActionOutcome::Applied);
        assert!(!debug.join("build/demo/0123456789abcdef").exists());

        // 2. Live lock on `doc/.lock` blocks RemoveDoc
        let doc_holder = fs::File::open(&doc_lock).unwrap();
        doc_holder.try_lock().unwrap();
        let mut dlocks = SmallVec::new();
        dlocks.push(doc_lock);
        let doc_action = ReclaimAction::RemoveDoc {
            target_root: root.clone(),
            target_dev: dev,
            target_ino: ino,
            expected_doc_mtime_unix: future_mtime,
            worktree_root: None,
            locks: dlocks,
            estimated_allocated_bytes: 100,
        };
        let r2 = execute_action(&doc_action, &platform, DiskPressure::Calm, false);
        assert!(matches!(r2.outcome, ActionOutcome::SkippedContested { .. }));
        assert!(root.join("doc").exists());
        doc_holder.unlock().unwrap();
        drop(doc_holder);

        // 3. Live lock on `s-*.lock` blocks PruneIncremental
        let inc_holder = fs::File::open(&inc_lock).unwrap();
        inc_holder.try_lock().unwrap();
        let inc_action = ReclaimAction::PruneIncremental {
            target_root: root,
            target_dev: dev,
            target_ino: ino,
            expected_activity_unix: future_mtime,
            expected_target_activity_unix: future_mtime,
            worktree_root: None,
            profile_rel: PathBuf::from("debug"),
            profile_locks: plocks,
            removals: vec![IncrementalRemoval::WholeCrateDir {
                dir_name: CompactString::new("app-abc1234567890"),
                allocated_bytes: 100,
            }],
            estimated_allocated_bytes: 100,
        };
        let r3 = execute_action(&inc_action, &platform, DiskPressure::Calm, false);
        assert!(matches!(r3.outcome, ActionOutcome::SkippedContested { .. }));
        assert!(debug.join("incremental/app-abc1234567890").exists());
        inc_holder.unlock().unwrap();
        drop(inc_holder);

        let r3_ok = execute_action(&inc_action, &platform, DiskPressure::Calm, false);
        assert_eq!(r3_ok.outcome, ActionOutcome::Applied);
        assert!(!debug.join("incremental/app-abc1234567890").exists());
    }

    #[cfg(unix)]
    #[test]
    fn v1_sweep_renames_fingerprint_first_and_dual_staging_recovery_cleans_leftovers() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let root = base.join("target");
        let debug = root.join("debug");
        fs::create_dir_all(debug.join(".fingerprint/demo-0123456789abcdef")).unwrap();
        fs::create_dir_all(debug.join("build/demo-0123456789abcdef/out")).unwrap();
        fs::create_dir_all(debug.join("deps/demo-0123456789abcdef.dSYM/Contents")).unwrap();
        fs::write(debug.join("deps/libdemo-0123456789abcdef.rlib"), b"rlib").unwrap();

        // Dual staging leftovers: internal `<target>/.targetwarden-reap.*` and sibling `<parent>/.target.targetwarden-reap.*`
        let internal_staging = root.join(".targetwarden-reap.999.1");
        let sibling_staging = base.join(".target.targetwarden-reap.999.2");
        fs::create_dir_all(&internal_staging).unwrap();
        fs::write(internal_staging.join("old"), b"x").unwrap();
        fs::create_dir_all(&sibling_staging).unwrap();
        fs::write(sibling_staging.join("old"), b"y").unwrap();

        let tmeta = fs::symlink_metadata(&root).unwrap();
        let dev = meta_dev(&tmeta);
        let ino = meta_ino(&tmeta);
        let future_mtime = meta_mtime_unix(&tmeta) + 1000;
        let platform = RealLockTestPlatform { now: future_mtime };

        // Dual staging recovery removes both leftovers
        for st in [&internal_staging, &sibling_staging] {
            let reap = ReclaimAction::ReapLeftoverStaging {
                staging_dir: st.clone(),
                expected_dev: dev,
            };
            let res = execute_action(&reap, &platform, DiskPressure::Calm, false);
            assert_eq!(res.outcome, ActionOutcome::Applied);
            assert!(!st.exists());
        }

        // V1 sweep removes fingerprint, build, .dSYM dir, and .rlib
        let v1_sweep = ReclaimAction::SweepBuildUnits {
            target_root: root.clone(),
            target_dev: dev,
            target_ino: ino,
            expected_activity_unix: future_mtime,
            expected_target_activity_unix: future_mtime,
            worktree_root: None,
            profile_rel: PathBuf::from("debug"),
            profile_locks: SmallVec::new(),
            ops: SweepOps::V1(vec![V1UnitRemoval {
                fingerprint_dir: CompactString::new("demo-0123456789abcdef"),
                build_dir: Some(CompactString::new("demo-0123456789abcdef")),
                dep_entries: vec![
                    CompactString::new("demo-0123456789abcdef.dSYM"),
                    CompactString::new("libdemo-0123456789abcdef.rlib"),
                ],
                allocated_bytes: 200,
                reason: SweepUnitReason::StaleRustcHash,
            }]),
            estimated_allocated_bytes: 200,
        };
        let res = execute_action(&v1_sweep, &platform, DiskPressure::Calm, false);
        assert_eq!(res.outcome, ActionOutcome::Applied);
        assert!(!debug.join(".fingerprint/demo-0123456789abcdef").exists());
        assert!(!debug.join("build/demo-0123456789abcdef").exists());
        assert!(!debug.join("deps/demo-0123456789abcdef.dSYM").exists());
        assert!(!debug.join("deps/libdemo-0123456789abcdef.rlib").exists());

        // V1 `.fingerprint/`-first invariant: if `.fingerprint/<dir>` is absent, `deps/` & `build/` stay untouched
        fs::create_dir_all(debug.join("build/other-1111111111111111")).unwrap();
        fs::write(debug.join("deps/libother-1111111111111111.rlib"), b"keep").unwrap();
        let v1_missing_fp = ReclaimAction::SweepBuildUnits {
            target_root: root,
            target_dev: dev,
            target_ino: ino,
            expected_activity_unix: future_mtime,
            expected_target_activity_unix: future_mtime,
            worktree_root: None,
            profile_rel: PathBuf::from("debug"),
            profile_locks: SmallVec::new(),
            ops: SweepOps::V1(vec![V1UnitRemoval {
                fingerprint_dir: CompactString::new("other-1111111111111111"),
                build_dir: Some(CompactString::new("other-1111111111111111")),
                dep_entries: vec![CompactString::new("libother-1111111111111111.rlib")],
                allocated_bytes: 200,
                reason: SweepUnitReason::StaleRustcHash,
            }]),
            estimated_allocated_bytes: 200,
        };
        let r_missing = execute_action(&v1_missing_fp, &platform, DiskPressure::Calm, false);
        assert!(matches!(
            r_missing.outcome,
            ActionOutcome::SkippedRevalidateChanged { .. }
        ));
        assert!(debug.join("build/other-1111111111111111").exists());
        assert!(debug.join("deps/libother-1111111111111111.rlib").exists());
    }

    #[cfg(unix)]
    #[test]
    fn evict_target_checks_nested_lock_worktree_process_and_trips_apfs_hold() {
        use std::sync::atomic::{AtomicU64, Ordering};

        use super::execute_plan;
        use crate::model::{EvictRule, ProcessEntry, ReclaimPlan};

        struct DynamicPlatform {
            now: u64,
            free_bytes: AtomicU64,
            procs: Vec<ProcessEntry>,
        }

        impl Platform for DynamicPlatform {
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
                    free_bytes: self.free_bytes.load(Ordering::Relaxed),
                    local_snapshots: Some(vec![CompactString::new("com.apple.os.update-test")]),
                })
            }
            fn process_snapshot(&self) -> Result<ProcessSnapshot, AppError> {
                Ok(ProcessSnapshot {
                    captured_at_unix: self.now,
                    self_pid: std::process::id(),
                    processes: self.procs.clone(),
                })
            }
            fn mount_table(&self) -> Result<Vec<MountEntry>, AppError> {
                Ok(vec![MountEntry {
                    source: CompactString::new("/dev/disk3s5"),
                    mount_point: PathBuf::from("/"),
                    fstype: CompactString::new("apfs"),
                }])
            }
            fn run_git(&self, _cwd: &Path, _args: &[&str]) -> Result<CommandOutput, AppError> {
                Err(AppError::CommandFailed {
                    program: "git",
                    message: "unused".to_owned(),
                })
            }
            fn try_lock_readonly(&self, path: &Path) -> Result<LockProbe, AppError> {
                RealLockTestPlatform { now: self.now }.try_lock_readonly(path)
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
        let wt1 = base.join("wt1");
        let t1 = wt1.join("target");
        let nested_lock = t1.join("grpc-codegen/debug/.cargo-build-lock");
        fs::create_dir_all(nested_lock.parent().unwrap()).unwrap();
        fs::write(&nested_lock, b"").unwrap();
        fs::write(wt1.join("Cargo.toml"), b"[package]\nname=\"wt1\"\n").unwrap();

        let t2 = base.join("wt2/target");
        fs::create_dir_all(t2.join("debug")).unwrap();

        let m1 = fs::symlink_metadata(&t1).unwrap();
        let m2 = fs::symlink_metadata(&t2).unwrap();
        let future = meta_mtime_unix(&m1).max(meta_mtime_unix(&m2)) + 1000;

        let evict1 = ReclaimAction::EvictTarget {
            rule: EvictRule::R5PressureLru,
            target_root: t1.clone(),
            target_dev: meta_dev(&m1),
            target_ino: meta_ino(&m1),
            expected_activity_unix: future,
            worktree_root: Some(wt1.clone()),
            all_locks: vec![nested_lock.clone()],
            estimated_allocated_bytes: 6 * GIB,
            reason: CompactString::new("pressure_lru_linked_worktree"),
        };
        let evict2 = ReclaimAction::EvictTarget {
            rule: EvictRule::R5PressureLru,
            target_root: t2.clone(),
            target_dev: meta_dev(&m2),
            target_ino: meta_ino(&m2),
            expected_activity_unix: future,
            worktree_root: None,
            all_locks: vec![],
            estimated_allocated_bytes: 6 * GIB,
            reason: CompactString::new("pressure_lru_non_git"),
        };

        // 1. Live nested lock blocks parent eviction
        let holder = fs::File::open(&nested_lock).unwrap();
        holder.try_lock().unwrap();
        let clean_plat = DynamicPlatform {
            now: future,
            free_bytes: AtomicU64::new(40 * GIB),
            procs: vec![],
        };
        let r_locked = execute_action(&evict1, &clean_plat, DiskPressure::High, false);
        assert!(matches!(
            r_locked.outcome,
            ActionOutcome::SkippedContested { .. }
        ));
        assert!(t1.exists());
        holder.unlock().unwrap();
        drop(holder);

        // 2. Live process in worktree aborts eviction at post-lock lsof revalidation
        let busy_plat = DynamicPlatform {
            now: future,
            free_bytes: AtomicU64::new(40 * GIB),
            procs: vec![ProcessEntry {
                pid: 7777,
                comm: CompactString::new("zsh"),
                exe_path: None,
                cwd: Some(wt1.clone()),
                open_paths: vec![],
            }],
        };
        let r_proc = execute_action(&evict1, &busy_plat, DiskPressure::High, false);
        assert!(matches!(
            r_proc.outcome,
            ActionOutcome::SkippedRevalidateChanged { .. }
        ));
        assert!(t1.exists());

        // 3. Plan with 2 x 6 GiB R5 actions where statvfs free stays 40 GiB (APFS snapshot holds blocks!):
        //    First evicts cleanly -> trips ReclaimHoldState -> second R5 action is HALTED!
        let plan = ReclaimPlan {
            generated_at_unix: future,
            disk: DiskStats {
                mount: PathBuf::from("/System/Volumes/Data"),
                total_bytes: 460 * GIB,
                free_bytes: 40 * GIB,
                local_snapshots: Some(vec![CompactString::new("com.apple.os.update-test")]),
            },
            pressure: DiskPressure::High,
            hold_active: false,
            actions: vec![evict1, evict2],
            estimated_allocated_bytes: 12 * GIB,
        };
        let outcome = execute_plan(
            &plan,
            &clean_plat,
            false,
            Some(55 * GIB),
            |reclaimed, gain| reclaimed >= 5 * GIB && gain * 5 < reclaimed,
            None,
        );
        assert_eq!(outcome.receipts.len(), 1);
        assert_eq!(outcome.receipts[0].outcome, ActionOutcome::Applied);
        assert!(outcome.triggered_hold.is_some());
        assert!(!t1.exists());
        assert!(wt1.join("Cargo.toml").exists()); // Source files untouched!
        assert!(t2.exists()); // Second R5 target halted by APFS hold circuit breaker!
    }

    #[cfg(unix)]
    #[test]
    fn revalidation_allows_newer_rustc_info_for_doc_and_blocks_worktree_compiler_or_pin_marker() {
        use crate::model::ProcessEntry;

        struct ProcPlatform {
            now: u64,
            procs: Vec<ProcessEntry>,
        }
        impl Platform for ProcPlatform {
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
                    self_pid: std::process::id(),
                    processes: self.procs.clone(),
                })
            }
            fn mount_table(&self) -> Result<Vec<MountEntry>, AppError> {
                Ok(vec![MountEntry {
                    source: CompactString::new("/dev/disk3s5"),
                    mount_point: PathBuf::from("/"),
                    fstype: CompactString::new("apfs"),
                }])
            }
            fn run_git(&self, _cwd: &Path, _args: &[&str]) -> Result<CommandOutput, AppError> {
                Err(AppError::CommandFailed {
                    program: "git",
                    message: "unused".to_owned(),
                })
            }
            fn try_lock_readonly(&self, path: &Path) -> Result<LockProbe, AppError> {
                RealLockTestPlatform { now: self.now }.try_lock_readonly(path)
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
        let wt = base.join("proj");
        let root = wt.join("target");
        fs::create_dir_all(root.join("doc")).unwrap();
        fs::create_dir_all(root.join("debug/build/demo/aaaaaaaaaaaaaaaa")).unwrap();
        // Make `.rustc_info.json` 1 hour newer than `doc/` and `debug/` deterministically without subprocesses.
        let future_ts = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        let ri_path = root.join(".rustc_info.json");
        fs::write(&ri_path, b"{}").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&ri_path)
            .unwrap()
            .set_modified(future_ts)
            .unwrap();

        let tmeta = fs::symlink_metadata(&root).unwrap();
        let doc_meta = fs::symlink_metadata(root.join("doc")).unwrap();
        let debug_meta = fs::symlink_metadata(root.join("debug")).unwrap();
        let ri_meta = fs::symlink_metadata(root.join(".rustc_info.json")).unwrap();
        let dev = meta_dev(&tmeta);
        let ino = meta_ino(&tmeta);

        // 1. RemoveDoc must SUCCEED even though `.rustc_info.json` is years newer than `target/doc/`.
        let doc_action = ReclaimAction::RemoveDoc {
            target_root: root.clone(),
            target_dev: dev,
            target_ino: ino,
            expected_doc_mtime_unix: meta_mtime_unix(&doc_meta),
            worktree_root: Some(wt.clone()),
            locks: SmallVec::new(),
            estimated_allocated_bytes: 100,
        };
        let clean_plat = ProcPlatform {
            now: meta_mtime_unix(&ri_meta) + 100,
            procs: vec![],
        };
        let doc_res = execute_action(&doc_action, &clean_plat, DiskPressure::Calm, false);
        assert_eq!(doc_res.outcome, ActionOutcome::Applied);
        assert!(!root.join("doc").exists());

        // 2. Active compiler (`cargo`) in worktree_root aborts SweepBuildUnits at post-lock lsof!
        let sweep_action = ReclaimAction::SweepBuildUnits {
            target_root: root.clone(),
            target_dev: dev,
            target_ino: ino,
            expected_activity_unix: meta_mtime_unix(&debug_meta),
            expected_target_activity_unix: meta_mtime_unix(&ri_meta),
            worktree_root: Some(wt.clone()),
            profile_rel: PathBuf::from("debug"),
            profile_locks: SmallVec::new(),
            ops: SweepOps::V2(vec![V2UnitRemoval {
                pkg: CompactString::new("demo"),
                unit_hash: CompactString::new("aaaaaaaaaaaaaaaa"),
                allocated_bytes: 100,
                reason: SweepUnitReason::StaleRustcHash,
            }]),
            estimated_allocated_bytes: 100,
        };
        let compiler_plat = ProcPlatform {
            now: meta_mtime_unix(&ri_meta) + 100,
            procs: vec![ProcessEntry {
                pid: 4242,
                comm: CompactString::new("cargo"),
                exe_path: None,
                cwd: Some(wt.clone()),
                open_paths: vec![],
            }],
        };
        let comp_res = execute_action(&sweep_action, &compiler_plat, DiskPressure::Calm, false);
        assert!(matches!(
            comp_res.outcome,
            ActionOutcome::SkippedRevalidateChanged { .. }
        ));
        assert!(root.join("debug/build/demo/aaaaaaaaaaaaaaaa").exists());

        // 3. Newly created `.targetwarden-pin` marker aborts sweep at post-lock revalidation!
        fs::write(wt.join(".targetwarden-pin"), b"").unwrap();
        let pin_res = execute_action(&sweep_action, &clean_plat, DiskPressure::Calm, false);
        assert!(matches!(
            pin_res.outcome,
            ActionOutcome::SkippedRevalidateChanged { .. }
        ));
        assert!(root.join("debug/build/demo/aaaaaaaaaaaaaaaa").exists());
    }
}
