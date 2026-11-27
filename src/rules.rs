//! Functional Core (Layer 3): pure deterministic reclamation planner (`R1`–`R5`).
//!
//! Allowed dependencies: `model`, `config`, `state`, `pressure`, `safety`, `sweep`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use compact_str::CompactString;

use crate::config::Config;
use crate::model::{
    CargoTarget, DiskPressure, EvictRule, GitDiscovery, PathPrefix, PlanMode, ProcessSnapshot,
    ReclaimAction, ReclaimPlan, ReclaimProfile, SafetyVerdict, ScanSnapshot, WorktreeKind,
};
use crate::safety;
use crate::state::State;
use crate::sweep;

/// Build a deterministic `ReclaimPlan` from a `ScanSnapshot`, evaluated `SafetyVerdict`s,
/// persisted `State`, `Config`, and `PlanMode`.
pub(crate) fn plan(
    snapshot: &ScanSnapshot,
    verdicts: &[SafetyVerdict],
    state: &State,
    config: &Config,
    pressure: DiskPressure,
    mode: PlanMode,
) -> ReclaimPlan {
    let hold_active = state.reclaim_hold.is_some() && !mode.ignore_snapshot_hold;

    // Global fail-closed: zero mutations when process snapshot or mount table is unavailable.
    let (Some(processes), true) = (&snapshot.processes, snapshot.mount_table_available) else {
        return ReclaimPlan {
            generated_at_unix: snapshot.captured_at_unix,
            disk: snapshot.disk.clone(),
            pressure,
            hold_active,
            actions: Vec::new(),
            estimated_allocated_bytes: 0,
        };
    };

    let index_by_root: HashMap<&Path, usize> = snapshot
        .targets
        .iter()
        .enumerate()
        .map(|(idx, target)| (target.root.as_path(), idx))
        .collect();

    let mut evict_r1_r4_actions: Vec<ReclaimAction> = Vec::new();
    let mut evicted_roots: HashSet<PathBuf> = HashSet::new();

    // 1. Full eviction rules `R1` and `R4` (only when `profile == Full` and verdict == `Eligible`).
    if mode.profile == ReclaimProfile::Full {
        // Order shallowest first so parent eviction subsumes nested child targets cleanly.
        let mut order: Vec<usize> = (0..snapshot.targets.len()).collect();
        order.sort_by(|&a, &b| {
            snapshot.targets[a]
                .root
                .components()
                .count()
                .cmp(&snapshot.targets[b].root.components().count())
                .then_with(|| snapshot.targets[a].root.cmp(&snapshot.targets[b].root))
        });

        // R1: dead worktree target (`worktree_dir_missing` or clean merged unlocked `LinkedWorktree`, age >= 30m).
        for &idx in &order {
            let target = &snapshot.targets[idx];
            if !can_evict_target(idx, target, verdicts, &index_by_root, &evicted_roots) {
                continue;
            }
            let age = snapshot
                .captured_at_unix
                .saturating_sub(target.last_activity_unix);
            if age >= config.cooling.eviction_cooling_secs
                && safety::is_r1_dead_worktree_candidate(target)
            {
                let reason = match &target.git {
                    GitDiscovery::Inspected(git) if git.worktree_dir_missing => {
                        CompactString::new("dead_worktree_dir_missing")
                    }
                    _ => CompactString::new("merged_clean_linked_worktree"),
                };
                evict_r1_r4_actions.push(build_evict_action(
                    EvictRule::R1DeadWorktree,
                    target,
                    &snapshot.targets,
                    &index_by_root,
                    reason,
                ));
                evicted_roots.insert(target.root.clone());
            }
        }

        // R4: cooled linked worktree target (72h Calm / 6h Elevated / 2h High / 30m Critical).
        let r4_min_age = config.cooling.r4_age_secs(pressure);
        for &idx in &order {
            let target = &snapshot.targets[idx];
            if !can_evict_target(idx, target, verdicts, &index_by_root, &evicted_roots) {
                continue;
            }
            if target.worktree_kind != WorktreeKind::LinkedWorktree {
                continue;
            }
            let age = snapshot
                .captured_at_unix
                .saturating_sub(target.last_activity_unix);
            if age >= r4_min_age && age >= config.cooling.eviction_cooling_secs {
                evict_r1_r4_actions.push(build_evict_action(
                    EvictRule::R4CooledWorktree,
                    target,
                    &snapshot.targets,
                    &index_by_root,
                    CompactString::new("cooled_linked_worktree"),
                ));
                evicted_roots.insert(target.root.clone());
            }
        }
    }

    // 3. Surgical intra-target sweep (`R2` build/doc + `R3` incremental) for non-Protected, non-evicted targets.
    let mut sweep_actions_by_target: Vec<(PathBuf, ReclaimAction)> = Vec::new();
    for (target, verdict) in snapshot.targets.iter().zip(verdicts) {
        if is_covered_by_eviction(target, &evicted_roots) {
            continue;
        }
        let pinned_paths: &[PathBuf] = match verdict {
            SafetyVerdict::Eligible => &[],
            SafetyVerdict::SweepOnly {
                pinned_unit_paths, ..
            } => pinned_unit_paths.as_slice(),
            SafetyVerdict::Protected(_) => continue,
        };
        for action in sweep::plan_target_sweeps(
            target,
            pinned_paths,
            snapshot.captured_at_unix,
            pressure,
            config,
        ) {
            sweep_actions_by_target.push((target.root.clone(), action));
        }
    }

    // 4. R5 pressure LRU eviction (`High` target 55 GiB / `Critical` target 45 GiB), paused under APFS hold.
    let mut r5_actions: Vec<ReclaimAction> = Vec::new();
    if mode.profile == ReclaimProfile::Full
        && !hold_active
        && let Some(target_free_bytes) = r5_headroom_target(pressure, config)
    {
        let already_estimated: u64 = evict_r1_r4_actions
            .iter()
            .map(ReclaimAction::estimated_allocated_bytes)
            .chain(
                sweep_actions_by_target
                    .iter()
                    .map(|(_, a)| a.estimated_allocated_bytes()),
            )
            .fold(0u64, u64::saturating_add);
        let mut projected_free = snapshot.disk.free_bytes.saturating_add(already_estimated);

        if projected_free < target_free_bytes {
            let mut candidates: Vec<usize> = (0..snapshot.targets.len())
                .filter(|&idx| {
                    let target = &snapshot.targets[idx];
                    if !can_evict_target(idx, target, verdicts, &index_by_root, &evicted_roots) {
                        return false;
                    }
                    let age = snapshot
                        .captured_at_unix
                        .saturating_sub(target.last_activity_unix);
                    if age < config.cooling.eviction_cooling_secs {
                        return false;
                    }
                    if target.worktree_kind == WorktreeKind::MainCheckout {
                        return config
                            .cooling
                            .r5_main_age_secs(pressure)
                            .is_some_and(|min_age| age >= min_age);
                    }
                    true
                })
                .collect();

            // Priority tier: (1) LinkedWorktree -> (2) NonGit -> (3) MainCheckout;
            // within tier: LRU (oldest `last_activity_unix` first), then largest allocated_bytes.
            candidates.sort_by(|&a, &b| {
                let ta = &snapshot.targets[a];
                let tb = &snapshot.targets[b];
                r5_priority_tier(ta.worktree_kind)
                    .cmp(&r5_priority_tier(tb.worktree_kind))
                    .then_with(|| ta.last_activity_unix.cmp(&tb.last_activity_unix))
                    .then_with(|| tb.allocated_bytes.cmp(&ta.allocated_bytes))
                    .then_with(|| ta.root.cmp(&tb.root))
            });

            for idx in candidates {
                if projected_free >= target_free_bytes {
                    break;
                }
                let target = &snapshot.targets[idx];
                if is_covered_by_eviction(target, &evicted_roots) {
                    continue;
                }
                let action = build_evict_action(
                    EvictRule::R5PressureLru,
                    target,
                    &snapshot.targets,
                    &index_by_root,
                    CompactString::from(format!(
                        "pressure_lru_{}",
                        worktree_tier_label(target.worktree_kind)
                    )),
                );
                // Replace any redundant sweep or already-queued descendant eviction actions
                // (e.g. an older nested child selected earlier by R4 or R5) with the single
                // parent eviction so bytes are never double-counted and child removal never
                // bumps the parent directory's mtime before parent eviction revalidates.
                let dropped_sweep_bytes: u64 = sweep_actions_by_target
                    .iter()
                    .filter(|(root, _)| root.starts_with(&target.root))
                    .map(|(_, a)| a.estimated_allocated_bytes())
                    .fold(0u64, u64::saturating_add);
                sweep_actions_by_target.retain(|(root, _)| !root.starts_with(&target.root));

                let dropped_r5_bytes: u64 = r5_actions
                    .iter()
                    .filter(|a| a.target_root().starts_with(&target.root))
                    .map(ReclaimAction::estimated_allocated_bytes)
                    .fold(0u64, u64::saturating_add);
                r5_actions.retain(|a| !a.target_root().starts_with(&target.root));

                let dropped_r1_r4_bytes: u64 = evict_r1_r4_actions
                    .iter()
                    .filter(|a| a.target_root().starts_with(&target.root))
                    .map(ReclaimAction::estimated_allocated_bytes)
                    .fold(0u64, u64::saturating_add);
                evict_r1_r4_actions.retain(|a| !a.target_root().starts_with(&target.root));

                let dropped_bytes = dropped_sweep_bytes
                    .saturating_add(dropped_r5_bytes)
                    .saturating_add(dropped_r1_r4_bytes);
                let total_evict_bytes = action.estimated_allocated_bytes();
                projected_free = projected_free
                    .saturating_sub(dropped_bytes)
                    .saturating_add(total_evict_bytes);

                evicted_roots.insert(target.root.clone());
                r5_actions.push(action);
            }
        }
    }

    // Dual staging crash recovery runs first (skipping internal staging dirs already inside a
    // target scheduled for full eviction so unlinking them doesn't bump target_root's mtime).
    let mut actions: Vec<ReclaimAction> = Vec::new();
    for staging in &snapshot.leftover_staging {
        let subsumed_by_eviction = evicted_roots
            .iter()
            .any(|root| staging.staging_dir.starts_with(root));
        if !subsumed_by_eviction && !any_process_inside(processes, &staging.staging_dir) {
            actions.push(ReclaimAction::ReapLeftoverStaging {
                staging_dir: staging.staging_dir.clone(),
                expected_dev: staging.expected_dev,
            });
        }
    }

    actions.extend(evict_r1_r4_actions);
    actions.extend(sweep_actions_by_target.into_iter().map(|(_, a)| a));
    actions.extend(r5_actions);

    let estimated_allocated_bytes = actions
        .iter()
        .map(ReclaimAction::estimated_allocated_bytes)
        .fold(0u64, u64::saturating_add);

    ReclaimPlan {
        generated_at_unix: snapshot.captured_at_unix,
        disk: snapshot.disk.clone(),
        pressure,
        hold_active,
        actions,
        estimated_allocated_bytes,
    }
}

pub(crate) fn r5_headroom_target(pressure: DiskPressure, config: &Config) -> Option<u64> {
    match pressure {
        DiskPressure::Calm | DiskPressure::Elevated => None,
        DiskPressure::High => Some(config.pressure.r5_high_target_bytes),
        DiskPressure::Critical => Some(config.pressure.r5_critical_target_bytes),
    }
}

fn r5_priority_tier(kind: WorktreeKind) -> u8 {
    match kind {
        WorktreeKind::LinkedWorktree => 0,
        WorktreeKind::NonGit => 1,
        WorktreeKind::MainCheckout => 2,
    }
}

fn worktree_tier_label(kind: WorktreeKind) -> &'static str {
    match kind {
        WorktreeKind::LinkedWorktree => "linked_worktree",
        WorktreeKind::NonGit => "non_git",
        WorktreeKind::MainCheckout => "main_checkout",
    }
}

fn can_evict_target(
    idx: usize,
    target: &CargoTarget,
    verdicts: &[SafetyVerdict],
    index_by_root: &HashMap<&Path, usize>,
    evicted_roots: &HashSet<PathBuf>,
) -> bool {
    if !matches!(verdicts.get(idx), Some(SafetyVerdict::Eligible)) {
        return false;
    }
    if is_covered_by_eviction(target, evicted_roots) {
        return false;
    }
    // Belt-and-suspenders nested target invariant (Section 2.2):
    // full eviction of a parent target is forbidden unless ALL nested children are also Eligible.
    target.nested_target_roots.iter().all(|child| {
        index_by_root
            .get(child.as_path())
            .and_then(|&cidx| verdicts.get(cidx))
            .is_some_and(|v| matches!(v, SafetyVerdict::Eligible))
    })
}

fn is_covered_by_eviction(target: &CargoTarget, evicted_roots: &HashSet<PathBuf>) -> bool {
    if evicted_roots.contains(&target.root) {
        return true;
    }
    if target
        .parent_target
        .as_deref()
        .is_some_and(|p| evicted_roots.contains(p))
    {
        return true;
    }
    evicted_roots
        .iter()
        .any(|evicted| target.root.starts_with(evicted))
}

fn build_evict_action(
    rule: EvictRule,
    target: &CargoTarget,
    all_targets: &[CargoTarget],
    index_by_root: &HashMap<&Path, usize>,
    reason: CompactString,
) -> ReclaimAction {
    let mut all_locks = Vec::new();
    let mut total_bytes = target.allocated_bytes;
    let mut max_activity = target.last_activity_unix;

    collect_target_locks(target, &mut all_locks);
    let mut visited: HashSet<&Path> = HashSet::new();
    visited.insert(target.root.as_path());
    let mut queue: VecDeque<&Path> = target
        .nested_target_roots
        .iter()
        .map(PathBuf::as_path)
        .collect();
    while let Some(child_root) = queue.pop_front() {
        if !visited.insert(child_root) {
            continue;
        }
        if let Some(&cidx) = index_by_root.get(child_root) {
            let child = &all_targets[cidx];
            collect_target_locks(child, &mut all_locks);
            total_bytes = total_bytes.saturating_add(child.allocated_bytes);
            max_activity = max_activity.max(child.last_activity_unix);
            for grandchild in &child.nested_target_roots {
                queue.push_back(grandchild.as_path());
            }
        }
    }
    all_locks.sort();
    all_locks.dedup();

    ReclaimAction::EvictTarget {
        rule,
        target_root: target.root.clone(),
        target_dev: target.dev_id,
        target_ino: target.ino,
        expected_root_mtime_unix: target.root_mtime_unix,
        expected_activity_unix: max_activity,
        worktree_root: target.worktree_root().map(Path::to_path_buf),
        all_locks,
        estimated_allocated_bytes: total_bytes,
        reason,
    }
}

fn collect_target_locks(target: &CargoTarget, out: &mut Vec<PathBuf>) {
    if let Some(root_lock) = &target.root_lock_file {
        out.push(root_lock.clone());
    }
    for profile in &target.profiles {
        for lock in &profile.lock_files {
            out.push(lock.clone());
        }
        let inc_root = target.root.join(&profile.rel_path).join("incremental");
        for inc_dir in &profile.incremental_dirs {
            let crate_dir = inc_root.join(inc_dir.dir_name.as_str());
            for sess in &inc_dir.sessions {
                if let Some(lf) = &sess.lock_file {
                    out.push(crate_dir.join(lf.as_str()));
                }
            }
        }
    }
    if let Some(doc) = &target.doc_dir
        && let Some(lock) = &doc.lock_file
    {
        out.push(lock.clone());
    }
}

fn any_process_inside(snapshot: &ProcessSnapshot, dir: &Path) -> bool {
    let prefix = PathPrefix::new(dir);
    snapshot.processes.iter().any(|proc_entry| {
        if snapshot.self_pid != 0 && proc_entry.pid == snapshot.self_pid {
            return false;
        }
        snapshot.cwd_has_prefix(proc_entry, &prefix)
            || snapshot.any_open_has_prefix(proc_entry, &prefix)
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use compact_str::CompactString;
    use smallvec::SmallVec;

    use super::plan;
    use crate::config::Config;
    use crate::model::{
        BuildUnit, BuildUnitId, CargoTarget, DiskPressure, DiskStats, EvictRule, GIB, GitDiscovery,
        GitInspection, LeftoverStaging, PlanMode, ProcessSnapshot, ProfileDir, ProtectedReason,
        ReclaimAction, ReclaimHoldState, ReclaimProfile, SafetyVerdict, ScanSnapshot, TargetLayout,
        TargetOrigin, TestProcessEntry, UnitMetadata, WorktreeKind,
    };
    use crate::state::State;

    const NOW: u64 = 1_800_000_000;
    const HOUR: u64 = 3600;

    fn mk_target_with(
        root: &str,
        kind: WorktreeKind,
        age_secs: u64,
        bytes: u64,
        merged: Option<bool>,
    ) -> CargoTarget {
        let root_path = PathBuf::from(root);
        let wt_root = root_path.parent().unwrap().to_path_buf();
        let git = match kind {
            WorktreeKind::NonGit => GitDiscovery::NotInGitRepo,
            WorktreeKind::MainCheckout | WorktreeKind::LinkedWorktree => {
                GitDiscovery::Inspected(GitInspection {
                    repo_common_dir: PathBuf::from("/repo/.git"),
                    worktree_root: wt_root.clone(),
                    worktree_kind: kind,
                    worktree_dir_missing: false,
                    is_dirty: false,
                    git_op_in_progress: false,
                    worktree_locked: false,
                    branch_merged_into_default: merged,
                    has_tracked_files_in_target: false,
                })
            }
        };
        CargoTarget {
            root: root_path,
            dev_id: 1,
            ino: 10,
            origin: TargetOrigin::VerifiedCargoTag,
            layout: TargetLayout::BuildDirV2,
            symlink_or_mount_boundary: false,
            has_unverified_top_entries: false,
            has_pin_marker: false,
            parent_target: None,
            nested_target_roots: vec![],
            worktree_kind: kind,
            git,
            project_dir: Some(wt_root),
            profiles: vec![ProfileDir {
                name: CompactString::new("debug"),
                rel_path: PathBuf::from("debug"),
                layout: TargetLayout::BuildDirV2,
                lock_files: SmallVec::new(),
                locked_now: false,
                fingerprint_corrupt: false,
                v2_unit_count: 0,
                v1_unit_count: 0,
                incremental_dir_count: 0,
                v2_units: vec![],
                v1_units: vec![],
                dep_fp_pool: vec![],
                incremental_dirs: vec![],
                profile_mtime_unix: NOW - age_secs,
                inc_root_mtime_unix: NOW - age_secs,
                allocated_bytes: bytes,
                last_activity_unix: NOW - age_secs,
            }],
            doc_dir: None,
            root_lock_file: None,
            root_locked_now: false,
            root_mtime_unix: NOW - age_secs,
            allocated_bytes: bytes,
            last_activity_unix: NOW - age_secs,
        }
    }

    #[test]
    fn global_fail_closed_produces_zero_actions_when_lsof_or_mounts_unavailable() {
        let snap = ScanSnapshot {
            captured_at_unix: NOW,
            disk: DiskStats {
                mount: PathBuf::from("/System/Volumes/Data"),
                total_bytes: 460 * GIB,
                free_bytes: 100 * GIB,
                local_snapshots: Some(vec![]),
            },
            processes: None,
            process_snapshot_error: Some("lsof failed".to_owned()),
            mount_table_available: true,
            mount_table_error: None,
            targets: vec![],
            walk_partial: false,
            leftover_staging: vec![LeftoverStaging {
                staging_dir: PathBuf::from("/tmp/.targetwarden-reap.1"),
                expected_dev: 1,
            }],
            scanned_roots: vec![],
        };
        let p = plan(
            &snap,
            &[],
            &State::new_default(),
            &Config::default(),
            DiskPressure::Calm,
            PlanMode {
                profile: ReclaimProfile::Full,
                ignore_snapshot_hold: false,
            },
        );
        assert!(p.actions.is_empty());
    }

    #[test]
    fn plans_crash_recovery_and_sweep_while_skipping_protected_targets_and_busy_staging() {
        let mut t_a = mk_target_with("/a/target", WorktreeKind::NonGit, 10_000, 4096, None);
        t_a.profiles[0].v2_units.push(BuildUnit {
            id: BuildUnitId::V2 {
                pkg: CompactString::new("aborted"),
                unit_hash: CompactString::new("0123456789abcdef"),
            },
            metadata: UnitMetadata::Incomplete {
                mtime_unix: NOW - 10_000,
            },
            v1: None,
            allocated_bytes: 4096,
        });
        let t_b = mk_target_with("/b/target", WorktreeKind::NonGit, 10_000, 4096, None);

        let snap = ScanSnapshot {
            captured_at_unix: NOW,
            disk: DiskStats {
                mount: PathBuf::from("/System/Volumes/Data"),
                total_bytes: 460 * GIB,
                free_bytes: 100 * GIB,
                local_snapshots: Some(vec![]),
            },
            processes: Some(ProcessSnapshot::from_test_entries(
                NOW,
                1,
                vec![TestProcessEntry {
                    pid: 42,
                    comm: CompactString::new("cat"),
                    exe_path: None,
                    cwd: None,
                    open_paths: vec![PathBuf::from("/tmp/.targetwarden-reap.busy/file")],
                }],
            )),
            process_snapshot_error: None,
            mount_table_available: true,
            mount_table_error: None,
            targets: vec![t_a, t_b],
            walk_partial: false,
            leftover_staging: vec![
                LeftoverStaging {
                    staging_dir: PathBuf::from("/tmp/.targetwarden-reap.free"),
                    expected_dev: 1,
                },
                LeftoverStaging {
                    staging_dir: PathBuf::from("/tmp/.targetwarden-reap.busy"),
                    expected_dev: 1,
                },
            ],
            scanned_roots: vec![],
        };

        let mut prot = SmallVec::new();
        prot.push(ProtectedReason::PinnedFull);
        let verdicts = vec![SafetyVerdict::Eligible, SafetyVerdict::Protected(prot)];

        let p = plan(
            &snap,
            &verdicts,
            &State::new_default(),
            &Config::default(),
            DiskPressure::Calm,
            PlanMode {
                profile: ReclaimProfile::SweepOnly,
                ignore_snapshot_hold: false,
            },
        );
        assert_eq!(p.actions.len(), 2);
        assert!(matches!(
            &p.actions[0],
            ReclaimAction::ReapLeftoverStaging { staging_dir, .. }
                if staging_dir == Path::new("/tmp/.targetwarden-reap.free")
        ));
        assert!(matches!(
            &p.actions[1],
            ReclaimAction::SweepBuildUnits { target_root, .. }
                if target_root == Path::new("/a/target")
        ));
    }

    #[test]
    fn r5_respects_priority_tiers_lru_headroom_stop_and_snapshot_hold() {
        let cfg = Config::default();
        // High pressure: free = 40 GiB, headroom target = 55 GiB (needs 15 GiB).
        // Candidates:
        // - MainCheckout (10 GiB, 48h old) -> tier 2
        // - NonGit old (8 GiB, 10h old) -> tier 1 (LRU first)
        // - NonGit new (10 GiB, 2h old) -> tier 1 (LRU second)
        // - LinkedWorktree unmerged 1h old (not R4 since High R4=2h, eligible for R5! 8 GiB) -> tier 0
        // Expected R5 order: LinkedWorktree (8 GiB -> 48 GiB) -> NonGit old (8 GiB -> 56 GiB >= 55 GiB STOP!)
        // NonGit new and MainCheckout MUST NOT be scheduled!
        let targets = vec![
            mk_target_with(
                "/main/target",
                WorktreeKind::MainCheckout,
                48 * HOUR,
                10 * GIB,
                None,
            ),
            mk_target_with(
                "/nongit_new/target",
                WorktreeKind::NonGit,
                2 * HOUR,
                10 * GIB,
                None,
            ),
            mk_target_with(
                "/nongit_old/target",
                WorktreeKind::NonGit,
                10 * HOUR,
                8 * GIB,
                None,
            ),
            mk_target_with(
                "/wt1/target",
                WorktreeKind::LinkedWorktree,
                HOUR,
                8 * GIB,
                Some(false),
            ),
        ];
        let verdicts = vec![SafetyVerdict::Eligible; targets.len()];
        let snap = ScanSnapshot {
            captured_at_unix: NOW,
            disk: DiskStats {
                mount: PathBuf::from("/System/Volumes/Data"),
                total_bytes: 460 * GIB,
                free_bytes: 40 * GIB,
                local_snapshots: Some(vec![]),
            },
            processes: Some(ProcessSnapshot::empty(NOW, 1)),
            process_snapshot_error: None,
            mount_table_available: true,
            mount_table_error: None,
            targets,
            walk_partial: false,
            leftover_staging: vec![],
            scanned_roots: vec![],
        };

        let p = plan(
            &snap,
            &verdicts,
            &State::new_default(),
            &cfg,
            DiskPressure::High,
            PlanMode {
                profile: ReclaimProfile::Full,
                ignore_snapshot_hold: false,
            },
        );
        assert_eq!(p.actions.len(), 2);
        assert!(matches!(
            &p.actions[0],
            ReclaimAction::EvictTarget {
                rule: EvictRule::R5PressureLru,
                target_root,
                ..
            } if target_root == Path::new("/wt1/target")
        ));
        assert!(matches!(
            &p.actions[1],
            ReclaimAction::EvictTarget {
                rule: EvictRule::R5PressureLru,
                target_root,
                ..
            } if target_root == Path::new("/nongit_old/target")
        ));

        // With active ReclaimHoldState: R5 pauses completely while R1 still runs!
        let mut hold_state = State::new_default();
        hold_state.reclaim_hold = Some(ReclaimHoldState {
            detected_at_unix: NOW - 600,
            reclaimed_allocated_bytes: 6 * GIB,
            observed_free_gain_bytes: 0,
            free_bytes_at_detection: 40 * GIB,
            pressure_at_detection: DiskPressure::High,
            snapshots_at_detection: vec![],
        });
        let p_held = plan(
            &snap,
            &verdicts,
            &hold_state,
            &cfg,
            DiskPressure::High,
            PlanMode {
                profile: ReclaimProfile::Full,
                ignore_snapshot_hold: false,
            },
        );
        assert!(p_held.actions.is_empty());
        assert!(p_held.hold_active);

        // `--ignore-snapshot-hold` bypasses hold
        let p_ignored = plan(
            &snap,
            &verdicts,
            &hold_state,
            &cfg,
            DiskPressure::High,
            PlanMode {
                profile: ReclaimProfile::Full,
                ignore_snapshot_hold: true,
            },
        );
        assert_eq!(p_ignored.actions.len(), 2);
    }

    #[test]
    fn r1_and_r4_evict_dead_and_cooled_worktrees_and_subsume_nested_targets() {
        let cfg = Config::default();
        let mut parent = mk_target_with(
            "/wt_merged/target",
            WorktreeKind::LinkedWorktree,
            HOUR,
            4 * GIB,
            Some(true),
        );
        let mut child = mk_target_with(
            "/wt_merged/target/grpc-codegen",
            WorktreeKind::LinkedWorktree,
            HOUR,
            GIB,
            Some(true),
        );
        parent.nested_target_roots = vec![child.root.clone()];
        child.parent_target = Some(parent.root.clone());

        let cooled_wt = mk_target_with(
            "/wt_cooled/target",
            WorktreeKind::LinkedWorktree,
            80 * HOUR,
            2 * GIB,
            Some(false),
        );

        let snap = ScanSnapshot {
            captured_at_unix: NOW,
            disk: DiskStats {
                mount: PathBuf::from("/System/Volumes/Data"),
                total_bytes: 460 * GIB,
                free_bytes: 100 * GIB,
                local_snapshots: Some(vec![]),
            },
            processes: Some(ProcessSnapshot::empty(NOW, 1)),
            process_snapshot_error: None,
            mount_table_available: true,
            mount_table_error: None,
            targets: vec![parent, child, cooled_wt],
            walk_partial: false,
            leftover_staging: vec![],
            scanned_roots: vec![],
        };
        let verdicts = vec![SafetyVerdict::Eligible; 3];

        let p = plan(
            &snap,
            &verdicts,
            &State::new_default(),
            &cfg,
            DiskPressure::Calm,
            PlanMode {
                profile: ReclaimProfile::Full,
                ignore_snapshot_hold: false,
            },
        );
        // Only 2 EvictTarget actions (parent subsumes nested child with combined 5 GiB!)
        assert_eq!(p.actions.len(), 2);
        assert!(matches!(
            &p.actions[0],
            ReclaimAction::EvictTarget {
                rule: EvictRule::R1DeadWorktree,
                target_root,
                estimated_allocated_bytes,
                ..
            } if target_root == Path::new("/wt_merged/target") && *estimated_allocated_bytes == 5 * GIB
        ));
        assert!(matches!(
            &p.actions[1],
            ReclaimAction::EvictTarget {
                rule: EvictRule::R4CooledWorktree,
                target_root,
                ..
            } if target_root == Path::new("/wt_cooled/target")
        ));
    }

    #[test]
    fn safety_plus_plan_evicts_linked_worktree_first_in_high_with_grandchildren() {
        let cfg = Config::default();
        let mut parent = mk_target_with(
            "/wt_deep/target",
            WorktreeKind::LinkedWorktree,
            HOUR,
            4 * GIB,
            Some(false),
        );
        let mut child = mk_target_with(
            "/wt_deep/target/a",
            WorktreeKind::LinkedWorktree,
            HOUR,
            2 * GIB,
            Some(false),
        );
        let mut grandchild = mk_target_with(
            "/wt_deep/target/a/b",
            WorktreeKind::LinkedWorktree,
            HOUR,
            2 * GIB,
            Some(false),
        );
        let grandchild_lock = PathBuf::from("/wt_deep/target/a/b/debug/.cargo-lock");
        grandchild.profiles[0]
            .lock_files
            .push(grandchild_lock.clone());
        child.nested_target_roots = vec![grandchild.root.clone()];
        grandchild.parent_target = Some(child.root.clone());
        parent.nested_target_roots = vec![child.root.clone()];
        child.parent_target = Some(parent.root.clone());

        let nongit = mk_target_with(
            "/nongit/target",
            WorktreeKind::NonGit,
            10 * HOUR,
            8 * GIB,
            None,
        );

        let snap = ScanSnapshot {
            captured_at_unix: NOW,
            disk: DiskStats {
                mount: PathBuf::from("/System/Volumes/Data"),
                total_bytes: 460 * GIB,
                free_bytes: 40 * GIB,
                local_snapshots: Some(vec![]),
            },
            processes: Some(ProcessSnapshot::empty(NOW, 1)),
            process_snapshot_error: None,
            mount_table_available: true,
            mount_table_error: None,
            targets: vec![parent, child, grandchild, nongit],
            walk_partial: false,
            leftover_staging: vec![LeftoverStaging {
                staging_dir: PathBuf::from("/wt_deep/target/.targetwarden-reap.1.0"),
                expected_dev: 1,
            }],
            scanned_roots: vec![],
        };

        let state = State::new_default();
        let verdicts = crate::safety::evaluate_all(&snap, &state, &cfg, DiskPressure::High, false);
        let p = plan(
            &snap,
            &verdicts,
            &state,
            &cfg,
            DiskPressure::High,
            PlanMode {
                profile: ReclaimProfile::Full,
                ignore_snapshot_hold: false,
            },
        );
        // Subsumed internal staging dir must be skipped; Tier 0 LinkedWorktree (8 GiB total incl grandchild)
        // must be evicted BEFORE Tier 1 NonGit, carrying the grandchild lock!
        assert_eq!(p.actions.len(), 2);
        match &p.actions[0] {
            ReclaimAction::EvictTarget {
                rule: EvictRule::R5PressureLru,
                target_root,
                all_locks,
                estimated_allocated_bytes,
                ..
            } => {
                assert_eq!(target_root, Path::new("/wt_deep/target"));
                assert_eq!(*estimated_allocated_bytes, 8 * GIB);
                assert!(all_locks.contains(&grandchild_lock));
            }
            other => panic!("expected R5 EvictTarget on /wt_deep/target, got {other:?}"),
        }
        assert!(matches!(
            &p.actions[1],
            ReclaimAction::EvictTarget {
                rule: EvictRule::R5PressureLru,
                target_root,
                ..
            } if target_root == Path::new("/nongit/target")
        ));
    }

    #[test]
    fn r5_subsumes_older_nested_child_without_double_counting_bytes_or_duplicating_actions() {
        let cfg = Config::default();
        // High pressure: free = 40 GiB, headroom target = 55 GiB (needs 15 GiB).
        // Nested child is OLDER (5h, 10 GiB) than parent (1h, 2 GiB), plus another NonGit target (4 GiB).
        // Without subsumption, child (10 GiB) + parent (12 GiB) would double-count 10 GiB = 22 GiB
        // and falsely stop before NonGit (4 GiB), while also emitting two colliding EvictTarget actions.
        let mut parent = mk_target_with(
            "/wt/target",
            WorktreeKind::LinkedWorktree,
            HOUR,
            2 * GIB,
            Some(false),
        );
        let mut child = mk_target_with(
            "/wt/target/grpc-codegen",
            WorktreeKind::LinkedWorktree,
            5 * HOUR,
            10 * GIB,
            Some(false),
        );
        parent.nested_target_roots = vec![child.root.clone()];
        child.parent_target = Some(parent.root.clone());
        let nongit = mk_target_with(
            "/other/target",
            WorktreeKind::NonGit,
            2 * HOUR,
            4 * GIB,
            None,
        );

        let snap = ScanSnapshot {
            captured_at_unix: NOW,
            disk: DiskStats {
                mount: PathBuf::from("/System/Volumes/Data"),
                total_bytes: 460 * GIB,
                free_bytes: 40 * GIB,
                local_snapshots: Some(vec![]),
            },
            processes: Some(ProcessSnapshot::empty(NOW, 1)),
            process_snapshot_error: None,
            mount_table_available: true,
            mount_table_error: None,
            targets: vec![parent, child, nongit],
            walk_partial: false,
            leftover_staging: vec![],
            scanned_roots: vec![],
        };
        let verdicts = vec![SafetyVerdict::Eligible; 3];
        let p = plan(
            &snap,
            &verdicts,
            &State::new_default(),
            &cfg,
            DiskPressure::High,
            PlanMode {
                profile: ReclaimProfile::Full,
                ignore_snapshot_hold: false,
            },
        );
        // Must emit ONLY parent (12 GiB, subsuming child) + nongit (4 GiB) = 16 GiB (40 + 16 >= 55 GiB).
        assert_eq!(p.actions.len(), 2);
        assert_eq!(p.estimated_allocated_bytes, 16 * GIB);
        assert!(matches!(
            &p.actions[0],
            ReclaimAction::EvictTarget {
                rule: EvictRule::R5PressureLru,
                target_root,
                estimated_allocated_bytes,
                ..
            } if target_root == Path::new("/wt/target") && *estimated_allocated_bytes == 12 * GIB
        ));
        assert!(matches!(
            &p.actions[1],
            ReclaimAction::EvictTarget {
                rule: EvictRule::R5PressureLru,
                target_root,
                estimated_allocated_bytes,
                ..
            } if target_root == Path::new("/other/target") && *estimated_allocated_bytes == 4 * GIB
        ));
    }
}
