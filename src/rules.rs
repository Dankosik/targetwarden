//! Functional Core (Layer 3): pure deterministic reclamation planner (`R1`–`R5`).
//!
//! Allowed dependencies: `model`, `config`, `state`, `pressure`, `safety`, `sweep`.

use std::path::Path;

use crate::config::Config;
use crate::model::{
    DiskPressure, PlanMode, ProcessSnapshot, ReclaimAction, ReclaimPlan, SafetyVerdict,
    ScanSnapshot,
};
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

    let mut actions: Vec<ReclaimAction> = Vec::new();

    // 1. Dual staging crash recovery runs first when no process holds FDs inside the staging dir.
    for staging in &snapshot.leftover_staging {
        if !any_process_inside(processes, &staging.staging_dir) {
            actions.push(ReclaimAction::ReapLeftoverStaging {
                staging_dir: staging.staging_dir.clone(),
                expected_dev: staging.expected_dev,
            });
        }
    }

    // 2. Surgical intra-target sweep (`R2` build/doc + `R3` incremental) for every non-Protected target.
    for (target, verdict) in snapshot.targets.iter().zip(verdicts) {
        let pinned_paths: &[std::path::PathBuf] = match verdict {
            SafetyVerdict::Eligible => &[],
            SafetyVerdict::SweepOnly {
                pinned_unit_paths, ..
            } => pinned_unit_paths.as_slice(),
            SafetyVerdict::Protected(_) => continue,
        };
        actions.extend(sweep::plan_target_sweeps(
            target,
            pinned_paths,
            snapshot.captured_at_unix,
            pressure,
            config,
        ));
    }

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

fn any_process_inside(snapshot: &ProcessSnapshot, dir: &Path) -> bool {
    snapshot.processes.iter().any(|proc_entry| {
        if snapshot.self_pid != 0 && proc_entry.pid == snapshot.self_pid {
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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use compact_str::CompactString;
    use smallvec::SmallVec;

    use super::plan;
    use crate::config::Config;
    use crate::model::{
        BuildUnit, BuildUnitId, CargoTarget, DiskPressure, DiskStats, GIB, GitDiscovery,
        LeftoverStaging, PlanMode, ProcessEntry, ProcessSnapshot, ProfileDir, ProtectedReason,
        ReclaimAction, ReclaimProfile, SafetyVerdict, ScanSnapshot, TargetLayout, TargetOrigin,
        UnitMetadata, WorktreeKind,
    };
    use crate::state::State;

    const NOW: u64 = 1_800_000_000;

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
            mount_table_available: true,
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
                profile: ReclaimProfile::SweepOnly,
                ignore_snapshot_hold: false,
            },
        );
        assert!(p.actions.is_empty());
    }

    #[test]
    fn plans_crash_recovery_and_sweep_while_skipping_protected_targets_and_busy_staging() {
        let mk_target = |root: &str| CargoTarget {
            root: PathBuf::from(root),
            dev_id: 1,
            ino: 10,
            origin: TargetOrigin::VerifiedCargoTag,
            layout: TargetLayout::BuildDirV2,
            symlink_or_mount_boundary: false,
            has_unverified_top_entries: false,
            has_pin_marker: false,
            parent_target: None,
            nested_target_roots: vec![],
            worktree_kind: WorktreeKind::NonGit,
            git: GitDiscovery::NotInGitRepo,
            project_dir: None,
            profiles: vec![ProfileDir {
                name: CompactString::new("debug"),
                rel_path: PathBuf::from("debug"),
                layout: TargetLayout::BuildDirV2,
                lock_files: SmallVec::new(),
                locked_now: false,
                fingerprint_corrupt: false,
                v2_unit_count: 1,
                v1_unit_count: 0,
                incremental_dir_count: 0,
                v2_units: vec![BuildUnit {
                    id: BuildUnitId::V2 {
                        pkg: CompactString::new("aborted"),
                        unit_hash: CompactString::new("0123456789abcdef"),
                    },
                    pkg_group: CompactString::new("aborted"),
                    metadata: UnitMetadata::Incomplete {
                        mtime_unix: NOW - 10_000,
                    },
                    v1_build_dir: None,
                    v1_dep_entries: vec![],
                    allocated_bytes: 4096,
                }],
                v1_units: vec![],
                incremental_dirs: vec![],
                allocated_bytes: 4096,
                last_activity_unix: NOW - 10_000,
            }],
            doc_dir: None,
            allocated_bytes: 4096,
            last_activity_unix: NOW - 10_000,
        };

        let snap = ScanSnapshot {
            captured_at_unix: NOW,
            disk: DiskStats {
                mount: PathBuf::from("/System/Volumes/Data"),
                total_bytes: 460 * GIB,
                free_bytes: 100 * GIB,
                local_snapshots: Some(vec![]),
            },
            processes: Some(ProcessSnapshot {
                captured_at_unix: NOW,
                self_pid: 1,
                processes: vec![ProcessEntry {
                    pid: 42,
                    comm: CompactString::new("cat"),
                    exe_path: None,
                    cwd: None,
                    open_paths: vec![PathBuf::from("/tmp/.targetwarden-reap.busy/file")],
                }],
            }),
            mount_table_available: true,
            targets: vec![mk_target("/a/target"), mk_target("/b/target")],
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
}
